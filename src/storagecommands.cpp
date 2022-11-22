/*
// Copyright (c) 2017-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "storagecommands.hpp"

#include "commandutils.hpp"
#include "sdrutils.hpp"
#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/process.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <fstream>

static constexpr bool DEBUG = false;
namespace ipmi
{
using SDRObjectType =
    boost::container::flat_map<uint16_t, std::vector<uint8_t>>;
extern SDRObjectType sensorDataRecords;

namespace storage
{

constexpr static const size_t maxMessageSize = 64;
constexpr static const size_t maxFruSdrNameSize = 16;
using ObjectType = boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, DbusVariant>>;
using ManagedObjectType =
    boost::container::flat_map<sdbusplus::message::object_path, ObjectType>;
using ManagedEntry = std::pair<sdbusplus::message::object_path, ObjectType>;

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";
constexpr static const char* entityManagerServiceName =
    "xyz.openbmc_project.EntityManager";
// SEL ipmi event add in dbus
static constexpr char const *ipmiSELObj = "xyz.openbmc_project.Logging.IPMI";
static constexpr char const *ipmiSELPath = "/xyz/openbmc_project/Logging/IPMI";
static constexpr char const *ipmiSELAddInterface = "xyz.openbmc_project.Logging.IPMI";
static constexpr uint16_t selBMCGenID = 0x0020;
constexpr static const size_t writeTimeoutSeconds = 10;
constexpr static const char* chassisTypeRackMount = "23";

// event direction is bit[7] of eventType where 1b = Deassertion event
constexpr static const uint8_t deassertionEvent = 0x80;

static std::vector<uint8_t> fruCache;
static uint16_t cacheBus = 0xFFFF;
static uint8_t cacheAddr = 0XFF;
static uint8_t lastDevId = 0xFF;

static uint16_t writeBus = 0xFFFF;
static uint8_t writeAddr = 0XFF;

std::unique_ptr<phosphor::Timer> writeTimer = nullptr;
static std::vector<sdbusplus::bus::match::match> fruMatches;

ManagedObjectType frus;

// we unfortunately have to build a map of hashes in case there is a
// collision to verify our dev-id
boost::container::flat_map<uint8_t, std::pair<uint16_t, uint8_t>> deviceHashes;

void registerStorageFunctions() __attribute__((constructor));

bool writeFru()
{
    if (writeBus == 0xFFFF && writeAddr == 0xFF)
    {
        return true;
    }
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    sdbusplus::message::message writeFru = dbus->new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "WriteFru");
    writeFru.append(writeBus, writeAddr, fruCache);
    try
    {
        sdbusplus::message::message writeFruResp = dbus->call(writeFru);
    }
    catch (sdbusplus::exception_t&)
    {
        // todo: log sel?
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "error writing fru");
        return false;
    }
    writeBus = 0xFFFF;
    writeAddr = 0xFF;
    return true;
}

void createTimers()
{
    writeTimer = std::make_unique<phosphor::Timer>(writeFru);
}

void recalculateHashes()
{

    deviceHashes.clear();
    // hash the object paths to create unique device id's. increment on
    // collision
    std::hash<std::string> hasher;
    for (const auto& fru : frus)
    {
        auto fruIface = fru.second.find("xyz.openbmc_project.FruDevice");
        if (fruIface == fru.second.end())
        {
            continue;
        }

        auto busFind = fruIface->second.find("BUS");
        auto addrFind = fruIface->second.find("ADDRESS");
        if (busFind == fruIface->second.end() ||
            addrFind == fruIface->second.end())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "fru device missing Bus or Address",
                phosphor::logging::entry("FRU=%s", fru.first.str.c_str()));
            continue;
        }

        uint16_t fruBus = std::get<uint32_t>(busFind->second);
        uint8_t fruAddr = std::get<uint32_t>(addrFind->second);
        auto chassisFind = fruIface->second.find("CHASSIS_TYPE");
        std::string chassisType;
        if (chassisFind != fruIface->second.end())
        {
            chassisType = std::get<std::string>(chassisFind->second);
        }

        uint8_t fruHash = 0;
        if (chassisType.compare(chassisTypeRackMount) != 0)
        {
            fruHash = hasher(fru.first.str);
            // can't be 0xFF based on spec, and 0 is reserved for baseboard
            if (fruHash == 0 || fruHash == 0xFF)
            {
                fruHash = 1;
            }
        }
        std::pair<uint16_t, uint8_t> newDev(fruBus, fruAddr);

        bool emplacePassed = false;
        while (!emplacePassed)
        {
            auto resp = deviceHashes.emplace(fruHash, newDev);
            emplacePassed = resp.second;
            if (!emplacePassed)
            {
                fruHash++;
                // can't be 0xFF based on spec, and 0 is reserved for
                // baseboard
                if (fruHash == 0XFF)
                {
                    fruHash = 0x1;
                }
            }
        }
    }
}

void replaceCacheFru(const std::shared_ptr<sdbusplus::asio::connection>& bus,
                     boost::asio::yield_context& yield,
                     const std::optional<std::string>& path = std::nullopt)
{
    boost::system::error_code ec;

    frus = bus->yield_method_call<ManagedObjectType>(
        yield, ec, fruDeviceServiceName, "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetMangagedObjects for fruDeviceServiceName failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        return;
    }
    recalculateHashes();
}

ipmi::Cc getFru(ipmi::Context::ptr ctx, uint8_t devId)
{
    if (lastDevId == devId && devId != 0xFF)
    {
        return ipmi::ccSuccess;
    }

    auto deviceFind = deviceHashes.find(devId);
    if (deviceFind == deviceHashes.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    fruCache.clear();

    cacheBus = deviceFind->second.first;
    cacheAddr = deviceFind->second.second;

    boost::system::error_code ec;

    fruCache = ctx->bus->yield_method_call<std::vector<uint8_t>>(
        ctx->yield, ec, fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "GetRawFru", cacheBus,
        cacheAddr);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Couldn't get raw fru",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        cacheBus = 0xFFFF;
        cacheAddr = 0xFF;
        return ipmi::ccResponseError;
    }

    lastDevId = devId;
    return ipmi::ccSuccess;
}

void writeFruIfRunning()
{
    if (!writeTimer->isRunning())
    {
        return;
    }
    writeTimer->stop();
    writeFru();
}

void startMatch(void)
{
    if (fruMatches.size())
    {
        return;
    }

    fruMatches.reserve(2);

    auto bus = getSdBus();
    fruMatches.emplace_back(*bus,
                            "type='signal',arg0path='/xyz/openbmc_project/"
                            "FruDevice/',member='InterfacesAdded'",
                            [](sdbusplus::message::message& message) {
                                sdbusplus::message::object_path path;
                                ObjectType object;
                                try
                                {
                                    message.read(path, object);
                                }
                                catch (sdbusplus::exception_t&)
                                {
                                    return;
                                }
                                auto findType = object.find(
                                    "xyz.openbmc_project.FruDevice");
                                if (findType == object.end())
                                {
                                    return;
                                }
                                writeFruIfRunning();
                                frus[path] = object;
                                recalculateHashes();
                                // Invalidate SDRs
                                sensorDataRecords.clear();
                                lastDevId = 0xFF;
                            });

    fruMatches.emplace_back(*bus,
                            "type='signal',arg0path='/xyz/openbmc_project/"
                            "FruDevice/',member='InterfacesRemoved'",
                            [](sdbusplus::message::message& message) {
                                sdbusplus::message::object_path path;
                                std::set<std::string> interfaces;
                                try
                                {
                                    message.read(path, interfaces);
                                }
                                catch (sdbusplus::exception_t&)
                                {
                                    return;
                                }
                                auto findType = interfaces.find(
                                    "xyz.openbmc_project.FruDevice");
                                if (findType == interfaces.end())
                                {
                                    return;
                                }
                                writeFruIfRunning();
                                frus.erase(path);
                                recalculateHashes();
                                // Invalidate SDRs
                                sensorDataRecords.clear();
                                lastDevId = 0xFF;
                            });

    // call once to populate
    boost::asio::spawn(*getIoContext(), [](boost::asio::yield_context yield) {
        replaceCacheFru(getSdBus(), yield);
    });
}

/** @brief implements the read FRU data command
 *  @param fruDeviceId        - FRU Device ID
 *  @param fruInventoryOffset - FRU Inventory Offset to write
 *  @param countToRead        - Count to read
 *
 *  @returns ipmi completion code plus response data
 *   - countWritten  - Count written
 */
ipmi::RspType<uint8_t,             // Count
              std::vector<uint8_t> // Requested data
              >
    ipmiStorageReadFruData(ipmi::Context::ptr ctx, uint8_t fruDeviceId,
                           uint16_t fruInventoryOffset, uint8_t countToRead)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    ipmi::Cc status = getFru(ctx, fruDeviceId);

    if (status != ipmi::ccSuccess)
    {
        return ipmi::response(status);
    }

    size_t fromFruByteLen = 0;
    if (countToRead + fruInventoryOffset < fruCache.size())
    {
        fromFruByteLen = countToRead;
    }
    else if (fruCache.size() > fruInventoryOffset)
    {
        fromFruByteLen = fruCache.size() - fruInventoryOffset;
    }
    else
    {
        return ipmi::responseReqDataLenExceeded();
    }

    std::vector<uint8_t> requestedData;

    requestedData.insert(
        requestedData.begin(), fruCache.begin() + fruInventoryOffset,
        fruCache.begin() + fruInventoryOffset + fromFruByteLen);

    return ipmi::responseSuccess(static_cast<uint8_t>(requestedData.size()),
                                 requestedData);
}

/** @brief implements the write FRU data command
 *  @param fruDeviceId        - FRU Device ID
 *  @param fruInventoryOffset - FRU Inventory Offset to write
 *  @param dataToWrite        - Data to write
 *
 *  @returns ipmi completion code plus response data
 *   - countWritten  - Count written
 */
ipmi::RspType<uint8_t>
    ipmiStorageWriteFruData(ipmi::Context::ptr ctx, uint8_t fruDeviceId,
                            uint16_t fruInventoryOffset,
                            std::vector<uint8_t>& dataToWrite)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    size_t writeLen = dataToWrite.size();

    ipmi::Cc status = getFru(ctx, fruDeviceId);
    if (status != ipmi::ccSuccess)
    {
        return ipmi::response(status);
    }
    int lastWriteAddr = fruInventoryOffset + writeLen;
    if (fruCache.size() < lastWriteAddr)
    {
        fruCache.resize(fruInventoryOffset + writeLen);
    }

    std::copy(dataToWrite.begin(), dataToWrite.begin() + writeLen,
              fruCache.begin() + fruInventoryOffset);

    bool atEnd = false;

    if (fruCache.size() >= sizeof(FRUHeader))
    {
        FRUHeader* header = reinterpret_cast<FRUHeader*>(fruCache.data());

        int areaLength = 0;
        int lastRecordStart = std::max(
            {header->internalOffset, header->chassisOffset, header->boardOffset,
             header->productOffset, header->multiRecordOffset});
        lastRecordStart *= 8; // header starts in are multiples of 8 bytes

        if (header->multiRecordOffset)
        {
            // This FRU has a MultiRecord Area
            uint8_t endOfList = 0;
            // Walk the MultiRecord headers until the last record
            while (!endOfList)
            {
                // The MSB in the second byte of the MultiRecord header signals
                // "End of list"
                endOfList = fruCache[lastRecordStart + 1] & 0x80;
                // Third byte in the MultiRecord header is the length
                areaLength = fruCache[lastRecordStart + 2];
                // This length is in bytes (not 8 bytes like other headers)
                areaLength += 5; // The length omits the 5 byte header
                if (!endOfList)
                {
                    // Next MultiRecord header
                    lastRecordStart += areaLength;
                }
            }
        }
        else
        {
            // This FRU does not have a MultiRecord Area
            // Get the length of the area in multiples of 8 bytes
            if (lastWriteAddr > (lastRecordStart + 1))
            {
                // second byte in record area is the length
                areaLength = fruCache[lastRecordStart + 1];
                areaLength *= 8; // it is in multiples of 8 bytes
            }
        }
        if (lastWriteAddr >= (areaLength + lastRecordStart))
        {
            atEnd = true;
        }
    }
    uint8_t countWritten = 0;

    writeBus = cacheBus;
    writeAddr = cacheAddr;
    if (atEnd)
    {
        // cancel timer, we're at the end so might as well send it
        writeTimer->stop();
        if (!writeFru())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        countWritten = std::min(fruCache.size(), static_cast<size_t>(0xFF));
    }
    else
    {
        // start a timer, if no further data is sent  to check to see if it is
        // valid
        writeTimer->start(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(writeTimeoutSeconds)));
        countWritten = 0;
    }

    return ipmi::responseSuccess(countWritten);
}

/** @brief implements the get FRU inventory area info command
 *  @param fruDeviceId  - FRU Device ID
 *
 *  @returns IPMI completion code plus response data
 *   - inventorySize - Number of possible allocation units
 *   - accessType    - Allocation unit size in bytes.
 */
ipmi::RspType<uint16_t, // inventorySize
              uint8_t>  // accessType
    ipmiStorageGetFruInvAreaInfo(ipmi::Context::ptr ctx, uint8_t fruDeviceId)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    ipmi::Cc ret = getFru(ctx, fruDeviceId);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    constexpr uint8_t accessType =
        static_cast<uint8_t>(GetFRUAreaAccessType::byte);

    return ipmi::responseSuccess(fruCache.size(), accessType);
}

ipmi_ret_t getFruSdrCount(ipmi::Context::ptr ctx, size_t& count)
{
    count = deviceHashes.size();
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrs(ipmi::Context::ptr ctx, size_t index,
                      get_sdr::SensorDataFruRecord& resp)
{
    if (deviceHashes.size() < index)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto device = deviceHashes.begin() + index;
    uint16_t& bus = device->second.first;
    uint8_t& address = device->second.second;

    boost::container::flat_map<std::string, DbusVariant>* fruData = nullptr;
    auto fru =
        std::find_if(frus.begin(), frus.end(),
                     [bus, address, &fruData](ManagedEntry& entry) {
                         auto findFruDevice =
                             entry.second.find("xyz.openbmc_project.FruDevice");
                         if (findFruDevice == entry.second.end())
                         {
                             return false;
                         }
                         fruData = &(findFruDevice->second);
                         auto findBus = findFruDevice->second.find("BUS");
                         auto findAddress =
                             findFruDevice->second.find("ADDRESS");
                         if (findBus == findFruDevice->second.end() ||
                             findAddress == findFruDevice->second.end())
                         {
                             return false;
                         }
                         if (std::get<uint32_t>(findBus->second) != bus)
                         {
                             return false;
                         }
                         if (std::get<uint32_t>(findAddress->second) != address)
                         {
                             return false;
                         }
                         return true;
                     });
    if (fru == frus.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    
    std::string name;

#ifdef USING_ENTITY_MANAGER_DECORATORS

    boost::container::flat_map<std::string, DbusVariant>* entityData = nullptr;

    // todo: this should really use caching, this is a very inefficient lookup
    boost::system::error_code ec;
    ManagedObjectType entities = ctx->bus->yield_method_call<ManagedObjectType>(
        ctx->yield, ec, entityManagerServiceName, "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetMangagedObjects for entityManagerServiceName failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    auto entity = std::find_if(
        entities.begin(), entities.end(),
        [bus, address, &entityData, &name](ManagedEntry& entry) {
            auto findFruDevice = entry.second.find(
                "xyz.openbmc_project.Inventory.Decorator.FruDevice");
            if (findFruDevice == entry.second.end())
            {
                return false;
            }

            // Integer fields added via Entity-Manager json are uint64_ts by
            // default.
            auto findBus = findFruDevice->second.find("Bus");
            auto findAddress = findFruDevice->second.find("Address");

            if (findBus == findFruDevice->second.end() ||
                findAddress == findFruDevice->second.end())
            {
                return false;
            }
            if ((std::get<uint64_t>(findBus->second) != bus) ||
                (std::get<uint64_t>(findAddress->second) != address))
            {
                return false;
            }

            auto fruName = findFruDevice->second.find("Name");
            if (fruName != findFruDevice->second.end())
            {
                name = std::get<std::string>(fruName->second);
            }

            // At this point we found the device entry and should return
            // true.
            auto findIpmiDevice = entry.second.find(
                "xyz.openbmc_project.Inventory.Decorator.Ipmi");
            if (findIpmiDevice != entry.second.end())
            {
                entityData = &(findIpmiDevice->second);
            }

            return true;
        });

    if (entity == entities.end())
    {
        if constexpr (DEBUG)
        {
            std::fprintf(stderr, "Ipmi or FruDevice Decorator interface "
                                 "not found for Fru\n");
        }
    }

#endif

    if (name.empty())
    {
        auto findProductName = fruData->find("BOARD_PRODUCT_NAME");
        auto findBoardName = fruData->find("PRODUCT_PRODUCT_NAME");
        if (findProductName != fruData->end())
        {
            name = std::get<std::string>(findProductName->second);
        }
        else if (findBoardName != fruData->end())
        {
            name = std::get<std::string>(findBoardName->second);
        }
        else
        {
            name = "UNKNOWN";
        }
    }

    if (name.size() > maxFruSdrNameSize)
    {
        name = name.substr(0, maxFruSdrNameSize);
    }
    size_t sizeDiff = maxFruSdrNameSize - name.size();

    resp.header.record_id_lsb = 0x0; // calling code is to implement these
    resp.header.record_id_msb = 0x0;
    resp.header.sdr_version = ipmiSdrVersion;
    resp.header.record_type = get_sdr::SENSOR_DATA_FRU_RECORD;
    resp.header.record_length = sizeof(resp.body) + sizeof(resp.key) - sizeDiff;
    resp.key.deviceAddress = 0x20;
    resp.key.fruID = device->first;
    resp.key.accessLun = 0x80; // logical / physical fru device
    resp.key.channelNumber = 0x0;
    resp.body.reserved = 0x0;
    resp.body.deviceType = 0x10;
    resp.body.deviceTypeModifier = 0x0;

    uint8_t entityID = 0;
    uint8_t entityInstance = 0x1;

#ifdef USING_ENTITY_MANAGER_DECORATORS
    if (entityData)
    {
        auto entityIdProperty = entityData->find("EntityId");
        auto entityInstanceProperty = entityData->find("EntityInstance");

        if (entityIdProperty != entityData->end())
        {
            entityID = static_cast<uint8_t>(
                std::get<uint64_t>(entityIdProperty->second));
        }
        if (entityInstanceProperty != entityData->end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProperty->second));
        }
    }
#endif

    resp.body.entityID = entityID;
    resp.body.entityInstance = entityInstance;

    resp.body.oem = 0x0;
    resp.body.deviceIDLen = name.size();
    name.copy(resp.body.deviceID, name.size());

    return IPMI_CC_OK;
}

std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId)
{
    std::vector<uint8_t> resp;
    if (index == 0)
    {
        Type12Record bmc = {};
        bmc.header.record_id_lsb = recordId;
        bmc.header.record_id_msb = recordId >> 8;
        bmc.header.sdr_version = ipmiSdrVersion;
        bmc.header.record_type = 0x12;
        bmc.header.record_length = 0x1b;
        bmc.slaveAddress = 0x20;
        bmc.channelNumber = 0;
        bmc.powerStateNotification = 0;
        bmc.deviceCapabilities = 0xBF;
        bmc.reserved = 0;
        bmc.entityID = 0x2E;
        bmc.entityInstance = 1;
        bmc.oem = 0;
        bmc.typeLengthCode = 0xD0;
        std::string bmcName = "Basbrd Mgmt Ctlr";
        std::copy(bmcName.begin(), bmcName.end(), bmc.name);
        uint8_t* bmcPtr = reinterpret_cast<uint8_t*>(&bmc);
        resp.insert(resp.end(), bmcPtr, bmcPtr + sizeof(Type12Record));
    }
    else if (index == 1)
    {
        Type12Record me = {};
        me.header.record_id_lsb = recordId;
        me.header.record_id_msb = recordId >> 8;
        me.header.sdr_version = ipmiSdrVersion;
        me.header.record_type = 0x12;
        me.header.record_length = 0x16;
        me.slaveAddress = 0x2C;
        me.channelNumber = 6;
        me.powerStateNotification = 0x24;
        me.deviceCapabilities = 0x21;
        me.reserved = 0;
        me.entityID = 0x2E;
        me.entityInstance = 2;
        me.oem = 0;
        me.typeLengthCode = 0xCB;
        std::string meName = "Mgmt Engine";
        std::copy(meName.begin(), meName.end(), me.name);
        uint8_t* mePtr = reinterpret_cast<uint8_t*>(&me);
        resp.insert(resp.end(), mePtr, mePtr + sizeof(Type12Record));
    }
    else
    {
        throw std::runtime_error("getType12SDRs:: Illegal index " +
                                 std::to_string(index));
    }

    return resp;
}

std::vector<uint8_t> getNMDiscoverySDR(uint16_t index, uint16_t recordId)
{
    std::vector<uint8_t> resp;
    if (index == 0)
    {
        NMDiscoveryRecord nm = {};
        nm.header.record_id_lsb = recordId;
        nm.header.record_id_msb = recordId >> 8;
        nm.header.sdr_version = ipmiSdrVersion;
        nm.header.record_type = 0xC0;
        nm.header.record_length = 0xB;
        nm.oemID0 = 0x57;
        nm.oemID1 = 0x1;
        nm.oemID2 = 0x0;
        nm.subType = 0x0D;
        nm.version = 0x1;
        nm.slaveAddress = 0x2C;
        nm.channelNumber = 0x60;
        nm.healthEventSensor = 0x19;
        nm.exceptionEventSensor = 0x18;
        nm.operationalCapSensor = 0x1A;
        nm.thresholdExceededSensor = 0x1B;

        uint8_t* nmPtr = reinterpret_cast<uint8_t*>(&nm);
        resp.insert(resp.end(), nmPtr, nmPtr + sizeof(NMDiscoveryRecord));
    }
    else
    {
        throw std::runtime_error("getNMDiscoverySDR:: Illegal index " +
                                 std::to_string(index));
    }

    return resp;
}

void registerStorageFunctions()
{
    createTimers();
    startMatch();


    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);
    // <READ FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReadFruData, ipmi::Privilege::User,
                          ipmiStorageReadFruData);

    // <WRITE FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdWriteFruData,
                          ipmi::Privilege::Operator, ipmiStorageWriteFruData);
}
} // namespace storage
} // namespace ipmi
