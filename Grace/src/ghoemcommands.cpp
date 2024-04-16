/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */






#include "ghoemcommands.hpp"

#include "gh-config.hpp"

#include <bits/stdc++.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <security/pam_appl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/process/child.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>
#include <boost/format.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

// IPMI OEM Major and Minor version
static constexpr uint8_t OEM_MAJOR_VER = 0x01;
static constexpr uint8_t OEM_MINOR_VER = 0x00;

// IPMI OEM USB Linux Gadget info
static constexpr uint16_t USB_VENDOR_ID = 0x0525;
static constexpr uint16_t USB_PRODUCT_ID = 0xA4A2;
static constexpr uint8_t USB_SERIAL_NUM = 0x00;

// GPU smbpbi object in dbus
static constexpr const char* gpuSMBPBIIntf =
    "xyz.openbmc_project.GpuMgr.Server";
static constexpr const char* gpuSMBPBIPath = "/xyz/openbmc_project/GpuMgr";

// BMC state object in dbus
static constexpr const char* bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr const char* currentBmcStateProp = "CurrentBMCState";
static constexpr const char* bmcStateReadyStr =
    "xyz.openbmc_project.State.BMC.BMCState.Ready";

// SEL policy in dbus
const char* selLogObj = "/xyz/openbmc_project/logging/settings";
const char* selLogIntf = "xyz.openbmc_project.Logging.Settings";

// PLDM policy in dbus
const char* pldmPollingObj = "/xyz/openbmc_project/pldm/sensor_polling";
const char* pldmPollingIntf = "xyz.openbmc_project.Object.Enable";

// Network object in dbus
static constexpr auto networkServiceName = "xyz.openbmc_project.Network";
static constexpr auto networkConfigObj = "/xyz/openbmc_project/network/config";
static constexpr auto networkConfigIntf =
    "xyz.openbmc_project.Network.SystemConfiguration";

// IPMI channel info
static constexpr uint8_t maxIpmiChannels = 16;
static constexpr const char* channelConfigDefaultFilename =
    "/usr/share/ipmi-providers/channel_config.json";

// STRING DEFINES: Should sync with key's in JSON
static constexpr const char* nameString = "name";
static constexpr const char* isValidString = "is_valid";
static constexpr const char* channelInfoString = "channel_info";
static constexpr const char* mediumTypeString = "medium_type";
static constexpr const char* protocolTypeString = "protocol_type";
static constexpr const char* sessionSupportedString = "session_supported";
static constexpr const char* isIpmiString = "is_ipmi";
static constexpr const char* redfishHostInterfaceChannel = "usb0";

// User Manager object in dbus
static constexpr const char* userMgrObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userMgrInterface =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* usersInterface =
    "xyz.openbmc_project.User.Attributes";
static constexpr const char* usersDeleteIface =
    "xyz.openbmc_project.Object.Delete";
static constexpr const char* createUserMethod = "CreateUser";
static constexpr const char* deleteUserMethod = "Delete";

// BIOSConfig Manager object in dbus
static constexpr const char* biosConfigMgrPath =
    "/xyz/openbmc_project/bios_config/manager";
static constexpr const char* biosConfigMgrIface =
    "xyz.openbmc_project.BIOSConfig.Manager";

// Cert Paths
std::string defaultCertPath = "/etc/ssl/certs/https/server.pem";

static constexpr const char* persistentDataFilePath =
    "/home/root/bmcweb_persistent_data.json";

void registerNvOemFunctions() __attribute__((constructor));

using namespace phosphor::logging;

using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using GetSubTreePathsType = std::vector<std::string>;
using BasicVariantType = std::variant<std::string>;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;

namespace ipmi
{

// HI Certificate FingerPrint error code
static constexpr Cc ipmiCCBootStrappingDisabled = 0x80;
static constexpr Cc ipmiCCCertificateNumberInvalid = 0xCB;

ipmi::RspType<uint8_t, // Major Version
              uint8_t  // Minor Version
              >
    ipmiGetOEMVersion()
{
    return ipmi::responseSuccess(OEM_MAJOR_VER, OEM_MINOR_VER);
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
              uint8_t, uint8_t>
    ipmiSMBPBIPassthroughCmd(uint8_t param, // GPU device : 0x01 fixed
                             uint8_t deviceId, uint8_t opcode, uint8_t arg1,
                             uint8_t arg2,
                             uint8_t execute // Execute bit : 0x80 fixed
    )
{
    /*
     * Request data:
     * Byte 1: Parameter
     *          00h: Reserved
     *          01h: GPU
     *          02h ~ FFh: Reserved
     * Byte 2: GPU device Id 0-based
     * Byte 3: SMPBI opcode
     * Byte 4: SMPBI opcode ARG1
     * Byte 5: SMPBI opcode ARG2
     * Byte 6: Execute bit: 0x80
     */

    /*
     * Response data:
     * Byte 1: GPU device Id 0-based
     * Byte 2: SMPBI opcode
     * Byte 3: SMPBI opcode ARG1
     * Byte 4: SMPBI opcode ARG2
     * Byte 5: Status
     * Byte 6~9: Data out LSB.
     */

    // Validate input
    if (param != 0x01)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughCmd: Request for non gpu device");
        return ipmi::responseResponseError();
    }
    if (execute != 0x80)
    {
        phosphor::logging::log<level::ERR>("ipmiSMBPBIPassthroughCmd: Not an "
                                           "smpbi passthrough command request");
        return ipmi::responseResponseError();
    }
    // Call smpbi passthrough call
    int rc;
    std::vector<uint32_t> dataOut;
    std::tuple<int, std::vector<uint32_t>> smbpbiRes;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, gpuSMBPBIIntf, gpuSMBPBIPath);
    auto method = bus->new_method_call(service.c_str(), gpuSMBPBIPath,
                                       gpuSMBPBIIntf, "Passthrough");
    std::vector<uint32_t> dataIn;
    // Add GPU device Id
    method.append(static_cast<int>(deviceId));
    // Add SMPBI opcode
    method.append(opcode);
    // Add ARG1
    method.append(arg1);
    // Add ARG2
    method.append(arg2);
    // Add dataIn
    method.append(dataIn);
    // Call passthrough dbus method
    auto reply = bus->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughCmd: Passthrough method returned error",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", gpuSMBPBIPath));
        return ipmi::responseUnspecifiedError();
    }

    reply.read(smbpbiRes);
    std::tie(rc, dataOut) = smbpbiRes;
    if (dataOut.size() != 4)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughCmd: Unknown SMBPBI response");
        return ipmi::responseUnspecifiedError();
    }
    /*
     * Read response from passthrough API
     * dataOut  - Output data. Format is as below
     * dword[0] = processing return code, 0 - succ; others - fail.
     * dword[1] = SMBPBI status code. LSB[opcode, arg1, arg2, stat]MSB.
     * dword[2] = SMBPBI data output if any.
     * dword[3] = SMBPBI extended data output if any.
     */

    // Read smpbi status code
    uint32_t statusVal = dataOut[1];
    uint8_t retOpcode = statusVal;
    uint8_t retArg1 = statusVal >> 8;
    uint8_t retArg2 = statusVal >> 16;
    uint8_t status = statusVal >> 24;

    // Read smpbi data output
    uint8_t res[4];
    uint32_t dataVal = dataOut[2];
    res[0] = dataVal;
    res[1] = dataVal >> 8;
    res[2] = dataVal >> 16;
    res[3] = dataVal >> 24;

    return ipmi::responseSuccess(deviceId, retOpcode, retArg1, retArg2, status,
                                 res[0], res[1], res[2], res[3]);
}

template <typename... ArgTypes>
static int executeCmd(const char* path, ArgTypes&&... tArgs)
{
    boost::process::child execProg(path, const_cast<char*>(tArgs)...);
    execProg.wait();
    return execProg.exit_code();
}

ipmi::RspType<uint8_t> ipmiBF2ResetControl(uint8_t resetOption)
{
    int response;
    switch (resetOption)
    {
        case 0x00: // soc hard reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "soc_hard_reset");
            break;
        case 0x01: // arm hard reset - nsrst
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "arm_hard_reset");
            break;
        case 0x02: // arm soft reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "arm_soft_reset");
            break;
        case 0x03: // tor eswitch reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "do_tor_eswitch_reset");
            break;
        case 0x04: // arm hard reset - nsrst - secondary DPU
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "bf2_nic_bmc_ctrl1");
            break;
        case 0x05: // arm soft reset - secondary DPU
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control",
                                  "bf2_nic_bmc_ctrl0");
            break;
        default:
            return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    if (response)
    {
        log<level::ERR>("Reset Command failed.",
                        phosphor::logging::entry("rc= %d", response));
        return ipmi::response(ipmi::ccResponseError);
    }

    return ipmi::response(ipmi::ccSuccess);
}

static ipmi::Cc i2cTransaction(uint8_t bus, uint8_t slaveAddr,
                               std::vector<uint8_t>& wrData,
                               std::vector<uint8_t>& rdData)
{
    std::string i2cBus = "/dev/i2c-" + std::to_string(bus);

    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        log<level::ERR>("Failed to open i2c bus",
                        phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
        return ipmi::ccInvalidFieldRequest;
    }
    std::shared_ptr<int> scopeGuard(&i2cDev, [](int* p) { ::close(*p); });

    auto ret = ipmi::i2cWriteRead(i2cBus, slaveAddr, wrData, rdData);
    if (ret != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed to perform I2C transaction!");
    }
    return ret;
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
              uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiSMBPBIPassthroughExtendedCmd(uint8_t deviceId, uint8_t opcode,
                                     uint8_t arg1, uint8_t arg2,
                                     uint8_t execute // Execute bit : 0x1f fixed
    )
{
    /*
     * Request data:
     * Byte 1: Device Id 0-based
     * Byte 2: SMPBI opcode
     * Byte 3: SMPBI opcode ARG1
     * Byte 4: SMPBI opcode ARG2
     * Byte 5: Execute bit: 0x1f
     */

    /*
     * Response data:
     * Byte 1: Device Id 0-based
     *         Device ID:
     *              GPU 1-8 is 0x00-0x07
     *              FPGA at I2C-1/2 is 0x08/0x09
     *              NVSwitch 1-6 is 0x0A-0x0F
     * Byte 2: SMPBI opcode
     * Byte 3: SMPBI opcode ARG1
     * Byte 4: SMPBI opcode ARG2
     * Byte 5: Status
     * Byte 6~9: Data out LSB.
     * Byte 10~13: Extended Data out LSB.
     */

    if (execute != 0x1f)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughExtendedCmd: Not an smpbi passthrough "
            "extended command request");
        return ipmi::responseResponseError();
    }
    // Call smpbi passthrough call
    int rc;
    std::vector<uint32_t> dataOut;
    std::tuple<int, std::vector<uint32_t>> smbpbiRes;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, gpuSMBPBIIntf, gpuSMBPBIPath);
    auto method = bus->new_method_call(service.c_str(), gpuSMBPBIPath,
                                       gpuSMBPBIIntf, "Passthrough");
    std::vector<uint32_t> dataIn;
    // Add GPU device Id
    method.append(static_cast<int>(deviceId));
    // Add SMPBI opcode
    method.append(opcode);
    // Add ARG1
    method.append(arg1);
    // Add ARG2
    method.append(arg2);
    // Add dataIn
    method.append(dataIn);
    // Call passthrough dbus method
    auto reply = bus->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughExtendedCmd: Passthrough method returned "
            "error",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", gpuSMBPBIPath));
        return ipmi::responseUnspecifiedError();
    }

    reply.read(smbpbiRes);
    std::tie(rc, dataOut) = smbpbiRes;
    if (dataOut.size() != 4)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughExtendedCmd: Unknown SMBPBI response");
        return ipmi::responseUnspecifiedError();
    }
    /*
     * Read response from passthrough API
     * dataOut  - Output data. Format is as below
     * dword[0] = processing return code, 0 - succ; others - fail.
     * dword[1] = SMBPBI status code. LSB[opcode, arg1, arg2, stat]MSB.
     * dword[2] = SMBPBI data output if any.
     * dword[3] = SMBPBI extended data output if any.
     */

    // Read smpbi status code
    uint32_t statusVal = dataOut[1];
    uint8_t retOpcode = statusVal;
    uint8_t retArg1 = statusVal >> 8;
    uint8_t retArg2 = statusVal >> 16;
    uint8_t status = statusVal >> 24;
    // Read smpbi data output
    uint8_t res[4];
    uint32_t dataVal = dataOut[2];
    res[0] = dataVal;
    res[1] = dataVal >> 8;
    res[2] = dataVal >> 16;
    res[3] = dataVal >> 24;
    // Read smpbi extended data output
    uint8_t extRes[4];
    uint32_t extDataVal = dataOut[3];
    extRes[0] = extDataVal;
    extRes[1] = extDataVal >> 8;
    extRes[2] = extDataVal >> 16;
    extRes[3] = extDataVal >> 24;

    return ipmi::responseSuccess(deviceId, retOpcode, retArg1, retArg2, status,
                                 res[0], res[1], res[2], res[3], extRes[0],
                                 extRes[1], extRes[2], extRes[3]);
}

ipmi::RspType<uint8_t> ipmiSetFanZonePWMDuty(uint8_t zone, uint8_t pwm,
                                             uint8_t request)
{
    std::string fanZoneHwMonNames[] = {nvidia::fanZoneCtrlName0,
                                       nvidia::fanZoneCtrlName1,
                                       nvidia::fanZoneCtrlName2};
    /* if not valid zone, return error */
    if (zone >= nvidia::fanZones)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    /* if not valid pwm, return error */
    if ((pwm > nvidia::pwm) || (pwm <= 0))
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    /* if zone control namae is blank, return success */
    if (fanZoneHwMonNames[zone].length() == 0)
    {
        return ipmi::responseSuccess();
    }

    /* get the control paths for the fans */
    std::array<std::string, nvidia::fanZones> ctrlPaths = {"", "", ""};
    std::filesystem::path hwmonPath("/sys/class/hwmon/");
    for (auto const& path : std::filesystem::directory_iterator{hwmonPath})
    {
        /* get the name from this hwmon path */
        std::filesystem::path namePath = path;
        namePath /= "uevent";
        std::ifstream nameFile(namePath);
        if (!nameFile.is_open())
        {
            phosphor::logging::log<level::ERR>(
                "ipmiSetFanZonePWMDuty: Failed to open hwmon name file");
            continue;
        }
        /* use uevent interface to get pull name, which includes address for i2c
            devices */
        std::string fullname;
        while (!nameFile.eof())
        {
            std::string l;
            nameFile >> l;
            if (boost::starts_with(l, "OF_FULLNAME"))
            {
                fullname = l;
            }
        }

        if (fullname.length() == 0)
        {
            continue;
        }

        /* now iterate through HwMon expected names and find a match */
        for (int i = 0; i < nvidia::fanZones; i++)
        {
            if (fanZoneHwMonNames[i].length() == 0)
            {
                continue;
            }
            if (ctrlPaths[i].length() != 0)
            {
                continue;
            }
            if (boost::ends_with(fullname, fanZoneHwMonNames[i]))
            {
                ctrlPaths[i] = path.path();
                ctrlPaths[i] += "/pwm" + std::to_string(pwm);
                break;
            }
        }
    }

    /* convert control % to a pwm value */
    int value = 255;
    if ((request % 10 == 0) && (request <= 100) && (request >= 20))
    {
        value = value * request / 100;
        std::ofstream ofs(ctrlPaths[zone]);
        if (!ofs.is_open())
        {
            std::string errString = "ipmiSetFanZonePWMDuty: Failed to open hwmon pwm file. zone = " \
                                    + std::to_string(zone) + ", pwm = " + std::to_string(pwm);
            phosphor::logging::log<level::WARNING>(errString.c_str());

            return ipmi::response(ipmi::ccResponseError);
        }
        ofs << value;
        ofs.close();
        return ipmi::responseSuccess();
    }
    else
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
}

ipmi::RspType<uint8_t> ipmiSetAllFanZonesPWMDuty(uint8_t request)
{
    bool isSetFanZonePWMDutySuccess = false;
    ipmi::RspType<uint8_t> ret = ipmi::responseSuccess();

    for (int i = 0; i < nvidia::fanZones; i++)
    {
        for (int j = 1; j <= nvidia::pwm; j++)
        {
            ret = ipmiSetFanZonePWMDuty(i, j, request);
            if (ret == ipmi::responseSuccess())
            {
                // Return the CC to success if at least one value is present
                isSetFanZonePWMDutySuccess = true;
            }
        }
    }

    if (isSetFanZonePWMDutySuccess == true)
    {
        return ipmi::responseSuccess();
    }
    else
    {
       phosphor::logging::log<level::ERR>(
           "ipmiSetAllFanZonesPWMDuty: Failed to set zone");

       return ret;
    }
}

ipmi::RspType<uint8_t> ipmiSetFanControl(uint8_t mode)
{
    if (mode == 0x00)
    {
        /* auto mode startup the fan control service */
        std::string startupFanString = "systemctl start ";
        startupFanString += nvidia::fanServiceName;
        auto r = system(startupFanString.c_str());
        if (r != 0)
        {
            /* log that the fan control service doesn't exist */
            phosphor::logging::log<level::ERR>(
                "ipmiSetFanControl: failed to start auto fan service, falling "
                "back to default speed");
            /* set fans to default speed, we will support this as "auto", so we
                still return success via ipmi */
            return ipmiSetAllFanZonesPWMDuty(nvidia::fanNoServiceSpeed);
        }
        return ipmi::responseSuccess();
    }
    else if (mode == 0x01)
    {
        /* manual mode, stop fan service */
        std::string stopFanString = "systemctl stop ";
        stopFanString += nvidia::fanServiceName;
        system(stopFanString.c_str());

        /* set fans to default speed */
        return ipmiSetAllFanZonesPWMDuty(nvidia::fanNoServiceSpeed);
    }
    return ipmi::response(ipmi::ccInvalidFieldRequest);
}

/**
 * @brief send control command to the system manager
 *
 * This function is to send control command to the systemd manager
 *
 * @param[in] dbus - Dbus obj
 * @param[in] service - service name
 * @param[in] action - action to the service
 *
 **/
void controlSystemUnit(std::shared_ptr<sdbusplus::asio::connection>& dbus,
                      const std::string& service, const std::string& action)
{
    auto method = dbus->new_method_call(systemBusName, systemPath,
                                            systemIntf, action.c_str());
    method.append(service.c_str());
    method.append("replace");
    dbus->async_send(method, [service, action](boost::system::error_code ec,
                                               sdbusplus::message_t& m) {
        if (ec || m.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Failed to do " + action + " on " + service + ": " +
                 ec.message()).c_str());
            return;
        }
    });
}

ipmi::RspType<> ipmiSensorScanEnableDisable(uint8_t mode)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto pldmService = ipmi::getService(*dbus, pldmPollingIntf, pldmPollingObj);

    if (mode == static_cast<uint8_t>(ipmi::nvidia::misc::Mode::Stop))
    {
        /* Stop polling PLDM sensors */
        ipmi::setDbusProperty(*dbus, pldmService, pldmPollingObj,
                                            pldmPollingIntf, "Enabled", bool(false));
        // Stop all services in the list
        for (auto service : ipmi::nvidia::sensorMonitorServiceList)
        {
            controlSystemUnit(dbus, service, "StopUnit");
        }
    }
    else if (mode == static_cast<uint8_t>(ipmi::nvidia::misc::Mode::Start))
    {
        /* Start polling PLDM sensors */
        ipmi::setDbusProperty(*dbus, pldmService, pldmPollingObj,
                                            pldmPollingIntf, "Enabled", bool(true));
        // Start all services in the list
        for (auto service : ipmi::nvidia::sensorMonitorServiceList)
        {
            controlSystemUnit(dbus, service, "StartUnit");
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Invalid parameter: " + std::to_string(mode)).c_str());
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
    return ipmi::responseSuccess();
}

static uint8_t getSSDLedRegister(uint8_t type, uint8_t instance,
                                 uint8_t& offset, uint8_t& mask)
{
    using namespace ipmi::nvidia::misc;
    uint8_t reg = 0;
    offset = instance;
    mask = (1 << instance);
    switch (type)
    {
        case getSSDLedTypeReadyMove:
            reg = nvidia::fpgaMidSSDLedReadyMove;
            break;
        case getSSDLedTypeActivity:
            reg = nvidia::fpgaMidSSDLedActivity;
            break;
        case getSSDLedTypeFault:
            /*  offset 0 = instance 7, 6
                offset 1 = instance 5, 4
                offset 2 = instance 3, 2
                offset 3 = instance 1, 0 */
            reg = nvidia::fpgaMidSSDLedFaultBase +
                  (((getSSDLedNLed - 1) - instance) >> 1);
            /*  each register is:
                    xxbb baaa
                where aaa is 0 and bbb is 1 */
            offset = nvidia::fpgaMidSSDLedFaultWidth * (instance & 0x01);
            mask = ((1 << nvidia::fpgaMidSSDLedFaultWidth) - 1) << offset;
            break;
    }
    return reg;
}

ipmi::RspType<uint8_t> ipmiOemGetSSDLed(uint8_t type, uint8_t instance)
{
    using namespace ipmi::nvidia::misc;

    if (instance >= getSSDLedNLed)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED Instance");
        return ipmi::responseResponseError();
    }

    /* get register, offset, mask information */
    uint8_t reg, offset, mask;
    reg = getSSDLedRegister(type, instance, offset, mask);
    if (reg == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED type");
        return ipmi::responseResponseError();
    }

    /* get appropriate register */
    std::vector<uint8_t> writeData = {reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress,
                              writeData, readBuf);
    if (ret != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get SSD Led status from FPGA");
        return ipmi::responseResponseError();
    }

    /* decode and return */
    return ipmi::responseSuccess(readBuf[0] & mask >> offset);
}

ipmi::RspType<> ipmiOemSetSSDLed(uint8_t type, uint8_t instance,
                                 uint8_t pattern)
{
    using namespace ipmi::nvidia::misc;

    if ((instance >= getSSDLedNLed) ||
        ((type == getSSDLedTypeFault) &&
         (pattern > nvidia::fpgaMidSetLedFaultMaxPattern)) ||
        ((type != getSSDLedTypeFault) &&
         (pattern > nvidia::fpgaMidSetLedOtherMaxPattern)) ||
        (type == getSSDLedTypeActivity))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED Type, Instance or Pattern");
        return ipmi::responseResponseError();
    }

    /* get register, offset, mask information */
    uint8_t reg, offset, mask;
    reg = getSSDLedRegister(type, instance, offset, mask);
    if (reg == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED type");
        return ipmi::responseResponseError();
    }

    /* get appropriate register */
    std::vector<uint8_t> writeData = {reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress,
                              writeData, readBuf);
    if (ret != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get SSD Led status from FPGA");
        return ipmi::responseResponseError();
    }

    /* adjust register and write it out */
    writeData.push_back((readBuf[0] & ~mask) | (pattern << offset));
    ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress,
                         writeData, readBuf);
    if (ret != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set SSD Led pattern to FPGA");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOemGetLedStatus(uint8_t type)
{
    using namespace ipmi::nvidia::misc;
    std::string ledPath = "/sys/class/leds/";
    switch (type)
    {
        case getLedStatusPowerLed:
            ledPath += nvidia::powerLedName;
            break;
        case getLedStatusFaultLed:
            ledPath += nvidia::faultLedName;
            break;
        case getLedStatusMotherBoardLed:
            ledPath += nvidia::mbLedName;
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown LED type requested");
            return ipmi::responseResponseError();
    }

    /* have path to led, open brightness and check if it is 0 */
    int brightness;
    std::ifstream ledBrightness(ledPath + "/brightness");
    if (!ledBrightness.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to open LED brightness file");
        return ipmi::responseResponseError();
    }
    ledBrightness >> brightness;
    ledBrightness.close();
    if (brightness != 0)
    {
        return ipmi::responseSuccess(1);
    }
    return ipmi::responseSuccess(0);
}

ipmi::RspType<std::vector<uint8_t>>
    ipmiI2CMasterReadWrite(uint8_t bus, uint8_t slaveAddr, uint8_t readCount,
                           std::vector<uint8_t> writeData)
{
    std::vector<uint8_t> rdData(readCount);
    /* slaveaddr is expected to be in 8bit format, i2cTransaction expects 7bit
     */
    auto ret = i2cTransaction(bus, slaveAddr >> 1, writeData, rdData);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }
    return ipmi::responseSuccess(rdData);
}

ipmi::RspType<uint8_t> ipmiGetSELPolicy()
{
    // SEL policy:
    // Linear represents 0x00
    // Circular represents 0x01
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service = ipmi::getService(*dbus, selLogIntf, selLogObj);
        auto policy = ipmi::getDbusProperty(*dbus, service, selLogObj,
                                            selLogIntf, "SelPolicy");
        if (std::get<std::string>(policy) ==
            "xyz.openbmc_project.Logging.Settings.Policy.Linear")
        {
            return ipmi::responseSuccess(static_cast<uint8_t>(0));
        }
        else if (std::get<std::string>(policy) ==
                 "xyz.openbmc_project.Logging.Settings.Policy.Circular")
        {
            return ipmi::responseSuccess(static_cast<uint8_t>(1));
        }
        else
        {
            return ipmi::responseResponseError();
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get BMC SEL policy",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiSetSELPolicy(uint8_t policyType)
{
    // SEL policy:
    // Linear represents 0x00
    // Circular represents 0x01

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        // Read current policy
        auto service = ipmi::getService(*dbus, selLogIntf, selLogObj);
        auto policy = ipmi::getDbusProperty(*dbus, service, selLogObj,
                                            selLogIntf, "SelPolicy");

        switch (policyType)
        {
            case 0:
                // Do nothing for same policy request
                if (std::get<std::string>(policy) !=
                    "xyz.openbmc_project.Logging.Settings.Policy.Linear")
                {
                    ipmi::setDbusProperty(
                        *dbus, service, selLogObj, selLogIntf, "SelPolicy",
                        std::string("xyz.openbmc_project.Logging.Settings."
                                    "Policy.Linear"));
                }
                break;
            case 1:
                // Do nothing for same policy request
                if (std::get<std::string>(policy) !=
                    "xyz.openbmc_project.Logging.Settings.Policy.Circular")
                {
                    ipmi::setDbusProperty(
                        *dbus, service, selLogObj, selLogIntf, "SelPolicy",
                        std::string("xyz.openbmc_project.Logging.Settings."
                                    "Policy.Circular"));
                }
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "SEL policy: invalid type!",
                    phosphor::logging::entry("Request Value=%d", policyType));
                return ipmi::responseResponseError();
                break;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set BMC SEL policy",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbDescription(uint8_t type)
{
    uint8_t msbId;
    uint8_t lsbId;
    if (type == 0x01)
    {
        // Get the USB Vendor Id
        msbId = (uint8_t)((USB_VENDOR_ID >> 8) & 0xff);
        lsbId = (uint8_t)(USB_VENDOR_ID & 0xff);
        return ipmi::responseSuccess(msbId, lsbId);
    }
    else if (type == 0x02)
    {
        // Get the USB Product Id
        msbId = (uint8_t)((USB_PRODUCT_ID >> 8) & 0xff);
        lsbId = (uint8_t)(USB_PRODUCT_ID & 0xff);
        return ipmi::responseSuccess(msbId, lsbId);
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetUsbSerialNum()
{
    // Get the USB Serial Number
    std::vector<uint8_t> usbSerialNum;
    usbSerialNum.push_back(USB_SERIAL_NUM);
    return ipmi::responseSuccess(usbSerialNum);
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishHostName()
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*dbus, networkConfigIntf, networkConfigObj);
        auto hostname = ipmi::getDbusProperty(*dbus, service, networkConfigObj,
                                              networkConfigIntf, "HostName");
        std::vector<uint8_t> respHostNameBuf;
        std::copy(std::get<std::string>(hostname).begin(),
                  std::get<std::string>(hostname).end(),
                  std::back_inserter(respHostNameBuf));
        return ipmi::responseSuccess(respHostNameBuf);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get HostName",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<uint8_t> ipmiGetipmiChannelRfHi()
{
    std::ifstream jsonFile(channelConfigDefaultFilename);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found",
                         entry("FILE_NAME=%s", channelConfigDefaultFilename));
        return ipmi::responseResponseError();
    }

    nlohmann::json data = nullptr;
    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        log<level::ERR>("Corrupted channel config.",
                          entry("MSG=%s", e.what()));
        return ipmi::responseResponseError();
    }

    bool chFound = false;
    uint8_t chNum;
    for (chNum = 0; chNum < maxIpmiChannels; chNum++)
    {
        try
        {
            std::string chKey = std::to_string(chNum);
            nlohmann::json jsonChData = data[chKey].get<nlohmann::json>();
            if (jsonChData.is_null() ||
                (jsonChData[nameString].get<std::string>().find(
                 redfishHostInterfaceChannel) == std::string::npos))
            {
                log<level::DEBUG>(
                    "Channel not configured for Redfish Host Interface",
                    entry("CHANNEL_NUM=%d", chNum));
                continue;
            }
            nlohmann::json jsonChInfo =
                jsonChData[channelInfoString].get<nlohmann::json>();
            if (jsonChInfo.is_null())
            {
                log<level::ERR>("Invalid/corrupted channel config file");
                return ipmi::responseResponseError();
            }

            if ((jsonChData[isValidString].get<bool>() == true) &&
                (jsonChInfo[mediumTypeString].get<std::string>() ==
                 "lan-802.3") &&
                (jsonChInfo[protocolTypeString].get<std::string>() ==
                 "ipmb-1.0") &&
                (jsonChInfo[sessionSupportedString].get<std::string>() ==
                 "multi-session") &&
                (jsonChInfo[isIpmiString].get<bool>() == true))
            {
                chFound = true;
                break;
            }
        }
        catch (const nlohmann::json::parse_error& e)
        {
            log<level::ERR>("Json Exception caught.",
                              entry("MSG=%s", e.what()));
            return ipmi::responseResponseError();
        }
    }
    jsonFile.close();
    if (chFound)
    {
        return ipmi::responseSuccess(chNum);
    }
    return ipmi::responseInvalidCommandOnLun();
}

bool getRfUuid(std::string& rfUuid)
{
    std::ifstream persistentDataFilePath(
        "/var/lib/bmcweb/bmcweb_persistent_data.json");
    if (persistentDataFilePath.is_open())
    {
        auto data =
            nlohmann::json::parse(persistentDataFilePath, nullptr, false);
        if (data.is_discarded())
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetRedfishServiceUuid: Error parsing persistent data in "
                "json file.");
            return false;
        }
        else
        {
            for (const auto& item : data.items())
            {
                if (item.key() == "system_uuid")
                {
                    const std::string* jSystemUuid =
                        item.value().get_ptr<const std::string*>();
                    if (jSystemUuid != nullptr)
                    {
                        rfUuid = *jSystemUuid;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishServiceUuid()
{
    std::string rfUuid;
    bool ret = getRfUuid(rfUuid);
    if (!ret)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetRedfishServiceUuid: Error reading Redfish Service UUID "
            "File.");
        return ipmi::responseResponseError();
    }

    // As per Redfish Host Interface Spec v1.3.0
    // The Redfish UUID is 16byte and should be represented as below:
    // Ex: {00112233-4455-6677-8899-AABBCCDDEEFF}
    // 0x33 0x22 0x11 0x00 0x55 0x44 0x77 0x66 0x88 0x99 0xAA 0xBB 0xCC 0xDD
    // 0xEE 0xFF

    int start = 0;
    int noOfBytes = 5;
    int leftBytes = 3;
    int totalBytes = 16;
    std::string bytes;
    std::string::size_type found = 0;
    std::vector<uint8_t> resBuf;

    for (int index = 0; index < noOfBytes; index++)
    {
        found = rfUuid.find('-', found + 1);
        if (found == std::string::npos)
        {
            if (index != noOfBytes - 1)
            {
                break;
            }
        }

        if (index == noOfBytes - 1)
        {
            bytes = rfUuid.substr(start);
        }
        else
        {
            bytes = rfUuid.substr(start, found - start);
        }

        if (index < leftBytes)
        {
            std::reverse(bytes.begin(), bytes.end());
            for (int leftIndex = 0; leftIndex < bytes.length(); leftIndex += 2)
            {
                std::swap(bytes[leftIndex + 1], bytes[leftIndex]);
                resBuf.push_back(
                    std::stoi(bytes.substr(leftIndex, 2), nullptr, 16));
            }
        }
        else
        {
            for (int rightIndex = 0; rightIndex < bytes.length();
                 rightIndex += 2)
            {
                resBuf.push_back(
                    std::stoi(bytes.substr(rightIndex, 2), nullptr, 16));
            }
        }
        start = found + 1;
    }

    if (resBuf.size() != totalBytes)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetRedfishServiceUuid: Invalid Redfish Service UUID found.");
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(resBuf);
}

ipmi::RspType<uint8_t, uint8_t> ipmiGetRedfishServicePort()
{
    // default Redfish Service Port Number is 443
    int redfishPort = 443;
    uint8_t lsb = redfishPort & 0xff;
    uint8_t msb = redfishPort >> 8 & 0xff;
    return ipmi::responseSuccess(msb, lsb);
}

ipmi::RspType<std::vector<uint8_t>> ipmiSetBiosPassword(
    uint8_t id, uint8_t type,
    std::array<uint8_t, ipmi::nvidia::misc::biosPasswordSaltSize> salt,
    std::array<uint8_t, ipmi::nvidia::misc::biosPasswordMaxHashSize> hash)
{
    using namespace ipmi::nvidia::misc;
    nlohmann::json json;

    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    switch (type)
    {
        case biosPasswordTypeNoPassowrd:
            json["HashAlgo"] = "SHA256";
            RAND_bytes(salt.data(), salt.size());
            // password is only Null-terminated character
            PKCS5_PBKDF2_HMAC("", 1, salt.data(), salt.size(), biosPasswordIter,
                              EVP_sha256(), SHA256_DIGEST_LENGTH, hash.data());
            json["Seed"] = salt;
            json["AdminPwdHash"] = hash;
            break;
        case biosPasswordTypePbkdf2Sha256:
            json["HashAlgo"] = "SHA256";
            json["Seed"] = salt;
            json["AdminPwdHash"] = hash;
            break;
        case biosPasswordTypePbkdf2Sha384:
            json["HashAlgo"] = "SHA384";
            json["Seed"] = salt;
            json["AdminPwdHash"] = hash;
            break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    json["IsAdminPwdChanged"] = false;
    json["IsUserPwdChanged"] = false;

    // initializing with 0 as user password hash field
    // is not used presently
    constexpr std::array<uint8_t, biosPasswordMaxHashSize> userPwdHash = {0};
    json["UserPwdHash"] = userPwdHash;

    try
    {
        std::ofstream ofs(biosPasswordFilePath, std::ios::out);
        const auto& writeData = json.dump();
        ofs << writeData;
        ofs.close();
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to save BIOS Password information",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t,
              std::array<uint8_t, ipmi::nvidia::misc::biosPasswordSaltSize>,
              std::array<uint8_t, ipmi::nvidia::misc::biosPasswordMaxHashSize>>
    ipmiGetBiosPassword(uint8_t id)
{
    using namespace ipmi::nvidia::misc;
    uint8_t action = biosPasswordTypeNoChange;
    std::array<uint8_t, biosPasswordSaltSize> salt = {0};
    std::array<uint8_t, biosPasswordMaxHashSize> hash = {0};

    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::ifstream ifs(biosPasswordFilePath);
    if (!ifs.is_open())
    {
        // return No change if no file
        return ipmi::responseSuccess(action, salt, hash);
    }

    nlohmann::json json = nlohmann::json::parse(ifs, nullptr, false);
    if (json.is_discarded() || !json.contains("IsAdminPwdChanged") ||
        !json.contains("HashAlgo") || !json.contains("Seed") ||
        !json.contains("AdminPwdHash"))
    {
        return ipmi::responseResponseError();
    }
    bool IsAdminPwdChanged = json["IsAdminPwdChanged"];
    if (IsAdminPwdChanged == false)
    {
        return ipmi::responseSuccess(action, salt, hash);
    }

    salt = json["Seed"];
    hash = json["AdminPwdHash"];

    std::string HashAlgo = json["HashAlgo"];
    auto digest = EVP_sha256();
    int keylen = SHA256_DIGEST_LENGTH;

    if (HashAlgo == "SHA256")
    {
        action = biosPasswordTypePbkdf2Sha256;
    }
    else if (HashAlgo == "SHA384")
    {
        action = biosPasswordTypePbkdf2Sha384;
        digest = EVP_sha384();
        keylen = SHA384_DIGEST_LENGTH;
    }

    std::array<uint8_t, biosPasswordMaxHashSize> nullHash = {0};
    PKCS5_PBKDF2_HMAC("", 1, salt.data(), salt.size(), biosPasswordIter, digest,
                      keylen, nullHash.data());
    if (hash == nullHash)
    {
        action = biosPasswordTypeNoPassowrd;
        salt.fill(0x00);
        hash.fill(0x00);
    }

    return ipmi::responseSuccess(action, salt, hash);
}

static bool getCredentialBootStrap()
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto biosService =
            ipmi::getService(*dbus, biosConfigMgrIface, biosConfigMgrPath);
        auto credentialBootStrap =
            ipmi::getDbusProperty(*dbus, biosService, biosConfigMgrPath,
                                  biosConfigMgrIface, "CredentialBootstrap");

        return std::get<bool>(credentialBootStrap);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get CredentialBootstrap status",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return false;
    }
}

static void setCredentialBootStrap(const uint8_t& disableCredBootStrap)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto biosService =
        ipmi::getService(*dbus, biosConfigMgrIface, biosConfigMgrPath);
    // if disable crendential BootStrap status is 0xa5,
    // then Keep credential bootstrapping enabled
    if (disableCredBootStrap == 0xa5)
    {
        ipmi::setDbusProperty(*dbus, biosService, biosConfigMgrPath,
                              biosConfigMgrIface, "CredentialBootstrap",
                              bool(true));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiGetBootStrapAccount: Disable CredentialBootstrapping"
            "property set to true");
    }
    else
    {
        ipmi::setDbusProperty(*dbus, biosService, biosConfigMgrPath,
                              biosConfigMgrIface, "CredentialBootstrap",
                              bool(false));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiGetBootStrapAccount: Disable CredentialBootstrapping"
            "property set to false");
    }
}

static int pamFunctionConversation(int numMsg, const struct pam_message** msg,
                                   struct pam_response** resp, void* appdataPtr)
{
    if (appdataPtr == nullptr)
    {
        return PAM_CONV_ERR;
    }
    if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG)
    {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < numMsg; ++i)
    {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }

        /* Assume PAM is only prompting for the password as hidden input */
        /* Allocate memory only when PAM_PROMPT_ECHO_OFF is encounterred */
        char* appPass = reinterpret_cast<char*>(appdataPtr);
        size_t appPassSize = std::strlen(appPass);
        if (appPassSize >= PAM_MAX_RESP_SIZE)
        {
            return PAM_CONV_ERR;
        }

        char* pass = reinterpret_cast<char*>(malloc(appPassSize + 1));
        if (pass == nullptr)
        {
            return PAM_BUF_ERR;
        }

        void* ptr =
            calloc(static_cast<size_t>(numMsg), sizeof(struct pam_response));
        if (ptr == nullptr)
        {
            free(pass);
            return PAM_BUF_ERR;
        }

        std::strncpy(pass, appPass, appPassSize + 1);
        *resp = reinterpret_cast<pam_response*>(ptr);
        resp[i]->resp = pass;
        return PAM_SUCCESS;
    }
    return PAM_CONV_ERR;
}

bool getRandomUserName(std::string& uniqueStr)
{
    std::ifstream randFp("/dev/urandom", std::ifstream::in);
    char byte;
    uint8_t maxStrSize = 16;

    if (!randFp.is_open())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: Failed to open urandom file");
        return false;
    }

    for (uint8_t it = 0; it < maxStrSize; it++)
    {
        while (1)
        {
            if (randFp.get(byte))
            {
                if (iswalnum(byte))
                {
                    if (it == 0)
                    {
                        if (iswalpha(byte))
                        {
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
        uniqueStr.push_back(byte);
    }
    randFp.close();
    return true;
}

/**
 * Checks if a password is valid by performing the following validations:
 *
 * 1. Checks for the presence of adjacent characters that differ by one.
 *    For example, "ab" and "321" would be considered invalid due to adjacent characters that differ by one.
 *
 * 2. Limits the number of adjacent characters to a threshold based on the password length.
 *    In our case, since the password size is 16 characters, the threshold for adjacent characters is set to 4.
 *    If the count of adjacent characters surpasses this threshold, the password is considered too simplistic/systematic.
 *
 * Note: The `fascist.c` file in CrackLib includes a function called `FascistLookUser`
 *       that uses a similar logic to validate passwords. However, please note that
 *       passwords generated by `getRandomPassword` may fail by CrackLib validation.
 *       Therefore, isValidPassword is needed here.
 *
 * @param password The password string to be validated.
 * @return True if the password is valid, false otherwise.
 */
bool isValidPassword(const std::string& password) {
    int i = 0;
    const char* ptr = password.c_str();

    while (ptr[0] && ptr[1]) {
        if ((ptr[1] == (ptr[0] + 1)) || (ptr[1] == (ptr[0] - 1))) {
            i++;
        }
        ptr++;
    }

    int maxrepeat = 3 + (0.09 * password.length());
    if (i > maxrepeat) {
        phosphor::logging::log<level::DEBUG>(
            "isValidPassword: Password is too simplistic/systematic");
        return false;
    }
    return true;
}

bool getRandomPassword(std::string& uniqueStr)
{
    std::ifstream randFp("/dev/urandom", std::ifstream::in);
    char byte;
    uint8_t maxStrSize = 16;
    std::string invalidChar = "\'\"";

    if (!randFp.is_open())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: Failed to open urandom file");
        return false;
    }

    for (uint8_t it = 0; it < maxStrSize; it++)
    {
        while (1)
        {
            if (randFp.get(byte))
            {
                if (iswprint(byte))
                {
                    if (!iswspace(byte) &&
                        invalidChar.find(byte) == std::string::npos)
                    {
                        if (it == 0)
                        {
                            if (iswlower(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 1)
                        {
                            if (iswupper(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 2)
                        {
                            if (iswdigit(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 3)
                        {
                            if (!iswdigit(byte) && !iswalpha(byte))
                            {
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            }
        }
        uniqueStr.push_back(byte);
    }
    randFp.close();
    std::random_device rd;  // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::shuffle(uniqueStr.begin(), uniqueStr.end(), gen);
    return true;
}

int pamUpdatePasswd(const char* username, const char* password)
{
    const struct pam_conv localConversation = {pamFunctionConversation,
                                               const_cast<char*>(password)};
    pam_handle_t* localAuthHandle = NULL; // this gets set by pam_start
    int retval =
        pam_start("passwd", username, &localConversation, &localAuthHandle);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, retval);
        return retval;
    }
    return pam_end(localAuthHandle, PAM_SUCCESS);
}

bool isValidUserName(ipmi::Context::ptr ctx, const std::string& userName)
{
    if (userName.empty())
    {
        phosphor::logging::log<level::ERR>("Requested empty UserName string");
        return false;
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        phosphor::logging::log<level::ERR>("Unsupported characters in string");
        return false;
    }

    boost::system::error_code ec;
    GetSubTreePathsType subtreePaths =
        ctx->bus->yield_method_call<GetSubTreePathsType>(
            ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
            userMgrObjBasePath, 0, std::array<const char*, 1>{usersInterface});
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: Failed to get User Paths");
        return false;
    }

    if (subtreePaths.empty())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: empty subtreepaths");
        return false;
    }

    for (const auto& objectPath : subtreePaths)
    {
        if (objectPath.find(userName) != std::string::npos)
        {
            log<level::ERR>(
                "User name already exists",
                phosphor::logging::entry("UserName= %s", userName.c_str()));
            return false;
        }
    }
    return true;
}

#define RETRIES_EXCEEDED    10

ipmi::RspType<std::vector<uint8_t>, std::vector<uint8_t>>
    ipmiGetBootStrapAccount(ipmi::Context::ptr ctx,
                            uint8_t disableCredBootStrap)
{
    uint64_t oemStart = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    try
    {
        // Check the CredentialBootstrapping property status,
        // if disabled, then reject the command with success code.
        bool isCredentialBooStrapSet = getCredentialBootStrap();
        if (!isCredentialBooStrapSet)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Credential BootStrapping Disabled "
                "Get BootStrap Account command rejected.");
            return ipmi::response(ipmi::ipmiCCBootStrappingDisabled);
        }

        std::string userName;
        std::string password;

        bool ret = getRandomUserName(userName);
        if (!ret)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate alphanumeric "
                "UserName");
            return ipmi::responseResponseError();
        }
        if (!isValidUserName(ctx, userName))
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate valid UserName");
            return ipmi::responseResponseError();
        }

        bool passwordIsValid = false;
        int max_retries = RETRIES_EXCEEDED;

        while (!passwordIsValid && (max_retries != 0)) {
            ret = getRandomPassword(password);
            if (!ret)
            {
                phosphor::logging::log<level::ERR>(
                    "ipmiGetBootStrapAccount: Failed to generate alphanumeric "
                    "Password");
                return ipmi::responseResponseError();
            }
            passwordIsValid = isValidPassword(password);
            max_retries--;
        }

        if (!passwordIsValid) {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate valid "
                "Password");
            return ipmi::responseResponseError();
        }

        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, userMgrInterface, userMgrObjBasePath);

        // create the new user with only redfish-hostiface group access
        auto method = dbus->new_method_call(service.c_str(), userMgrObjBasePath,
                                            userMgrInterface, createUserMethod);
        method.append(userName, std::vector<std::string>{"redfish-hostiface"},
                      "priv-admin", true);
        // asynchronous method call to avoid ssif timeout
        dbus->async_send(method, [dbus, service, userName, password,
                                  disableCredBootStrap](
                                     boost::system::error_code ec,
                                     sdbusplus::message_t& reply) {
            if (ec || reply.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error returns from call to dbus. BootStrap Failed");
                return;
            }

            // update the password
            int retval = pamUpdatePasswd(userName.c_str(), password.c_str());
            if (retval != PAM_SUCCESS)
            {
                dbus->async_method_call(
                    [](boost::system::error_code ec2, sdbusplus::message_t& m) {
                        if (ec2 || m.is_method_error())
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "Error returns from call to dbus. delete user "
                                "failed");
                            return;
                        }
                    },
                    service.c_str(),
                    std::string(userMgrObjBasePath)
                        .append("/")
                        .append(userName),
                    usersDeleteIface, "Delete");

                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiGetBootStrapAccount : Failed to update password.");
                return;
            }
            else
            {
                // update the "CredentialBootstrap" Dbus property w.r.to
                // disable crendential BootStrap status
                setCredentialBootStrap(disableCredBootStrap);
            }
            return;
        });

        std::vector<uint8_t> respUserNameBuf, respPasswordBuf;
        std::copy(userName.begin(), userName.end(),
                  std::back_inserter(respUserNameBuf));
        std::copy(password.begin(), password.end(),
                  std::back_inserter(respPasswordBuf));
        uint64_t oemEnd = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
        std::string info =
            (boost::format("ipmiGetBootStrapAccount exe_time=%dms") %
             (oemEnd - oemStart))
                .str();
        log<level::INFO>(info.c_str());
        return ipmi::responseSuccess(respUserNameBuf, respPasswordBuf);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiGetBootStrapAccount : Failed to generate BootStrap Account "
            "Credentials");
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<std::vector<uint8_t>>
    ipmiGetManagerCertFingerPrint(ipmi::Context::ptr ctx, uint8_t certNum)
{
    unsigned int n;
    const EVP_MD* fdig = EVP_sha256();
    // Check the CredentialBootstrapping property status,
    // if disabled, then reject the command with success code.
    bool isCredentialBooStrapSet = getCredentialBootStrap();
    if (!isCredentialBooStrapSet)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: Credential BootStrapping Disabled "
            "Get Manager Certificate FingerPrint command rejected.");
        return ipmi::response(ipmi::ipmiCCBootStrappingDisabled);
    }

    if (certNum != 1)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: Invalid certificate number "
            "Get Manager Certificate failed");
        return ipmi::response(ipmi::ipmiCCCertificateNumberInvalid);
    }
    BIO* cert;
    X509* x = NULL;
    cert = BIO_new_file(defaultCertPath.c_str(), "rb");
    if (cert == NULL)
    {
        log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: unable to open certificate");
        return ipmi::response(ipmi::ccResponseError);
    }
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if (x == NULL)
    {
        BIO_free(cert);
        log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: unable to load certificate");
        return ipmi::response(ipmi::ccResponseError);
    }
    std::vector<uint8_t> fingerPrintData(EVP_MAX_MD_SIZE);
    if (!X509_digest(x, fdig, fingerPrintData.data(), &n))
    {
        X509_free(x);
        BIO_free(cert);
        log<level::ERR>("ipmiGetManagerCertFingerPrint: out of memory");
        return ipmi::response(ipmi::ccResponseError);
    }
    fingerPrintData.resize(n);

    X509_free(x);
    BIO_free(cert);

    try
    {
        std::vector<uint8_t> respBuf;

        respBuf.push_back(1); // 01h: SHA-256. The length of the fingerprint
                              // will be 32 bytes.

        for (const auto& data : fingerPrintData)
        {
            respBuf.push_back(data);
        }
        return ipmi::responseSuccess(respBuf);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get Manager Cert FingerPrint",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiOemSoftReboot()
{
    /* TODO: Should be handled by dbus call once backend exists */
    /* call powerctrl grace_off to trigger soft off */
    system("powerctrl grace_off");
    /* call powerctrl for power cycle, this will force off if the grace off
     * didn't occur */
    system("powerctrl power_cycle");
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiGetBMCBootComplete(ipmi::Context::ptr ctx)
{
    /*
     * Response data:
     * Byte 1    : 0x00 if BMC boot complete.
     *           : 0x01 if BMC boot un-complete.
     */

    DbusObjectInfo objInfo;
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, bmcStateIntf, "/", "bmc0", objInfo);
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBMCBootComplete: Failed to perform GetSubTree action",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()),
            phosphor::logging::entry("INTERFACE=%s", bmcStateIntf));
        return ipmi::responseResponseError();
    }

    std::string bmcState;
    ec = ipmi::getDbusProperty(ctx, objInfo.second, objInfo.first, bmcStateIntf,
                               currentBmcStateProp, bmcState);
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBMCBootComplete: Failed to get CurrentBMCState property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseResponseError();
    }

    if (bmcState == bmcStateReadyStr)
    {
        return ipmi::responseSuccess(static_cast<uint8_t>(0));
    }

    return ipmi::responseSuccess(static_cast<uint8_t>(1));
}





/* This function will export the gpio if it doesn't exist in sysfs,
   have to use the sysfs interface because the char device interface
   resets once closed, and also sysfs gives persistance  */
static int gpioExport(std::string gpiochip, uint32_t gpio) {

    int base;
    std::ifstream chipbase("/sys/class/gpio/" + gpiochip + "/base", std::ifstream::in);
    if (!chipbase.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>("Failed to open gpiochip base!");
        return -1;
    }

    chipbase >> base;
    chipbase.close();

    gpio += base;

    if (!std::filesystem::exists("/sys/class/gpio/gpio" + std::to_string(gpio))) {
        std::ofstream exportOf("/sys/class/gpio/export", std::ofstream::out);
        if (!exportOf.is_open()) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio export!");
            return -2;
        }
        exportOf << gpio;
        exportOf.close();
    }
    return gpio;
}

static ipmi::RspType<uint8_t> getGpioCmd(std::string gpiochip, uint32_t gpio)
{
    int gp = gpioExport(gpiochip, gpio);
    if (gp < 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to export gpio!");
        return ipmi::responseUnspecifiedError();
    }
    std::ifstream valueIf("/sys/class/gpio/gpio886/value", std::ifstream::in);
    if (!valueIf.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio value!");
        return ipmi::responseUnspecifiedError();
    }
    int r;
    valueIf >> r;

    return ipmi::responseSuccess(r);
}


static ipmi::RspType<> setGpioCmd(std::string gpiochip, uint32_t gpio, uint32_t value)
{
    int gp = gpioExport(gpiochip, gpio);

    if (gp < 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to export gpio!");
        return ipmi::responseUnspecifiedError();
    }

    int fd = open("/sys/class/gpio/gpio886/direction", O_WRONLY);
    if (fd == -1) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
			"Unable to open /sys/class/gpio/gpio886/direction");
        return ipmi::responseUnspecifiedError();
    }

    if (write(fd, "out", 3) != 3) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
			"Error writing to /sys/class/gpio/gpio886/direction");
        return ipmi::responseUnspecifiedError();
    }

    close(fd);

    fd = open("/sys/class/gpio/gpio886/value", O_WRONLY);
    if (fd == -1) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
			"Unable to open /sys/class/gpio/gpio886/value");
        return ipmi::responseUnspecifiedError();
    }

    if(value)
    {   
        if (write(fd, "1", 1) != 1) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
			    "Error writing to /sys/class/gpio/gpio886/value");
            return ipmi::responseUnspecifiedError();
        }
    }

    else {

        if (write(fd, "0", 1) != 1) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
			    "Error writing to /sys/class/gpio/gpio886/value");
            return ipmi::responseUnspecifiedError();
        }
    }    
    

    close(fd);
    return ipmi::responseSuccess();
}


ipmi::RspType<> ipmiOemMiscSetWP(uint8_t type, uint8_t id, uint8_t value)
{
    using namespace ipmi::nvidia::misc;
    if (type == getWPType) {
        return setGpioCmd(nvidia::GWpGpioChip, nvidia::GWpGpioId, value);
    }
    else {
        phosphor::logging::log<phosphor::logging::level::ERR>("Unknown  device  for WP requested");
    }

}

ipmi::RspType<uint8_t> ipmiOemMiscGetWP(uint8_t type, uint8_t id)
{
    using namespace ipmi::nvidia::misc;
    if (type == getWPType) {
        return getGpioCmd(nvidia::GWpGpioChip, nvidia::GWpGpioId);
    }
    else {
        phosphor::logging::log<phosphor::logging::level::ERR>("Unknown  device  for WP requested");

    }

}


bool isServiceActive(const std::string& serviceName)
{
    std::variant<std::string> propertyValue;
    std::string activeState;
    std::string objectPath = "/org/freedesktop/systemd1/unit/" + serviceName;
    auto bus = getSdBus();
    auto message =
        bus->new_method_call("org.freedesktop.systemd1",
                             objectPath.c_str(),
                             "org.freedesktop.DBus.Properties",
                             "Get");

    message.append("org.freedesktop.systemd1.Unit", "ActiveState");

    try
    {
        auto response = bus->call(message);
        response.read(propertyValue);
        activeState = std::get<std::string>(propertyValue);
        return (activeState == "active");
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            "Failed to get the service state",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return false;
    }
}

ipmi::RspType<uint8_t> ipmicmdStandByPowerOnOff(uint8_t StandByPowerOption)
{
    int response;
    if (StandByPowerOption == 0x00)
    {
        // To start nvidia-standby-poweroff 'run power' has to be DOWN i.e RUN_POWER_EN = 0
        std::string standbyPoweroff = "systemctl start nvidia-standby-poweroff.service";
        std::string runPower = "obmcutil poweroff";
        auto r = system(runPower.c_str());
        if (r != 0)
        {
            phosphor::logging::log<level::ERR>(
                "Run Power Error: Run power is still UP");
            
            return ipmi::response(ipmi::ccResponseError);
        }

        
        auto s = system(standbyPoweroff.c_str());
        if (s != 0)
        {
            phosphor::logging::log<level::ERR>(
            "Stand By Power OFF Error : Not able to set it UP");
            return ipmi::response(ipmi::ccResponseError);
        }
            
        return ipmi::response(ipmi::ccSuccess);

    }

    else if (StandByPowerOption == 0x01)
    {
        // To start nvidia-standby-poweron 'run power' should be UP which will turn nvidia-standby-poweroff down and set RUN_POWER_PG = 1
        std::string standbyPoweron = "systemctl start nvidia-standby-poweron.service";
        std::string runPower = "obmcutil poweron";
        auto r = system(runPower.c_str());
        if (r != 0)
        {
            phosphor::logging::log<level::ERR>(
                "Run Power Error: Run power is not coming UP");
            
            return ipmi::response(ipmi::ccResponseError);
        }

        
        auto s = system(standbyPoweron.c_str());
        if (s != 0)
        {
            phosphor::logging::log<level::ERR>(
            "Stand By Power ON Error : Not able to set it UP");
            return ipmi::response(ipmi::ccResponseError);
        }
            
        return ipmi::response(ipmi::ccSuccess);

    }
    else if (StandByPowerOption == 0x02)
    {
        constexpr uint8_t standbyPowerOn = 0x1;
        constexpr uint8_t standbyPowerOff = 0x0;
        bool isStandbyPowerOffServiceActive = isServiceActive("nvidia_2dstandby_2dpoweroff_2eservice");
        bool isStandbyPowerOnServiceActive = isServiceActive("nvidia_2dstandby_2dpoweron_2eservice");
        uint8_t standbyPowerStatus = 0;
        if (isStandbyPowerOffServiceActive == false && \
            isStandbyPowerOnServiceActive == false)
        {
            standbyPowerStatus = standbyPowerOn;
        }
        else if (isStandbyPowerOffServiceActive == false)
        {
            standbyPowerStatus = standbyPowerOn;
        }
        else
        {
            standbyPowerStatus = standbyPowerOff;
        }

        return ipmi::responseSuccess(standbyPowerStatus);
    }

return ipmi::response(ipmi::ccInvalidFieldRequest);

}

ipmi::RspType<uint8_t> ipmiStandbyPowerCycle()
{
    int response;
    std::string standbyPowerCycle = "stbypowerctrl.sh aux_cycle";
    phosphor::logging::log<level::INFO>(
        "Starting standby power cycle");
    auto r = system(standbyPowerCycle.c_str());
    if (r != 0)
    {
        phosphor::logging::log<level::ERR>(
            "Standby Power Cycle Error: Could not complete standby power cycle");
        return ipmi::response(ipmi::ccResponseError);
    }
    return ipmi::response(ipmi::ccSuccess);
}

} // namespace ipmi

void registerNvOemFunctions()
{

    // <Get IPMI OEM Version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetOEMVersion));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetOEMVersion,
                          ipmi::Privilege::User, ipmi::ipmiGetOEMVersion);

 #ifdef ENABLE_SMBPBI_PASSTHRU
    #if ENABLE_SMBPBI_PASSTHRU == 1
    // <Execute SMBPBI passthrough command>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSMBPBIPassthrough));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSMBPBIPassthrough,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSMBPBIPassthroughCmd);

    // <Execute SMBPBI passthrough command for extended data>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSMBPBIPassthroughExtended));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSMBPBIPassthroughExtended,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSMBPBIPassthroughExtendedCmd);
    #endif
#endif

    // <Set fan control mode>
    log<level::NOTICE>("Registering ",
                       entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
                       entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetFanMode));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdSetFanMode,
                          ipmi::Privilege::Admin, ipmi::ipmiSetFanControl);

    // <Set All Fan Zones PWM Duty>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdAllFanZonesPWMDuty));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdAllFanZonesPWMDuty,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetAllFanZonesPWMDuty);

    // <Set Fan Zone PWM Duty>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetFanZonePWMDuty));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdSetFanZonePWMDuty,
                          ipmi::Privilege::Admin, ipmi::ipmiSetFanZonePWMDuty);

    // <Enable/Disable sensor scanning>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSensorScanEnable));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSensorScanEnable,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSensorScanEnableDisable);

    // <Get SSD LED Status>
    log<level::NOTICE>("Registering ",
                       entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
                       entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetSSDLed));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetSSDLed,
                          ipmi::Privilege::Admin, ipmi::ipmiOemGetSSDLed);

    // <Set SSD LED Status>
    log<level::NOTICE>("Registering ",
                       entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
                       entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetSSDLed));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetSSDLed,
                          ipmi::Privilege::Admin, ipmi::ipmiOemSetSSDLed);

    // <Get LED Status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetLedStatus));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetLedStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemGetLedStatus);

    // <Master Read Write>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemPost),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdI2CMasterReadWrite));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdI2CMasterReadWrite,
                          ipmi::Privilege::Admin, ipmi::ipmiI2CMasterReadWrite);
    // <Get SEL Policy>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetSELPolicy));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetSELPolicy,
                          ipmi::Privilege::Admin, ipmi::ipmiGetSELPolicy);
    // <Set SEL Policy>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetSELPolicy));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetSELPolicy,
                          ipmi::Privilege::Admin, ipmi::ipmiSetSELPolicy);
    // <Get USB Description>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetUsbDescription));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetUsbDescription,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbDescription);

    // <Get Virtual USB Serial Number>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetUsbSerialNum));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetUsbSerialNum,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbSerialNum);

    // <Get Redfish Service Hostname>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetRedfishHostName));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetRedfishHostName,
                          ipmi::Privilege::Admin, ipmi::ipmiGetRedfishHostName);

    // <Get IPMI Channel Number of Redfish HostInterface>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetipmiChannelRfHi));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetipmiChannelRfHi,
                          ipmi::Privilege::Admin, ipmi::ipmiGetipmiChannelRfHi);

    // <Get Bootstrap Account Credentials>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBootStrapAcc));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetBootStrapAcc,
                               ipmi::Privilege::sysIface,
                               ipmi::ipmiGetBootStrapAccount);

    // <Get Redfish Service UUID>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetRedfishServiceUuid));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetRedfishServiceUuid,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServiceUuid);

    // <Set BIOS Password>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetBiosPassword));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiSetBiosPassword);

    // <Get BIOS Password>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBiosPassword));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPassword);

    // <Get Redfish Service Port Number>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetRedfishServicePort));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetRedfishServicePort,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServicePort);

    // <Get Manager Certificate Fingerprint>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetManagerCertFingerPrint));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetManagerCertFingerPrint,
                               ipmi::Privilege::Admin,
                               ipmi::ipmiGetManagerCertFingerPrint);

    // <Soft Reboot>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSoftPowerCycle));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSoftPowerCycle,
                          ipmi::Privilege::Admin, ipmi::ipmiOemSoftReboot);

    // <Get BMC Boot complete>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBMCBootComplete));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBMCBootComplete,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBMCBootComplete);

    // <Get WP status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetWpStatus));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetWpStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscGetWP);

    // <Set WP status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetWpStatus));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetWpStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscSetWP);
  
    // <set stand by power on-off>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::chassis::cmdStandByPower));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::chassis::cmdStandByPower,
                          ipmi::Privilege::Admin, ipmi::ipmicmdStandByPowerOnOff);

    // <Standby Power Cycle>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::chassis::cmdStandbyPowerCycle));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::chassis::cmdStandbyPowerCycle,
                          ipmi::Privilege::Admin, ipmi::ipmiStandbyPowerCycle);

    return;
}

