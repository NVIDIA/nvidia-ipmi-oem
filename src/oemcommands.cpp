/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>
#include <array>
#include <tuple>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <bits/stdc++.h>
#include <boost/algorithm/string.hpp>
#include <boost/process/child.hpp>

// Network object in dbus
const char* networkService = "xyz.openbmc_project.Network";
const char* networkObj = "/xyz/openbmc_project/network";
const char* networkResetIntf = "xyz.openbmc_project.Common.FactoryReset";

// Software BMC Updater object in dbus
const char* sftBMCService = "xyz.openbmc_project.Software.BMC.Updater";
const char* sftBMCObj = "/xyz/openbmc_project/software";
const char* sftBMCResetIntf = "xyz.openbmc_project.Common.FactoryReset";

const char* sftVendorFieldModeService = "xyz.openbmc_project.Software.BMC.VendorFieldModeService";
const char* vendorFieldModeBMCObj = "/xyz/openbmc_project/software/vendorfieldmode";
std::string sftBMCVendorFieldModeIntf = "xyz.openbmc_project.Common.VendorFieldMode";

//dbus names for interacting with systemd
const char* systemdService = "org.freedesktop.systemd1";
const char* systemdUnitIntf = "org.freedesktop.systemd1.Unit";
const char* rshimSystemdObj = "/org/freedesktop/systemd1/unit/rshim_2eservice";
// BMC state object in dbus
static constexpr const char* bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr const char* currentBmcStateProp = "CurrentBMCState";
static constexpr const char* bmcStateReadyStr =
    "xyz.openbmc_project.State.BMC.BMCState.Ready";

// GPU smbpbi object in dbus
static constexpr const char* gpuSMBPBIIntf = "xyz.openbmc_project.GpuMgr.Server";
static constexpr const char* gpuSMBPBIPath = "/xyz/openbmc_project/GpuMgr";

// SEL policy in dbus
const char* selLogObj = "/xyz/openbmc_project/logging/settings";
const char* selLogIntf = "xyz.openbmc_project.Logging.Settings";

// BMC time object in dbus
const char* timeObj = "/xyz/openbmc_project/time/sync_method";
const char* timeIntf = "xyz.openbmc_project.Time.Synchronization";

// BMC network object in dbus
#if USE_ETH1_NETWORK_DEVICE
   std::string networkNTPObj = "/xyz/openbmc_project/network/eth1";
#else
   std::string networkNTPObj = "/xyz/openbmc_project/network/eth0";
#endif
std::string networkNTPIntf = "xyz.openbmc_project.Network.EthernetInterface";

// PSU Inventory
static constexpr const std::array<const char*, 1> psuIntf = {
    "xyz.openbmc_project.Inventory.Item.PowerSupply"};

// IPMI OEM Major and Minor version
static constexpr uint8_t OEM_MAJOR_VER = 0x01;
static constexpr uint8_t OEM_MINOR_VER = 0x00;

void registerNvOemFunctions() __attribute__((constructor));

using namespace phosphor::logging;

using GetSubTreeType = std::vector<
    std::pair<std::string,
        std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using BasicVariantType = std::variant<std::string>;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;

namespace ipmi
{

static std::tuple <int, std::string>
    execBusctlCmd(std::string cmd)
{
    char buffer[128];
    std::string result = "";
    std::string command = "busctl ";
    command += cmd;

    // Open pipe to file
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exec busctl cmd popen failed!");
    }

    // Read till end of process
    while (!feof(pipe)) {
        // Use buffer to read and add to result
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }

    // Return result with exit code
    int ret = pclose(pipe);
    return make_tuple(ret, result);
}

static std::tuple <int, std::string>
    busctlSetProperty(std::string service,
                      std::string obj,
                      std::string inf,
                      std::string prop,
                      std::string args)
{
    // Set property
    std::string cmd = "set-property ";
    cmd += service + " ";
    cmd += obj + " ";
    cmd += inf + " ";
    cmd += prop + " ";
    cmd += args;

    return execBusctlCmd(cmd);
}

static std::tuple <int, std::string>
    busctlGetProperty(std::string service,
                      std::string obj,
                      std::string inf,
                      std::string prop)
{
    // Get property
    std::string cmd = "get-property ";
    cmd += service + " ";
    cmd += obj + " ";
    cmd += inf + " ";
    cmd += prop;

    return execBusctlCmd(cmd);
}

ipmi::RspType<> ipmiSystemFactoryReset(boost::asio::yield_context yield)
{
    /*
     * BMC factory reset must be use to restore the BMC to its
     * original manufacturer settings.
     * IPMI performs below 2 steps:
     * 1. The network factory reset, it overwrites the configuration
     *    for all configured network interfaces to a DHCP setting.
     * 2. The BMC software updater factory reset, it clears any
     *    volumes and persistence files created by the BMC processes.
     *    This reset occurs only on the next BMC reboot.
     */

    auto sdbusp = getSdBus();
    boost::system::error_code ec;

    // Network factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            networkService,
            networkObj,
            networkResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on network reset");
            return ipmi::responseUnspecifiedError();
        }

    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    // BMC software updater factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            sftBMCService,
            sftBMCObj,
            sftBMCResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on BMC software reset");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

template <typename... ArgTypes>
static int executeCmd(const char* path, ArgTypes&&... tArgs)
{
    boost::process::child execProg(path, const_cast<char*>(tArgs)...);
    execProg.wait();
    return execProg.exit_code();
}


ipmi::RspType<uint8_t>
ipmiBF2ResetControl(uint8_t resetOption)
{
    int response;
    switch(resetOption)
    {
        case 0x00: // soc hard reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "soc_hard_reset");
            break;
        case 0x01: // arm hard reset - nsrst
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "arm_hard_reset");
            break;
        case 0x02: // arm soft reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "arm_soft_reset");
            break;
        case 0x03: // tor eswitch reset
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "do_tor_eswitch_reset");
            break;
        case 0x04: // arm hard reset - nsrst - secondary DPU
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "bf2_nic_bmc_ctrl1");
            break;
        case 0x05: // arm soft reset - secondary DPU
            response = executeCmd("/usr/sbin/mlnx_bf2_reset_control", "bf2_nic_bmc_ctrl0");
            break;
        default:
            return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    if(response)
    {
        log<level::ERR>("Reset Command failed.",
                phosphor::logging::entry("rc= %d", response));
        return ipmi::response(ipmi::ccResponseError);
    }

    return ipmi::response(ipmi::ccSuccess);
}

ipmi::Cc i2cSMBusWriteRead(int i2cdev, const uint8_t slaveAddr, uint8_t devAddr,
                           uint8_t read_write, uint8_t* buf)
{
    struct i2c_smbus_ioctl_data ioctl_data;
    union i2c_smbus_data smbus_data;
    int rc;
    uint8_t len = buf[0];

    if (len > (I2C_SMBUS_BLOCK_MAX+1))
    {
        log<level::ERR>("Invalid length",
                        phosphor::logging::entry("read_write= %u, len=%u",
                        read_write, len));
        return ipmi::ccReqDataLenInvalid;
    }

    if ((rc = ::ioctl(i2cdev, I2C_SLAVE, slaveAddr)) < 0)
    {
        log<level::ERR>("Failed to acquire bus access",
                        phosphor::logging::entry("read_write=%u, len=%u, slaveAddr=0x%x, rc=%d",
                        read_write, len, slaveAddr, rc));
        return ipmi::ccDestinationUnavailable;
    }

    smbus_data.block[0] = len;

    if (read_write != I2C_SMBUS_READ)
    {
        for(int i = 1; i < (len+1); i++)
        {
            smbus_data.block[i] = buf[i];
        }
    }

    ioctl_data.read_write = read_write;
    ioctl_data.command = devAddr;
    ioctl_data.size = I2C_SMBUS_I2C_BLOCK_DATA;
    ioctl_data.data = &smbus_data;

    rc = ::ioctl(i2cdev, I2C_SMBUS, &ioctl_data);
    if (rc < 0)
    {
        log<level::ERR>("Failed to access I2C_SMBUS Read/Write",
                        phosphor::logging::entry("read_write=%u, len=%u, slaveAddr=0x%x, devAddr=0x%x, rc=%d",
                        read_write, len, slaveAddr, devAddr, rc));
        return ipmi::ccDestinationUnavailable;
    }

    if (read_write == I2C_SMBUS_READ)
    {
        buf[0] = smbus_data.block[0];
        for(int i = 1; i < (len+1); i++)
        {
            // Skip the first byte, which is the length of the rest of the block.
            buf[i] = smbus_data.block[i];
        }
    }

    return ipmi::ccSuccess;
}

ipmi::RspType<uint8_t, std::vector<uint8_t>>
ipmiPSUInventoryInfo(uint8_t psuNum, uint8_t psuInfoSelector)
{

    std::array<uint8_t, 4> psuCmd = {0x9E, 0x9A, 0x99, 0x9B};
    std::array<uint8_t, 4> psuInfoLen = {0x0D, 0x0C, 0x06, 0x06};
    std::array<uint8_t, 3> slaveAddress = {0x40, 0x41, 0x42};
    std::vector<uint8_t> dataReceived;
    int size = I2C_SMBUS_I2C_BLOCK_DATA;
    uint8_t bus = 3;

    if (psuNum > 5)
    {
        log<level::ERR>("Invalid psuNum",
                        phosphor::logging::entry("psuNum=%u", psuNum));
        return ipmi::responseInvalidFieldRequest();
    }
    else
    {
        if (psuNum < 3)
        {
            bus = 4;
        }
        else
        {
            bus = 3;
        }
    }

    // psuInfoSelector
    // 0 = Serial Number
    // 1 = Part Number
    // 2 = Vendor
    // 3 = Model
    if (psuInfoSelector > 3)
    {
        log<level::ERR>("Invalid psuInfoSelector",
                        phosphor::logging::entry("psuInfoSelector=%u",
                        psuInfoSelector));
        return ipmi::responseInvalidFieldRequest();
    }

    std::string i2cBus = "/dev/i2c-" + std::to_string(bus);

    // Open the i2c device, for low-level combined data write/read
    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        log<level::ERR>("Failed to open i2c bus",
                        phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
        return ipmi::responseInvalidFieldRequest();
    }

    // psuNum range is 0 to 5.  Under each mux channel number is 0 to 2
    // Select mux channel first: i2cMux@0x70 device_address@0x04
    // chanel_number is bit 0 and 1 ith bit 2 as enable bit in data_byte=000001xx
    uint8_t muxData[2] = {0};
    muxData[0] = 1;
    muxData[1] = (0x04 | (psuNum % 3));
    auto retI2C = i2cSMBusWriteRead(i2cDev, 0x70, 0x04, I2C_SMBUS_WRITE,
                                    muxData);
    if (retI2C != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed doing i2c SMBus Write to set channel to the MUX",
                        phosphor::logging::entry("BUS=%s, muxData[0]=0x%x",
                        i2cBus.c_str(), muxData[0]));
        ::close(i2cDev);
        return ipmi::response(retI2C);
    }

    uint8_t psuInfoBuf[I2C_SMBUS_BLOCK_MAX+1] = {0};
    psuInfoBuf[0] = psuInfoLen[psuInfoSelector];
    retI2C = i2cSMBusWriteRead(i2cDev, slaveAddress[(psuNum % 3)],
                               psuCmd[psuInfoSelector], I2C_SMBUS_READ,
                               psuInfoBuf);
    ::close(i2cDev);

    if (retI2C != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed doing i2c SMBus Read of psu_info",
                        phosphor::logging::entry("BUS=%s, slaveAddress[%u]=0x%x, psuCmd[%u]=0x%x, psuInfoLen[%u]=%u",
                        i2cBus.c_str(), (psuNum % 3),
                        slaveAddress[(psuNum % 3)], psuInfoSelector,
                        psuCmd[psuInfoSelector], psuInfoSelector,
                        psuInfoLen[psuInfoSelector]));
        return ipmi::response(retI2C);
    }

    for (int i = 1; i < (psuInfoBuf[0] + 1); i++)
    {
        dataReceived.emplace_back(psuInfoBuf[i]);
    }

    return ipmi::responseSuccess(psuInfoSelector, dataReceived);
}

ipmi::RspType<std::vector<std::string>> ipmiGetDNSConfig()
{
    /*
     * Response data:
     * Byte 1    : Size N of DNS server string
     * Byte 2-N  : DNS Server IP, MSB First
     * Byte N+1  : Size P of next DNS server string
     * Byte N+2-P: Next DNS Server IP, MSB First
     */
    std::vector<std::string> recordData;

    // Get DNS Servers
    try
    {
        int ret;
        std::string dnsServerStr;
        std::string networkServiceStr = networkService;
        // Improvement: Use dbus API for array of strings dbus property type
        tie(ret, dnsServerStr) = busctlGetProperty(networkServiceStr,
                                                   networkNTPObj,
                                                   networkNTPIntf,
                                                   "StaticNameServers");
        // Check return code
        if(ret)
        {
            log<level::ERR>("busctl get-property dns servers failed.",
                phosphor::logging::entry("rc= %d", ret));
            return ipmi::responseResponseError();
        }
        // Parse the result
        // get-property format: as <size> <dnsserver1> <dnsserver2>
        std::vector<std::string> dnsServers;
        boost::split(dnsServers, dnsServerStr, boost::is_any_of(" "));
        // Populate DNS servers result
        int dnsCount = stoi(dnsServers[1]);
        for(int i = 2; i < (2+dnsCount); i++)
        {
            std::string dns;
            if (i == (dnsCount+1))
            {
                // Strip trailing `"\n`
                dns = dnsServers[i].substr(1, dnsServers[i].length() - 3);
            }
            else
            {
                // Strip trailing `"`
                dns = dnsServers[i].substr(1, dnsServers[i].length() - 2);
            }
            recordData.push_back(dns);
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get DNS server config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(recordData);
}

ipmi::RspType<uint8_t> ipmiSetDNSConfig(std::vector<std::string> dnsServers)
{
    try
    {
        // Add args
        std::string args = "as ";
        std::string s = std::to_string(dnsServers.size());
        // Add array string size
        args += s;
        // Add DNS servers
        for (auto it = dnsServers.begin();
                it != dnsServers.end(); ++it)
        {
            args += " " + *it;
        }
        // Improvement: Use dbus API for array of strings dbus property type
        int ret;
        std::string dnsServerStr;
        std::string networkServiceStr = networkService;
        tie(ret, dnsServerStr) = busctlSetProperty(networkServiceStr,
                                                   networkNTPObj,
                                                   networkNTPIntf,
                                                   "StaticNameServers",
                                                   args);
        // Check return code
        if (ret)
        {
            log<level::ERR>("busctl set-property dns servers failed.",
                phosphor::logging::entry("rc= %d", ret));
            return ipmi::responseResponseError();
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to set DNS config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t,                 // NTP Status
              std::vector<std::string> // NTP Servers
              >
    ipmiGetNTPConfig()
{
    /*
     * Response data:
     * Byte 1: Enable/Disable/Failure Status of NTP (0x01 / 0x00 / 0x02)
     * Byte 2    : Size N of primary NTP Server Address
     * Byte 3-N  : Primary NTP Server Address, MSB First
     * Byte N+1  : Size P of secondary NTP Server Address
     * Byte N+2-P: Secondary NTP Server Address, MSB First
     */
    uint8_t ntpStatus;
    std::vector<std::string> recordData;

    // Get NTP status
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        // Check NTP enabled or disabled
        auto service =
            ipmi::getService(*dbus, timeIntf, timeObj);
        auto timeMethod =
            ipmi::getDbusProperty(*dbus, service, timeObj,
                timeIntf, "TimeSyncMethod");

        if (std::get<std::string>(timeMethod) ==
            "xyz.openbmc_project.Time.Synchronization.Method.Manual")
        {
            ntpStatus = 0;
        }
        else if (std::get<std::string>(timeMethod) ==
           "xyz.openbmc_project.Time.Synchronization.Method.NTP")
        {
            ntpStatus = 1;
        }
        else
        {
            ntpStatus = 2;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get NTP status",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }

    // Get NTP Servers
    try
    {
        int ret;
        std::string ntpServerStr;
        std::string networkServiceStr = networkService;
        // Improvement: Use dbus API for array of strings dbus property type
        tie(ret, ntpServerStr) = busctlGetProperty(networkServiceStr,
                                                   networkNTPObj,
                                                   networkNTPIntf,
                                                   "NTPServers");
        // Check return code
        if(ret)
        {
            log<level::ERR>("busctl get-property ntpservers failed.",
                phosphor::logging::entry("rc= %d", ret));
            return ipmi::responseResponseError();
        }
        // Parse the result
        // get-property format: as <size> <ntpserver1> <ntpserver2>
        std::vector<std::string> ntpServers;
        boost::split(ntpServers, ntpServerStr, boost::is_any_of(" "));
        // Check NTP Servers exists
        if (stoi(ntpServers[1]) > 0)
        {
            // Strip trailing `"\n`
            std::string ntp;
            if (stoi(ntpServers[1]) > 1)
            {
                ntp = ntpServers[2].substr(1, ntpServers[2].length() - 2);
                recordData.push_back(ntp);
                ntp = ntpServers[3].substr(1, ntpServers[3].length() - 3);
                recordData.push_back(ntp);
            }
            else
            {
                ntp = ntpServers[2].substr(1, ntpServers[2].length() - 3);
                recordData.push_back(ntp);
            }
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get NTP server config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(static_cast<uint8_t>(ntpStatus), recordData);
}

ipmi::RspType<uint8_t> ipmiSetNTPConfig(uint8_t ntpOption, std::vector<uint8_t>& ntpserver)
{
    /*
     * Request data:
     * Byte 1:
     *   00 -> Set Primary Server IP
     *   01 -> Set Secondary Server IP
     *   02 -> Enable/Disable NTP
     * Byte 2-129: Server Address
     * Byte 2: 1/0 Enable/Disable NTP Server
     */
    try
    {
        if (ntpOption == 0x02)
        {
            // Enable/Disable NTP
            if (ntpserver.size() != 1)
            {
                return ipmi::responseReqDataLenInvalid();
            }

            uint8_t enableNTP = ntpserver[0];
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            auto service = ipmi::getService(*dbus, timeIntf, timeObj);

            if (enableNTP == 1)
            {
                ipmi::setDbusProperty(*dbus, service, timeObj,
                    timeIntf, "TimeSyncMethod",
                    std::string("xyz.openbmc_project.Time.Synchronization.Method.NTP"));
            }
            else if (enableNTP == 0)
            {
                ipmi::setDbusProperty(*dbus, service, timeObj,
                    timeIntf, "TimeSyncMethod",
                    std::string("xyz.openbmc_project.Time.Synchronization.Method.Manual"));
            }
            else
            {
                return ipmi::response(ipmi::ccInvalidFieldRequest);
            }
        }
        else if ((ntpOption == 0x00) || (ntpOption == 0x01))
        {
            if ((ntpserver.size() > 128) || (ntpserver.size() < 1))
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // Get NTP servers
            int ret;
            std::string ntpServerStr;
            std::string networkServiceStr = networkService;
            // Improvement: Use dbus API for array of strings dbus property type
            tie(ret, ntpServerStr) = busctlGetProperty(networkServiceStr,
                                                       networkNTPObj,
                                                       networkNTPIntf,
                                                       "NTPServers");
            // Check return code
            if (ret)
            {
                log<level::ERR>("busctl get-property ntpservers failed.",
                    phosphor::logging::entry("rc= %d", ret));
                return ipmi::responseResponseError();
            }
            std::vector<std::string> ntpServers;
            std::string pri = "";
            std::string sec = "";
            boost::split(ntpServers, ntpServerStr, boost::is_any_of(" "));
            // Get old primary and secondary
            // Strip trailing `"\n`
            if (stoi(ntpServers[1]) > 1)
            {
                pri = ntpServers[2].substr(1, ntpServers[2].length() - 2);
                sec = ntpServers[3].substr(1, ntpServers[3].length() - 3);
            }
            else if (stoi(ntpServers[1]) > 0)
            {
                pri = ntpServers[2].substr(1, ntpServers[2].length() - 3);
            }
            // Get new primary and secondary
            if (ntpOption == 0x00)
            {
                // Set primary NTP
                std::string newPri(ntpserver.begin(), ntpserver.end());
                pri = newPri;
            }
            else
            {
                // Set secondary NTP
                std::string newSec(ntpserver.begin(), ntpserver.end());
                if (pri == "")
                {
                    pri = newSec;
                }
                sec = newSec;
            }
            // Add args
            std::string args = "as ";
            // Add array string size
            if (sec == "")
            {
                args += "1 ";
            }
            else
            {
                args += "2 ";
            }
            // Add ntpserver strings
            if (pri != "")
            {
                args += pri;
            }
            if (sec != "")
            {
                args += " " + sec;
            }
            // Improvement: Use dbus API for array of strings dbus property type
            tie(ret, ntpServerStr) = busctlSetProperty(networkServiceStr,
                                                       networkNTPObj,
                                                       networkNTPIntf,
                                                       "NTPServers",
                                                       args);
            // Check return code
            if (ret)
            {
                log<level::ERR>("busctl set-property ntpservers failed.",
                    phosphor::logging::entry("rc= %d", ret));
                return ipmi::responseResponseError();
            }
        }
        else
        {
            return ipmi::response(ipmi::ccInvalidFieldRequest);
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to set NTP config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiGetSELPolicy()
{
    // SEL policy:
    // Linear represents 0x00
    // Circular represents 0x01
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*dbus, selLogIntf, selLogObj);
        auto policy =
            ipmi::getDbusProperty(*dbus, service, selLogObj,
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
        auto service =
            ipmi::getService(*dbus, selLogIntf, selLogObj);
        auto policy =
            ipmi::getDbusProperty(*dbus, service, selLogObj,
                selLogIntf, "SelPolicy");

        switch (policyType)
        {
            case 0:
                // Do nothing for same policy request
                if (std::get<std::string>(policy) !=
                    "xyz.openbmc_project.Logging.Settings.Policy.Linear")
                {
                    ipmi::setDbusProperty(*dbus, service, selLogObj,
                        selLogIntf, "SelPolicy",
                        std::string("xyz.openbmc_project.Logging.Settings.Policy.Linear"));
                }
                break;
            case 1:
                // Do nothing for same policy request
                if (std::get<std::string>(policy) !=
                    "xyz.openbmc_project.Logging.Settings.Policy.Circular")
                {
                    ipmi::setDbusProperty(*dbus, service, selLogObj,
                        selLogIntf, "SelPolicy",
                        std::string("xyz.openbmc_project.Logging.Settings.Policy.Circular"));
                }
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "SEL policy: invalid type!",
                    phosphor::logging::entry(
                        "Request Value=%d", policyType));
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

ipmi::RspType<> ipmiSetVendorFieldModeConfig(boost::asio::yield_context yield, uint8_t setEnabled)
{

    /*
     * BMC set vendor field mode is used to set the state of
     * vendor field mode in the u-boot-env.
     * State can be either Enabled if the status is set to true,
     * or Disbaled if the status is set to false.
     */
    /*
     * Request data:
     * Byte 1:
     *   00 -> Disable Vendor Field Mode
     *   01 -> Enable Vendor Field Mode
    */

    auto sdbusp = getSdBus();
    boost::system::error_code ec;

    try
    {
        bool status{false};

        if (setEnabled != 0x00 && setEnabled != 0x01)
        {
            return ipmi::response(ipmi::ccInvalidFieldRequest);
        }

        status = (setEnabled) ? true: false;

        sdbusp->yield_method_call<void>(
            yield, ec,
            sftVendorFieldModeService,
            vendorFieldModeBMCObj,
            sftBMCVendorFieldModeIntf,
            "SetVendorFieldModeStatus",
            status);

        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on BMC set vendor field mode");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiGetVendorFieldModeConfig(boost::asio::yield_context yield)
{
    /*
     * Response data:
     * Byte 1    : 0x01 if field mode set Enabled or 0x00.
    */

    auto sdbusp = getSdBus();
    boost::system::error_code ec;
    bool status = false;
    try
    {
        status = sdbusp->yield_method_call<bool>(
                    yield, ec,
                    sftVendorFieldModeService,
                    vendorFieldModeBMCObj,
                    sftBMCVendorFieldModeIntf,
                    "IsVendorFieldModeEnabled");
    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(status);
}

ipmi::RspType<> ipmiSetRshimState(uint8_t newState)
{
    /*
     * Change rshim service state.
     */
    /*
     * Request data:
     * Byte 1:
     *   00 -> Stop Rshim
     *   01 -> Start Rshim
    */
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string systemdCmd;

    switch (newState)
    {
    case 0 : //Stop
        systemdCmd = "Stop";
        break;

    case 1 : //Start
        systemdCmd = "Start";
        break;

    default: //Error
        log<level::ERR>("Unsupported argument",
            phosphor::logging::entry("Requested State=%d", newState));
        return ipmi::responseInvalidFieldRequest();
        break;
    }

    try
    {
        sdbusplus::message::message rshimControl = dbus->new_method_call(
            systemdService, rshimSystemdObj,
            systemdUnitIntf, systemdCmd.c_str());
        rshimControl.append("replace");
        dbus->call_noreply(rshimControl);
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to change Rshim service state",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiGetRshimState()
{
    /*
     * Response data:
     * Byte 1    : 0x01 if rshim service is running or 0x00 otherwise.
    */

    auto sdbusp = getSdBus();
    bool status = false;
    try
    {
        auto rshimActiveState =
            ipmi::getDbusProperty(*sdbusp, systemdService, rshimSystemdObj,
                systemdUnitIntf, "ActiveState");

        status = (std::get<std::string>(rshimActiveState) == "active");
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get Rshim service status",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(status);
}

ipmi::RspType<
    uint8_t,  // Major Version
    uint8_t  // Minor Version
    > ipmiGetOEMVersion()
{
    return ipmi::responseSuccess(OEM_MAJOR_VER, OEM_MINOR_VER);
}

ipmi::RspType<uint8_t> ipmiGetFwBootupSlot(uint8_t FwType)
{
    switch (FwType)
    {
        case 0x00: // BMC
        {
            // TODO: Enable i2cWriteRead on actual hardware
            /*
            std::string i2cBus = "/dev/i2c-1";
            // Open the i2c device, for low-level combined data write/read
            int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
            if (i2cDev < 0)
            {
                log<level::ERR>("Failed to open i2c bus",
                    phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
                return ipmi::responseInvalidFieldRequest();
            }
            uint7_t slaveAddr = 0x55;
            std::vector<uint8_t> writeData={0x00, 0x9B};
            static const constexpr size_t bufLen = 7;
            std::vector<uint8_t> readBuf(bufLen);

            ipmi::Cc ret = ipmi::i2cWriteRead(i2cBus,
                static_cast<uint8_t>(slaveAddr), writeData, readBuf);

            ::close(i2cDev);

            if (ret != ipmi::ccSuccess)
            {
                return ipmi::response(ret);
            }

            if (0x00 == readBuf[0])
            {
                if ((0x01 == readBuf[1]) || (0x02 == readBuf[2]) || (0x05 == readBuf[3]))
                {
                    return ipmi::responseSuccess(static_cast<uint8_t>(0));
                }
                else if ((0x03 == readBuf[4]) || (0x04 == readBuf[5]) || (0x06 == readBuf[6]))
                {
                    return ipmi::responseSuccess(static_cast<uint8_t>(1));
                }
                else
                {
                    return ipmi::responseResponseError();
                }
            }
            else
            {
                return ipmi::responseResponseError();
            }
            */
            return ipmi::responseSuccess(static_cast<uint8_t>(0));
        }
        break;

        default:
            return ipmi::responseParmOutOfRange();
    }
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

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
    uint8_t, uint8_t, uint8_t, uint8_t, uint8_t> ipmiSMBPBIPassthroughCmd(
    uint8_t param, // GPU device : 0x01 fixed
    uint8_t deviceId,
    uint8_t opcode,
    uint8_t arg1,
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
        phosphor::logging::log<level::ERR>(
            "ipmiSMBPBIPassthroughCmd: Not an smpbi passthrough command request");
        return ipmi::responseResponseError();
    }
    // Call smpbi passthrough call
    int rc;
    std::vector<uint32_t> dataOut;
    std::tuple <int, std::vector<uint32_t>> smbpbiRes;
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
    std::tie (rc, dataOut) = smbpbiRes;
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

    return ipmi::responseSuccess(deviceId, retOpcode, retArg1, retArg2,
        status, res[0], res[1], res[2], res[3]);
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
    uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
    uint8_t, uint8_t, uint8_t, uint8_t> ipmiSMBPBIPassthroughExtendedCmd(
    uint8_t deviceId,
    uint8_t opcode,
    uint8_t arg1,
    uint8_t arg2,
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
            "ipmiSMBPBIPassthroughExtendedCmd: Not an smpbi passthrough extended command request");
        return ipmi::responseResponseError();
    }
    // Call smpbi passthrough call
    int rc;
    std::vector<uint32_t> dataOut;
    std::tuple <int, std::vector<uint32_t>> smbpbiRes;
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
            "ipmiSMBPBIPassthroughExtendedCmd: Passthrough method returned error",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", gpuSMBPBIPath));
        return ipmi::responseUnspecifiedError();
    }

    reply.read(smbpbiRes);
    std::tie (rc, dataOut) = smbpbiRes;
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

    return ipmi::responseSuccess(deviceId, retOpcode, retArg1, retArg2,
        status, res[0], res[1], res[2], res[3], extRes[0], extRes[1], extRes[2], extRes[3]);
}

ipmi::RspType<uint8_t>
ipmiSetAllFanZonesPWMDuty(uint8_t request)
{

    int value = 255;
	if ((request%10 == 0) && (request <= 100) && (request >= 20))
	{
		value = value*request/100;
		std::ofstream ofs;
		for(int i=6; i<=7; i++)
		{
			std::string path("/sys/class/hwmon/");
			path = path + "hwmon" + std::to_string(i) + "/pwm1";
			if (!ofs.is_open())
			{
				ofs.open(path);
			}
			ofs.clear();
			ofs.seekp(0);
			ofs << value;
			ofs.close();
		}
		return ipmi::responseSuccess();
	}
	else
	{
		return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
}

ipmi::RspType<uint8_t, std::vector<uint8_t>>
ipmiSetFanZonePWMDuty(uint8_t zone, uint8_t request)
{
	int value = 255;
	if(zone == 0x00)
	{
		return ipmi::responseSuccess();
	}
	else if(zone == 0x01)
	{
		if ((request%10 == 0) && (request <= 100) && (request >= 20))
		{
			value = value*request/100;
			std::ofstream ofs;
			std::string path("/sys/class/hwmon/hwmon6/pwm1");
			if (!ofs.is_open())
			{
				ofs.open(path);
			}
			ofs.clear();
			ofs.seekp(0);
			ofs << value;
			ofs.close();
			return ipmi::responseSuccess();
		}
		else
		{
			return ipmi::response(ipmi::ccInvalidFieldRequest);
		}
	}
	else if(zone == 0x02)
	{
		if ((request%10 == 0) && (request <= 100) && (request >= 20))
		{
			value = value*request/100;
			std::ofstream ofs;
			std::string path("/sys/class/hwmon/hwmon7/pwm1");
			if (!ofs.is_open())
			{
				ofs.open(path);
			}
			ofs.clear();
			ofs.seekp(0);
			ofs << value;
			ofs.close();
			return ipmi::responseSuccess();
		}
		else
		{
			return ipmi::response(ipmi::ccInvalidFieldRequest);
		}
	}
	else
	{
		return ipmi::response(ipmi::ccInvalidFieldRequest);
	}
}

ipmi::RspType<uint8_t, std::string> ipmiGetPSUInventory(
    ipmi::Context::ptr ctx,
    uint8_t psuNumber,
    uint8_t psuInfo)
{
    /*
     * Request data:
     * Byte 1: PSU Number
     * Byte 2: PSU Info
     *         00h: Serial Number
     *         01h: Part Number
     *         02h: Manufacturer
     *         03h: Revision
     */

    /*
     * Response data:
     * Byte 1: PSU Info
     *         00h: Serial Number
     *         01h: Part Number
     *         02h: Manufacturer
     *         03h: Revision
     * Byte Array 2~N: [2] string size and [3:N] string content
     */

    boost::system::error_code ec;
    GetSubTreeType subtree = ctx->bus->yield_method_call<GetSubTreeType>(
        ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/inventory", 0, psuIntf);
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetPSUInventory: Failed to get PSU inventory");
        return ipmi::responseResponseError();
    }

    // Validate request PSU number is within PSU inventory paths limit
    if (psuNumber >= subtree.size())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetPSUInventory: Requested PSU number not in range");
        return ipmi::responseInvalidFieldRequest();
    }

    for (const auto& object : subtree)
    {
        // Get the requested PSU number
        if (!boost::ends_with(object.first, std::to_string(psuNumber)))
        {
            continue;
        }
        for (const auto& serviceIface : object.second)
        {
            std::string serviceName = serviceIface.first;
            ec.clear();
            PropertyMapType propMap =
                ctx->bus->yield_method_call<PropertyMapType>(
                    ctx->yield, ec, serviceName, object.first,
                    "org.freedesktop.DBus.Properties", "GetAll", "");
            if (ec)
            {
                phosphor::logging::log<level::ERR>(
                    "ipmiGetPSUInventory: Failed to get dbus properties");
                return ipmi::responseResponseError();
            }
            std::string* res = nullptr;
            // Get requested info
            switch (psuInfo)
            {
                case 0 : // Serial Number
                    res = std::get_if<std::string>(&propMap["SerialNumber"]);
                    break;

                case 1 : // Part Number
                    res = std::get_if<std::string>(&propMap["PartNumber"]);
                    break;

                case 2 : // Manufacturer
                    res = std::get_if<std::string>(&propMap["Manufacturer"]);
                    break;

                case 3 : // Revision
                    res = std::get_if<std::string>(&propMap["Version"]);
                    break;

                default: // Error
                    phosphor::logging::log<level::ERR>(
                        "ipmiGetPSUInventory: Invalid PSU requested info");
                    return ipmi::responseInvalidFieldRequest();
                    break;
            }

            if (res == nullptr)
            {
                phosphor::logging::log<level::ERR>(
                        "ipmiGetPSUInventory: Empty requested dbus property");
                return ipmi::responseResponseError();
            }

            return ipmi::responseSuccess(psuInfo, *res);
        }
    }
    return ipmi::responseInvalidFieldRequest();
}

} // namespace ipmi
void registerNvOemFunctions()
{
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSystemFactoryReset));

    // <BMC Factory Reset>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSystemFactoryReset,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSystemFactoryReset);

    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdBF2ResetControl));

    // <BF2 Reset Control>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdBF2ResetControl,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiBF2ResetControl);

    // <Get DNS Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetDNSConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetDNSConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetDNSConfig);

    // <Set DNS Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetDNSConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetDNSConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetDNSConfig);

    // <Get NTP Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetNTPConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetNTPConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetNTPConfig);

    // <Set NTP Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetNTPConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetNTPConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetNTPConfig);

    // <PSU Inventory Info>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdPSUInventoryInfo));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPSUInventoryInfo,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiPSUInventoryInfo);

    // <Get SEL Policy>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetSELPolicy));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetSELPolicy,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetSELPolicy);

    // <Set SEL Policy>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetSELPolicy));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetSELPolicy,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetSELPolicy);

    // <Get Field Mode Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetVendorFieldModeConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetVendorFieldModeConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetVendorFieldModeConfig);

    // <Set Field Mode Config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetVendorFieldModeConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetVendorFieldModeConfig,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetVendorFieldModeConfig);

    // <Get RSHIM state>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetRshimState));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetRshimState,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRshimState);

    // <Start/Stop RSHIM service>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetRshimState));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetRshimState,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetRshimState);

    // <Get IPMI OEM Version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetOEMVersion));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetOEMVersion,
                          ipmi::Privilege::User,
                          ipmi::ipmiGetOEMVersion);

    // <Get FW Bootup slot>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetFwBootupSlot));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetFwBootupSlot,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetFwBootupSlot);

    // <Get BMC Boot complete>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBMCBootComplete));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBMCBootComplete,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetBMCBootComplete);

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

    // <Set All Fan Zones PWM Duty>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemFan),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdAllFanZonesPWMDuty));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemFan,
                          ipmi::nvidia::app::cmdAllFanZonesPWMDuty,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetAllFanZonesPWMDuty);

    // <Set Fan Zone PWM Duty>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemFan),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetFanZonePWMDuty));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemFan,
                          ipmi::nvidia::app::cmdSetFanZonePWMDuty,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetFanZonePWMDuty);

    // <Get PSU Inventory details>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetPSUInventory));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetPSUInventory,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetPSUInventory);

    return;
}
