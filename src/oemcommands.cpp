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

// IPMI OEM Major and Minor version
static constexpr uint8_t OEM_MAJOR_VER = 0x01;
static constexpr uint8_t OEM_MINOR_VER = 0x00;

void registerNvOemFunctions() __attribute__((constructor));

using namespace phosphor::logging;

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

    return;
}
