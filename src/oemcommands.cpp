/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#include "oemcommands.hpp"

#include "biosversionutils.hpp"
#include "dgx-a100-config.hpp"

#include <bits/stdc++.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <security/pam_appl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/process/child.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

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

// Powermanager in dbus
const char* powerManagerCurrentChassisLimitObj =
    "/xyz/openbmc_project/control/power/CurrentChassisLimit";
const char* powerManagerCurrentChassisModeIntf =
    "xyz.openbmc_project.Control.Power.Mode";
const char* powerManagerCurrentChassisCapIntf =
    "xyz.openbmc_project.Control.Power.Cap";
const char* powerManagerChassisLimitPObj =
    "/xyz/openbmc_project/control/power/ChassisLimitP";
const char* powerManagerChassisLimitQObj =
    "/xyz/openbmc_project/control/power/ChassisLimitQ";
const char* powerManagerRestOfSystemPowerObj =
    "/xyz/openbmc_project/control/power/RestOfSystemPower";
const char* powerManagerRestOfSystemPowerIntf =
    "xyz.openbmc_project.Sensor.Value";
const char* powerManagerService = "com.Nvidia.Powermanager";

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

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

// BIOS PostCode object in dbus
static constexpr const char* postCodesService =
    "xyz.openbmc_project.State.Boot.PostCode0";
static constexpr const char* postCodesObjPath =
    "/xyz/openbmc_project/State/Boot/PostCode0";
static constexpr const char* postCodesIntf =
    "xyz.openbmc_project.State.Boot.PostCode";
const static constexpr char* postCodesProp = "CurrentBootCycleCount";

static constexpr const char* chassisStateService =
    "xyz.openbmc_project.State.Chassis";
static constexpr const char* chassisStatePath =
    "/xyz/openbmc_project/state/chassis0";
static constexpr const char* chassisStateIntf =
    "xyz.openbmc_project.State.Chassis";
// IPMI OEM Major and Minor version
static constexpr uint8_t OEM_MAJOR_VER = 0x01;
static constexpr uint8_t OEM_MINOR_VER = 0x00;

// IPMI OEM USB Linux Gadget info
static constexpr uint16_t USB_VENDOR_ID = 0x0525;
static constexpr uint16_t USB_PRODUCT_ID = 0xA4A2;
static constexpr uint8_t USB_SERIAL_NUM = 0x00;

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
// BIOS PostCode return error code
static constexpr Cc ipmiCCBIOSPostCodeError = 0x89;

// HI Certificate FingerPrint error code
static constexpr Cc ipmiCCBootStrappingDisabled = 0x80;
static constexpr Cc ipmiCCCertificateNumberInvalid = 0xCB;

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
	return make_tuple(-1, result);
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

static ipmi::Cc i2cTransaction(uint8_t bus, uint8_t slaveAddr, std::vector<uint8_t> &wrData, std::vector<uint8_t> &rdData) {
    std::string i2cBus = "/dev/i2c-" + std::to_string(bus);

    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        log<level::ERR>("Failed to open i2c bus",
                        phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
        return ipmi::ccInvalidFieldRequest;
    }
    std::shared_ptr<int> scopeGuard(&i2cDev, [](int *p) { ::close(*p); });

    auto ret = ipmi::i2cWriteRead(i2cBus, slaveAddr, wrData, rdData);
    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("Failed to perform I2C transaction!");
    }
    return ret;
}

ipmi::Cc psuReadInformation(uint8_t psuNum, uint8_t cmd, std::vector<uint8_t> &buffer) {
    if (psuNum >= nvidia::psuNumber) {
        return ipmi::ccParmOutOfRange;
    }

    std::vector<uint8_t> wr = {cmd};
    auto retI2C = i2cTransaction(nvidia::psuBus[psuNum], nvidia::psuAddr[psuNum], wr, buffer);
    if (retI2C != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed doing i2c SMBus Read of psu_info",
                        phosphor::logging::entry("BUS=%d, slaveAddress=0x%x, cmd=0x%x, len=%u",
                        nvidia::psuBus[psuNum], nvidia::psuAddr[psuNum], cmd, buffer.size()));
    }

    return retI2C;
}

ipmi::RspType<uint8_t, std::vector<uint8_t>>
ipmiPSUInventoryInfo(uint8_t psuNum, uint8_t psuInfoSelector)
{

    std::array<uint8_t, 4> psuCmd = {nvidia::psuRegSerialNumber,
                                        nvidia::psuRegPartNumber,
                                        nvidia::psuRegVendor,
                                        nvidia::psuRegModel};
    std::array<uint8_t, 4> psuInfoLen = {nvidia::psuRegSerialNumberLen,
                                        nvidia::psuRegPartNumberLen,
                                        nvidia::psuRegVendorLen,
                                        nvidia::psuRegModelLen};

    if (psuNum >= nvidia::psuNumber)
    {
        log<level::ERR>("Invalid psuNum",
                        phosphor::logging::entry("psuNum=%u", psuNum));
        return ipmi::responseInvalidFieldRequest();
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

    std::vector<uint8_t> psuInfoBuf(psuInfoLen[psuInfoSelector]);
    auto retI2C = psuReadInformation(psuNum, psuCmd[psuInfoSelector], psuInfoBuf);

    if (retI2C != ipmi::ccSuccess)
    {
        return ipmi::response(retI2C);
    }

    return ipmi::responseSuccess(psuInfoSelector, psuInfoBuf);
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

ipmi::RspType<std::vector<uint8_t>> ipmiI2CMasterReadWrite(
                                                uint8_t bus,
                                                uint8_t slaveAddr,
                                                uint8_t readCount,
                                                std::vector<uint8_t> writeData) {
    std::vector<uint8_t> rdData(readCount);
    /* slaveaddr is expected to be in 8bit format, i2cTransaction expects 7bit */
    auto ret = i2cTransaction(bus, slaveAddr >> 1, writeData, rdData);
    if (ret != ipmi::ccSuccess) {
        return ipmi::response(ret);
    }
    return ipmi::responseSuccess(rdData);
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
            std::vector<uint8_t> writeData={0x00, nvidia::cecI2cFwSlotReg};
            std::vector<uint8_t> readBuf(7);
            ipmi::Cc ret =  i2cTransaction(nvidia::cecI2cBus, nvidia::cecI2cAddress, writeData, readBuf);
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
ipmiSetFanZonePWMDuty(uint8_t zone, uint8_t request)
{
    std::string fanZoneHwMonNames[] = {nvidia::fanZoneCtrlName0,
                                        nvidia::fanZoneCtrlName1,
                                        nvidia::fanZoneCtrlName2};
    /* if not valid zone, return error */
    if (zone >= nvidia::fanZones) {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }

    /* if zone control namae is blank, return success */
    if (fanZoneHwMonNames[zone].length() == 0) {
        return ipmi::responseSuccess();
    }

    /* get the control paths for the fans */
    std::array<std::string, nvidia::fanZones> ctrlPaths = {"", "", ""};
    std::filesystem::path hwmonPath("/sys/class/hwmon/");
    for (auto const& path : std::filesystem::directory_iterator{hwmonPath}) {
        /* get the name from this hwmon path */
        std::filesystem::path namePath = path;
        namePath /= "uevent";
        std::ifstream nameFile(namePath);
        if (!nameFile.is_open()) {
            phosphor::logging::log<level::ERR>(
                "ipmiSetFanZonePWMDuty: Failed to open hwmon name file");
            continue;
        }
        /* use uevent interface to get pull name, which includes address for i2c
            devices */
        std::string fullname;
        while (!nameFile.eof()) {
            std::string l;
            nameFile >> l;
            if (boost::starts_with(l, "OF_FULLNAME")) {
                fullname = l;
            }
        }

        if (fullname.length() == 0) {
            continue;
        }

        /* now iterate through HwMon expected names and find a match */
        for (int i = 0; i < nvidia::fanZones; i++) {
            if (fanZoneHwMonNames[i].length() == 0) {
                continue;
            }
            if (ctrlPaths[i].length() != 0) {
                continue;
            }
            if (boost::ends_with(fullname, fanZoneHwMonNames[i])) {
                ctrlPaths[i] = path.path();
                ctrlPaths[i] += "/pwm1";
                break;
            }
        }
    }

    /* convert control % to a pwm value */
	int value = 255;
    if ((request%10 == 0) && (request <= 100) && (request >= 20))
    {
        value = value*request/100;
        std::ofstream ofs(ctrlPaths[zone]);
        if (!ofs.is_open())
        {
             phosphor::logging::log<level::ERR>(
                "ipmiSetFanZonePWMDuty: Failed to open hwmon pwm file");
             return ipmi::response(ipmi::ccResponseError);
        }
        ofs << value;
        ofs.close();
        return ipmi::responseSuccess();
    }
    else {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
}

ipmi::RspType<uint8_t>
ipmiSetAllFanZonesPWMDuty(uint8_t request)
{
    for (int i = 0; i < nvidia::fanZones; i++) {
        auto r = ipmiSetFanZonePWMDuty(i, request);
        if (r != ipmi::responseSuccess()) {
            phosphor::logging::log<level::ERR>(
                "ipmiSetAllFanZonesPWMDuty: Failed to set zone");
            return r;
        }
    }
    return ipmi::responseSuccess();;
}

ipmi::RspType<uint8_t> ipmiSetFanControl(uint8_t mode) {
    if (mode == 0x00) {
        /* auto mode startup the fan control service */
        std::string startupFanString = "systemctl start ";
        startupFanString += nvidia::fanServiceName;
        auto r = system(startupFanString.c_str());
        if (r != 0) {
            /* log that the fan control service doesn't exist */
            phosphor::logging::log<level::ERR>(
                "ipmiSetFanControl: failed to start auto fan service, falling back to default speed");
            /* set fans to default speed, we will support this as "auto", so we
                still return success via ipmi */
            return ipmiSetAllFanZonesPWMDuty(nvidia::fanNoServiceSpeed);
        }
        return ipmi::responseSuccess();
    }
    else if (mode == 0x01) {
        /* manual mode, stop fan service */
        std::string stopFanString = "systemctl stop ";
        stopFanString += nvidia::fanServiceName;
        system(stopFanString.c_str());

        /* set fans to default speed */
        return ipmiSetAllFanZonesPWMDuty(nvidia::fanNoServiceSpeed);
    }
    return ipmi::response(ipmi::ccInvalidFieldRequest);
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

ipmi::RspType<uint8_t> ipmiGetBiosPostStatus(uint8_t requestData)
{
    try
    {
        std::ofstream ofs;
        std::string path;
        switch (requestData)
        {
            case 0: // Post Clear
                // Do nothing.
                return ipmi::responseSuccess();
                break;
            case 1: // Post Start
                // Do nothing.
                return ipmi::responseSuccess();
                break;
            case 2: // Post End
                // Set SPD read by BMC.
                path = "/sys/class/gpio/gpio800/value";
                if (!ofs.is_open())
                {
                    ofs.open(path);
                }
                ofs.clear();
                ofs.seekp(0);
                ofs << 0;
                ofs.close();

                // Workaround:Restart DIMM temperature reading and ipmi host
                // when getting POST end service
                system("systemctl restart phosphor-virtual-sensor.service");
                //system("systemctl restart phosphor-ipmi-host.service");

                return ipmi::responseSuccess();
                break;
            default:
                return ipmi::responseResponseError();
                break;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to Get Bios Post Status",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

/** @brief implement to get the BIOS boot count
 *  @returns status
 */
static int getBIOSbootCycCount(uint16_t& BootCycCount)
{
    BootCycCount = 0;

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, postCodesIntf, postCodesObjPath);
        // get boot count
        Value variant = getDbusProperty(*dbus, service, postCodesObjPath,
                                        postCodesIntf, postCodesProp);
        BootCycCount = static_cast<uint16_t>(std::get<std::uint16_t>(variant));

        return ipmi::ccSuccess;
    }
    catch (const std::exception& e)
    {
        return ipmi::ccUnspecifiedError;
    }
}

/** @brief Get the latest boot cycle's POST Code, if there is one.
 ** @param[in] ctx   - ipmi Context point
 ** @return   Boot Cycle indes, Post Code length, POST Code vector
 **/
ipmi::RspType<uint16_t, uint16_t, std::vector<uint8_t>>
    ipmiGetBiosPostCode(ipmi::Context::ptr ctx)
{
    using namespace ipmi::nvidia::app;
    uint64_t pcode = 0;
    uint16_t bootIndex = 1; // 1 for the latest boot cycle's POST Code
    uint16_t postVecLen = 0;
    uint16_t postVecStart = 0;
    uint16_t postRetLen = 0;
    using postcode_t = std::tuple<uint64_t, std::vector<uint8_t>>;
    postcode_t postCodeTup (0, {0});
    std::vector<postcode_t> postCodeVector = {};
    std::vector<uint8_t> postCodeVectorRet = {};

    // to get the oldest POST Code
    // getBIOSbootCycCount(bootIndex);

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        // if chassis in power off state, return error code
        auto powerState =
            ipmi::getDbusProperty(*dbus, chassisStateService, chassisStatePath,
                                  chassisStateIntf, "CurrentPowerState");
        if (std::get<std::string>(powerState) ==
            "xyz.openbmc_project.State.Chassis.PowerState.Off")
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Host is in power off state");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        std::string service =
            getService(*dbus, postCodesIntf, postCodesObjPath);
        // call POST Code Service method
        auto method = dbus->new_method_call (postCodesService, postCodesObjPath,
                                             postCodesIntf, "GetPostCodes");
        method.append(bootIndex);
        auto postCodesMsgRet = dbus->call(method);

        if (postCodesMsgRet.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                                   "Error returns from call to dbus.");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        postCodesMsgRet.read(postCodeVector);
        if (postCodeVector.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                                   "No post code is found from call to dbus.");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        postVecLen = postCodeVector.size();

        if (postVecLen <= cmdGetBiosPostCodeToIpmiMaxSize)
            postVecStart = 0;
        else
        {
            // adjust the start position so the end-portion of post code is sent
            postVecStart = postVecLen - cmdGetBiosPostCodeToIpmiMaxSize;
        }

        for (int i = postVecStart; i < postVecLen; i++)
        {
            postCodeTup = postCodeVector[i];
            pcode = std::get<0>(postCodeTup);
            postCodeVectorRet.push_back(pcode);
            //sd_journal_print(LOG_ERR, "0x%02llx ", pcode);
        }

        postRetLen = postCodeVectorRet.size();
        return ipmi::responseSuccess(bootIndex, postRetLen, postCodeVectorRet);
    }
    catch (const std::exception& e)
    {
        return ipmi::response(ipmiCCBIOSPostCodeError);
    }

    return ipmi::response(ipmiCCBIOSPostCodeError);
}

ipmi::RspType<> ipmiOemSoftReboot()
{
    /* TODO: Should be handled by dbus call once backend exists */
    /* call powerctrl grace_off to trigger soft off */
    system("powerctrl grace_off");
    /* call powerctrl for power cycle, this will force off if the grace off didn't occur */
    system("powerctrl power_cycle");
    return ipmi::responseSuccess();
}

static ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMiscGetFPGAVersion(uint8_t bus, uint8_t reg) {
    using namespace ipmi::nvidia::misc;

    std::vector<uint8_t> writeData={reg};
    std::vector<uint8_t> readBuf(2);

    auto ret = i2cTransaction(bus, ipmi::nvidia::fpgaI2cAddress, writeData, readBuf);

    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("FPGA Version read failed",
            phosphor::logging::entry("BUS=%d", bus));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(0x00, readBuf);
}

static ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMiscGetPEXSwVersion(uint8_t bus, uint8_t devid) {
    using namespace ipmi::nvidia::misc;

    std::vector<uint8_t> writeData(std::begin(ipmi::nvidia::pexSwitchVersionWrite), std::end(ipmi::nvidia::pexSwitchVersionWrite));
    std::vector<uint8_t> readBuf(4);

    auto ret = i2cTransaction(bus, devid, writeData, readBuf);

    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("PEX SW Version read failed",
            phosphor::logging::entry("BUS=%d", bus));
        return ipmi::responseResponseError();
    }

    std::vector<uint8_t> version = {static_cast<uint8_t>(((readBuf[2] >> 4) & 0x0f)),
        static_cast<uint8_t>(readBuf[2] & 0x0f)};
    return ipmi::responseSuccess(0x01, version);
}

static ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMiscCECCommand(uint8_t bus, uint8_t reg) {
    using namespace ipmi::nvidia::misc;

    std::vector<uint8_t> writeData={0x00, reg};
    std::vector<uint8_t> readBuf(2);
    auto ret = i2cTransaction(bus, ipmi::nvidia::cecI2cAddress, writeData, readBuf);

    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("CEC version read failed",
            phosphor::logging::entry("BUS=%d", bus));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(0x00, readBuf);
}

static uint8_t hexAsciiToInt(uint8_t c) {
    switch (c) {
        case '0' ... '9':
            return c - '0';
        case 'A' ... 'F':
            return c - 'A';
        case 'a' ... 'f':
            return c -'a';
    }
    return 0;
}

static ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMisGetPsuFWVersion(uint8_t psuNum) {
    /* get vendor information */
    std::vector<uint8_t> psuVendorInfo(6);
    auto ret = psuReadInformation(psuNum, ipmi::nvidia::psuRegVendor, psuVendorInfo);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PSU vendor information");
        return ipmi::responseResponseError();
    }
    psuVendorInfo.erase(psuVendorInfo.begin());
    /* delta PSU handles FW version in binary */
    if (boost::starts_with(psuVendorInfo, "Delt")) {
        std::vector<uint8_t> fwv(7);
        ret = psuReadInformation(psuNum, ipmi::nvidia::psuRegFWVersion, fwv);
        if ((ret != ipmi::ccSuccess)||((fwv[1] == 0)&&(fwv[2]==0)&&(fwv[3]==0)&&
                                    (fwv[4] == 0)&&(fwv[5]==0)&&(fwv[6]==0))) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PSU firmware version");
            return ipmi::responseResponseError();
        }
        /* flip byte ordering */
        fwv.erase(fwv.begin());
        for (int i = 0; i < sizeof(fwv); i += 2) {
            uint8_t t = fwv[i];
            fwv[i] = fwv[i + 1];
            fwv[i + 1] = t;
        }
        return ipmi::responseSuccess(0x00, fwv);
    }
    /* LiteOn PSU handles FW version in ascii */
    else if (boost::starts_with(psuVendorInfo, "Lite")) {
        std::vector<uint8_t> fwv(5);
        ret = psuReadInformation(psuNum, ipmi::nvidia::psuRegFWVersion, fwv);
        if ((ret != ipmi::ccSuccess)||((fwv[1] == 0)&&(fwv[2]==0)&&(fwv[3]==0)&&
                                    (fwv[4] == 0))) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PSU firmware version");
            return ipmi::responseResponseError();
        }
        fwv.erase(fwv.begin());
        /* ascii to binary conversion */
        for (int i = 0; i < sizeof(fwv); i++) {
            fwv[i] = hexAsciiToInt(fwv[i]);
        }
        return ipmi::responseSuccess(0x00, fwv);
    }
    else {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PSU Vendor unrecognized");
            return ipmi::responseResponseError();
    }
}

static std::tuple <int, std::vector<uint8_t>> smbpbiRequestFPGA(uint8_t op, uint8_t arg1, uint8_t arg2 = 0) {
        // Call smpbi passthrough call
    int rc;
    std::vector<uint32_t> dataOut;
    std::tuple <int, std::vector<uint32_t>> smbpbiRes;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, gpuSMBPBIIntf, gpuSMBPBIPath);
    auto method = bus->new_method_call(service.c_str(), gpuSMBPBIPath,
                                       gpuSMBPBIIntf, "PassthroughFpga");
    std::vector<uint32_t> dataIn;
    // Add GPU device Id
    method.append(static_cast<int>(ipmi::nvidia::gpFpgaSmbpbiDeviceId));
    // Add SMPBI opcode
    method.append(op);
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
            "smbpbi request: Passthrough method returned error",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", gpuSMBPBIPath));
        return std::tuple <int, std::vector<uint8_t>>(-1, {});
    }

    reply.read(smbpbiRes);
    std::tie (rc, dataOut) = smbpbiRes;
    std::vector<uint8_t> returnData(dataOut.size() * sizeof(uint32_t));
    for (int i = 0; i < dataOut.size(); i++) {
        returnData[i * 4 + 0] = dataOut[i] & 0xff;
        returnData[i * 4 + 1] = (dataOut[i] >> 8) & 0xff;
        returnData[i * 4 + 2] = (dataOut[i] >> 16) & 0xff;
        returnData[i * 4 + 3] = (dataOut[i] >> 24) & 0xff;
    }
    return std::tuple <int, std::vector<uint8_t>>(rc, returnData);
}

static ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemGetFirmwareVersionGBFpga(void) {
    int rc;
    std::vector<uint8_t> dataOut;

    // Call passthrough dbus method
    try {
        std::tuple <int, std::vector<uint8_t>> smbpbiRes =
                smbpbiRequestFPGA(nvidia::gbFpgaSmbpbiVersionOpcode, nvidia::gbFpgaSmbpbiVersionArg1);
        std::tie (rc, dataOut) = smbpbiRes;

        if ((rc == 0)&&(dataOut.size() == 16)) {
            dataOut[0] = hexAsciiToInt(dataOut[8]);
            dataOut[1] = (hexAsciiToInt(dataOut[10]) << 4) + hexAsciiToInt(dataOut[11]);
            dataOut.resize(2);
            return ipmi::responseSuccess(0x00, dataOut);
        }
        else {
            log<level::ERR>("Unexpected response from SMPBI");
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to query GPFPGA FW Version",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseUnspecifiedError();
}

ipmi::RspType<uint8_t, std::vector<uint8_t>> getBMCActiveSoftwareVersionInfo(ipmi::Context::ptr ctx)
{
    std::string revision{};
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree =
            ipmi::getAllDbusObjects(*ctx->bus, softwareRoot, redundancyIntf);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to fetch redundancy object from dbus",
                        entry("INTERFACE=%s", redundancyIntf),
                        entry("ERRMSG=%s", e.what()));
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service =
            ipmi::getService(*ctx->bus, redundancyIntf, softObject.first);
        auto objValueTree =
            ipmi::getManagedObjects(*ctx->bus, service, softwareRoot);

        auto minPriority = 0xFF;
        for (const auto& objIter : objValueTree)
        {
            try
            {
                auto& intfMap = objIter.second;
                auto& redundancyPriorityProps = intfMap.at(redundancyIntf);
                auto& versionProps = intfMap.at(versionIntf);
                auto& activationProps = intfMap.at(activationIntf);
                auto priority =
                    std::get<uint8_t>(redundancyPriorityProps.at("Priority"));
                auto purpose =
                    std::get<std::string>(versionProps.at("Purpose"));
                auto activation =
                    std::get<std::string>(activationProps.at("Activation"));
                auto version =
                    std::get<std::string>(versionProps.at("Version"));
                if ((sdbusplus::xyz::openbmc_project::Software::server::Version::convertVersionPurposeFromString(purpose) ==
                     sdbusplus::xyz::openbmc_project::Software::server::Version::VersionPurpose::BMC)&&
                     (sdbusplus::xyz::openbmc_project::Software::server::Activation::convertActivationsFromString(activation) ==
                     sdbusplus::xyz::openbmc_project::Software::server::Activation::Activations::Active))
                {
                    if (priority < minPriority)
                    {
                        minPriority = priority;
                        objectFound = true;
                        revision = std::move(version);
                    }
                }
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(e.what());
            }
        }
    }

    if (!objectFound)
    {
        log<level::ERR>("Could not found an BMC software Object");
        return ipmi::responseResponseError();
    }

    /* format looks like: 2.9.1-415-g12badb987.1633991995.39335 */
    std::vector<std::string> parts;
    auto location = revision.find_first_of('v');
    if (location != std::string::npos) {
        revision = revision.substr(location + 1);
    }

    boost:split(parts, revision, boost::is_any_of(".-"));

    if (parts.size() < 3) {
        return ipmi::responseResponseError();
    }

    /* pack into bytes */
    std::vector<uint8_t> ret(6);
    /* first 3 parts are convertable to bytes, if 4th part exists we tag it */
    uint8_t maj = std::stoi(parts[0]); /* major rev */
    uint8_t min = std::stoi(parts[1]); /* minor rev, need to convert to bcd */
    uint16_t d0 = std::stoi(parts[2]); /* extra part 1 */
    uint8_t d1 = 0;
    if (parts.size() > 3) {
        d1 = 1;
    }

    ret[0] = maj & ~(1 << 7); /* mask MSB off */
    min = (min > 99 ? 99 : min);
    ret[1] = min % 10 + (min / 10) * 16;
    ret[2] = d0 & 0xff;
    ret[3] = (d0 >> 8) & 0xff;
    ret[4] = d1; /* can only be 0 or 1 */
    ret[5] = 0;

    return ipmi::responseSuccess(2, ret);;
}


ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMiscFirmwareVersion(ipmi::Context::ptr ctx, uint8_t device)
{
    using namespace ipmi::nvidia::misc;
    switch (device) {
        /* FPGA I2C request */
        case getFirmwareVersionDeviceMBFPGA:
            return ipmiOemMiscGetFPGAVersion(ipmi::nvidia::fpgaMbI2cBus,
                    ipmi::nvidia::fpgaMbVersionAddr);
        case getFirmwareVersionDeviceMIDFPGA:
            return ipmiOemMiscGetFPGAVersion(ipmi::nvidia::fpgaMidI2cBus,
                    ipmi::nvidia::fpgaMidVersionAddr);
        /* smbpbi request op_Code 0x05 arg 0x88. ID = 9*/
        case getFirmwareVersionDeviceGBFPGA:
            return ipmiOemGetFirmwareVersionGBFpga();
        break;
        /* PSU require vendor switching */
        case getFirmwareVersionDevicePSU0...getFirmwareVersionDevicePSU5:
            return ipmiOemMisGetPsuFWVersion(device - getFirmwareVersionDevicePSU0);
        break;
        /* PEX I2C req */
        case getFirmwareVersionDevicePEXSwitch0...getFirmwareVersionDevicePEXSwitch3:
            return ipmiOemMiscGetPEXSwVersion(ipmi::nvidia::pexSwitchI2CBus[device - getFirmwareVersionDevicePEXSwitch0],
                    ipmi::nvidia::pexSwitchI2CVersionAddress[device - getFirmwareVersionDevicePEXSwitch0]);

        /* CEC Req */
        case getFirmwareVersionDeviceCEC:
            return ipmiOemMiscCECCommand(ipmi::nvidia::cecI2cBus,
                    ipmi::nvidia::cecI2cVersionRegister);
        /* FPGA CEC */
        case getFirmwareVersionDeviceFPGACEC:
            return ipmiOemMiscCECCommand(ipmi::nvidia::cecFpgaI2cBus,
                    ipmi::nvidia::cecFpgaI2cVersionRegister);

        /* BMC FW version requests */
        case getFirmwareVersionDeviceBMCActive:
            return getBMCActiveSoftwareVersionInfo(ctx);
        case getFirmwareVersionDeviceBMCInactive:
            /* Inactive FW version not tracked in openBMC currently TODO: Fix */
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown firmware device version requested");
    }
    return ipmi::responseResponseError();
}

static ipmi::RspType<uint8_t> getWpStatusFromMidFPGA(uint8_t bitOffset, uint8_t reg, uint8_t devid) {
    using namespace ipmi::nvidia::misc;

    std::vector<uint8_t> writeData={reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, devid, writeData, readBuf);

    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("WP Status I2C transaction failed");
        return ipmi::responseResponseError();
    }

    uint8_t wp = (readBuf[0] & (1 << bitOffset)) >> bitOffset;
    return ipmi::responseSuccess(wp);
}

static ipmi::RspType<> setWpStatusFromMidFPGA(uint8_t bitOffset, uint8_t reg,
                                                uint8_t devid, uint8_t newValue) {
    using namespace ipmi::nvidia::misc;

    std::vector<uint8_t> writeData={reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, devid, writeData, readBuf);

    if (ret != ipmi::ccSuccess) {
        uint8_t newRegValue = (readBuf[0] & (~(1 << bitOffset)));
        if (newValue) {
            newRegValue |= (1 << bitOffset);
        }
        writeData.push_back(newRegValue);
        readBuf.resize(0);
        ret = i2cTransaction(nvidia::fpgaMidI2cBus, devid, writeData, readBuf);
    }

    if (ret != ipmi::ccSuccess) {
        log<level::ERR>("WP Status I2C transaction failed");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

static ipmi::RspType<uint8_t> getWpStatusGB(void) {
    int rc;
    std::vector<uint8_t> dataOut;

    // Call passthrough dbus method
    try {
        std::tuple <int, std::vector<uint8_t>> smbpbiRes =
                        smbpbiRequestFPGA(nvidia::gbFpgaSmbpbiWpOpcode, nvidia::gbFpgaSmbpbiWpReadArg1);
        std::tie (rc, dataOut) = smbpbiRes;
        if (dataOut.size() > 0) {
            return ipmi::responseSuccess(dataOut[1] & nvidia::gbFpgaSmbpbiWpMask ? 1 : 0);
        }
        else {
            log<level::ERR>("Unexpected response from SMBPBI");
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to query GPFPGA WP Status",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseUnspecifiedError();
}

static ipmi::RspType<> setWpStatusGB(uint8_t newStatus) {
    int rc;
    std::vector<uint8_t> dataOut;

    // Call passthrough dbus method
    try {
        std::tuple <int, std::vector<uint8_t>> smbpbiRes =
                        smbpbiRequestFPGA(nvidia::gbFpgaSmbpbiWpOpcode,
                        nvidia::gbFpgaSmbpbiWpWriteArg1, newStatus);
        std::tie (rc, dataOut) = smbpbiRes;
        if (dataOut.size() > 0) {
            return ipmi::responseSuccess();
        }
        else {
            log<level::ERR>("Unexpected response from SMBPBI");
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to set GPFPGA WP Status",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseUnspecifiedError();
}

static int gpioExport(std::string gpiochip, uint32_t gpio) {
    /* will export the gpio if it doesn't exist,
        need to use the sysfs interface since the char
        device interface resets once closed, we want
        persistance here */
    int base;
    std::ifstream chipbase("/sys/class/gpio/" + gpiochip + "/base", std::ifstream::in);
    if (!chipbase.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpiochip base!");
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

static bool getGpioRaw(std::string gpiochip, uint32_t gpio, uint8_t &v) {
    int gp = gpioExport(gpiochip, gpio);
    if (gp < 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to export gpio!");
        return false;
    }
    std::ifstream valueIf("/sys/class/gpio/gpio" + std::to_string(gp) + "/value", std::ifstream::in);
    if (!valueIf.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio value!");
        return false;
    }
    int r;
    valueIf >> r;
    v = r;
    return true;
}

static ipmi::RspType<uint8_t> getGpioCmd(std::string gpiochip, uint32_t gpio)
{
    uint8_t r;
    if (!getGpioRaw(gpiochip, gpio, r)) {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(r);
}

static bool setGpioRaw(std::string gpiochip, uint32_t gpio, uint32_t value) {
    int gp = gpioExport(gpiochip, gpio);

    std::ofstream directionOf("/sys/class/gpio/gpio" + std::to_string(gp) + "/direction", std::ofstream::out);
    if (!directionOf.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio direction!");
        return false;
    }
    /* set to ouput, then set value */
    directionOf << "out";
    directionOf.close();
    std::ofstream valueOf("/sys/class/gpio/gpio" + std::to_string(gp) + "/value", std::ofstream::out);
    if (!valueOf.is_open()) {
        directionOf.close();
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio value!");
        return false;
    }
    valueOf << value;
    valueOf.close();
    return true;
}

static ipmi::RspType<> setGpioCmd(std::string gpiochip, uint32_t gpio, uint32_t value)
{
    /* note, in order to not glitch the IO we note that it is high when GPIO
        is set as input. To set this high set GPIO to input mode, to set low
        set to output and value to 0 */
    int gp = gpioExport(gpiochip, gpio);
    if (gp < 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to export gpio!");
        return ipmi::responseUnspecifiedError();
    }

    std::ofstream directionOf("/sys/class/gpio/gpio" + std::to_string(gp) + "/direction", std::ofstream::out);
    if (!directionOf.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open gpio direction!");
        return ipmi::responseUnspecifiedError();
    }
    if (value) {
        /* set to input mode allow HW pullup to pull it up */
        directionOf << "in";
    }
    else {
        /* set to ouput, then set value to 0 */
        directionOf << "out";
        std::ofstream valueOf("/sys/class/gpio/gpio" + std::to_string(gp) + "/value", std::ofstream::out);
        if (!valueOf.is_open()) {
            directionOf.close();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to open gpio value!");
            return ipmi::responseUnspecifiedError();
        }
        valueOf << "0";
        valueOf.close();
    }
    directionOf.close();
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOemMiscGetWP(uint8_t type, uint8_t id)
{
    using namespace ipmi::nvidia::misc;
    /* break up by type of transaction required */
    if (type == getWPTypePEX) {
        if ((id >= getWPIdPexSW0)&&(id <= getWPIdPexSW3)) {
            return getWpStatusFromMidFPGA(id - getWPIdPexSW0,
                                            nvidia::fpgaMidPexSwWpReg,
                                            nvidia::fpgaI2cAddress);
        }
        else {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown PEX device id for WP requested");
        }
    }
    else if (type == getWPTypeFRU) {
        switch (id) {
            case getWPIdMB:
            case getWPIdM2:
                return getGpioCmd(nvidia::mbWpGpioChip, nvidia::mbWpGpioId);
            case getWPIdMid:
                return getWpStatusFromMidFPGA(nvidia::fpgaMidWpMidBit,
                                    nvidia::fpgaMidWpReg, nvidia::fpgaI2cAddress);
            case getWPIdIOEL:
                return getWpStatusFromMidFPGA(nvidia::fpgaMidWpIOELBit,
                                    nvidia::fpgaMidWpReg, nvidia::fpgaI2cAddress);
            case getWpIdIOER:
                return getWpStatusFromMidFPGA(nvidia::fpgaMidWpIOERBit,
                                    nvidia::fpgaMidWpReg, nvidia::fpgaI2cAddress);
            case getWpIdPDB:
                return getWpStatusFromMidFPGA(nvidia::fpgaMidWpPDB,
                                    nvidia::fpgaMidWpReg, nvidia::fpgaI2cAddress);
            case getWpIdGB:
                return getWpStatusGB();
            case getWpIdSW:
                return getWpStatusFromMidFPGA(nvidia::fpgaMidWpSw,
                                    nvidia::fpgaMidWpReg, nvidia::fpgaI2cAddress);
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown FRU device id for WP requested");
        }
    }
    else {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown device type for WP requested");
    }
    return ipmi::responseResponseError();
}

ipmi::RspType<> ipmiOemMiscSetWP(uint8_t type, uint8_t id, uint8_t value)
{
    using namespace ipmi::nvidia::misc;
    /* break up by type of transaction required */
    if (type == getWPTypePEX) {
        if ((id >= getWPIdPexSW0)&&(id <= getWPIdPexSW3)) {
            return setWpStatusFromMidFPGA(id - getWPIdPexSW0, nvidia::fpgaMidPexSwWpReg,
                                            nvidia::fpgaI2cAddress, value);
        }
        else {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown PEX device id for WP requested");
        }
    }
    else if (type == getWPTypeFRU) {
        switch (id) {
            case getWPIdMB:
            case getWPIdM2:
                return setGpioCmd(nvidia::mbWpGpioChip, nvidia::mbWpGpioId, value);
            case getWPIdMid:
                return setWpStatusFromMidFPGA(nvidia::fpgaMidWpMidBit, nvidia::fpgaMidWpReg,
                                                nvidia::fpgaI2cAddress, value);
            case getWPIdIOEL:
                return setWpStatusFromMidFPGA(nvidia::fpgaMidWpIOELBit, nvidia::fpgaMidWpReg,
                                                nvidia::fpgaI2cAddress, value);
            case getWpIdIOER:
                return setWpStatusFromMidFPGA(nvidia::fpgaMidWpIOERBit, nvidia::fpgaMidWpReg,
                                                nvidia::fpgaI2cAddress, value);
            case getWpIdPDB:
                return setWpStatusFromMidFPGA(nvidia::fpgaMidWpPDB, nvidia::fpgaMidWpReg,
                                                nvidia::fpgaI2cAddress, value);
            case getWpIdGB:
                return setWpStatusGB(value);
            case getWpIdSW:
                return setWpStatusFromMidFPGA(nvidia::fpgaMidWpSw, nvidia::fpgaMidWpReg,
                                                nvidia::fpgaI2cAddress, value);
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown FRU device id for WP requested");
        }
    }
    else {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unknown device type for WP requested");
    }
    return ipmi::responseResponseError();
}

static uint8_t getSSDLedRegister(uint8_t type, uint8_t instance, uint8_t &offset, uint8_t &mask) {
    using namespace ipmi::nvidia::misc;
    uint8_t reg = 0;
    offset = instance;
    mask = (1 << instance);
    switch (type) {
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
            reg = nvidia::fpgaMidSSDLedFaultBase + (((getSSDLedNLed - 1) - instance) >> 1);
            /*  each register is:
                    xxbb baaa
                where aaa is 0 and bbb is 1 */
            offset = nvidia::fpgaMidSSDLedFaultWidth * (instance & 0x01);
            mask = ((1 << nvidia::fpgaMidSSDLedFaultWidth) - 1) << offset;
        break;
    }
    return reg;
}

ipmi::RspType<uint8_t> ipmiOemGetSSDLed(uint8_t type, uint8_t instance) {
    using namespace ipmi::nvidia::misc;

    if (instance >= getSSDLedNLed) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid SSD LED Instance");
        return ipmi::responseResponseError();
    }

    /* get register, offset, mask information */
    uint8_t reg, offset, mask;
    reg = getSSDLedRegister(type, instance, offset, mask);
    if (reg == 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED type");
        return ipmi::responseResponseError();
    }

    /* get appropriate register */
    std::vector<uint8_t> writeData={reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress, writeData, readBuf);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get SSD Led status from FPGA");
            return ipmi::responseResponseError();
    }

    /* decode and return */
    return ipmi::responseSuccess(readBuf[0] & mask >> offset);
}

ipmi::RspType<> ipmiOemSetSSDLed(uint8_t type, uint8_t instance, uint8_t pattern) {
    using namespace ipmi::nvidia::misc;

    if ((instance >= getSSDLedNLed)||
        ((type == getSSDLedTypeFault)&&(pattern > nvidia::fpgaMidSetLedFaultMaxPattern))||
        ((type != getSSDLedTypeFault)&&(pattern > nvidia::fpgaMidSetLedOtherMaxPattern))||
        (type == getSSDLedTypeActivity)) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid SSD LED Type, Instance or Pattern");
        return ipmi::responseResponseError();
    }

    /* get register, offset, mask information */
    uint8_t reg, offset, mask;
    reg = getSSDLedRegister(type, instance, offset, mask);
    if (reg == 0) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid SSD LED type");
        return ipmi::responseResponseError();
    }

    /* get appropriate register */
    std::vector<uint8_t> writeData={reg};
    std::vector<uint8_t> readBuf(1);
    auto ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress, writeData, readBuf);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get SSD Led status from FPGA");
            return ipmi::responseResponseError();
    }

    /* adjust register and write it out */
    writeData.push_back((readBuf[0] & ~mask) | (pattern << offset));
    ret = i2cTransaction(nvidia::fpgaMidI2cBus, nvidia::fpgaI2cAddress, writeData, readBuf);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to set SSD Led pattern to FPGA");
            return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOemGetLedStatus(uint8_t type) {
    using namespace ipmi::nvidia::misc;
    std::string ledPath = "/sys/class/leds/";
    switch (type) {
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
    if (!ledBrightness.is_open()) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to open LED brightness file");
        return ipmi::responseResponseError();
    }
    ledBrightness >> brightness;
    ledBrightness.close();
    if (brightness != 0) {
        return ipmi::responseSuccess(1);
    }
    return ipmi::responseSuccess(0);
}


ipmi::RspType<> ipmiSensorScanEnableDisable(uint8_t mode) {
    if (mode == 0x00) {
        /* stop services that scan sensors */
        std::string stopSensorScan = "systemctl stop ";
        stopSensorScan += nvidia::sensorScanSerivcesList;
        auto r = system(stopSensorScan.c_str());
        if (r != 0) {
            /* log that the stop failed */
            phosphor::logging::log<level::ERR>(
                "ipmiSensorScanEnableDisable: failed to stop services");
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
    }
    else if (mode == 0x01) {
        /* start services */
        std::string startSensorScan = "systemctl start ";
        startSensorScan += nvidia::sensorScanSerivcesList;
        auto r = system(startSensorScan.c_str());

        if (r != 0) {
            /* log that the stop failed */
            phosphor::logging::log<level::ERR>(
                "ipmiSensorScanEnableDisable: failed to start services");
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
    }
    return ipmi::response(ipmi::ccInvalidFieldRequest);
}

// convert from 16-bit linear FP representation
static uint16_t PsuLinearConversion(uint16_t raw) {
    uint16_t n, ret;

    n = (raw >> 11) & 0x1f;  //[15:11]
    ret = raw & 0x7ff;         //[10:0]

    // Pout = Y * 2^N
    if (n & 0x10) {//n is negative
        // convert from 2's complement
        n = (~n & 0x0f) + 1;
        // shift down appropiate amount
        ret = ret >> n;
    }
    else {
        //n is positive, shift up
        ret = ret << n;
    }

    return ret;
}


ipmi::RspType<uint16_t, uint16_t, uint8_t> ipmiOemPsuPower(uint8_t type, uint8_t id) {
    if ((type != 0x00)||(id >=6)) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid type or PSU number");
        return ipmi::responseInvalidFieldRequest();
    }

    std::vector<uint8_t> powerRaw(2);

    auto ret = psuReadInformation(id, nvidia::psuRegPowerReal, powerRaw);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to read real power from PSU");
        return ipmi::responseResponseError();
    }
    uint16_t realPower = PsuLinearConversion(((uint16_t)powerRaw[1] << 8) | (powerRaw[0]));
    ret = psuReadInformation(id, nvidia::pseRegPowerAparent, powerRaw);
    if (ret != ipmi::ccSuccess) {
        phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to read apparent power from PSU");
        return ipmi::responseResponseError();
    }
    uint16_t aparPower = PsuLinearConversion(((uint16_t)powerRaw[1] << 8) | (powerRaw[0]));
    uint8_t pf = 0;
    if ((aparPower == 0)&&(realPower == 0)) {
        pf = 100; /*both are too low to measure, but close to eachother */
    }
    else if (aparPower == 0) {
        pf = 0;
    }
    else {
        pf = ((uint32_t)realPower * 100)/aparPower;
    }

    return ipmi::responseSuccess(realPower, aparPower, pf);
}

/* gets the bios boot slot */
static uint8_t getBiosBootSlot(void) {
    /* checked by looking at the GPIO */
    uint8_t v;
    if (!getGpioRaw(nvidia::biosGpioChip, nvidia::biosGpioId, v)) {
        phosphor::logging::log<level::ERR>(
                "Failed to read bootslot GPIO");
        return 0;
    }
    /* secondary slot = 0, primary = 1 */
    return v == 0 ? 1 : 0;
}

//BIOS test - Set BIOS version command (0x30 0x10)
//Takes: Major (uint8_t), Minor (uint8_t)
//Returns completion code
ipmi::RspType<> ipmiBiosSetVersion(uint8_t major, uint8_t minor) {
    std::stringstream msg;
    uint8_t bootslot = getBiosBootSlot();
    nvidia::BiosVersionInformation::get().updateBiosSlot(bootslot, major, minor);
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiBiosGetBootImage(void) {
    return ipmi::responseSuccess(nvidia::BiosVersionInformation::get().getLastBootSlot());
}

ipmi::RspType<uint8_t> ipmiBiosGetNextBootImage(void) {
    return ipmi::responseSuccess(getBiosBootSlot());
}

ipmi::RspType<> ipmiBiosSetNextBootImage(uint8_t bootimage) {
    if (!setGpioRaw(nvidia::biosGpioChip, nvidia::biosGpioId, bootimage ? 0 : 1)) {
        phosphor::logging::log<level::ERR>(
                "Failed to set bootslot GPIO");
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t> ipmiBiosGetVerion(uint8_t image) {
    uint8_t major = 0, minor = 0;
    if (nvidia::BiosVersionInformation::get().getBiosSlotInformation(image, major, minor)) {
        return ipmi::responseSuccess(major, minor);
    }
    return ipmi::responseResponseError();
}

ipmi::RspType<uint8_t> ipmiBiosGetConfig(uint8_t type) {
    using namespace ipmi::nvidia::misc;

    if ((type != biosConfigTypeNetwork)&&(type != biosConfigTypeRedFish)) {
        return ipmi::responseResponseError();
    }

    bool status = nvidia::BiosVersionInformation::get().getConfigFlag(type - 1);
    return ipmi::responseSuccess((type & 0x7f) | (status ? 0x80 : 0x00));
}

ipmi::RspType<> ipmiBiosSetConfig(uint8_t type) {
    using namespace ipmi::nvidia::misc;
    bool status = ((type & 0x80) != 0);
    type = type & 0x7f;
    if ((type != biosConfigTypeNetwork)&&(type != biosConfigTypeRedFish)) {
        return ipmi::responseResponseError();
    }
    nvidia::BiosVersionInformation::get().setConfigFlag(type - 1, status);
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
        log<level::INFO>("JSON file not found",
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
        log<level::DEBUG>("Corrupted channel config.",
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
                (jsonChData[nameString].get<std::string>() !=
                 redfishHostInterfaceChannel))
            {
                log<level::WARNING>(
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
            log<level::DEBUG>("Json Exception caught.",
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
        "/home/root/bmcweb_persistent_data.json");
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
    std::random_shuffle(uniqueStr.begin(), uniqueStr.end());
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

ipmi::RspType<std::vector<uint8_t>, std::vector<uint8_t>>
    ipmiGetBootStrapAccount(ipmi::Context::ptr ctx,
                            uint8_t disableCredBootStrap)
{
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

        ret = getRandomPassword(password);
        if (!ret)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate alphanumeric "
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
        auto reply = dbus->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error returns from call to dbus. BootStrap Failed");
            return ipmi::responseResponseError();
        }

        // update the password
        boost::system::error_code ec;
        int retval = pamUpdatePasswd(userName.c_str(), password.c_str());
        if (retval != PAM_SUCCESS)
        {
            dbus->yield_method_call<void>(ctx->yield, ec, service.c_str(),
                                          userMgrObjBasePath + userName,
                                          usersDeleteIface, "Delete");

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiGetBootStrapAccount : Failed to update password.");
            return ipmi::responseUnspecifiedError();
        }
        else
        {
            // update the "CredentialBootstrap" Dbus property w.r.to
            // disable crendential BootStrap status
            setCredentialBootStrap(disableCredBootStrap);

            std::vector<uint8_t> respUserNameBuf, respPasswordBuf;
            std::copy(userName.begin(), userName.end(),
                      std::back_inserter(respUserNameBuf));
            std::copy(password.begin(), password.end(),
                      std::back_inserter(respPasswordBuf));
            return ipmi::responseSuccess(respUserNameBuf, respPasswordBuf);
        }
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

ipmi::RspType<uint8_t, std::vector<uint8_t>>
    ipmiOemGetMaxPMaxQConfiguration(uint8_t parameter)
{
    using namespace ipmi::nvidia::misc;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        switch (parameter)
        {
            case getMaxPMaxQConfigurationMode: // Mode
            {

                auto mode = ipmi::getDbusProperty(
                    *dbus, powerManagerService,
                    powerManagerCurrentChassisLimitObj,
                    powerManagerCurrentChassisModeIntf, "PowerMode");
                if (std::get<std::string>(mode) ==
                    "xyz.openbmc_project.Control.Power.Mode.PowerMode."
                    "Static")
                {
                    std::vector<uint8_t> returndataOut(1);
                    returndataOut[0] = staticMode;
                    return ipmi::responseSuccess(ipmi::ccSuccess,
                                                 returndataOut);
                }
                else if (std::get<std::string>(mode) ==
                         "xyz.openbmc_project.Control.Power.Mode.PowerMode."
                         "PowerSaving")
                {
                    std::vector<uint8_t> returndataOut(1);
                    returndataOut[0] = powerSavingMode;
                    return ipmi::responseSuccess(ipmi::ccSuccess,
                                                 returndataOut);
                }
                else if (std::get<std::string>(mode) ==
                         "xyz.openbmc_project.Control.Power.Mode.PowerMode."
                         "MaximumPerformance")
                {
                    std::vector<uint8_t> returndataOut(1);
                    returndataOut[0] = maximumPerformanceMode;
                    return ipmi::responseSuccess(ipmi::ccSuccess,
                                                 returndataOut);
                }
                else if (std::get<std::string>(mode) ==
                         "xyz.openbmc_project.Control.Power.Mode.PowerMode."
                         "OEM")
                {
                    std::vector<uint8_t> returndataOut(1);
                    returndataOut[0] = OemMode;
                    return ipmi::responseSuccess(ipmi::ccSuccess,
                                                 returndataOut);
                }
                else
                {
                    return ipmi::responseResponseError();
                }
            }
            break;
            case getMaxPMaxQConfigurationCurrentPowerLimit: // currentPowerLimit
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService,
                    powerManagerCurrentChassisLimitObj,
                    powerManagerCurrentChassisCapIntf, "PowerCap");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            case getMaxPMaxQConfigurationCurrentPowerLimitP: // chassisPowerLimit_P
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService, powerManagerChassisLimitPObj,
                    powerManagerCurrentChassisCapIntf, "MaxPowerCapValue");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            case getMaxPMaxQConfigurationCurrentPowerLimitQ: // chassisPowerLimit_Q
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService, powerManagerChassisLimitQObj,
                    powerManagerCurrentChassisCapIntf, "MaxPowerCapValue");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            case getMaxPMaxQConfigurationCurrentPowerLimitMax: // chassisPowerLimit_Max
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService,
                    powerManagerCurrentChassisLimitObj,
                    powerManagerCurrentChassisCapIntf, "MinPowerCapValue");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            case getMaxPMaxQConfigurationCurrentPowerLimitMin: // chassisPowerLimit_Max
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService,
                    powerManagerCurrentChassisLimitObj,
                    powerManagerCurrentChassisCapIntf, "MaxPowerCapValue");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            case getMaxPMaxQConfigurationRestOfSytemPower: // RestOfSystemPower
            {
                auto value = ipmi::getDbusProperty(
                    *dbus, powerManagerService,
                    powerManagerRestOfSystemPowerObj,
                    powerManagerRestOfSystemPowerIntf, "Value");
                uint32_t data = std::get<uint32_t>(value);
                std::vector<uint8_t> returndataOut(4);
                returndataOut[0] = getMaskdata(data, 0);
                returndataOut[1] = getMaskdata(data, 1);
                returndataOut[2] = getMaskdata(data, 2);
                returndataOut[3] = getMaskdata(data, 3);
                return ipmi::responseSuccess(ipmi::ccSuccess, returndataOut);
            }
            break;
            default:
                return ipmi::response(ipmi::ccInvalidFieldRequest);
        }
        return ipmi::responseSuccess();
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to  Get ipmiOemGetMaxPMaxQConfiguration",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<uint8_t>
    ipmiOemSetMaxPMaxQConfiguration(uint8_t parameter,
                                    std::vector<uint8_t> dataIn)
{
    using namespace ipmi::nvidia::misc;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        switch (parameter)
        {
            case setMaxPMaxQConfigurationMode: // Set Mode
            {
                if (dataIn.size() != 1)
                {
                    return ipmi::response(ipmi::ccReqDataLenInvalid);
                }

                switch (dataIn[0])
                {
                    case maximumPerformanceMode:
                        ipmi::setDbusProperty(
                            *dbus, powerManagerService,
                            powerManagerCurrentChassisLimitObj,
                            powerManagerCurrentChassisModeIntf, "PowerMode",
                            std::string("xyz.openbmc_project.Control.Power."
                                        "Mode.PowerMode.MaximumPerformance"));
                        break;
                    case powerSavingMode:
                        ipmi::setDbusProperty(
                            *dbus, powerManagerService,
                            powerManagerCurrentChassisLimitObj,
                            powerManagerCurrentChassisModeIntf, "PowerMode",
                            std::string("xyz.openbmc_project.Control.Power."
                                        "Mode.PowerMode.PowerSaving"));
                        break;
                    case OemMode:
                        ipmi::setDbusProperty(
                            *dbus, powerManagerService,
                            powerManagerCurrentChassisLimitObj,
                            powerManagerCurrentChassisModeIntf, "PowerMode",
                            std::string("xyz.openbmc_project.Control.Power."
                                        "Mode.PowerMode.OEM"));
                        break;
                    default:
                        return ipmi::response(ipmi::ccInvalidFieldRequest);
                }
            }
            break;
            case setMaxPMaxQConfigurationCurrentPowerLimit: // set sPowerCap
                                                            // Value
            {
                if (dataIn.size() != 4)
                {
                    return ipmi::response(ipmi::ccReqDataLenInvalid);
                }
                uint32_t value = dataIn[3] << 24 | dataIn[2] << 16 |
                                 dataIn[1] << 8 | dataIn[0];
                ipmi::setDbusProperty(*dbus, powerManagerService,
                                      powerManagerCurrentChassisLimitObj,
                                      powerManagerCurrentChassisCapIntf,
                                      "PowerCap", value);
            }
            break;

            default:
                return ipmi::response(ipmi::ccInvalidFieldRequest);
        }
        return ipmi::responseSuccess();
    }
    catch (sdbusplus::exception_t& e)
    {
        std::string error = e.name();
        if (error == "xyz.openbmc_project.Control.Power.Cap.Error."
                     "NotSupportedInCurrentMode")
        {
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
        else if (error == "xyz.openbmc_project.Control.Power.Cap.Error."
                          "chassisLimitOutOfRange")
        {
            return ipmi::response(ipmi::ccParmOutOfRange);
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to  Get ipmiOemSetMaxPMaxQConfiguration",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
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

    // <Set fan control mode>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetFanMode));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdSetFanMode,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetFanControl);

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

    // <Get BIOS POST Status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemPost),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetBiosPostStatus));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdGetBiosPostStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPostStatus);

    // <Get BIOS POST Code>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemPost),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdGetBiosPostCode));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdGetBiosPostCode,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPostCode);

    // <Soft Reboot>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSoftPowerCycle));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSoftPowerCycle,
                          ipmi::Privilege::Admin, ipmi::ipmiOemSoftReboot);

    // <Get device firmware version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetDeviceFirmwareVersion));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetDeviceFirmwareVersion,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscFirmwareVersion);

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

    // <Master Read Write>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemPost),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdI2CMasterReadWrite));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdI2CMasterReadWrite,
                          ipmi::Privilege::Admin, ipmi::ipmiI2CMasterReadWrite);

    // <Enable/Disable sensor scanning>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSensorScanEnable));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSensorScanEnable,
                          ipmi::Privilege::Admin, ipmi::ipmiSensorScanEnableDisable);

    // <Get SSD LED Status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetSSDLed));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetSSDLed,
                          ipmi::Privilege::Admin, ipmi::ipmiOemGetSSDLed);

    // <Set SSD LED Status>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
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

    // <Get PSU Power>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetPsuPower));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetPsuPower,
                          ipmi::Privilege::Admin, ipmi::ipmiOemPsuPower);

    // <Bios set version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemPost),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSetBiosVersion));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdSetBiosVersion,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetVersion);

    // <Bios get bootup image>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBiosBootupImage));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosBootupImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetBootImage);

    // <Bios get next bootup image>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBiosNextImage));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosNextImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetNextBootImage);

    // <Bios set next bootup image>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetBiosNextImage));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosNextImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetNextBootImage);

    // <Get bios version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBiosVerions));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosVerions,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetVerion);

    // <Get bios config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBiosConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosConfig,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetConfig);

    // <Set bios config>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetBiosConfig));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosConfig,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetConfig);

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

    // <Get Redfish Service UUID>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetRedfishServiceUuid));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetRedfishServiceUuid,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServiceUuid);

    // <Get Redfish Service Port Number>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetRedfishServicePort));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetRedfishServicePort,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServicePort);

    // <Get Bootstrap Account Credentials>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBootStrapAcc));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetBootStrapAcc,
                               ipmi::Privilege::sysIface,
                               ipmi::ipmiGetBootStrapAccount);

    // <Get Manager Certificate Fingerprint>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetManagerCertFingerPrint));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetManagerCertFingerPrint,
                               ipmi::Privilege::Admin,
                               ipmi::ipmiGetManagerCertFingerPrint);

    // <Get Maxp/MaxQ Configuration>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetMaxPMaxQConfiguration));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetMaxPMaxQConfiguration,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemGetMaxPMaxQConfiguration);

    // <Set Maxp/MaxQ Configuration>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSetMaxPMaxQConfiguration));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetMaxPMaxQConfiguration,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemSetMaxPMaxQConfiguration);
    return;
}
