/**
 * Copyright © 2020 NVIDIA Corporation
 * License Information here...
 */

#include "oemcommandsBF.hpp"
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
#include <unordered_map>

const char* systemdServiceBf = "org.freedesktop.systemd1";
const char* systemdUnitIntfBf = "org.freedesktop.systemd1.Unit";
const char* rshimSystemdObjBf = "/org/freedesktop/systemd1/unit/rshim_2eservice";
const char* dbusPropertyInterface = "org.freedesktop.DBus.Properties";

const char* ctlBMCtorSwitchModeService = "xyz.openbmc_project.Settings";
const char* ctlBMCtorSwitchModeBMCObj = "/xyz/openbmc_project/control/torswitchportsmode";
const char* ctlBMCtorSwitchModeIntf = "xyz.openbmc_project.Control.TorSwitchPortsMode";
const char* ctlBMCtorSwitchMode = "TorSwitchPortsMode";
const char* torSwitchModeSystemdObj = "/org/freedesktop/systemd1/unit/torswitch_2dmode_2eservice";

// PowerSubSystem
const char* powerCapacityObj = "/xyz/openbmc_project/control/host0/PowerLimit_0";
const char* powerCapacitySrvice = "com.Nvidia.Powermanager";
const char* powerCapacityInterface = "xyz.openbmc_project.Control.Power.Cap";
const char* powerCapacityModeInterface = "xyz.openbmc_project.Control.Power.Mode";
const char* powerSubsysObj = "/xyz/openbmc_project/control/host0/powercapacity";
const char* powerSubsysSrvice = "xyz.openbmc_project.Settings";
const char* powerSubsysInterface = "xyz.openbmc_project.Control.PowerSubsystem.Capacity";

// User Manager object in dbus
static constexpr const char* userMgrObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userMgrInterface =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* usersDeleteIface =
    "xyz.openbmc_project.Object.Delete";

// BIOSConfig Manager object in dbus
static constexpr const char* biosConfigMgrPath =
    "/xyz/openbmc_project/bios_config/manager";
static constexpr const char* biosConfigMgrIface =
    "xyz.openbmc_project.BIOSConfig.Manager";
static constexpr const char* createUserMethod = "CreateUser";

static const std::vector<std::string> nicExternalHostPrivileges = {
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_FLASH_ACCESS",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_FW_UPDATE",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_NIC_RESET",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_NV_GLOBAL",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_NV_HOST",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_NV_INTERNAL_CPU",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_NV_PORT",
            "/xyz/openbmc_project/network/connectx/external_host_privileges/external_host_privileges/HOST_PRIV_PCC_UPDATE"
            };

const char* connectxSevice = "xyz.openbmc_project.Settings.connectx";
const char* connectxSmartnicModeObj = "/xyz/openbmc_project/network/connectx/smartnic_mode/smartnic_mode/INTERNAL_CPU_OFFLOAD_ENGINE";
const char* connectxHostAccessObj = "/xyz/openbmc_project/network/connectx/host_access/HOST_PRIV_RSHIM";
const char* connectxSmartnicOsState = "/xyz/openbmc_project/network/connectx/smartnic_os_state/os_state";

struct PropertyInfo
{
    const char* intf;
    const char* prop;
    const std::unordered_map<std::string,int> strToInt;
    const std::unordered_map<int,std::string> intToStr;
};

const PropertyInfo nicAttributeInfo = {
    .intf = "xyz.openbmc_project.Control.NicAttribute",
    .prop = "NicAttribute",
    .strToInt = {{"xyz.openbmc_project.Control.NicAttribute.Modes.Enabled", 1},
                {"xyz.openbmc_project.Control.NicAttribute.Modes.Disabled", 0},
                {"xyz.openbmc_project.Control.NicAttribute.Modes.Invaild", -1}},
    .intToStr = {{1, "xyz.openbmc_project.Control.NicAttribute.Modes.Enabled"},
                {0, "xyz.openbmc_project.Control.NicAttribute.Modes.Disabled"}}
};

const PropertyInfo nicTristateAttributeInfo = {
    .intf = "xyz.openbmc_project.Control.NicTristateAttribute",
    .prop = "NicTristateAttribute",
    .strToInt = {{"xyz.openbmc_project.Control.NicTristateAttribute.Modes.Default", 0},
                 {"xyz.openbmc_project.Control.NicTristateAttribute.Modes.Enabled", 1},
                 {"xyz.openbmc_project.Control.NicTristateAttribute.Modes.Disabled", 2},
                 {"xyz.openbmc_project.Control.NicTristateAttribute.Modes.Invaild", -1}},
    .intToStr = {{0, "xyz.openbmc_project.Control.NicTristateAttribute.Modes.Default"},
                 {1, "xyz.openbmc_project.Control.NicTristateAttribute.Modes.Enabled"},
                 {2, "xyz.openbmc_project.Control.NicTristateAttribute.Modes.Disabled"}}
};

const PropertyInfo smartNicOsStateInfo = {
    .intf = "xyz.openbmc_project.Control.SmartNicOsState",
    .prop = "SmartNicOsState",
    .strToInt = {{"xyz.openbmc_project.Control.SmartNicOsState.Modes.BootRom", 0},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.BL2", 1},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.BL31", 2},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.UEFI", 3},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.OsStarting", 4},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.OsIsRunning", 5},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.LowPowerStandby", 6},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.FirmwareUpdateInProgress", 7},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.OsCrashDumpInProgress", 8},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.OsCrashDumpIsComplete", 9},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.FWFaultCrashDumpInProgress", 10},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.FWFaultCrashDumpIsComplete", 11},
                 {"xyz.openbmc_project.Control.SmartNicOsState.Modes.Invalid", -1}},
    .intToStr = {}
};

void registerNvOemPlatformFunctions() __attribute__((constructor(102)));


using namespace phosphor::logging;

constexpr uint8_t localChannel = 0x08;

using GetSubTreeType = std::vector<
    std::pair<std::string,
        std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using GetSubTreePathsType = std::vector<std::string>;
using BasicVariantType = std::variant<std::string>;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;

struct userInfo {
    std::string name;
    std::string password;
};

struct userInfoBuf {
    std::vector<uint8_t> respUserNameBuf;
    std::vector<uint8_t> respPasswordBuf;
};

namespace ipmi
{
    constexpr int BOOTSTRAP_ACCOUNTS_NUM = 2;
    const int BOOTSTRAP_PASSWORD_SIZE = 16;
    static constexpr Cc ipmiCCBootStrappingDisabled = 0x80;
    std::array<userInfo, BOOTSTRAP_ACCOUNTS_NUM> userDatabase = {{
        { "NvBluefieldUefi0", ""},
        { "NvBluefieldUefi1", ""}
    }};

    std::array<userInfoBuf, 2> userDatabaseBuff = {
        {{{'N', 'v', 'B', 'l', 'u', 'e', 'f', 'i', 'e', 'l', 'd', 'U', 'e', 'f', 'i', '0'}, {}},
         {{'N', 'v', 'B', 'l', 'u', 'e', 'f', 'i', 'e', 'l', 'd', 'U', 'e', 'f', 'i', '1'}, {}}}
    };

    static int BootStrapCurrentUserIndex = 0;
    static std::string accountService;

    template <typename... ArgTypes>
    static int executeCmd(const char* path, ArgTypes&&... tArgs)
    {
        boost::process::child execProg(path, const_cast<char*>(tArgs)...);
        execProg.wait();
        return execProg.exit_code();
    }

    ipmi::RspType<> ipmiSetRshimStateBf(uint8_t newState)
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
                systemdServiceBf, rshimSystemdObjBf,
                systemdUnitIntfBf, systemdCmd.c_str());
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
    
    
    ipmi::RspType<> ipmiSupportLaunchpad(uint8_t newState, uint8_t bfModel){
        if(bfModel != 2 && bfModel != 3 ){
             phosphor::logging::log<level::NOTICE>("BF model can be only  2 or 3");
            return ipmi::responseResponseError();
   
        }
        if(newState != 0 && newState != 1){
            log<level::ERR>("Unsupported argument",
                phosphor::logging::entry("Requested State=%d", newState));
            return ipmi::responseInvalidFieldRequest(); 
        }
        //disable/ enable rshim
        uint8_t newRshimState = 0;
        if (newState == 0)
            newRshimState = 1; 
        auto ret = ipmi::ipmiSetRshimStateBf(newRshimState);
        /*
        if (std::get<0>(ret)  != ipmi::ccSuccess)  {
            phosphor::logging::log<phosphor::logging::level::ERR>("Couldn't disable rshim");
            return ipmi::responseResponseError();
        }
        */
        //disable/ enable 3 port eth switch 
        std::vector<uint8_t> writeData={0x2a, 0x04, 0x00, 0x00, 0x00, 0x06};
        std::vector<uint8_t> readBuf(4);
        if (newState == 0)
            writeData[5] = 0x07; 

        uint8_t address =  ipmi::nvidia::ethSwitchI2caddressBF3;
        uint8_t bus =  ipmi::nvidia::ethSwitchI2cBusBF3; 
        if (bfModel == 2) {
            address = ipmi::nvidia::ethSwitchI2caddressBF2;
            bus =  ipmi::nvidia::ethSwitchI2cBusBF2;
        }       
        auto ret_eth = i2cTransaction(bus, address, writeData, readBuf);
        
        if (ret_eth != ipmi::ccSuccess)  {
            phosphor::logging::log<phosphor::logging::level::ERR>("Couldn't disable 3 port eth switch");
            return ipmi::responseResponseError();
        }
        //disable/ enable i2c0 (to the DPU)
        int response;
        std::string devmem = "devmem 0x1e78a080 ";
        if (bfModel == 2){
             devmem = "devmem 0x1e78a040 ";
        }
        response = executeCmd(devmem.c_str());
        if(response)
        {
            log<level::ERR>("devmem Command failed.",
                    phosphor::logging::entry("response= %d", response));
            return ipmi::response(ipmi::ccResponseError);
        }
        std::cout<<" response "<<response<<std::endl;
        if(newState == 1){
            response = response & 0xfffffffd;
        }else{
             response = response | 0x2;
        }
        std::cout<<"response "<<response<<std::endl;
        char writeResponse [9];
        sprintf(writeResponse, "%X", response);
        devmem = "devmem 0x1e78a080 w 0x";
         if (bfModel == 2){
           devmem = "devmem 0x1e78a040 w 0x";
        }
        std::string writeResponseString(writeResponse);
        devmem = devmem + writeResponseString;
        std::cout<<"devmem "<<devmem<<std::endl;
        response = executeCmd(devmem.c_str());
        if(response)
        {
            log<level::ERR>("devmem Command failed.",
                    phosphor::logging::entry("response= %d", response));
            return ipmi::response(ipmi::ccResponseError);
        }
        return ipmi::responseSuccess();
    }
    
    ipmi::RspType<uint8_t, std::vector<uint8_t>>ipmi3PortEthSwitchStatus( uint8_t bfModel) {
            if(bfModel != 2 && bfModel != 3 ){
                phosphor::logging::log<level::NOTICE>("BF model can be only  2 or 3");
                return ipmi::responseResponseError();
    
            }
            std::vector<uint8_t> writeData={0x2a, 0x04};
            std::vector<uint8_t> readBuf(4);
            uint8_t ethSwitchI2cBus = ipmi::nvidia::ethSwitchI2cBusBF3;
            uint8_t ethSwitchI2caddress = ipmi::nvidia::ethSwitchI2caddressBF3;
            if (bfModel == 2) {
                ethSwitchI2caddress = ipmi::nvidia::ethSwitchI2caddressBF2;
                ethSwitchI2cBus = ipmi::nvidia::ethSwitchI2cBusBF2;
            }       
            auto ret_eth = i2cTransaction(ethSwitchI2cBus,ethSwitchI2caddress, writeData, readBuf);
            
            if (ret_eth != ipmi::ccSuccess)  {
                phosphor::logging::log<phosphor::logging::level::ERR>("Couldn't read the 3 port eth switch status");
                return ipmi::responseResponseError();
            }
            
    
        return ipmi::responseSuccess(0x00, readBuf);
    
    } 
    static int gpioExportLF(uint32_t gpio) {
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

    static bool setGpioRawLF(uint32_t gpio, uint32_t value) {
        int gp = gpioExportLF(gpio);
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
            phosphor::logging::log<phosphor::logging::level::ERR>("Failed to open gpio value!");
            return false;
        }
        valueOf << value;
        valueOf.close();
        return true;
    }



    static bool getGpioRawLF( uint32_t gpio, uint8_t &v) {
        int gp = gpioExportLF(gpio);
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
    
   static void cleanGpio(){  
        if (!setGpioRawLF(nvidia::socRstGpio,ipmi::nvidia::gpioHigh) || !setGpioRawLF(nvidia::preRstGpio,ipmi::nvidia::gpioHigh) 
            || !setGpioRawLF(nvidia::liveFishGpio,ipmi::nvidia::gpioHigh)){ 
            phosphor::logging::log<level::ERR>("unable to restore gpios to default"); 
        }else{
            phosphor::logging::log<level::NOTICE>("restored gpios to default (1)");
        } 
        return;
    }

    static bool changeSocRstAndPreRstGpios(uint32_t value){
        if (!setGpioRawLF(nvidia::preRstGpio,value)){ 
            phosphor::logging::log<level::ERR>("failed to write to PRE_RESET gpio");
            cleanGpio();
            return false;
            }  
    
        std::this_thread::sleep_for(std::chrono::milliseconds(ipmi::nvidia::resetPause));

        if (!setGpioRawLF(nvidia::socRstGpio,value)){ 
            phosphor::logging::log<level::ERR>("failed to write to SOC_RESET gpio");
            cleanGpio();
            return false;
            }  
        return true;
    }



     static bool DPUHardRST(){
        if (!changeSocRstAndPreRstGpios(ipmi::nvidia::gpioLow)){
                phosphor::logging::log<level::ERR>("SOC_HARD_RST Command failed, can't change GPIO's to 0");
                return false;   
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(ipmi::nvidia::resetPause));
        if (!changeSocRstAndPreRstGpios(ipmi::nvidia::gpioHigh)){
                phosphor::logging::log<level::ERR>("SOC_HARD_RST Command failed, can't return GPIO's to 1");
                return false;  
        } 
        std::cout << "soc_hard_rst is being done " << std::endl; 
        return true;
    }

    static bool ipmiChangeLF(uint32_t value){
        //checks if we need to change the FNP GPIO value
        uint8_t lfGpio = 0;
        if (!getGpioRawLF(nvidia::liveFishGpio,lfGpio)){
            phosphor::logging::log<level::ERR>("failed to read from LIVE_FISH gpio");
            return false;
        }
        if (lfGpio == value){
            phosphor::logging::log<level::ERR>("LF GPIO is allready set, nothing to do ,aborting",
            phosphor::logging::entry("liveFish GPIO = %lu ", value));
            return false;
        }
        
    
        if (!setGpioRawLF(nvidia::liveFishGpio,value)){ 
            phosphor::logging::log<level::ERR>("failed to write to LIVE_FISH gpio");
            return false;
            }
        std::cout << "LF GPIO =" << value << std::endl; 
        return true;
    }

    ipmi::RspType<> ipmicmdForceSocHardRst() {
        // force SOC_HARD_RST on the DPU
        if(!DPUHardRST()){
            phosphor::logging::log<level::ERR>("Failed to preform SOC_HARD_RST");
            return ipmi::responseResponseError();   
        }
        return ipmi::responseSuccess();

    }

     ipmi::RspType<> ipmicmdEnterLiveFish() {
       //change the livefish GPIO value to 0 and restart the SOC
        if(!ipmiChangeLF(ipmi::nvidia::gpioLow)){
            phosphor::logging::log<level::ERR>("Failed to enter to liveFish mode");
            return ipmi::responseResponseError();   
        }
        // force SOC_HARD_RST on the DPU
        if (!DPUHardRST()){
            phosphor::logging::log<level::ERR>("Command failed, SOC_HARD_RST failed ");
            return ipmi::responseResponseError();   
        }
        return ipmi::responseSuccess();


    } 

    ipmi::RspType<> ipmicmdExitLiveFish() {
        //change the livefish GPIO value to 1 and restart the SOC
        if(!ipmiChangeLF(ipmi::nvidia::gpioHigh) ){
            phosphor::logging::log<level::ERR>("Failed to exit from liveFish mode");
            return ipmi::responseResponseError();   
        }

        // force SOC_HARD_RST on the DPU
        if (!DPUHardRST()){
            phosphor::logging::log<level::ERR>("Command failed, SOC_HARD_RST failed ");

            return ipmi::responseResponseError();   
        }
        return ipmi::responseSuccess();

    }

    ipmi::RspType<> ipmiNetworkReprovisioning(ipmi::Context::ptr ctx, uint8_t golden_image_timeout, uint8_t timeout_from_network, uint8_t verbosityLevel) {
        if (ctx->channel != localChannel){
            log<level::ERR>("Running the command is allowed only from BMC");
            return ipmi::response(ipmi::ccResponseError);
        }                
        if (golden_image_timeout == 0){
            golden_image_timeout=15;
        }
        if (timeout_from_network == 0){
            timeout_from_network=60;
        }
        if (verbosityLevel > 2){
            log<level::ERR>("Verbosity level can be a value between 0 to 2");
            return ipmi::response(ipmi::ccResponseError);
        }
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        try
        {
            
            auto method = dbus->new_method_call("xyz.openbmc_project.Software.BMC.GoldenImageUpdateService",
                                                "/xyz/openbmc_project/host0/software/goldenimageupdater",
                                                "xyz.openbmc_project.Common.GoldenImageUpdater", 
                                                "StartGoldenImageReprovisioning");
            method.append(golden_image_timeout, timeout_from_network, verbosityLevel);

            dbus->call_noreply(method); 
            return ipmi::responseSuccess();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmiNetworkReprovisioning error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
        
    }

    ipmi::RspType<uint8_t> ipmicmdTorSwitchSetMode(ipmi::Context::ptr ctx, uint8_t parameter);
    
    ipmi::RspType<uint8_t>
    ipmiBFResetControl(ipmi::Context::ptr ctx, uint8_t resetOption)
    {
        int response;
        switch(resetOption)
        {
            case 0x02: // arm soft reset
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "arm_soft_reset");
                break;
            case 0x03: // tor eswitch reset
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "do_tor_eswitch_reset");
                if(!response) // switch returns to a default mode after a reset- need to change the mode of TorSwitchPortsMode to that mode (0x00)
                    ipmicmdTorSwitchSetMode(ctx, ipmi::nvidia::enumTorSwitchAllowAll);
                break;
            case 0x04: // arm hard reset - nsrst - secondary DPU
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "bf2_nic_bmc_ctrl1");
                break;
            case 0x05: // arm soft reset - secondary DPU
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "bf2_nic_bmc_ctrl0");
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
        ipmi::RspType<uint8_t> ipmiGetFwBootupSlotBF(uint8_t FwType)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetFwBootupSlot command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }



    ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t, uint8_t, uint8_t, uint8_t> ipmiSMBPBIPassthroughCmdBF(
        uint8_t param, // GPU device : 0x01 fixed
        uint8_t deviceId,
        uint8_t opcode,
        uint8_t arg1,
        uint8_t arg2,
        uint8_t execute // Execute bit : 0x80 fixed
        )
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSMBPBIPassthroughCmd command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t, uint8_t, uint8_t> ipmiSMBPBIPassthroughExtendedCmBF(
        uint8_t deviceId,
        uint8_t opcode,
        uint8_t arg1,
        uint8_t arg2,
        uint8_t execute // Execute bit : 0x1f fixed
        )
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSMBPBIPassthroughExtendedCm command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t>
    ipmiSetFanZonePWMDutyBF(uint8_t zone, uint8_t request)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSetFanZonePWMDuty command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t>
    ipmiSetAllFanZonesPWMDutyBF(uint8_t request)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSetAllFanZonesPWMDuty command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiSetFanControlBF(uint8_t mode) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSetFanControl command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }


    ipmi::RspType<uint8_t> ipmiGetBiosPostStatusBF(uint8_t requestData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetBiosPostStatus command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }


    ipmi::RspType<uint16_t, uint16_t, std::vector<uint8_t>>
        ipmiGetBiosPostCodeBF(ipmi::Context::ptr ctx)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetBiosPostCode command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<> ipmiOemSoftRebootBF()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemSoftReboot command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }


    ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOemMiscFirmwareVersionBF(ipmi::Context::ptr ctx, uint8_t device)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemMiscFirmwareVersion command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }



    ipmi::RspType<uint8_t> ipmiOemMiscGetWPBF(uint8_t type, uint8_t id)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemMiscGetWP command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<> ipmiOemMiscSetWPBF(uint8_t type, uint8_t id, uint8_t value)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemMiscSetWP command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiOemGetSSDLedBF(uint8_t type, uint8_t instance)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemGetSSDLed command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<> ipmiOemSetSSDLedBF(uint8_t type, uint8_t instance, uint8_t pattern) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemSetSSDLed command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiOemGetLedStatusBF(uint8_t type) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemGetLedStatus command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }


    ipmi::RspType<> ipmiSensorScanEnableDisableBF(uint8_t mode) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiSensorScanEnableDisable command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint16_t, uint16_t, uint8_t> ipmiOemPsuPowerBF(uint8_t type, uint8_t id) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemPsuPower command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<> ipmiBiosSetVersionBF(uint8_t major, uint8_t minor) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosSetVersion command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiBiosGetBootImageBF(void) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosGetBootImage command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }
    ipmi::RspType<uint8_t> ipmiBiosGetNextBootImageBF(void){
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosGetNextBootImage command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    } 

    ipmi::RspType<> ipmiBiosSetNextBootImageBF(uint8_t bootimage)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosSetNextBootImage command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t, uint8_t> ipmiBiosGetVerionBF(uint8_t image) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosGetVerion command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiBiosGetConfigBF(uint8_t type) 
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosGetConfig command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<> ipmiBiosSetConfigBF(uint8_t type) {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiBiosSetConfig command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbDescriptionBF(uint8_t type){
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetUsbDescriptioncommand is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<std::vector<uint8_t>> ipmiGetUsbSerialNumBF()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetUsbSerialNum command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiGetipmiChannelRfHiBF()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetipmiChannelRfHi command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<std::vector<uint8_t>>
        ipmiGetManagerCertFingerPrintBF(ipmi::Context::ptr ctx, uint8_t certNum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetManagerCertFingerPrint command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t, std::vector<uint8_t>>
        ipmiOemGetMaxPMaxQConfigurationBF(uint8_t parameter)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemGetMaxPMaxQConfiguration command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t>
        ipmiOemSetMaxPMaxQConfigurationBF(uint8_t parameter,
                                        std::vector<uint8_t> dataIn)

    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiOemSetMaxPMaxQConfiguration command is unsupported in Bluefield 2/3");
        return ipmi::response(ipmi::ccResponseError);
    }

    /**
     * @brief IPMI OEM - Notify upon DPU boot
     * Called from DPU UEFI. Update Host0 property: BootProgressLastUpdate
     * @param[in] ctx ipmi command context
     *
     * @returns RspType - response return  */
    ipmi::RspType<uint8_t> ipmiOemNotifyDpuBoot(ipmi::Context::ptr ctx)
    {
        try
        {
            uint64_t timeValue(std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count());
            std::variant<uint64_t> variantTimeValue(timeValue);             
            auto method = ctx->bus->new_method_call("xyz.openbmc_project.State.Host",
                                                    "/xyz/openbmc_project/state/host0",
                                                    "org.freedesktop.DBus.Properties", 
                                                    "Set");
            method.append("xyz.openbmc_project.State.Boot.Progress", "BootProgressLastUpdate", variantTimeValue);
            auto reply = ctx->bus->call(method); 
            return ipmi::responseSuccess();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmiOemSyncDpuVersion error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
    }

    ipmi::RspType<uint8_t> ipmicmdTorSwitchGetMode(ipmi::Context::ptr ctx)
    {
        try
        {
            auto method = ctx->bus->new_method_call(ctlBMCtorSwitchModeService,
                                                    ctlBMCtorSwitchModeBMCObj,
                                                    dbusPropertyInterface,
                                                    "Get");
            method.append(ctlBMCtorSwitchModeIntf, ctlBMCtorSwitchMode);
            auto reply = ctx->bus->call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("ipmicmdTorSwitchGetMode: Get Dbus error",
                                entry("SERVICE=%s", ctlBMCtorSwitchModeService));
                return ipmi::responseResponseError();
            }

            std::variant<std::string> variantValue;
            reply.read(variantValue);

            auto strValue = std::get<std::string>(variantValue);
            if (strValue ==
                "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.All")
            {
                return ipmi::responseSuccess(ipmi::nvidia::enumTorSwitchAllowAll);
            }
            if (strValue ==
                "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.BMC")
            {
                return ipmi::responseSuccess(ipmi::nvidia::enumTorSwitchAllowBMC);
            }
            if (strValue ==
                "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.DPU")
            {
                return ipmi::responseSuccess(ipmi::nvidia::enumTorSwitchAllowDPU);
            }
            if (strValue ==
                "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.None")
            {
                return ipmi::responseSuccess(ipmi::nvidia::enumTorSwitchDenyNone);
            }
            if (strValue ==
                "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.Disabled")
            {
                return ipmi::responseSuccess(ipmi::nvidia::enumTorSwitchDisabled);
            }

            log<level::ERR>("ipmicmdTorSwitchGetMode: Invalid Mode");
            return ipmi::responseResponseError();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdTorSwitchGetMode error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }

    }

    ipmi::RspType<uint8_t> ipmicmdTorSwitchSetMode(ipmi::Context::ptr ctx,
                                                   uint8_t parameter)
    {
        if (ctx->channel != localChannel){
            log<level::ERR>("Running the command is allowed only from BMC");
            return ipmi::response(ipmi::ccResponseError);
        }
        std::string strValue;
        switch(parameter)
        {
            case ipmi::nvidia::enumTorSwitchAllowAll:
                strValue = "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.All";
                break;
            case ipmi::nvidia::enumTorSwitchAllowBMC:
                strValue = "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.BMC";
                break;
            case ipmi::nvidia::enumTorSwitchAllowDPU:
                strValue = "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.DPU";
                break;
            case ipmi::nvidia::enumTorSwitchDenyNone:
                strValue = "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.None";
                break;
            case ipmi::nvidia::enumTorSwitchDisabled:
                strValue = "xyz.openbmc_project.Control.TorSwitchPortsMode.Modes.Disabled";
                break;
            default:
                log<level::ERR>("ipmicmdTorSwitchGetMode: Invalid Mode");
                return ipmi::responseInvalidFieldRequest();
        }

        // Set Tor Switch Mode
        try
        {
            std::variant<std::string> variantValue(strValue);

            auto method = ctx->bus->new_method_call(ctlBMCtorSwitchModeService,
                                                    ctlBMCtorSwitchModeBMCObj,
                                                    dbusPropertyInterface,
                                                    "Set");
            method.append(ctlBMCtorSwitchModeIntf, ctlBMCtorSwitchMode, variantValue);
            auto reply = ctx->bus->call(method);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdTorSwitchSetMode error",
                            entry("ERROR=%s", e.what()));
            return ipmi::responseUnspecifiedError();
        }

        // Restart TOR Switch Control Service
        try
        {
            auto method = ctx->bus->new_method_call(systemdServiceBf,
                                                    torSwitchModeSystemdObj,
                                                    systemdUnitIntfBf,
                                                    "Restart");
            method.append("replace");
            ctx->bus->call_noreply(method);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to restart TorSwitch Control service",
                phosphor::logging::entry("EXCEPTION=%s", e.what()));
            return ipmi::responseUnspecifiedError();
        }

        return ipmi::responseSuccess(parameter);
    }

/**
 * Retrieves the current status of the CredentialBootstrap property.
 *
 * @return The status of the CredentialBootstrap property:
 *         - True if credential bootstrapping is enabled.
 *         - False if credential bootstrapping is disabled or an error occurred.
 */
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

/**
 * Sets the CredentialBootstrap property based on the given disableCredBootStrap value.
 * If disableCredBootStrap is 0xa5, the CredentialBootstrap property is set to true
 * to disable credential bootstrapping. Otherwise, it is set to false to enable it.
 *
 * @param disableCredBootStrap The value indicating whether to disable credential bootstrapping.
 */
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


/**
 * Checks if a password is valid based on specific criteria.
 *
 * @param password The password to be checked.
 * @return True if the password is considered valid, false otherwise.
 */

static bool isValidPassword(const std::string& password)
{
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

/**
 * Generates a random password with specific criteria.
 *
 * @param uniqueStr[out] The generated random password.
 * @return True if the random password is generated successfully, false otherwise.
 */
static bool getRandomPasswordInternal(std::string& uniqueStr)
{
    std::ifstream randFp("/dev/urandom", std::ifstream::in);
    char byte;
    uint8_t maxStrSize = BOOTSTRAP_PASSWORD_SIZE;
    std::string invalidChar = "\'\\\"";

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
                            /* At least one lower case */
                            if (iswlower(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 1)
                        {
                            /* At least one upper case */
                            if (iswupper(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 2)
                        {
                            /* At least one digit */
                            if (iswdigit(byte))
                            {
                                break;
                            }
                        }
                        else if (it == 3)
                        {
                            /* At least one special char*/
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

static int pamUpdatePasswd(const char* username, const char* password)
{
    const struct pam_conv localConversation = {pamFunctionConversation,
                                               const_cast<char*>(password)};
    pam_handle_t* localAuthHandle = NULL; // this gets set by pam_start
    int retval =
        pam_start("passwd", username, &localConversation, &localAuthHandle);
    if (retval != PAM_SUCCESS)
    {
        phosphor::logging::log<level::ERR>("pamUpdatePasswd failed");
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, retval);
        phosphor::logging::log<level::ERR>("pamUpdatePasswd failed");
        return retval;
    }
    return pam_end(localAuthHandle, PAM_SUCCESS);
}


/**
 * Generates a random password with specific criteria.
 *
 * @param uniqueStr[out] The generated random password.
 * @return True if the random password is generated successfully, false otherwise.
 */
static bool getRandomPassword(std::string& uniqueStr)
{
    bool passwordIsValid = false;
    int max_retries = 10;
    bool ret;

    while (!passwordIsValid && (max_retries != 0)) {
        ret = getRandomPasswordInternal(uniqueStr);
        if (!ret)
        {
            phosphor::logging::log<level::ERR>(
                "getRandomPassword: Failed to generate alphanumeric "
                "Password");
            return false;
        }
        passwordIsValid = isValidPassword(uniqueStr);
        max_retries--;
    }

    if (!passwordIsValid) {
        phosphor::logging::log<level::ERR>(
            "getRandomPassword: Retries Exceeded,  Failed to generate valid Password");
        return false;
    }
    return true;
}

// Get the bootstrap username at the specified index
static std::string getBootstrapUserName(int index)
{
    if (index < userDatabase.size())
    {
        return ipmi::userDatabase[index].name;
    }
    return "";
}

// Get the bootstrap password at the specified index
static std::string getBootstrapPassword(int index)
{
    if (index < userDatabase.size())
    {
        return ipmi::userDatabase[index].password;
    }
    return "";
}

// Set the bootstrap password at the specified index
static void SetBootstrapPassword(int index, std::string password)
{
    if (index < userDatabase.size())
    {
        ipmi::userDatabase[index].password = password;
    }
}

static ipmi::RspType<> ipmiCreateBootStrapAccountBF(ipmi::Context::ptr ctx,
                                                    uint8_t disableCredBootStrap,
                                                    uint8_t index)
{
    int accountIndex = static_cast<int>(index);
    try
    {
        if (accountIndex > BOOTSTRAP_ACCOUNTS_NUM)
        {
            phosphor::logging::log<level::ERR>("ipmiCreateBootStrapAccountBF: Invalid index");
            return ipmi::responseResponseError();
        }

        // Check the CredentialBootstrapping property status,
        // if disabled, then reject the command with success code.
        bool isCredentialBooStrapSet = getCredentialBootStrap();
        if (!isCredentialBooStrapSet)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiCreateBootStrapAccountBF: Credential BootStrapping Disabled "
                "Get BootStrap Account command rejected.");

            return ipmi::response(ipmi::ipmiCCBootStrappingDisabled);
        }

        //Get username from DB
        std::string userName = ipmi::getBootstrapUserName(accountIndex);
        std::string password;
        if (!getRandomPassword(password)) {
            phosphor::logging::log<level::ERR>(
                "ipmiCreateBootStrapAccountBF: Failed to generate valid Password");
            return ipmi::responseResponseError();
        }
        //save password at the DB
        ipmi::SetBootstrapPassword(accountIndex, password);

        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        ipmi::accountService = getService(*dbus, userMgrInterface, userMgrObjBasePath);

        // create the new user with only redfish-hostiface group access
        auto method = dbus->new_method_call(ipmi::accountService.c_str(), userMgrObjBasePath,
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
            dbus->yield_method_call<void>(ctx->yield, ec, ipmi::accountService.c_str(),
                                          userMgrObjBasePath + userName,
                                          usersDeleteIface, "Delete");

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiCreateBootStrapAccountBF : Failed to update password.");
            return ipmi::responseUnspecifiedError();
        }
        else
        {
            // update the "CredentialBootstrap" Dbus property w.r.to
            // disable crendential BootStrap status
            setCredentialBootStrap(disableCredBootStrap);
            ipmi::userDatabaseBuff[accountIndex].respPasswordBuf.clear();
            std::copy(password.begin(), password.end(),
                      std::back_inserter(ipmi::userDatabaseBuff[accountIndex].respPasswordBuf));
            return ipmi::responseSuccess();
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiCreateBootStrapAccountBF : Failed to generate BootStrap Account "
            "Credentials");
        return ipmi::responseResponseError();
    }
}

static ipmi::RspType<std::vector<uint8_t>, std::vector<uint8_t>>
    ipmiGetBootStrapAccountBF(ipmi::Context::ptr ctx, uint8_t disableCredBootStrap)
    {
        //Remove the following account, and the bootstrap manager will recreate it.
        size_t passwordSize = ipmi::userDatabaseBuff[ipmi::BootStrapCurrentUserIndex].respPasswordBuf.size();

        if (passwordSize != BOOTSTRAP_PASSWORD_SIZE) {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                                "ipmiGetBootStrapAccountBF : Invalid password size.",
                                phosphor::logging::entry("SIZE= %zu", passwordSize));
                return ipmi::responseResponseError();
        }
        auto ret = ipmi::responseSuccess(ipmi::userDatabaseBuff[ipmi::BootStrapCurrentUserIndex].respUserNameBuf,
                                         ipmi::userDatabaseBuff[ipmi::BootStrapCurrentUserIndex].respPasswordBuf);
        // Switch current account
        ipmi::BootStrapCurrentUserIndex = ipmi::BootStrapCurrentUserIndex == 0 ? 1 : 0;

        int NextAccountIndex = (ipmi::BootStrapCurrentUserIndex == 0) ? 1 : 0;
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

        dbus->async_method_call(
            [](boost::system::error_code ec2, sdbusplus::message_t& m) {
                if (ec2 || m.is_method_error())
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Error returns from call to dbus. delete user failed");
                    return;
                }
            },
            ipmi::accountService.c_str(),
            std::string(userMgrObjBasePath)
                .append("/")
                .append(ipmi::getBootstrapUserName(NextAccountIndex)),
            usersDeleteIface, "Delete");
        return ret;
    }

    // read property return value as int, using propertyInfo to map string
    // property to int, regarding negative as error
    static int readPropToInt(ipmi::Context::ptr ctx, const char* service,
                             const char* obj, const PropertyInfo& propertyInfo)
    {
        auto method = ctx->bus->new_method_call(service, obj,
                                                dbusPropertyInterface, "Get");

        method.append(propertyInfo.intf, propertyInfo.prop);

        auto reply = ctx->bus->call(method);

        if (reply.is_method_error())
        {
        return -1;
        }
        std::variant<std::string> variantValue;
        reply.read(variantValue);

        auto strValue = std::get<std::string>(variantValue);
        auto ret = propertyInfo.strToInt.find(strValue);
        return ret != propertyInfo.strToInt.end() ? ret->second : -1;
    }

    // read property return value as int, using propertyInfo to map int to
    // string property
    static int writeIntToProp(ipmi::Context::ptr ctx, const char* service,
                              const char* obj, const PropertyInfo& propertyInfo,
                              int input)
    {
        auto it = propertyInfo.intToStr.find(input);
        if (it == propertyInfo.intToStr.end())
        {
        return -1;
        }

        std::variant<std::string> variantValue(it->second);
        auto method = ctx->bus->new_method_call(service, obj,
                                                dbusPropertyInterface, "Set");

        method.append(propertyInfo.intf, propertyInfo.prop, variantValue);

        auto reply = ctx->bus->call(method);
        return 0;
    }

    ipmi::RspType<uint8_t> simplePropertyGet(ipmi::Context::ptr ctx,
                                             const char* service,
                                             const char* obj,
                                             const PropertyInfo& propertyInfo)
    {
        try
        {
        auto val = readPropToInt(ctx, service, obj, propertyInfo);
        if (val < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                (std::string(obj) + " get invalid value").c_str());
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess(val);
        }
        catch (const std::exception& e)
        {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string(obj) + " get failed").c_str());
        return ipmi::responseResponseError();
        }
    }

    ipmi::RspType<> simplePropertySet(ipmi::Context::ptr ctx,
                                      const char* service, const char* obj,
                                      const PropertyInfo& propertyInfo,
                                      int input)
    {
        try
        {
        auto val = writeIntToProp(ctx, service, obj, propertyInfo, input);
        if (val < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                (std::string(obj) + "set invalid value").c_str());
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
        }
        catch (const std::exception& e)
        {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string(obj) + "set failed").c_str());
        return ipmi::responseResponseError();
        }
    }

    auto ipmicmdNicGetSmartnicMode = [](ipmi::Context::ptr ctx) {
        return simplePropertyGet(ctx, connectxSevice, connectxSmartnicModeObj,
                                 nicAttributeInfo);
    };
    auto ipmicmdNicGetHostAccess = [](ipmi::Context::ptr ctx) {
        return simplePropertyGet(ctx, connectxSevice, connectxHostAccessObj,
                                 nicAttributeInfo);
    };
    auto ipmicmdNicSetSmartnicMode = [](ipmi::Context::ptr ctx, uint8_t val) {
        return simplePropertySet(ctx, connectxSevice, connectxSmartnicModeObj,
                                 nicAttributeInfo, val);
    };
    auto ipmicmdNicSetHostAccess = [](ipmi::Context::ptr ctx, uint8_t val) {
        return simplePropertySet(ctx, connectxSevice, connectxHostAccessObj,
                                 nicAttributeInfo, val);
    };
    auto ipmicmdNicGetOsState = [](ipmi::Context::ptr ctx) {
        return simplePropertyGet(ctx, connectxSevice, connectxSmartnicOsState,
                                 smartNicOsStateInfo);
    };
    auto ipmicmdNicSetExternalHostPrivilege = [](ipmi::Context::ptr ctx,
                                                 uint8_t idx, uint8_t val) {
        return idx < nicExternalHostPrivileges.size()
                   ? simplePropertySet(ctx, connectxSevice,
                                       nicExternalHostPrivileges[idx].c_str(),
                                       nicTristateAttributeInfo, val)
                   : ipmi::responseInvalidFieldRequest();
    };

    ipmi::RspType<std::vector<uint8_t>>
        ipmicmdNicGetExternalHostPrivileges(ipmi::Context::ptr ctx)
    {
        std::vector<uint8_t> res(nicExternalHostPrivileges.size(), 0);
        try
        {
        for (int i = 0; i < nicExternalHostPrivileges.size(); ++i)
        {
            auto val = readPropToInt(ctx, connectxSevice,
                                     nicExternalHostPrivileges[i].c_str(),
                                     nicTristateAttributeInfo);
            if (val < 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    (std::string(__func__) + " invalid value").c_str());
                return ipmi::responseResponseError();
            }
            res[i] = val;
        }
        }
        catch (const std::exception& e)
        {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string(__func__) + " Failed").c_str());
        return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess(res);
    }

    ipmi::RspType<uint8_t, std::vector<uint8_t>, std::vector<uint8_t>>
        ipmicmdNicGetStrap(ipmi::Context::ptr ctx)
    {

        static const std::vector<std::string> strapFields = {
            "DISABLE_INBAND_RECOVER",
            "PRIMARY_IS_PCORE_1",
            "2PCORE_ACTIVE",
            "SOCKET_DIRECT",
            "PCI_REVERSAL",
            "PCI_PARTITION_1",
            "PCI_PARTITION_0",
            "OSC_FREQ_1",
            "OSC_FREQ_0",
            "CORE_BYPASS_N",
            "FNP"};

        const std::string connectxStrapMask =
            "/xyz/openbmc_project/network/connectx/strap_options/mask/";
        const std::string connectxStrapVal =
            "/xyz/openbmc_project/network/connectx/strap_options/"
            "strap_options/";
        std::vector<uint8_t> resVal(strapFields.size(), 0);
        std::vector<uint8_t> resMask(strapFields.size(), 0);
        try
        {
        for (int i = 0; i < strapFields.size(); ++i)
        {
            auto val = readPropToInt(
                ctx, connectxSevice,
                (connectxStrapVal + strapFields[i]).c_str(), nicAttributeInfo);
            auto mask = readPropToInt(
                ctx, connectxSevice,
                (connectxStrapMask + strapFields[i]).c_str(), nicAttributeInfo);
            if (val < 0 || mask < 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    (std::string(__func__) + " invalid value").c_str());
                return ipmi::responseResponseError();
            }
            resVal[i] = val;
            resMask[i] = mask;
        }
        }
        catch (const std::exception& e)
        {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string(__func__) + " Failed").c_str());
        return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess(0, resVal, resMask);
    }
    ipmi::RspType<uint8_t> ipmicmdPowerCapEnabledGet(ipmi::Context::ptr ctx)
    {
        try
        {
            auto method = ctx->bus->new_method_call(powerCapacitySrvice,
                                                    powerCapacityObj,
                                                    dbusPropertyInterface,
                                                    "Get");
            method.append(powerCapacityModeInterface, "PowerMode");
            auto reply = ctx->bus->call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("ipmicmdPowerCapEnabledGet: Get Dbus error");
                return ipmi::responseResponseError();
            }

            std::variant<std::string> variantValue;
            reply.read(variantValue);

            auto strValue = std::get<std::string>(variantValue);
            if (strValue ==
                "xyz.openbmc_project.Control.Power.Mode.PowerMode.Static")
            {
                return ipmi::responseSuccess(0x00);
            }
            return ipmi::responseSuccess(0x01);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdPowerCapEnabledGet error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
    }

    ipmi::RspType<uint8_t> ipmicmdPowerCapEnabledSet(ipmi::Context::ptr ctx, uint8_t parameter)
    {
        if (ctx->channel != localChannel){
            log<level::ERR>("Running the command is allowed only from BMC");
            return ipmi::response(ipmi::ccResponseError);
        }
        std::string strValue;
        if (parameter == 1)
        {
            strValue = "xyz.openbmc_project.Control.Power.Mode.PowerMode.PowerSaving";
        }
        else
        {
            strValue = "xyz.openbmc_project.Control.Power.Mode.PowerMode.Static";
        }

        try
        {
            std::variant<std::string> variantValue(strValue);
            auto method = ctx->bus->new_method_call(powerCapacitySrvice,
                                                    powerCapacityObj,
                                                   dbusPropertyInterface,
                                                  "Set");
            method.append(powerCapacityModeInterface, "PowerMode", variantValue);
            auto reply = ctx->bus->call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("ipmicmdPowerCapEnabledSet: Get Dbus error");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdPowerCapEnabledSet error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
    }

/**
 * @brief Retrieve a generic power capacity property using D-Bus.
 *
 * This function communicates with the D-Bus system to retrieve a specific
 * power capacity property identified by the provided 'property' parameter.
 *
 * @param ctx         A pointer to the IPMI context, which includes information
 *                   about the D-Bus connection and other context-related data.
 * @param property    The name of the property to retrieve.
 *
 * @return An instance of ipmi::RspType<uint32_t> representing the result of the
 *         operation. If the property is successfully retrieved, it contains
 *         the property value. If an error occurs during the process, an error
 *         response is returned.
 *
 * @remarks This function constructs a D-Bus method call to request the specified
 *          power capacity property and handles potential D-Bus errors. If the
 *          property retrieval is successful, it returns the property value as
 *          an unsigned 32-bit integer wrapped in an ipmi::RspType. In case of
 *          any exceptions or D-Bus errors, it logs the error and returns an
 *          error response.
 */

static ipmi::RspType<uint32_t> ipmicmdPowerCapGenericGet(
                                            ipmi::Context::ptr ctx,
                                            const char* property,
                                            const char* object,
                                            const char* service,
                                            const char* interface)
    {
        try
        {
            auto method = ctx->bus->new_method_call(service,
                                                    object,
                                                    dbusPropertyInterface,
                                                    "Get");
            method.append(interface,
                          property);
            auto reply = ctx->bus->call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("ipmicmdPowerCapGenericGet: Get Dbus error");
                return ipmi::responseResponseError();
            }
            std::variant<uint32_t> variantValue;
            reply.read(variantValue);
            auto retValue = std::get<uint32_t>(variantValue);
            return ipmi::responseSuccess(retValue);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdPowerCapGenericGet error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
    }

static ipmi::RspType<> ipmicmdPowerCapGenericSet(
                                                ipmi::Context::ptr ctx,
                                                const char* property,
                                                uint8_t parameter,
                                                const char* object,
                                                const char* service,
                                                const char* interface)
    {
        try
        {
            auto method = ctx->bus->new_method_call(service,
                                                    object,
                                                    dbusPropertyInterface,
                                                    "Set");
            std::variant<uint32_t> variantValue = parameter;

            method.append(interface,
                          property, variantValue);
            auto reply = ctx->bus->call(method);
            if (reply.is_method_error())
            {
                log<level::ERR>("ipmicmdPowerCapGenericSet: Get Dbus error");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("ipmicmdPowerCapGenericSet error",
                            entry("ERROR=%s", e.what()));
            return ipmi::response(ipmi::ccResponseError);
        }
    }

    ipmi::RspType<> ipmicmdPowerCapMaxSet(ipmi::Context::ptr ctx,
                                        uint8_t parameter)
    {
        return ipmicmdPowerCapGenericSet(ctx,
                                        "MaxPowerCapValue",
                                        parameter,
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);
    }
    ipmi::RspType<uint32_t> ipmicmdPowerCapMaxGet(ipmi::Context::ptr ctx)
    {
        return ipmicmdPowerCapGenericGet(ctx,
                                        "MaxPowerCapValue",
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);
    }


    ipmi::RspType<> ipmicmdPowerCapMinSet(ipmi::Context::ptr ctx,
                                                                uint8_t parameter)
    {
        return ipmicmdPowerCapGenericSet(ctx,
                                        "MinPowerCapValue",
                                        parameter,
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);
    }

     ipmi::RspType<uint32_t> ipmicmdPowerCapMinGet(ipmi::Context::ptr ctx)
    {
        return ipmicmdPowerCapGenericGet(ctx,
                                        "MinPowerCapValue",
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);
    }

    ipmi::RspType<> ipmicmdPowerCapAllocatedWattsSet(ipmi::Context::ptr ctx,
                                                               uint8_t parameter)
    {
        return ipmicmdPowerCapGenericSet(ctx,
                                        "AllocatedWatts",
                                        parameter,
                                        powerSubsysObj,
                                        powerSubsysSrvice,
                                        powerSubsysInterface);
    }

    ipmi::RspType<uint32_t> ipmicmdPowerCapAllocatedWattsGet(ipmi::Context::ptr ctx)
    {
        return ipmicmdPowerCapGenericGet(ctx,
                                        "AllocatedWatts",
                                        powerSubsysObj,
                                        powerSubsysSrvice,
                                        powerSubsysInterface);
    }

    static ipmi::RspType<> ipmicmdPowerPowerCapSet(ipmi::Context::ptr ctx,
                                                   uint8_t parameter)
    {
        if (parameter > 100)
        {
            log<level::ERR>("ipmicmdPowerPowerCapSet: Invalid input,"
                            "valid range [0,100]");
            return ipmi::responseResponseError();
        }
        return ipmicmdPowerCapGenericSet(ctx,
                                        "PowerCapPercentage",
                                        parameter,
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);
    }

    static ipmi::RspType<uint8_t> ipmicmdPowerPowerCapGet(ipmi::Context::ptr ctx)
    {
        ipmi::RspType<uint32_t> capWattRet =
                                        ipmicmdPowerCapGenericGet(ctx,
                                        "PowerCapPercentage",
                                        powerCapacityObj,
                                        powerCapacitySrvice,
                                        powerCapacityInterface);

        if (std::get<0>(capWattRet) == ipmi::ccSuccess)
        {
            uint32_t value = std::get<0>(std::get<1>(capWattRet).value());
            return ipmi::responseSuccess(static_cast<uint8_t>(value));
        }
        return ipmi::responseResponseError();
    }

 } // namespace ipmi


void registerNvOemPlatformFunctions()
{
   
    //Support Launchpad
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSupportLaunchpad));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSupportLaunchpad,
                          ipmi::Privilege::Admin, ipmi::ipmiSupportLaunchpad);
    
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmd3PortEthSwitchStatus));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmd3PortEthSwitchStatus,
                          ipmi::Privilege::Admin, ipmi::ipmi3PortEthSwitchStatus);

     //Enter Live Fish mode  
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdEnterLiveFish));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdEnterLiveFish,
                          ipmi::Privilege::Admin, ipmi::ipmicmdEnterLiveFish); 

    //Exit Live Fish mode 
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdExitLiveFish));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdExitLiveFish,
                          ipmi::Privilege::Admin, ipmi::ipmicmdExitLiveFish);
    //Force Soc HArd Reset
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdForceSocHardRst));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdForceSocHardRst,
                          ipmi::Privilege::Admin, ipmi::ipmicmdForceSocHardRst); 
    
    // <BF2 and BF3 Reset Control>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdBFResetControl));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdBFResetControl,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiBFResetControl);
    
    // <Get FW Bootup slot>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetFwBootupSlot,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetFwBootupSlotBF);

    // <Execute SMBPBI passthrough command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSMBPBIPassthrough,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSMBPBIPassthroughCmdBF);

    // <Execute SMBPBI passthrough command for extended data>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSMBPBIPassthroughExtended,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSMBPBIPassthroughExtendedCmBF);

    // <Set fan control mode>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdSetFanMode,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetFanControlBF);

    // <Set All Fan Zones PWM Duty>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdAllFanZonesPWMDuty,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetAllFanZonesPWMDutyBF);

    // <Set Fan Zone PWM Duty>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::app::cmdSetFanZonePWMDuty,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSetFanZonePWMDutyBF);

    // <Get BIOS POST Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdGetBiosPostStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPostStatusBF);

    // <Get BIOS POST Code>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdGetBiosPostCode,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPostCodeBF);

    // <Soft Reboot>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSoftPowerCycle,
                          ipmi::Privilege::Admin, ipmi::ipmiOemSoftRebootBF);

    // <Get device firmware version>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetDeviceFirmwareVersion,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscFirmwareVersionBF);

    // <Get WP status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetWpStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscGetWPBF);

    // <Set WP status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetWpStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemMiscSetWPBF);

    // <Enable/Disable sensor scanning>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSensorScanEnable,
                          ipmi::Privilege::Admin, ipmi::ipmiSensorScanEnableDisableBF);

    // <Get SSD LED Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetSSDLed,
                          ipmi::Privilege::Admin, ipmi::ipmiOemGetSSDLedBF);

    // <Set SSD LED Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetSSDLed,
                          ipmi::Privilege::Admin, ipmi::ipmiOemSetSSDLedBF);

    // <Get LED Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetLedStatus,
                          ipmi::Privilege::Admin, ipmi::ipmiOemGetLedStatusBF);

    // <Get PSU Power>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetPsuPower,
                          ipmi::Privilege::Admin, ipmi::ipmiOemPsuPowerBF);

    // <Bios set version>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemPost,
                          ipmi::nvidia::app::cmdSetBiosVersion,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetVersionBF);

    // <Bios get bootup image>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosBootupImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetBootImageBF);

    // <Bios get next bootup image>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosNextImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetNextBootImageBF);

    // <Bios set next bootup image>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosNextImage,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetNextBootImageBF);

    // <Get bios version>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosVerions,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetVerionBF);

    // <Get bios config>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosConfig,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosGetConfigBF);

    // <Set bios config>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosConfig,
                          ipmi::Privilege::Admin, ipmi::ipmiBiosSetConfigBF);

    // <Get USB Description>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetUsbDescription,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbDescriptionBF);

    // <Get Virtual USB Serial Number>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetUsbSerialNum,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbSerialNumBF);

    // <Get IPMI Channel Number of Redfish HostInterface>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetipmiChannelRfHi,
                          ipmi::Privilege::Admin, ipmi::ipmiGetipmiChannelRfHiBF);

    // <Get Manager Certificate Fingerprint>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetManagerCertFingerPrint,
                               ipmi::Privilege::Admin,
                               ipmi::ipmiGetManagerCertFingerPrintBF);

    // <Get Maxp/MaxQ Configuration>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetMaxPMaxQConfiguration,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemGetMaxPMaxQConfigurationBF);

    // <Set Maxp/MaxQ Configuration>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetMaxPMaxQConfiguration,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemSetMaxPMaxQConfigurationBF);
   
    // <sync DPU versions>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdNotifyHostBoot,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemNotifyDpuBoot);
    
    // < Tor Switch Mode Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdTorSwitchGetMode,
                          ipmi::Privilege::Admin, ipmi::ipmicmdTorSwitchGetMode);

    // < Tor Switch Mode Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdTorSwitchSetMode,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdTorSwitchSetMode);

    // < Start DPU Network-Based Reprovisioning >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNetworkReprovisioning,
                          ipmi::Privilege::sysIface, ipmi::ipmiNetworkReprovisioning);

    // <Get Bootstrap Account Credentials>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetBootStrapAccount));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetBootStrapAccount,
                               ipmi::Privilege::sysIface,
                               ipmi::ipmiGetBootStrapAccountBF);
    // <Initialized Bootstrap Account Credentials>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::nvidia::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdCreateBootStrapAccount));

    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdCreateBootStrapAccount,
                               ipmi::Privilege::Admin,
                               ipmi::ipmiCreateBootStrapAccountBF);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetStrap,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicGetStrap);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetHostAccess,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicGetHostAccess);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetSmartnicMode,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicGetSmartnicMode);
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetHostAccess,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicSetHostAccess);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetSmartnicMode,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicSetSmartnicMode);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetOsState,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicGetOsState);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetExternalHostPrivileges,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicGetExternalHostPrivileges);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetExternalHostPrivilege,
                          ipmi::Privilege::Admin, ipmi::ipmicmdNicSetExternalHostPrivilege);

    // < Power Cap Enabled Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapEnabledGet);

    // < Power Cap Enabled Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapEnabledSet);

    // < Power Cap Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapMaxGet);

    // < Power Cap Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapMaxSet);
    // < Power Allocation Percentage Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerPowerCapGet);
    // < Power Allocation Percentage Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerPowerCapSet);

    // < Power Cap Min Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapMinSet);
    // < Power Cap Min Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapMinGet);

    // < Power Cap Allocated Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapAllocatedWattsGet);

    // < Power Cap Allocated Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapAllocatedWattsSet);

    return;
}
