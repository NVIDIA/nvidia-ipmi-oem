/**
 * Copyright © 2020 NVIDIA Corporation
 *
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
const char* systemdServiceBf = "org.freedesktop.systemd1";
const char* systemdUnitIntfBf = "org.freedesktop.systemd1.Unit";
const char* rshimSystemdObjBf = "/org/freedesktop/systemd1/unit/rshim_2eservice";
const char* dbusPropertyInterface = "org.freedesktop.DBus.Properties";

const char* ctlBMCtorSwitchModeService = "xyz.openbmc_project.Settings";
const char* ctlBMCtorSwitchModeBMCObj = "/xyz/openbmc_project/control/torswitchportsmode";
const char* ctlBMCtorSwitchModeIntf = "xyz.openbmc_project.Control.TorSwitchPortsMode";
const char* ctlBMCtorSwitchMode = "TorSwitchPortsMode";
const char* torSwitchModeSystemdObj = "/org/freedesktop/systemd1/unit/torswitch_2dmode_2eservice";


void registerNvOemPlatformFunctions() __attribute__((constructor(102)));


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

    ipmi::RspType<> ipmiNetworkReprovisioning() {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        try
        {
            auto method = dbus->new_method_call("xyz.openbmc_project.Software.BMC.GoldenImageUpdateService",
                                                "/xyz/openbmc_project/host0/software/goldenimageupdater",
                                                "xyz.openbmc_project.Common.GoldenImageUpdater", 
                                                "StartGoldenImageReprovisioning");

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

    ipmi::RspType<uint8_t>
    ipmiBFResetControl(uint8_t resetOption)
    {
        int response;
        switch(resetOption)
        {
            case 0x02: // arm soft reset
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "arm_soft_reset");
                break;
            case 0x03: // tor eswitch reset
                response = executeCmd("/usr/sbin/mlnx_bf_reset_control", "do_tor_eswitch_reset");
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
                          ipmi::Privilege::Admin, ipmi::ipmicmdTorSwitchSetMode);

    // < Start DPU Network-Based Reprovisioning >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNetworkReprovisioning,
                          ipmi::Privilege::sysIface, ipmi::ipmiNetworkReprovisioning);

    return;
}
