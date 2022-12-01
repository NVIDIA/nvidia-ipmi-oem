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
using namespace phosphor::logging;
using GetSubTreeType = std::vector<
    std::pair<std::string,
        std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using GetSubTreePathsType = std::vector<std::string>;
using BasicVariantType = std::variant<std::string>;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;




void registerNvOemPlatformFunctions() __attribute__((constructor(102)));





namespace ipmi
{
  

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


   

    ipmi::RspType<std::vector<uint8_t>, std::vector<uint8_t>>
        ipmiGetBootStrapAccountBF(ipmi::Context::ptr ctx,
                                uint8_t disableCredBootStrap)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ipmiGetBootStrapAccount command is unsupported in Bluefield 2/3");
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


} // namespace ipmi

void registerNvOemPlatformFunctions()
{
    
    
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


    // <Get Bootstrap Account Credentials>
 
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetBootStrapAcc,
                               ipmi::Privilege::sysIface,
                               ipmi::ipmiGetBootStrapAccountBF);


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
    
   
 
    
    
    return;


}
