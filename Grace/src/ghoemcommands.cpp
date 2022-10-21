/**
 * Copyright © 2022 NVIDIA Corporation
 * 
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

 */
#include "ghoemcommands.hpp"
#include "gh-config.hpp"

#include <bits/stdc++.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
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

// IPMI OEM Major and Minor version
static constexpr uint8_t OEM_MAJOR_VER = 0x01;
static constexpr uint8_t OEM_MINOR_VER = 0x00;

// GPU smbpbi object in dbus
static constexpr const char* gpuSMBPBIIntf = "xyz.openbmc_project.GpuMgr.Server";
static constexpr const char* gpuSMBPBIPath = "/xyz/openbmc_project/GpuMgr";

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
ipmi::RspType<
    uint8_t,  // Major Version
    uint8_t  // Minor Version
    > ipmiGetOEMVersion()
{
    return ipmi::responseSuccess(OEM_MAJOR_VER, OEM_MINOR_VER);
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


}



void registerNvOemFunctions()
{

// <Get IPMI OEM Version>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdGetOEMVersion));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetOEMVersion,
                          ipmi::Privilege::User,
                          ipmi::ipmiGetOEMVersion);

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

// <Enable/Disable sensor scanning>
    log<level::NOTICE>(
	"Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
	 entry("Cmd:[%02Xh]", ipmi::nvidia::misc::cmdSensorScanEnable));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
		          ipmi::nvidia::misc::cmdSensorScanEnable,
			  ipmi::Privilege::Admin, ipmi::ipmiSensorScanEnableDisable);


}