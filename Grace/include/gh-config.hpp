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
#pragma once

#include <unistd.h>
#include <string>

namespace ipmi
{
namespace nvidia
{

constexpr auto fanServiceName               = "phosphor-pid-control";
constexpr auto fanNoServiceSpeed            = 100;
constexpr auto fanZones                     = 3;
constexpr auto fanZoneCtrlName0             = "";
constexpr auto fanZoneCtrlName1             = "max31790@20";
constexpr auto fanZoneCtrlName2             = "max31790@2c";

constexpr auto sensorScanSerivcesList       = "xyz.openbmc_project.exitairsensor "
                                              "xyz.openbmc_project.externalsensor "
                                              "xyz.openbmc_project.hwmontempsensor "
                                              "xyz.openbmc_project.mcutempsensor "
                                              "xyz.openbmc_project.psusensor "
                                              "nvidia-gpu-manager "
                                              "xyz.openbmc_project.fansensor";

constexpr auto fpgaMidSSDLedReadyMove   = 0x0e;
constexpr auto fpgaMidSSDLedActivity    = 0x0c;
constexpr auto fpgaMidSSDLedFaultBase   = 0x08;
constexpr auto fpgaMidSSDLedFaultWidth  = 3;
constexpr auto fpgaMidSetLedFaultMaxPattern = 4;
constexpr auto fpgaMidSetLedOtherMaxPattern = 1;
constexpr auto fpgaMidI2cBus            = 2;
constexpr auto fpgaI2cAddress           = 0x3c;

constexpr auto powerLedName                 = "power_led";
constexpr auto faultLedName                 = "fault_led";
constexpr auto mbLedName                    = "motherboard_debug_led";  




}
}