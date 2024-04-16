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




#pragma once

#include <unistd.h>
#include <string>
#include <vector>

#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

// system manager dbus object for Start/Stop system unit
static constexpr auto systemBusName = "org.freedesktop.systemd1";
static constexpr auto systemPath = "/org/freedesktop/systemd1";
static constexpr auto systemIntf = "org.freedesktop.systemd1.Manager";

namespace ipmi
{
namespace nvidia
{

constexpr auto fanServiceName               = "phosphor-pid-control";
constexpr auto fanNoServiceSpeed            = 100;
constexpr auto fanZones                     = 3;
constexpr auto fanZoneCtrlName0             = "";
#ifdef CUSTOM_PWM_FAN
constexpr auto pwm                          = int(CONFIG_PWM);
constexpr auto fanZoneCtrlName1             = STR(CONFIG_FAN_ZONE_CTRL_NAME1);
constexpr auto fanZoneCtrlName2             = STR(CONFIG_FAN_ZONE_CTRL_NAME2);
#else
constexpr auto pwm                          = 4;
constexpr auto fanZoneCtrlName1             = "max31790_1";
constexpr auto fanZoneCtrlName2             = "max31790_2";
#endif

std::vector<std::string> sensorMonitorServiceList = {
   "nvidia-gpu-manager.service",
   "xyz.openbmc_project.exitairsensor.service",
   "xyz.openbmc_project.externalsensor.service",
   "xyz.openbmc_project.hwmontempsensor.service",
   "xyz.openbmc_project.mcutempsensor.service",
   "xyz.openbmc_project.psusensor.service",
   "xyz.openbmc_project.fansensor.service",
   "xyz.openbmc_project.nvmesensor.service"
};

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

constexpr auto GWpGpioId                    = 70;
constexpr auto GWpGpioChip                  = "gpiochip816";



}
}
