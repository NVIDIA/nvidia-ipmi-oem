/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include <cstdint>

namespace ipmi
{
namespace nvidia
{
constexpr auto ethSwitchI2cBusBF2 = 0xe;
constexpr auto ethSwitchI2caddressBF2 = 0x5f;
constexpr auto cecI2cAddressBF2 = 0x55;
constexpr auto cecI2cBusBF2 = 0x7;

constexpr auto cecI2cAddressBF3 = 0x52;
constexpr auto cecI2cBusBF3 = 0xf;
constexpr auto ethSwitchI2cBusBF3 = 10;
constexpr auto ethSwitchI2caddressBF3 = 0x5f;
constexpr auto liveFishGpio = 929;
constexpr auto socRstGpio = 932;
constexpr auto preRstGpio = 952;
constexpr auto gpioHigh = 1;
constexpr auto gpioLow = 0;
constexpr auto resetPause = 2;
constexpr auto enumTorSwitchAllowAll = 0x00;
constexpr auto enumTorSwitchAllowBMC = 0x01;
constexpr auto enumTorSwitchAllowDPU = 0x02;
constexpr auto enumTorSwitchDenyNone = 0x1F;
constexpr auto enumTorSwitchDisabled = 0x2F;

namespace app
{

constexpr auto cmdBFResetControl = 0xA1;

constexpr auto cmdEnterLiveFish = 0x92;
constexpr auto cmdExitLiveFish = 0x93;
constexpr auto cmdSupportLaunchpad = 0x94;
constexpr auto cmd3PortEthSwitchStatus = 0x95;
constexpr auto cmdForceSocHardRst = 0x96;
constexpr auto cmdTorSwitchGetMode = 0x97;
constexpr auto cmdTorSwitchSetMode = 0x98;
constexpr auto cmdNetworkReprovisioning = 0x99;
constexpr auto cmdNicGetExternalHostPrivileges = 0x9A;
constexpr auto cmdNicSetExternalHostPrivilege = 0x9B;
constexpr auto cmdNicGetSmartnicMode = 0x9C;
constexpr auto cmdNicSetSmartnicMode = 0x9D;
constexpr auto cmdNicGetHostAccess = 0x9E;
constexpr auto cmdNicSetHostAccess = 0x9F;
constexpr auto cmdNicGetStrap = 0xA2;
constexpr auto cmdNicGetOsState = 0xA3;
constexpr auto cmdPowerCapEnabledGet = 0xC4;
constexpr auto cmdPowerCapEnabledSet = 0xC5;
constexpr auto cmdPowerCapMaxGet = 0xC6;
constexpr auto cmdPowerCapMaxSet = 0xC7;
constexpr auto cmdPowerPowerCapGet = 0xC8;
constexpr auto cmdPowerPowerCapSet = 0xC9;
constexpr auto cmdPowerCapMinGet = 0xCA;
constexpr auto cmdPowerCapMinSet = 0xCB;
constexpr auto CmdPowerCapAllocatedWattsGet = 0xCE;
constexpr auto CmdPowerCapAllocatedWattsSet = 0xCF;
constexpr auto CmdERoTReset = 0xD2;

} // namespace app

namespace misc
{
constexpr auto cmdGetBootStrapAccount = 0x02;
constexpr auto cmdCreateBootStrapAccount = 0xF2;
} // namespace misc

namespace chassis
{} // namespace chassis
} // namespace nvidia
} // namespace ipmi
