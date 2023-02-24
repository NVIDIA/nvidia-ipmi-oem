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

#include <cstdint>

namespace ipmi
{
namespace nvidia
{
constexpr auto netFnOemNV = 0x3C;
constexpr auto netFnOemPost = 0x30;
constexpr auto netFnOemGlobal = 0x32;
constexpr auto netGroupExt = 0x52;

namespace app
{
constexpr auto cmdSetFanMode = 0x73;
constexpr auto cmdAllFanZonesPWMDuty = 0x74;
constexpr auto cmdSetFanZonePWMDuty = 0x75;
constexpr auto cmdI2CMasterReadWrite = 0x81;
constexpr auto cmdGetSELPolicy = 0x7E;
constexpr auto cmdSetSELPolicy = 0x7F;
} // namespace app

namespace misc
{
constexpr auto cmdGetOEMVersion = 0x01;
constexpr auto cmdSoftPowerCycle = 0x04;
constexpr auto cmdGetBMCBootComplete = 0x05;
constexpr auto cmdSMBPBIPassthrough = 0x09;
constexpr auto cmdSMBPBIPassthroughExtended = 0x0A;
constexpr auto cmdSensorScanEnable = 0x85;
constexpr auto cmdSetSSDLed = 0x63;
constexpr auto cmdGetSSDLed = 0x64;
constexpr auto cmdGetLedStatus = 0x65;

constexpr auto getSSDLedTypeReadyMove = 0x30;
constexpr auto getSSDLedTypeActivity = 0x31;
constexpr auto getSSDLedTypeFault = 0x32;

constexpr auto getSSDLedNLed = 8;

constexpr auto getLedStatusPowerLed = 0x00;
constexpr auto getLedStatusFaultLed = 0x01;
constexpr auto getLedStatusMotherBoardLed = 0x10;

constexpr auto cmdGetUsbDescription = 0x30;
constexpr auto cmdGetUsbSerialNum = 0x31;
constexpr auto cmdGetRedfishHostName = 0x32;
constexpr auto cmdGetipmiChannelRfHi = 0x33;
constexpr auto cmdGetBootStrapAcc = 0x02;
constexpr auto cmdGetRedfishServiceUuid = 0x34;
constexpr auto cmdGetRedfishServicePort = 0x35;
constexpr auto cmdGetManagerCertFingerPrint = 0x01;

} // namespace misc
namespace chassis
{} // namespace chassis
} // namespace nvidia
} // namespace ipmi
