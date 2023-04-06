/**
 * Copyright © 2022-2023 NVIDIA Corporation
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

#include <array>
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
constexpr auto cmdGetRedfishServiceUuid = 0x34;
constexpr auto cmdGetRedfishServicePort = 0x35;
constexpr auto cmdSetBiosPassword = 0x36;
constexpr auto cmdGetBiosPassword = 0x37;
constexpr auto cmdGetManagerCertFingerPrint = 0x01;
constexpr auto cmdGetBootStrapAcc = 0x02;

// BiosPassword
constexpr char biosPasswordFilePath[] =
    "/var/lib/bios-settings-manager/seedData";
constexpr int biosPasswordIter = 1000;
constexpr uint8_t biosPasswordSaltSize = 32;
constexpr uint8_t biosPasswordMaxHashSize = 64;
constexpr uint8_t biosPasswordSelectorAdmin = 0x01;
constexpr uint8_t biosPasswordTypeNoChange = 0x00;
constexpr uint8_t biosPasswordTypeNoPassowrd = 0x01;
constexpr uint8_t biosPasswordTypePbkdf2Sha256 = 0x02;
constexpr uint8_t biosPasswordTypePbkdf2Sha384 = 0x03;

constexpr auto cmdGetWpStatus = 0x8A;
constexpr auto cmdSetWpStatus = 0x8B;
constexpr auto getWPType = 0x00;

} // namespace misc
namespace chassis
{
constexpr auto cmdStandByPower = 0x12;
} // namespace chassis
} // namespace nvidia
} // namespace ipmi
