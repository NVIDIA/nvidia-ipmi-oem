/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#pragma once

namespace ipmi
{
namespace nvidia
{
constexpr auto netFnOemGlobal = 0x32;
constexpr auto netFnOemNV = 0x3C;
constexpr auto netFnOemFan = 0x3C;

namespace app
{
constexpr auto cmdSystemFactoryReset = 0x66;
constexpr auto cmdSetVendorFieldModeConfig = 0x67;
constexpr auto cmdGetVendorFieldModeConfig = 0x68;
constexpr auto cmdGetRshimState = 0x69;
constexpr auto cmdSetRshimState = 0x6A;
constexpr auto cmdPSUInventoryInfo = 0x0E;
constexpr auto cmdGetSELPolicy = 0x7E;
constexpr auto cmdSetSELPolicy = 0x7F;
constexpr auto cmdBF2ResetControl = 0xA1;
constexpr auto cmdGetNTPConfig = 0xA7;
constexpr auto cmdSetNTPConfig = 0xA8;
constexpr auto cmdGetDNSConfig = 0x6B;
constexpr auto cmdSetDNSConfig = 0x6C;
constexpr auto cmdAllFanZonesPWMDuty = 0x74;
constexpr auto cmdSetFanZonePWMDuty = 0x75;

} // namespace app

namespace misc
{
constexpr auto cmdGetOEMVersion = 0x01;
constexpr auto cmdGetFwBootupSlot = 0x03;
constexpr auto cmdGetBMCBootComplete = 0x05;
constexpr auto cmdSMBPBIPassthrough = 0x09;
constexpr auto cmdSMBPBIPassthroughExtended = 0x0A;
constexpr auto cmdGetPSUInventory = 0x0E;

} // namespace misc

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi

