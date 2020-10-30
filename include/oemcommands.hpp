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

namespace app
{
constexpr auto cmdSystemFactoryReset = 0x66;
constexpr auto cmdPSUInventoryInfo = 0x0E;
constexpr auto cmdGetSELPolicy = 0x7E;
constexpr auto cmdSetSELPolicy = 0x7F;
constexpr auto cmdBF2ResetControl = 0xA1;
constexpr auto cmdGetNTPConfig = 0xA7;
constexpr auto cmdSetNTPConfig = 0xA8;
constexpr auto cmdGetDNSConfig = 0x6B;
constexpr auto cmdSetDNSConfig = 0x6C;

} // namespace app

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi

