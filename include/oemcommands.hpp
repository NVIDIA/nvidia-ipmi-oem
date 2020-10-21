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

} // namespace app

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi

