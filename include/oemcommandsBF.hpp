#pragma once

#include <cstdint>

namespace ipmi
{
namespace nvidia
{


namespace app
{

constexpr auto cmdBFResetControl = 0xA1;
constexpr auto cmdGetFirmwareVersionCEC = 0x90;
constexpr auto cmdGetFirmwareVersionBMC = 0x91;
constexpr auto cmdEnterLiveFish = 0x92;
constexpr auto cmdExitLiveFish = 0x93;
constexpr auto cmdSupportLaunchpad = 0x94;
constexpr auto cmd3PortEthSwitchStatus = 0x95;
} // namespace app

namespace misc
{

} // namespace misc

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi
