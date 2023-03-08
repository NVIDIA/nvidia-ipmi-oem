#pragma once

#include <cstdint>

namespace ipmi
{
namespace nvidia
{
constexpr auto ethSwitchI2cBusBF2        = 0xe;
constexpr auto ethSwitchI2caddressBF2    = 0x5f;
constexpr auto cecI2cAddressBF2          = 0x55;
constexpr auto cecI2cBusBF2              = 0x7;

constexpr auto cecI2cAddressBF3          = 0x52;
constexpr auto cecI2cBusBF3              = 0xf;
constexpr auto ethSwitchI2cBusBF3        = 10;
constexpr auto ethSwitchI2caddressBF3    = 0x5f;
constexpr auto liveFishGpio              = 929;
constexpr auto socRstGpio                = 932;
constexpr auto preRstGpio                = 952;	


namespace app
{

constexpr auto cmdBFResetControl = 0xA1;

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
