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
constexpr auto gpioHigh                  = 1;
constexpr auto gpioLow                   = 0;
constexpr auto resetPause                = 2;
constexpr auto enumTorSwitchAllowAll     = 0x00;
constexpr auto enumTorSwitchAllowBMC     = 0x01;
constexpr auto enumTorSwitchAllowDPU     = 0x02;
constexpr auto enumTorSwitchDenyNone     = 0x1F;
constexpr auto enumTorSwitchDisabled     = 0x2F;

namespace app
{

constexpr auto cmdBFResetControl = 0xA1;

constexpr auto cmdEnterLiveFish                 = 0x92;
constexpr auto cmdExitLiveFish                  = 0x93;
constexpr auto cmdSupportLaunchpad              = 0x94;
constexpr auto cmd3PortEthSwitchStatus          = 0x95;
constexpr auto cmdForceSocHardRst               = 0x96;
constexpr auto cmdTorSwitchGetMode              = 0x97;
constexpr auto cmdTorSwitchSetMode              = 0x98;
constexpr auto cmdNetworkReprovisioning         = 0x99;
constexpr auto cmdNicGetExternalHostPrivileges  = 0x9A;
constexpr auto cmdNicSetExternalHostPrivilege   = 0x9B;
constexpr auto cmdNicGetSmartnicMode            = 0x9C;
constexpr auto cmdNicSetSmartnicMode            = 0x9D;
constexpr auto cmdNicGetHostAccess              = 0x9E;
constexpr auto cmdNicSetHostAccess              = 0x9F;
constexpr auto cmdNicGetStrap                   = 0xA2;
constexpr auto cmdNicGetOsState                 = 0xA3;
constexpr auto cmdPowerCapEnabledGet            = 0xA4;
constexpr auto cmdPowerCapEnabledSet            = 0xA5;
constexpr auto cmdPowerCapCapacityWattsGet      = 0xA6;
constexpr auto cmdPowerCapCapacityWattsSet      = 0xA7;
constexpr auto cmdPowerAllocPercentageGet       = 0xA8;
constexpr auto cmdPowerAllocPercentageSet       = 0xA9;
constexpr auto CmdPowerCapMinCapacityWattsGet   = 0xAA;
constexpr auto CmdPowerCapMinCapacityWattsSet   = 0xAB;
constexpr auto CmdPowerCapRequestedWattsGet     = 0xAC;
constexpr auto CmdPowerCapRequestedWattsSet     = 0xAD;
constexpr auto CmdPowerCapAllocatedWattsGet     = 0xAE;
constexpr auto CmdPowerCapAllocatedWattsSet     = 0xAF;


} // namespace app

namespace misc
{
    constexpr auto cmdGetBootStrapAccount = 0x02;
    constexpr auto cmdCreateBootStrapAccount = 0xF2;
} // namespace misc

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi
