#pragma once

namespace ipmi
{
namespace sbmr
{
constexpr auto groupExtIpmi = 0xAE;
constexpr auto netFnOemSbmr = 0x2C;
} // namespace sbmr
namespace sbmrcmds
{
constexpr auto cmdSendBootProgressCode = 0x02;
constexpr auto cmdGetBootProgressCode = 0x03;
} // namespace sbmrcmds
} // namespace ipmi
constexpr auto sbmrBootProgressService = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrBootProgressObj = "/xyz/openbmc_project/state/boot/raw0";
constexpr auto sbmrBootProgressIntf = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto dbusPropertyInterface = "org.freedesktop.DBus.Properties";

constexpr auto sbmrBootProgressSize = 9;
