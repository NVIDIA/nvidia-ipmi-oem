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
namespace nvidia
{
constexpr auto netFnOemNV = 0x3C;
constexpr auto cmdSbmrSendDescription = 0xD1;
} // namespace nvidia
} // namespace ipmi
constexpr auto sbmrBootProgressService = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrBootProgressObj = "/xyz/openbmc_project/state/boot/raw0";
constexpr auto sbmrBootProgressIntf = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto dbusPropertyInterface = "org.freedesktop.DBus.Properties";
constexpr auto loggingService = "xyz.openbmc_project.Logging";
constexpr auto loggingObject = "/xyz/openbmc_project/logging";
constexpr auto loggingInterface = "xyz.openbmc_project.Logging.Create";
constexpr auto sbmrBootProgressSize = 9;
constexpr auto maxDescriptionLength = 256;
constexpr auto bootProgressCode = 0x01;
constexpr auto bootErrorCode = 0x02;
constexpr auto bootDebugCode = 0x03;
constexpr auto bootErrorMinor = 0x40;
constexpr auto bootErrorMajor = 0x80;
constexpr auto bootErrorUnrecoverd = 0x90;
constexpr auto bootErrorUncontained = 0xa0;
