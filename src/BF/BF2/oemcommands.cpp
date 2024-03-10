/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#include "oemcommandsBF.hpp"
#include "oemcommands.hpp"
#include "biosversionutils.hpp"
#include "dgx-a100-config.hpp"

#include <bits/stdc++.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <security/pam_appl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/process/child.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <tuple>
#include <vector>




void registerNvOemPlatformFunctionsBF2() __attribute__((constructor(103)));


using namespace phosphor::logging;

using GetSubTreeType = std::vector<
    std::pair<std::string,
        std::vector<std::pair<std::string, std::vector<std::string>>>>>;
using GetSubTreePathsType = std::vector<std::string>;
using BasicVariantType = std::variant<std::string>;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;

namespace ipmi
{
    ipmi::RspType<uint8_t>ipmicmdEnterLiveFishBF2()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Enter LiveFish command is unsupported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t>ipmicmdExitLiveFishBF2()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Exit LiveFish command is unsupported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<>nicManagerBF2NA()
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Nic Manager not supported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmicmdPowerCapGet(ipmi::Context::ptr ctx)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Power Capping not supported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmicmdPowerCapSet(ipmi::Context::ptr ctx, uint8_t parameter)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Power Capping not supported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

    ipmi::RspType<uint8_t> ipmiCmdERoTReset(ipmi::Context::ptr ctx)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("ERoT reset is not supported in Bluefield 2");
        return ipmi::response(ipmi::ccResponseError);
    }

} // namespace ipmi

void registerNvOemPlatformFunctionsBF2()
{

    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdEnterLiveFish));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdEnterLiveFish,
                          ipmi::Privilege::Admin, ipmi::ipmicmdEnterLiveFishBF2); 

    //Exit Live Fish mode 

    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdExitLiveFish));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdExitLiveFish,
                          ipmi::Privilege::Admin, ipmi::ipmicmdExitLiveFishBF2);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetStrap,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetHostAccess,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetSmartnicMode,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetHostAccess,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetSmartnicMode,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetOsState,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetExternalHostPrivileges,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetExternalHostPrivilege,
                          ipmi::Privilege::Admin, ipmi::nicManagerBF2NA);

    // < Power Cap Enabled Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapGet);

    // < Power Cap Enabled Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapSet);

    // < Power Cap Max Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapGet);

    // < Power Cap Max Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapSet);
    // < Power Cap (Percentage) Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapGet);
    // < Power Cap (Percentage) Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapSet);

    // < Power Cap Min Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapSet);
    // < Power Cap Min Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapGet);

    // < Power Cap Allocated Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsGet,
                          ipmi::Privilege::Admin, ipmi::ipmicmdPowerCapGet);

    // < Power Cap Allocated Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsSet,
                          ipmi::Privilege::sysIface, ipmi::ipmicmdPowerCapSet);

    // <ERoT Reset>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdERoTReset,
                          ipmi::Privilege::Admin, ipmi::ipmiCmdERoTReset);

    return;


}
