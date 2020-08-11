/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#include "oem_global_handler.hpp"
#include "include/oem_commands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>

// Network object in dbus
const char* networkService = "xyz.openbmc_project.Network";
const char* networkObj = "/xyz/openbmc_project/network";
const char* networkResetIntf = "xyz.openbmc_project.Common.FactoryReset";

// Software BMC Updater object in dbus
const char* sftBMCService = "xyz.openbmc_project.Software.BMC.Updater";
const char* sftBMCObj = "/xyz/openbmc_project/software";
const char* sftBMCResetIntf = "xyz.openbmc_project.Common.FactoryReset";

void registerNvOemFunctions() __attribute__((constructor));

using namespace phosphor::logging;

namespace ipmi
{

ipmi::RspType<> ipmiSystemFactoryReset(boost::asio::yield_context yield)
{
    /*
     * BMC factory reset must be use to restore the BMC to its
     * original manufacturer settings.
     * IPMI performs below 2 steps:
     * 1. The network factory reset, it overwrites the configuration
     *    for all configured network interfaces to a DHCP setting.
     * 2. The BMC software updater factory reset, it clears any
     *    volumes and persistence files created by the BMC processes.
     *    This reset occurs only on the next BMC reboot.
     */

    auto sdbusp = getSdBus();
    boost::system::error_code ec;

    // Network factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            networkService,
            networkObj,
            networkResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on network reset");
            return ipmi::responseUnspecifiedError();
        }

    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    // BMC software updater factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            sftBMCService,
            sftBMCObj,
            sftBMCResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on BMC software reset");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}
} // namespace ipmi

void registerNvOemFunctions()
{
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSystemFactoryReset));

    // <BMC Factory Reset>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSystemFactoryReset,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSystemFactoryReset);
    return;
}
