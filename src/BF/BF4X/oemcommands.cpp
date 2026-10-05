/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "oemcommands.hpp"

#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/exception.hpp>

#include <string>

using namespace phosphor::logging;

namespace ipmi
{

static constexpr const char* factoryResetPath =
    "/xyz/openbmc_project/software/bmc";
static constexpr const char* factoryResetIntf =
    "xyz.openbmc_project.Common.FactoryReset";
static constexpr const char* bmcStateService = "xyz.openbmc_project.State.BMC";
static constexpr const char* bmcStatePath = "/xyz/openbmc_project/state/bmc0";
static constexpr const char* bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr const char* rebootTransition =
    "xyz.openbmc_project.State.BMC.Transition.Reboot";

/**
 * @brief IPMI OEM command: BMC Factory Reset (0x32 0x66)
 *
 * Same path as Redfish Manager.ResetToDefaults: FactoryReset.Reset on
 * /xyz/openbmc_project/software/bmc, then RequestedBMCTransition=Reboot.
 * The Reset method sets openbmconce and openbmclog.
 */
ipmi::RspType<> ipmiSystemFactoryResetBF4X(ipmi::Context::ptr ctx)
{
    std::string service;
    boost::system::error_code ec;

    try
    {
        ec = ipmi::getService(ctx, factoryResetIntf, factoryResetPath, service);
        if (ec)
        {
            log<level::ERR>("FactoryReset service lookup failed",
                            entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }

        ec = ipmi::callDbusMethod(ctx, service, factoryResetPath,
                                  factoryResetIntf, "Reset");
        if (ec)
        {
            log<level::ERR>("FactoryReset.Reset failed",
                            entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }

        log<level::INFO>("BMC factory reset scheduled, rebooting now");

        ec = ipmi::setDbusProperty(ctx, bmcStateService, bmcStatePath,
                                   bmcStateIntf, "RequestedBMCTransition",
                                   std::string{rebootTransition});
        if (ec)
        {
            log<level::ERR>("Failed to trigger BMC reboot via D-Bus",
                            entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("BMC factory reset exception",
                        entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

} // namespace ipmi

void registerBF4XOemFunctions() __attribute__((constructor(103)));

void registerBF4XOemFunctions()
{
    log<level::NOTICE>("Registering BF4X factory reset IPMI command");

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSystemFactoryReset,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSystemFactoryResetBF4X);
}
