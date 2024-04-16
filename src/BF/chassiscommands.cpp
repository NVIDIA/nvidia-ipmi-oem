/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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





#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <xyz/openbmc_project/State/Chassis/server.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>

// Phosphor Host State manager
namespace State = sdbusplus::xyz::openbmc_project::State::server;
using namespace phosphor::logging;
using sdbusplus::xyz::openbmc_project::State::server::convertForMessage;

// Various Chassis operations under a single command.
enum ipmi_chassis_control_cmds : uint8_t
{
    CMD_POWER_OFF = 0x00,
    CMD_POWER_ON = 0x01,
    CMD_POWER_CYCLE = 0x02,
    CMD_HARD_RESET = 0x03,
    CMD_PULSE_DIAGNOSTIC_INTR = 0x04,
    CMD_SOFT_OFF_VIA_OVER_TEMP = 0x05,
};

// OpenBMC Host State Manager dbus framework
constexpr auto hostStatePath = "/xyz/openbmc_project/state/host0";
constexpr auto hostStateIntf = "xyz.openbmc_project.State.Host";

//------------------------------------------
// Calls into Host State Manager Dbus object
//------------------------------------------
int initiateHostStateTransition(ipmi::Context::ptr& ctx,
                                State::Host::Transition transition)
{
    // Convert to string equivalent of the passed in transition enum.
    auto request = State::convertForMessage(transition);

    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, hostStateIntf, hostStatePath, service);

    if (!ec)
    {
        ec = ipmi::setDbusProperty(ctx, service, hostStatePath, hostStateIntf,
                                   "RequestedHostTransition", request);
    }
    if (ec)
    {
        phosphor::logging::log<level::ERR>("Failed to initiate transition",
                        entry("EXCEPTION=%s, REQUEST=%s", ec.message().c_str(),
                              request.c_str()));
        return -1;
    }
    phosphor::logging::log<level::ERR>(
        "Transition request initiated successfully",
        entry("USERID=%d, REQUEST=%s", ctx->userId, request.c_str()));
    return 0;
}

void registerChassisFunctions() __attribute__((constructor));

namespace ipmi
{

/** @brief impitool chassis power command. Only Reboot and ForceWarmReboot 
 *  are supported by BF2 in BF3 also Soft Off is supported.
 *
 *  @returns success or unspecified error.
 */
ipmi::RspType<> ipmiChassisPowerBF(ipmi::Context::ptr& ctx,
                                   uint8_t chassisControl)
{
    int rc = 0;

    switch (chassisControl)
    {
        case CMD_POWER_CYCLE:
            rc = initiateHostStateTransition(ctx, State::Host::Transition::Reboot);

            break;
        case CMD_HARD_RESET:
            rc = initiateHostStateTransition(ctx, State::Host::Transition::ForceWarmReboot);
            break;
#ifdef BF3_CHASSIS_COMMAND
        case CMD_SOFT_OFF_VIA_OVER_TEMP:
            rc = initiateHostStateTransition(ctx, State::Host::Transition::Off);
            break;
#endif
        default:
        {
	        phosphor::logging::log<level::ERR>("Unsupported command");
            return ipmi::response(ipmi::ccResponseError);
        }
    }

    return ((rc < 0) ? ipmi::responseUnspecifiedError()
                     : ipmi::responseSuccess());
}

/** @brief impitool chassis policy command is unsupported by BF.
 *
 *  @returns Error.
 */
ipmi::RspType<>
    ipmiChassisRestorePolicyBF(boost::asio::yield_context yield,
                                     uint3_t policy, uint5_t reserved)
{
    phosphor::logging::log<level::ERR>("Unsupported command");
    return ipmi::response(ipmi::ccResponseError);
}

} // namespace ipmi


void registerChassisFunctions()
{
    // <Chassis Control>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::netFnChassis),
        entry("Cmd:[%02Xh]", ipmi::chassis::cmdChassisControl));

    ipmi::registerHandler(ipmi::prioCustomBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdChassisControl,
                          ipmi::Privilege::Operator, ipmi::ipmiChassisPowerBF);

    // <Set Power Restore Policy>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::netFnChassis),
        entry("Cmd:[%02Xh]", ipmi::chassis::cmdSetPowerRestorePolicy));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetPowerRestorePolicy,
                          ipmi::Privilege::Operator, ipmi::ipmiChassisRestorePolicyBF);
}
