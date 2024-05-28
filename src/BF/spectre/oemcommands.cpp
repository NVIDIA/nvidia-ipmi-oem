/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "biosversionutils.hpp"
#include "dgx-a100-config.hpp"
#include "oemcommandsBF.hpp"

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

void registerNvOemPlatformFunctionsSpectre() __attribute__((constructor(103)));

using namespace phosphor::logging;

namespace ipmi
{
ipmi::RspType<uint8_t> ipmicmdRejectNoParamSpectre()
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectCtxNoParamSpectre(ipmi::Context::ptr ctx)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectOneParamSpectre(uint8_t p1)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectCtxOneParamSpectre(ipmi::Context::ptr ctx,
                                                       uint8_t p1)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectTwoParamSpectre(uint8_t p1, uint8_t p2)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectCtxTwoParamSpectre(ipmi::Context::ptr ctx,
                                                       uint8_t p1, uint8_t p2)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}

ipmi::RspType<uint8_t> ipmicmdRejectCtxThreeParamSpectre(ipmi::Context::ptr ctx,
                                                         uint8_t p1, uint8_t p2,
                                                         uint8_t p3)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Command is unsupported on Spectre");
    return ipmi::response(ipmi::ccInvalidCommand);
}
} /* namespace ipmi */

void registerNvOemPlatformFunctionsSpectre()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSupportLaunchpad,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectTwoParamSpectre);

    // < BF enter to live fish mode >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmd3PortEthSwitchStatus,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectOneParamSpectre);

    // < BF enter to live fish mode >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdEnterLiveFish,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectNoParamSpectre);

    // < BF exit from live fish mode >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdExitLiveFish,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectNoParamSpectre);

    // <BF Reset Control>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdBFResetControl,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // <sync DPU versions>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdNotifyHostBoot,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Tor Switch Mode Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdTorSwitchGetMode,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Tor Switch Mode Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdTorSwitchSetMode,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Start DPU Network-Based Reprovisioning >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNetworkReprovisioning,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxThreeParamSpectre);

    // <Get Bootstrap Account Credentials>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdGetBootStrapAccount,
                               ipmi::Privilege::sysIface,
                               ipmi::ipmicmdRejectCtxOneParamSpectre);

    // <Initialized Bootstrap Account Credentials>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::nvidia::netGroupExt,
                               ipmi::nvidia::misc::cmdCreateBootStrapAccount,
                               ipmi::Privilege::Admin,
                               ipmi::ipmicmdRejectCtxTwoParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetStrap,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetHostAccess,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetSmartnicMode,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetHostAccess,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetSmartnicMode,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetOsState,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicGetExternalHostPrivileges,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Nic command >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdNicSetExternalHostPrivilege,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxTwoParamSpectre);

    // < Power Cap Enabled Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledGet,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Power Cap Enabled Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapEnabledSet,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Power Cap Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxGet,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Power Cap Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMaxSet,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Power Allocation Percentage Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapGet,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Power Allocation Percentage Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerPowerCapSet,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Power Cap Min Capacity Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinSet,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // < Power Cap Min Capacity Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPowerCapMinGet,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Power Cap Allocated Watts Get >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsGet,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectCtxNoParamSpectre);

    // < Power Cap Allocated Watts Set >
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::CmdPowerCapAllocatedWattsSet,
                          ipmi::Privilege::sysIface,
                          ipmi::ipmicmdRejectCtxOneParamSpectre);

    // <Get RSHIM state>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdGetRshimState,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectNoParamSpectre);

    // <Start/Stop RSHIM service>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSetRshimState,
                          ipmi::Privilege::Admin,
                          ipmi::ipmicmdRejectOneParamSpectre);
}
