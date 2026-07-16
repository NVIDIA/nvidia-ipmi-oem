/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION &
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

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/property.hpp>

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>

namespace ipmi
{

namespace
{

using namespace sdbusplus::bus::match::rules;

static constexpr const char* metricsService = "xyz.openbmc_project.Settings";
static constexpr const char* metricsObjpath =
    "/xyz/openbmc_project/logging/bmc_cmd_metrics";
static constexpr const char* metricsIntf = "xyz.openbmc_project.Object.Enable";
static constexpr const char* metricsProperty = "Enabled";

template <typename T>
std::string toHexString(const T& data)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');

    auto it = data.begin();
    if (it != data.end())
    {
        stream << std::setw(2) << static_cast<int>(*it);
        for (++it; it != data.end(); ++it)
        {
            stream << ' ' << std::setw(2) << static_cast<int>(*it);
        }
    }
    return stream.str();
}

inline bool& getIpmiMetricsEnabled()
{
    static bool enabled = true;
    return enabled;
}

inline void handleInitProperty(const boost::system::error_code& ec,
                               bool enabled)
{
    if (ec)
    {
        lg2::error(
            "Failed to get IPMI Metrics setting, using default=enabled: {ERROR}",
            "ERROR", ec.message());
        return;
    }
    getIpmiMetricsEnabled() = enabled;
}

inline void onPropertyChanged(sdbusplus::message_t& msg)
{
    std::string iface;
    std::map<std::string, std::variant<bool>> props;

    try
    {
        msg.read(iface, props);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error reading IPMI Metrics property change: {ERROR}",
                   "ERROR", e.what());
        return;
    }

    auto it = props.find(metricsProperty);
    if (it != props.end())
    {
        const bool* enabled = std::get_if<bool>(&it->second);
        if (enabled)
        {
            getIpmiMetricsEnabled() = *enabled;
            lg2::debug("IPMI Metrics: {STATE}", "STATE",
                       *enabled ? "enabled" : "disabled");
        }
    }
}

inline void onServiceStarted(sdbusplus::message_t& msg)
{
    std::string name;
    std::string oldOwner;
    std::string newOwner;

    try
    {
        msg.read(name, oldOwner, newOwner);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error reading Settings service state change: {ERROR}",
                   "ERROR", e.what());
        return;
    }

    if (!newOwner.empty())
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
        sdbusplus::asio::getProperty<bool>(*bus, metricsService, metricsObjpath,
                                           metricsIntf, metricsProperty,
                                           handleInitProperty);
    }
}

inline void registerIpmiMetricsSignal()
{
    lg2::info("Register IPMI Metrics PropertiesChanged Signal");

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    // Monitor property changes
    static std::unique_ptr<sdbusplus::bus::match_t> metricsMatchPtr =
        std::make_unique<sdbusplus::bus::match_t>(
            *bus, propertiesChanged(metricsObjpath, metricsIntf),
            onPropertyChanged);

    // Monitor service start/restart
    static std::unique_ptr<sdbusplus::bus::match_t> serviceMatchPtr =
        std::make_unique<sdbusplus::bus::match_t>(
            *bus, nameOwnerChanged(metricsService), onServiceStarted);

    // Get initial value after match is set up
    sdbusplus::asio::getProperty<bool>(*bus, metricsService, metricsObjpath,
                                       metricsIntf, metricsProperty,
                                       handleInitProperty);
}

/**
 * @brief NVIDIA IPMI Metrics Logging
 *
 * This logging module records all IPMI commands for audit and debugging
 * purposes. It uses the IPMI filter mechanism but only logs, never blocks
 * commands. It can be enabled/disabled at runtime via D-Bus property.
 */
class NvidiaMetricsLogging
{
  public:
    NvidiaMetricsLogging()
    {
        lg2::info("Loading NVIDIA IPMI Metrics Logging");

        ipmi::registerFilter(ipmi::prioOemBase,
                             [this](ipmi::message::Request::ptr request) {
            return logIpmiRequest(request);
        });

        // Wait until io->run is going to initialize D-Bus metrics monitoring
        post_work([]() { registerIpmiMetricsSignal(); });
    }

  private:
    /**
     * @brief Get channel medium type string from channel number
     */
    std::string getMediumTypeStr(uint8_t channel)
    {
        ChannelInfo chInfo;
        if (getChannelInfo(channel, chInfo) != ccSuccess)
        {
            return "Unknown";
        }

        switch (static_cast<EChannelMediumType>(chInfo.mediumType))
        {
            case EChannelMediumType::reserved:
                return "Reserved";
            case EChannelMediumType::ipmb:
                return "IPMB";
            case EChannelMediumType::icmbV10:
                return "ICMB-v1.0";
            case EChannelMediumType::icmbV09:
                return "ICMB-v0.9";
            case EChannelMediumType::lan8032:
                return "LAN";
            case EChannelMediumType::serial:
                return "Serial";
            case EChannelMediumType::otherLan:
                return "Other-LAN";
            case EChannelMediumType::pciSmbus:
                return "PCI-SMBus";
            case EChannelMediumType::smbusV11:
                return "SMBus-v1.1";
            case EChannelMediumType::smbusV20:
                return "SMBus-v2.0";
            case EChannelMediumType::usbV1x:
                return "USB-v1.x";
            case EChannelMediumType::usbV2x:
                return "USB-v2.x";
            case EChannelMediumType::systemInterface:
                return "SysIntf";
            case EChannelMediumType::oem:
                return "OEM";
            case EChannelMediumType::unknown:
                return "Unknown";
            default:
                return "Other";
        }
    }

    /**
     * @brief Check whether an IPMI command's request data contains a secret
     * @param netFn - IPMI Network Function of the command
     * @param cmd   - IPMI command code
     * @return true if the request data must be redacted from the log
     */
    static bool isSecretBearingCommand(uint8_t netFn, uint8_t cmd)
    {
        return netFn == ipmi::netFnApp &&
               cmd == ipmi::app::cmdSetUserPasswordCommand;
    }

    /**
     * @brief Log IPMI request for metrics collection
     * @param request - IPMI request object containing command details
     * @return Always returns ccSuccess (never blocks requests)
     */
    ipmi::Cc logIpmiRequest(ipmi::message::Request::ptr request)
    {
        try
        {
            if (!getIpmiMetricsEnabled())
            {
                return ipmi::ccSuccess;
            }

            std::string medium = getMediumTypeStr(request->ctx->channel);
            bool isSecret = isSecretBearingCommand(request->ctx->netFn,
                                                   request->ctx->cmd);
            std::string reqDataStr = isSecret ? "redacted"
                                     : request->payload.raw.empty()
                                         ? "empty"
                                         : toHexString(request->payload.raw);

            lg2::info(
                "IPMI Metrics: Medium={MEDIUM} NetFn={NETFN} LUN={LUN} Cmd={CMD} "
                "Chan={CHAN} ReqData=[{DATA}]",
                "MEDIUM", medium, "NETFN", lg2::hex, request->ctx->netFn, "LUN",
                lg2::hex, request->ctx->lun, "CMD", lg2::hex, request->ctx->cmd,
                "CHAN", request->ctx->channel, "DATA", reqDataStr);
        }
        catch (const std::exception& e)
        {
            lg2::error("IPMI Metrics logging failed: {ERROR}", "ERROR",
                       e.what());
        }

        return ipmi::ccSuccess;
    }
};

// Instantiate the logging module when this shared object is loaded
NvidiaMetricsLogging nvidiaMetricsLogging;

} // namespace
} // namespace ipmi
