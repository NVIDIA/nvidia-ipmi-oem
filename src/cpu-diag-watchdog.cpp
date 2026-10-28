// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES

#include <boost/asio/steady_timer.hpp>
#include <cpu-diag-check.hpp>
#include <ipmid/api.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace ipmi::nvidia::diag
{

namespace
{

using namespace sdbusplus::bus::match::rules;

constexpr auto diagService = "xyz.openbmc_project.Settings";
constexpr auto diagObj = "/xyz/openbmc_project/Control/Diag";
constexpr auto diagIntf = "xyz.openbmc_project.Control.Diag";
constexpr auto hostIpmiService = "xyz.openbmc_project.Ipmi.Host";
// The old timer kept running across an ipmid restart but not a reboot,
// so a persisted DiagMode re-arms only while this tmpfs marker exists.
constexpr auto armedMarker = "/run/cpu-diag-watchdog.armed";
constexpr auto checkInterval = std::chrono::seconds(30);

class Watchdog
{
  public:
    explicit Watchdog(std::shared_ptr<sdbusplus::asio::connection> conn) :
        bus(std::move(conn)), timer(bus->get_io_context()),
        modeMatch(
            *bus, propertiesChanged(diagObj, diagIntf),
            [this](sdbusplus::message_t& msg) { onPropertiesChanged(msg); }),
        ownerMatch(*bus, nameOwnerChanged(diagService),
                   [this](sdbusplus::message_t& msg) { onOwnerChanged(msg); })
    {
        readMode();
    }

  private:
    void readMode()
    {
        sdbusplus::asio::getProperty<bool>(
            *bus, diagService, diagObj, diagIntf, "DiagMode",
            [this](const boost::system::error_code& ec, bool mode) {
            onMode(ec, mode);
        });
    }

    void onMode(const boost::system::error_code& ec, bool mode)
    {
        if (ec)
        {
            lg2::error("Failed to get DiagMode: {ERROR}", "ERROR",
                       ec.message());
            return;
        }
        std::error_code fsEc;
        if (mode && !std::filesystem::exists(armedMarker, fsEc))
        {
            return;
        }
        setArmed(mode);
    }

    void onPropertiesChanged(sdbusplus::message_t& msg)
    {
        std::string iface;
        std::map<std::string, std::variant<bool, uint8_t, std::string>> props;
        try
        {
            msg.read(iface, props);
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to read Diag PropertiesChanged: {ERROR}",
                       "ERROR", e);
            return;
        }
        auto it = props.find("DiagMode");
        if (it == props.end())
        {
            return;
        }
        if (const bool* mode = std::get_if<bool>(&it->second))
        {
            setArmed(*mode);
        }
    }

    void onOwnerChanged(sdbusplus::message_t& msg)
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
            lg2::error("Failed to read NameOwnerChanged: {ERROR}", "ERROR", e);
            return;
        }
        if (!newOwner.empty())
        {
            readMode();
        }
    }

    void setArmed(bool mode)
    {
        std::error_code fsEc;
        if (!mode)
        {
            std::filesystem::remove(armedMarker, fsEc);
        }
        if (mode == armed)
        {
            return;
        }
        armed = mode;
        ++generation;
        misses = 0;
        if (!armed)
        {
            timer.cancel();
            lg2::info("CPU diag heartbeat watchdog stopped");
            return;
        }
        std::ofstream marker(armedMarker);
        if (!marker)
        {
            lg2::warning("Failed to create {PATH}; DiagMode will not re-arm "
                         "the watchdog after an ipmid restart",
                         "PATH", armedMarker);
        }
        lg2::info("CPU diag heartbeat watchdog started");
        runCheck();
    }

    void runCheck()
    {
        const size_t gen = generation;
        timer.expires_after(checkInterval);
        timer.async_wait([this, gen](const boost::system::error_code& ec) {
            if (!ec && gen == generation)
            {
                runCheck();
            }
        });

        sdbusplus::asio::getProperty<uint8_t>(
            *bus, diagService, diagObj, diagIntf, "DiagStatus",
            [this, gen](const boost::system::error_code& ec, uint8_t value) {
            onStatus(gen, ec, value);
        });
    }

    void onStatus(size_t gen, const boost::system::error_code& ec,
                  uint8_t value)
    {
        if (gen != generation)
        {
            return;
        }
        if (ec)
        {
            lg2::error("Failed to get DiagStatus: {ERROR}", "ERROR",
                       ec.message());
            return;
        }
        apply(value);
    }

    // A failed error write keeps the count exhausted, so the next idle
    // check sets the error again instead of counting from zero.
    void onStatusSet(size_t gen, uint8_t value,
                     const boost::system::error_code& ec)
    {
        if (!ec)
        {
            return;
        }
        lg2::error("Failed to set DiagStatus: {ERROR}", "ERROR", ec.message());
        if (value == status::error && gen == generation)
        {
            misses = missLimit - 1;
        }
    }

    void apply(uint8_t diagStatus)
    {
        const CheckResult result = check(diagStatus, misses);
        misses = result.counter;
        if (result.setStatus)
        {
            const size_t gen = generation;
            const uint8_t value = *result.setStatus;
            sdbusplus::asio::setProperty(
                *bus, diagService, diagObj, diagIntf, "DiagStatus", value,
                [this, gen, value](const boost::system::error_code& ec) {
                onStatusSet(gen, value, ec);
            });
            if (value == status::error)
            {
                lg2::error("Please check the CPU");
            }
        }

        switch (diagStatus)
        {
            case status::inProgress:
                lg2::info("Test cases in progress");
                break;
            case status::finished:
                lg2::info("Test finished");
                break;
            case status::notStarted:
                lg2::info("Test not started");
                break;
            default:
                break;
        }
    }

    std::shared_ptr<sdbusplus::asio::connection> bus;
    boost::asio::steady_timer timer;
    sdbusplus::bus::match_t modeMatch;
    sdbusplus::bus::match_t ownerMatch;
    bool armed = false;
    size_t generation = 0;
    size_t misses = 0;
};

std::unique_ptr<Watchdog>& watchdog()
{
    static std::unique_ptr<Watchdog> instance;
    return instance;
}

// Only the process that owns the host IPMI bus name runs the watchdog,
// so a second load (e.g. a net-ipmid) cannot double the checks.
void startIfHostIpmid()
{
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    bus->async_method_call(
        [bus](const boost::system::error_code& ec, const std::string& owner) {
        if (ec || owner != bus->get_unique_name())
        {
            lg2::info("Not {SERVICE}, CPU diag watchdog not loaded", "SERVICE",
                      hostIpmiService);
            return;
        }
        watchdog() = std::make_unique<Watchdog>(bus);
    }, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetNameOwner", hostIpmiService);
}

} // namespace

void registerDiagWatchdog() __attribute__((constructor));
void registerDiagWatchdog()
{
    // ipmid requests its bus name just before it starts the io loop.
    post_work(startIfHostIpmid);
}

} // namespace ipmi::nvidia::diag
