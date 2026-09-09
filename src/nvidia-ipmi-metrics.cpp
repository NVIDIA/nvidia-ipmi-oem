// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES

#include "nvidia-ipmi-metrics.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <span>
#include <string_view>
#include <system_error>

namespace ipmi::metrics
{
namespace
{

constexpr std::string_view truncationMarker = " [truncated]";
constexpr std::string_view socketPath = "/run/bmc-cmd-metrics.sock";
constexpr size_t maxRecordSize = 4096;
constexpr std::string_view protocolHeader =
    "<14>1 - - bmc-cmd-metrics - CMDMETRICS-V1 - ";
constexpr std::string_view ipmiMessagePrefix = "IPMI Metrics: ";
constexpr std::string_view hexDigits = "0123456789ABCDEF";
constexpr socklen_t socketAddressLength = static_cast<socklen_t>(
    offsetof(sockaddr_un, sun_path) + socketPath.size() + 1U);
static_assert(truncationMarker.size() <= maxRecordSize);

class RecordBuilder
{
  public:
    void append(std::string_view value) noexcept
    {
        for (char ch : value)
        {
            if (size >= data.size())
            {
                truncated = true;
                return;
            }
            data[size++] = (ch == '\n' || ch == '\r' || ch == '\0') ? ' ' : ch;
        }
    }

    template <typename... Parts>
    void appendParts(const Parts&... parts) noexcept
    {
        (append(std::string_view{parts}), ...);
    }

    void appendByteHex(uint8_t value) noexcept
    {
        const std::array<char, 2> output = {
            hexDigits[static_cast<size_t>((value >> 4U) & 0x0FU)],
            hexDigits[static_cast<size_t>(value & 0x0FU)]};
        append({output.data(), output.size()});
    }

    void appendHexField(std::string_view label, uint8_t value,
                        size_t minimumWidth = 2) noexcept
    {
        appendParts(label, "0x");
        if (minimumWidth == 1 && value < hexDigits.size())
        {
            append({hexDigits.data() + value, 1});
        }
        else
        {
            appendByteHex(value);
        }
    }

    void appendDecimalField(std::string_view label, uint8_t value) noexcept
    {
        append(label);
        std::array<char, 3> output{};
        const auto result = std::to_chars(output.data(),
                                          output.data() + output.size(), value);
        if (result.ec == std::errc{})
        {
            append(std::string_view(output.data(), result.ptr));
        }
    }

    std::span<const char> finish() noexcept
    {
        if (truncated)
        {
            const size_t markerOffset = data.size() - truncationMarker.size();
            std::memcpy(data.data() + markerOffset, truncationMarker.data(),
                        truncationMarker.size());
        }
        return {data.data(), size};
    }

  private:
    std::array<char, maxRecordSize> data{};
    size_t size = 0;
    bool truncated = false;
};

class SocketSender
{
  public:
    SocketSender() noexcept
    {
        static_assert(socketPath.size() < sizeof(address.sun_path));
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, socketPath.data(), socketPath.size());
        address.sun_path[socketPath.size()] = '\0';

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }

    ~SocketSender()
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }

    SocketSender(const SocketSender&) = delete;
    SocketSender& operator=(const SocketSender&) = delete;

    void send(std::span<const char> record) const noexcept
    {
        if (fd < 0)
        {
            return;
        }

        static_cast<void>(sendto(
            fd, record.data(), record.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
            reinterpret_cast<const sockaddr*>(&address), socketAddressLength));
    }

  private:
    int fd = -1;
    sockaddr_un address{};
};

static SocketSender& getSender() noexcept
{
    static SocketSender sender;
    return sender;
}

} // namespace

void submit(std::string_view medium, uint8_t netFn, uint8_t lun,
            uint8_t command, uint8_t channel,
            std::span<const uint8_t> requestData,
            RequestDataMode requestDataMode) noexcept
{
    RecordBuilder record;
    record.appendParts(protocolHeader, ipmiMessagePrefix, "Medium=", medium);
    record.appendHexField(" NetFn=", netFn);
    record.appendHexField(" LUN=", lun, 1);
    record.appendHexField(" Cmd=", command);
    record.appendDecimalField(" Chan=", channel);
    record.append(" ReqData=[");
    if (requestDataMode == RequestDataMode::redact)
    {
        record.append("redacted");
    }
    else if (requestData.empty())
    {
        record.append("empty");
    }
    else
    {
        bool first = true;
        for (uint8_t byte : requestData)
        {
            if (!first)
            {
                record.append(" ");
            }
            record.appendByteHex(byte);
            first = false;
        }
    }
    record.append("]");
    getSender().send(record.finish());
}

} // namespace ipmi::metrics
