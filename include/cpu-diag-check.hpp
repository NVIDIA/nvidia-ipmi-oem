// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace ipmi::nvidia::diag
{

namespace status
{
constexpr uint8_t idle = 0;
constexpr uint8_t inProgress = 1;
constexpr uint8_t finished = 2;
constexpr uint8_t error = 3;
constexpr uint8_t notStarted = 4;
} // namespace status

// Missed heartbeats before DiagStatus is set to error.
constexpr size_t missLimit = 3;

struct CheckResult
{
    std::optional<uint8_t> setStatus;
    size_t counter = 0;
};

// One heartbeat check: the host sets DiagStatus to inProgress, and the
// BMC acknowledges by setting it back to idle. A status still idle on
// missLimit consecutive checks means the host has stopped.
constexpr CheckResult check(uint8_t diagStatus, size_t counter)
{
    switch (diagStatus)
    {
        case status::idle:
            if (counter + 1 == missLimit)
            {
                return {status::error, 0};
            }
            return {std::nullopt, counter + 1};
        case status::inProgress:
            return {status::idle, 0};
        case status::finished:
        case status::notStarted:
            return {std::nullopt, 0};
        default:
            return {std::nullopt, counter};
    }
}

} // namespace ipmi::nvidia::diag
