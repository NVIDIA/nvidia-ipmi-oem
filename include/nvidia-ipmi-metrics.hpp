// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace ipmi::metrics
{

enum class RequestDataMode : uint8_t
{
    include,
    redact,
};

void submit(std::string_view medium, uint8_t netFn, uint8_t lun,
            uint8_t command, uint8_t channel,
            std::span<const uint8_t> requestData,
            RequestDataMode requestDataMode) noexcept;

} // namespace ipmi::metrics
