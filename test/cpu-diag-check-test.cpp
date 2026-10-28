// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES

#include <cpu-diag-check.hpp>

#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

namespace ipmi::nvidia::diag
{

TEST(CpuDiagCheck, IdleCountsMissedHeartbeats)
{
    CheckResult r = check(status::idle, 0);
    EXPECT_FALSE(r.setStatus);
    EXPECT_EQ(r.counter, 1U);

    r = check(status::idle, 1);
    EXPECT_FALSE(r.setStatus);
    EXPECT_EQ(r.counter, 2U);
}

TEST(CpuDiagCheck, ThirdMissSetsError)
{
    const CheckResult r = check(status::idle, 2);
    EXPECT_EQ(r.setStatus, status::error);
}

TEST(CpuDiagCheck, OnlyExactLimitSetsError)
{
    const CheckResult r = check(status::idle, 3);
    EXPECT_FALSE(r.setStatus);
    EXPECT_EQ(r.counter, 4U);
}

TEST(CpuDiagCheck, InProgressIsAcknowledged)
{
    const CheckResult r = check(status::inProgress, 2);
    EXPECT_EQ(r.setStatus, status::idle);
    EXPECT_EQ(r.counter, 0U);
}

TEST(CpuDiagCheck, FinishedAndNotStartedResetCounter)
{
    for (uint8_t s : {status::finished, status::notStarted})
    {
        const CheckResult r = check(s, 2);
        EXPECT_FALSE(r.setStatus);
        EXPECT_EQ(r.counter, 0U);
    }
}

TEST(CpuDiagCheck, OtherStatusLeavesEverything)
{
    for (int s : {static_cast<int>(status::error), 5, 255})
    {
        const CheckResult r = check(static_cast<uint8_t>(s), 2);
        EXPECT_FALSE(r.setStatus);
        EXPECT_EQ(r.counter, 2U);
    }
}

} // namespace ipmi::nvidia::diag
