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

#pragma once

namespace ipmi
{
namespace sbmr
{
constexpr auto groupExtIpmi = 0xAE;
constexpr auto netFnOemSbmr = 0x2C;
} // namespace sbmr
namespace sbmrcmds
{
constexpr auto cmdSendBootProgressCode = 0x02;
constexpr auto cmdGetBootProgressCode = 0x03;
} // namespace sbmrcmds
namespace nvidia
{
constexpr auto netFnOemNV = 0x3C;
constexpr auto cmdSbmrSendDescription = 0xD1;
} // namespace nvidia
} // namespace ipmi
constexpr auto sbmrBootProgressService = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrBootProgressObj = "/xyz/openbmc_project/state/boot/raw0";
constexpr auto sbmrBootProgressIntf = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto dbusPropertyInterface = "org.freedesktop.DBus.Properties";
constexpr auto loggingService = "xyz.openbmc_project.Logging";
constexpr auto loggingObject = "/xyz/openbmc_project/logging";
constexpr auto loggingInterface = "xyz.openbmc_project.Logging.Create";
constexpr auto sbmrBootProgressSize = 9;
constexpr auto maxDescriptionLength = 256;
constexpr auto bootProgressCode = 0x01;
constexpr auto bootErrorCode = 0x02;
constexpr auto bootDebugCode = 0x03;
constexpr auto bootErrorMinor = 0x40;
constexpr auto bootErrorMajor = 0x80;
constexpr auto bootErrorUnrecoverd = 0x90;
constexpr auto bootErrorUncontained = 0xa0;
