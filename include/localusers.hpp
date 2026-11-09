// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <pwd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>

namespace ipmi
{

// Look up a local account in /etc/passwd; nullopt if the file can't be read.
inline std::optional<bool> localUserExists(const std::string& userName)
{
    struct FileCloser
    {
        void operator()(FILE* f) const
        {
            std::fclose(f);
        }
    };
    std::unique_ptr<FILE, FileCloser> fp(std::fopen("/etc/passwd", "re"));
    if (!fp)
    {
        return std::nullopt;
    }

    struct passwd pwd{};
    struct passwd* result = nullptr;
    std::array<char, 4096> buf{};
    int rc = 0;
    while ((rc = fgetpwent_r(fp.get(), &pwd, buf.data(), buf.size(),
                             &result)) == 0 &&
           result != nullptr)
    {
        if (userName == result->pw_name)
        {
            return true;
        }
    }
    if (rc != 0 && rc != ENOENT)
    {
        return std::nullopt;
    }
    return false;
}

} // namespace ipmi
