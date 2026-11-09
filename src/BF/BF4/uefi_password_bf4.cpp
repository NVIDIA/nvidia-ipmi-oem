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
#include "oemcommandsBF.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <shadow.h>
#include <unistd.h>

#include <boost/asio/steady_timer.hpp>
#include <boost/filesystem.hpp>
#include <boost/process/v2/process.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace phosphor::logging;

namespace ipmi
{

namespace nvidia
{
namespace misc
{
// Only the host SSIF channel may use these commands. It must be mapped to the
// "ipmi_ssif" channel in channel_config.json, otherwise SSIF requests arrive on
// the intra-BMC channel that every local process can reach.
constexpr uint8_t ssifChannel = 0x0F;

// The host is in the UEFI phase while this GPIO property is false.
constexpr char gpioStatusService[] = "xyz.openbmc_project.GpioStatusHandler";
constexpr char gpioStatusObjPath[] = "/xyz/openbmc_project/GpioStatusHandler";
constexpr char gpioStatusIface[] = "xyz.openbmc_project.GpioStatus";
constexpr char gpioPreOsPhaseProp[] = "cpu_pre_os_phase";

// Wire format of the Get/Set commands, fixed by the UEFI side: action(1) +
// salt(32) + hash(64). The salt and hash fields are zero-padded ASCII, larger
// than the yescrypt content so the wire format does not depend on the hash.
// "No password" (type 1) carries no salt or hash: it is stored as an empty
// /etc/shadow password field, which pam_unix accepts with nullok.
constexpr uint8_t biosPasswordSaltSize = 32;
constexpr uint8_t biosPasswordMaxHashSize = 64;
constexpr uint8_t biosPasswordSelectorAdmin = 0x01;
constexpr uint8_t biosPasswordTypeNoChange = 0x00;
constexpr uint8_t biosPasswordTypeNoPassword = 0x01;
constexpr uint8_t biosPasswordTypeGlibcYescrypt = 0x03;

// The hash is stored in /etc/shadow as "$y$j9T$<salt>$<hash>", as pam_unix
// writes it. "j9T" is the libxcrypt default cost preset; it is not sent over
// IPMI, both sides agree on it.
constexpr char biosPasswordShadowUser[] = "ArmBios";
constexpr char biosPasswordYescryptPrefix[] = "$y$j9T$";
// yescrypt encodes a 16-byte salt in 22 characters and a 32-byte hash in 43.
constexpr size_t biosPasswordYescryptSaltLen = 22;
constexpr size_t biosPasswordYescryptHashLen = 43;
// The last character carries only 2 (salt) or 4 (hash) bits; the rest must be
// zero, otherwise libxcrypt rejects the salt and the hash never verifies.
constexpr char biosPasswordSaltLastChars[] = "./01";
constexpr char biosPasswordHashLastChars[] = "./0123456789ABCD";

// useradd/usermod normally take 0.1-0.5 s; kill one that hangs so it cannot
// stall ipmid.
constexpr auto helperTimeout = std::chrono::seconds(5);

// bios-settings-mgr state: PasswordSync is set by bmcweb after a Redfish
// ChangePassword and cleared by Set; PasswordInitialized is set by Set once
// UEFI has supplied a password, and Redfish ChangePassword requires it.
constexpr char biosPasswordObjPath[] =
    "/xyz/openbmc_project/bios_config/password";
constexpr char biosPasswordIface[] = "xyz.openbmc_project.BIOSConfig.Password";
} // namespace misc
} // namespace nvidia

using namespace ipmi::nvidia::misc;

static constexpr char biosPasswordAlphabet[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** @brief Result of reading the ArmBios row of /etc/shadow. */
enum class ShadowRead
{
    found,
    missing,
    error,
};

/** @brief What Set does with the hash UEFI sent. */
enum class SetAction
{
    write,
    alreadyStored,
    keepPending,
    fail,
};

/**
 * @brief Check that the command may run now.
 *
 * Allowed only on the SSIF channel and while the host is still in the UEFI
 * phase, so the host OS cannot read or change the password after boot.
 * Fails closed if the phase cannot be read.
 *
 * TODO: builds with another OEM command set do not include this file yet;
 * add the same check when they do.
 */
static bool isCommandAllowed(ipmi::Context::ptr ctx)
{
    if (ctx->channel != ssifChannel)
    {
        log<level::ERR>("BIOS Password: channel is not SSIF",
                        entry("CHANNEL=%d", static_cast<int>(ctx->channel)));
        return false;
    }

    bool preOsPhase = true;
    boost::system::error_code ec =
        ipmi::getDbusProperty(ctx, gpioStatusService, gpioStatusObjPath,
                              gpioStatusIface, gpioPreOsPhaseProp, preOsPhase);
    if (ec)
    {
        log<level::ERR>("BIOS Password: failed to read the UEFI phase",
                        entry("ERROR=%s", ec.message().c_str()));
        return false;
    }
    // cpu_pre_os_phase is true once the host has left the UEFI phase.
    if (preOsPhase)
    {
        log<level::ERR>("BIOS Password: host is not in the UEFI phase");
        return false;
    }
    return true;
}

/**
 * @brief True if s is exactly len characters of the crypt(3) alphabet.
 *
 * Keeps ':' and newline out of /etc/shadow.
 */
static bool isYescryptField(const std::string& s, size_t len,
                            const char* lastChars)
{
    return s.size() == len &&
           s.find_first_not_of(biosPasswordAlphabet) == std::string::npos &&
           std::strchr(lastChars, s.back()) != nullptr;
}

/** @brief Copy the leading non-NUL bytes of a zero-padded IPMI field. */
template <size_t N>
static std::string fieldToString(const std::array<uint8_t, N>& f)
{
    size_t len = 0;
    while (len < N && f[len] != 0)
    {
        len++;
    }
    return std::string(reinterpret_cast<const char*>(f.data()), len);
}

/** @brief True if a shadow password field is in the "$y$j9T$" format. */
static bool hasYescryptPrefix(const std::string& stored)
{
    return stored.rfind(biosPasswordYescryptPrefix, 0) == 0;
}

/**
 * @brief Split "$y$j9T$<salt>$<hash>" into salt and hash.
 *
 * @return false unless stored is a complete yescrypt entry with a valid salt
 * and hash.
 */
static bool splitYescryptEntry(const std::string& stored, std::string& salt,
                               std::string& hash)
{
    if (!hasYescryptPrefix(stored))
    {
        return false;
    }
    const std::string body =
        stored.substr(std::strlen(biosPasswordYescryptPrefix));
    const size_t sep = body.find('$');
    if (sep == std::string::npos)
    {
        return false;
    }
    salt = body.substr(0, sep);
    hash = body.substr(sep + 1);
    return isYescryptField(salt, biosPasswordYescryptSaltLen,
                           biosPasswordSaltLastChars) &&
           isYescryptField(hash, biosPasswordYescryptHashLen,
                           biosPasswordHashLastChars);
}

/**
 * @brief Run a program without a shell; true if it exited with status 0.
 *
 * Waits on yield, so ipmid keeps running meanwhile. The program is killed if
 * it runs longer than helperTimeout.
 */
static bool runProgram(boost::asio::yield_context yield, const char* path,
                       const std::vector<std::string>& args)
{
    try
    {
        boost::asio::io_context& io = *getIoContext();
        // Shared with the timer handler, which can run after we return.
        auto proc = std::make_shared<boost::process::v2::process>(
            io, boost::filesystem::path(path), args);
        auto timedOut = std::make_shared<bool>(false);
        boost::asio::steady_timer timer(io, helperTimeout);
        timer.async_wait([proc, timedOut](const boost::system::error_code& ec) {
            if (!ec)
            {
                *timedOut = true;
                boost::system::error_code killEc;
                proc->terminate(killEc);
            }
        });

        boost::system::error_code ec;
        const int status = proc->async_wait(yield[ec]);
        timer.cancel();
        if (*timedOut)
        {
            log<level::ERR>("Helper program timed out, killing it",
                            entry("PROGRAM=%s", path));
            return false;
        }
        return !ec && boost::process::v2::evaluate_exit_code(status) == 0;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to run helper program",
                        entry("PROGRAM=%s", path), entry("ERROR=%s", e.what()));
        return false;
    }
}

/**
 * @brief Append an empty-password /etc/shadow row for ArmBios; other rows are
 * untouched.
 *
 * Takes the shadow lock only while appending, so usermod(8) can take it next.
 * The aging fields are left empty (no aging).
 */
static bool appendShadowEntry()
{
    if (lckpwdf() != 0)
    {
        return false;
    }
    struct Unlock
    {
        ~Unlock()
        {
            ulckpwdf();
        }
    } unlock;

    int fd = open("/etc/shadow", O_RDWR | O_APPEND | O_CLOEXEC);
    if (fd < 0)
    {
        return false;
    }
    // A last row without a newline would join the new row.
    bool needNewline = false;
    const off_t size = lseek(fd, 0, SEEK_END);
    if (size > 0)
    {
        char last = '\n';
        needNewline = pread(fd, &last, 1, size - 1) == 1 && last != '\n';
    }
    FILE* out = fdopen(fd, "a");
    if (!out)
    {
        close(fd);
        return false;
    }

    struct spwd sp = {};
    sp.sp_namp = const_cast<char*>(biosPasswordShadowUser);
    sp.sp_pwdp = const_cast<char*>("");
    sp.sp_lstchg = -1;
    sp.sp_min = -1;
    sp.sp_max = -1;
    sp.sp_warn = -1;
    sp.sp_inact = -1;
    sp.sp_expire = -1;
    sp.sp_flag = ~0UL;

    bool ok = !needNewline || fputc('\n', out) != EOF;
    ok = ok && putspent(&sp, out) == 0 && fflush(out) == 0 &&
         fsync(fileno(out)) == 0;
    // Close even after a failure, but report it.
    return fclose(out) == 0 && ok;
}

/**
 * @brief Make sure ArmBios has both a passwd and a shadow entry.
 *
 * A BMC update restores the old /etc/passwd and /etc/shadow, which can lack an
 * account that the new image added, so Set would fail on every boot. Only the
 * ArmBios account is touched.
 */
static bool ensureShadowUser(boost::asio::yield_context yield)
{
    if (getpwnam(biosPasswordShadowUser) == nullptr)
    {
        // Missing from both files: create it like the image does.
        log<level::INFO>("ArmBios account is missing, creating it");
        return runProgram(yield, "/usr/sbin/useradd",
                          {"--system", "--no-create-home", "--home-dir",
                           "/nonexistent", "-g", "nogroup", "--shell",
                           "/sbin/nologin", "--password", "",
                           biosPasswordShadowUser});
    }
    if (getspnam(biosPasswordShadowUser) == nullptr)
    {
        // In passwd but not in shadow: add only its shadow row.
        log<level::INFO>("ArmBios shadow entry is missing, restoring it");
        return appendShadowEntry();
    }
    return true;
}

/**
 * @brief Replace the ArmBios password field in /etc/shadow.
 *
 * usermod(8) takes the shadow lock and replaces the file atomically. -p stores
 * the string verbatim without PAM. pwd must already be validated; it is passed
 * as one argument, never through a shell.
 */
static bool writeShadowPassword(boost::asio::yield_context yield,
                                const std::string& pwd)
{
    return ensureShadowUser(yield) &&
           runProgram(yield, "/usr/sbin/usermod",
                      {"-p", pwd, biosPasswordShadowUser});
}

/** @brief Read the stored password field of ArmBios from /etc/shadow. */
static ShadowRead readShadowPassword(std::string& pwd)
{
    if (lckpwdf() != 0)
    {
        return ShadowRead::error;
    }
    struct Unlock
    {
        ~Unlock()
        {
            ulckpwdf();
        }
    } unlock;

    struct spwd sp;
    struct spwd* res = nullptr;
    std::array<char, 1024> buf;
    const int rc = getspnam_r(biosPasswordShadowUser, &sp, buf.data(),
                              buf.size(), &res);
    if (rc == 0 && res != nullptr)
    {
        pwd = res->sp_pwdp ? res->sp_pwdp : "";
        return ShadowRead::found;
    }
    // glibc reports "no such entry" as 0 or one of these; anything else
    // (ERANGE, EIO, ...) is a real failure.
    if (rc == 0 || rc == ENOENT || rc == ESRCH || rc == EBADF || rc == EPERM)
    {
        return ShadowRead::missing;
    }
    return ShadowRead::error;
}

/** @brief Read PasswordSync. The ctx overloads yield instead of blocking. */
static boost::system::error_code getPasswordSync(ipmi::Context::ptr ctx,
                                                 bool& sync)
{
    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, biosPasswordIface, biosPasswordObjPath, service);
    if (ec)
    {
        return ec;
    }
    return ipmi::getDbusProperty(ctx, service, biosPasswordObjPath,
                                 biosPasswordIface, "PasswordSync", sync);
}

/** @brief Set PasswordSync=false and PasswordInitialized=true. */
static boost::system::error_code setPasswordApplied(ipmi::Context::ptr ctx)
{
    std::string service;
    boost::system::error_code ec =
        ipmi::getService(ctx, biosPasswordIface, biosPasswordObjPath, service);
    if (ec)
    {
        return ec;
    }
    ec = ipmi::setDbusProperty(ctx, service, biosPasswordObjPath,
                               biosPasswordIface, "PasswordSync", false);
    if (ec)
    {
        return ec;
    }
    return ipmi::setDbusProperty(ctx, service, biosPasswordObjPath,
                                 biosPasswordIface, "PasswordInitialized",
                                 true);
}

/**
 * @brief Build the shadow password field that Set stores.
 *
 * "No password" is an empty field. A yescrypt password is the validated
 * "$y$j9T$<salt>$<hash>" string.
 *
 * @return ccSuccess, or the completion code to send back.
 */
static ipmi::Cc
    buildShadowHash(uint8_t type,
                    const std::array<uint8_t, biosPasswordSaltSize>& salt,
                    const std::array<uint8_t, biosPasswordMaxHashSize>& hash,
                    std::string& shadowHash)
{
    switch (type)
    {
        case biosPasswordTypeNoPassword:
            shadowHash.clear();
            return ipmi::ccSuccess;
        case biosPasswordTypeGlibcYescrypt:
        {
            // Build the shadow entry and check it with the same function that
            // checks the stored entry in Get and Set.
            shadowHash = std::string(biosPasswordYescryptPrefix) +
                         fieldToString(salt) + "$" + fieldToString(hash);
            std::string saltStr;
            std::string hashStr;
            if (!splitYescryptEntry(shadowHash, saltStr, hashStr))
            {
                return ipmi::ccInvalidFieldRequest;
            }
            return ipmi::ccSuccess;
        }
        default:
            return ipmi::ccInvalidFieldRequest;
    }
}

/**
 * @brief Decide whether Set may store newHash.
 *
 * bmcweb stores a Redfish password in /etc/shadow before it sets PasswordSync,
 * so while PasswordSync is set the shadow hash is the pending password. A Set
 * with a different hash comes from UEFI failing to apply it and must not
 * replace it. Anything that is not a complete yescrypt entry is not pending
 * (an entry from an older image) and is replaced. A Set with the hash that
 * is already stored needs no write. If the shadow file cannot be read while a
 * password is pending, nothing is written, so the pending password is not
 * lost.
 */
static SetAction decideSetAction(bool pendingSync, const std::string& newHash)
{
    std::string stored;
    switch (readShadowPassword(stored))
    {
        case ShadowRead::error:
            return pendingSync ? SetAction::fail : SetAction::write;
        case ShadowRead::missing:
            // Nothing stored, so nothing pending to lose.
            return SetAction::write;
        case ShadowRead::found:
            break;
    }
    if (stored == newHash)
    {
        return SetAction::alreadyStored;
    }
    std::string salt;
    std::string hash;
    if (pendingSync && splitYescryptEntry(stored, salt, hash))
    {
        return SetAction::keepPending;
    }
    return SetAction::write;
}

/** @brief Store the password UEFI sent and report it as applied. */
ipmi::RspType<std::vector<uint8_t>>
    ipmiSetBiosPassword(ipmi::Context::ptr ctx, uint8_t id, uint8_t type,
                        std::array<uint8_t, biosPasswordSaltSize> salt,
                        std::array<uint8_t, biosPasswordMaxHashSize> hash)
{
    if (!isCommandAllowed(ctx))
    {
        log<level::ERR>("BIOS Password command not allowed");
        return ipmi::response(ipmi::ccResponseError);
    }
    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string newHash;
    ipmi::Cc cc = buildShadowHash(type, salt, hash, newHash);
    if (cc != ipmi::ccSuccess)
    {
        return ipmi::response(cc);
    }

    bool pendingSync = false;
    boost::system::error_code ec = getPasswordSync(ctx, pendingSync);
    if (ec)
    {
        log<level::ERR>("Failed to read PasswordSync",
                        entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    const SetAction action = decideSetAction(pendingSync, newHash);
    if (action == SetAction::fail)
    {
        log<level::ERR>("Failed to read BIOS Password from /etc/shadow while "
                        "a Redfish password is pending, not overwriting it");
        return ipmi::responseUnspecifiedError();
    }
    if (action == SetAction::keepPending)
    {
        // Keep the Redfish password and PasswordSync; UEFI gets it from Get.
        log<level::WARNING>("BIOS Password: Set differs from the pending "
                            "Redfish password, keeping the pending one");
        return ipmi::responseSuccess();
    }
    if (action == SetAction::write && !writeShadowPassword(ctx->yield, newHash))
    {
        log<level::ERR>("Failed to write BIOS Password to /etc/shadow");
        return ipmi::responseUnspecifiedError();
    }

    // UEFI applied the password: end the pending sync and allow Redfish
    // ChangePassword.
    ec = setPasswordApplied(ctx);
    if (ec)
    {
        log<level::ERR>("Failed to set PasswordSync/PasswordInitialized",
                        entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

/**
 * @brief Return the password changed through Redfish for UEFI to apply.
 *
 * NoChange when no sync is pending or the stored entry is not a usable
 * yescrypt hash.
 */
ipmi::RspType<uint8_t, std::array<uint8_t, biosPasswordSaltSize>,
              std::array<uint8_t, biosPasswordMaxHashSize>>
    ipmiGetBiosPassword(ipmi::Context::ptr ctx, uint8_t id)
{
    if (!isCommandAllowed(ctx))
    {
        log<level::ERR>("BIOS Password command not allowed");
        return ipmi::response(ipmi::ccResponseError);
    }
    if (id != biosPasswordSelectorAdmin)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::array<uint8_t, biosPasswordSaltSize> salt = {0};
    std::array<uint8_t, biosPasswordMaxHashSize> hash = {0};

    bool pendingSync = false;
    boost::system::error_code ec = getPasswordSync(ctx, pendingSync);
    if (ec)
    {
        log<level::ERR>("Failed to read PasswordSync",
                        entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }
    if (!pendingSync)
    {
        return ipmi::responseSuccess(biosPasswordTypeNoChange, salt, hash);
    }

    std::string stored;
    if (readShadowPassword(stored) != ShadowRead::found)
    {
        log<level::ERR>("Failed to read BIOS Password from /etc/shadow");
        return ipmi::responseUnspecifiedError();
    }
    if (stored.empty())
    {
        return ipmi::responseSuccess(biosPasswordTypeNoPassword, salt, hash);
    }

    std::string saltStr;
    std::string hashStr;
    if (!splitYescryptEntry(stored, saltStr, hashStr))
    {
        // Not a password UEFI can use (e.g. left by an older image). Report no
        // change: the Set UEFI sends next replaces it.
        log<level::WARNING>("BIOS Password in /etc/shadow is not a valid "
                            "yescrypt entry, returning NoChange");
        return ipmi::responseSuccess(biosPasswordTypeNoChange, salt, hash);
    }

    std::copy(saltStr.begin(), saltStr.end(), salt.begin());
    std::copy(hashStr.begin(), hashStr.end(), hash.begin());
    return ipmi::responseSuccess(biosPasswordTypeGlibcYescrypt, salt, hash);
}

} // namespace ipmi

void registerUefiPasswordBf4Handlers() __attribute__((constructor(104)));

void registerUefiPasswordBf4Handlers()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdSetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiSetBiosPassword);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::misc::cmdGetBiosPassword,
                          ipmi::Privilege::Admin, ipmi::ipmiGetBiosPassword);
}
