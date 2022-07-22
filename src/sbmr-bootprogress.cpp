#include "sbmr-bootprogress.hpp"

#include <ipmid/api.hpp>
#include <phosphor-logging/log.hpp>

void registerBootprogressFunctions() __attribute__((constructor));
using SbmrBootProgressRecord = std::tuple<uint64_t, std::vector<uint8_t>>;

using namespace phosphor::logging;

namespace ipmi
{
ipmi::RspType<uint8_t> ipmiSbmrSendBootProgressCode(
    ipmi::Context::ptr ctx, uint8_t statuscode, uint8_t reserved1st,
    uint8_t reserved2nd, uint8_t severity, uint8_t operation1st,
    uint8_t operation2nd, uint8_t subClass, uint8_t codeClass, uint8_t instance)
{
    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSbmrSendBootProgressCode: Failed to get Channel Info",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSbmrSendBootProgressCode: Error - supported only in SSIF "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }
    try
    {
        /* Create Boot progress codes */
        std::vector<uint8_t> sbmrBootProgressData{
            statuscode,   reserved1st, reserved2nd, severity, operation1st,
            operation2nd, subClass,    codeClass,   instance};
        /* Store the Boot progress record to Dbus property */
        SbmrBootProgressRecord record{0, {sbmrBootProgressData}};
        std::variant<SbmrBootProgressRecord> variantValue(record);

        auto method = ctx->bus->new_method_call(sbmrBootProgressService,
                                                sbmrBootProgressObj,
                                                dbusPropertyInterface, "Set");
        method.append(sbmrBootProgressIntf, "Value", variantValue);
        auto reply = ctx->bus->call(method);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<std::vector<uint8_t>>
    ipmiSbmrGetBootProgressCode(ipmi::Context::ptr ctx)
{
    try
    {
        auto method = ctx->bus->new_method_call(sbmrBootProgressService,
                                                sbmrBootProgressObj,
                                                dbusPropertyInterface, "Get");
        method.append(sbmrBootProgressIntf, "Value");

        auto reply = ctx->bus->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<level::ERR>(
                "ipmiSbmrGetBootProgressCodeCmd: Get Dbus method returned "
                "error",
                phosphor::logging::entry("SERVICE=%s",
                                         sbmrBootProgressService));
            return ipmi::responseUnspecifiedError();
        }
        std::variant<SbmrBootProgressRecord> variantValue;
        reply.read(variantValue);
        auto getRecord =
            std::get<std::tuple<uint64_t, std::vector<uint8_t>>>(variantValue);
        auto respBootProgressCode = std::get<std::vector<uint8_t>>(getRecord);
        if (respBootProgressCode.empty() ||
            respBootProgressCode.size() != sbmrBootProgressSize)
        {
            return ipmi::responseUnspecifiedError();
        }

        return ipmi::responseSuccess(respBootProgressCode);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("storeSbmrBootProgressData: can't get property Value",
                        entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
}
} // namespace ipmi
void registerBootprogressFunctions()
{
#ifdef FEATURE_SBMR_BOOTPROGRESS
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::sbmr::groupExtIpmi),
        entry("Cmd:[%02Xh]", ipmi::sbmrcmds::cmdGetBootProgressCode));
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::sbmr::groupExtIpmi,
                               ipmi::sbmrcmds::cmdSendBootProgressCode,
                               ipmi::Privilege::Admin,
                               ipmi::ipmiSbmrSendBootProgressCode);
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::sbmr::groupExtIpmi),
        entry("Cmd:[%02Xh]", ipmi::sbmrcmds::cmdGetBootProgressCode));
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::sbmr::groupExtIpmi,
                               ipmi::sbmrcmds::cmdGetBootProgressCode,
                               ipmi::Privilege::User,
                               ipmi::ipmiSbmrGetBootProgressCode);
#endif
}
