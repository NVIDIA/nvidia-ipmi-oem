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
    if ((chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::oem)))
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
	     phosphor::logging::log<phosphor::logging::level::ERR>
	         ("ipmiSbmrGetBootProgressCode: xyz.openbmc_project.State.Boot.Raw"
                 "not initialized, or the host power is OFF");
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
ipmi::RspType<uint8_t> ipmiOemSbmrSendDescription(
    ipmi::Context::ptr ctx, uint8_t statuscode, uint8_t, uint8_t,
    uint8_t severity, uint8_t operation1st, uint8_t operation2nd,
    uint8_t subClass, uint8_t codeClass, std::vector<uint8_t> description)
{

    std::string messageData;

    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOemSbmrSendDescription: Failed to get Channel Info",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    if ((chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::smbusV20)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface)) &&
        (chInfo.mediumType !=
         static_cast<uint8_t>(ipmi::EChannelMediumType::oem)))

    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOemSbmrSendDescription: Error - supported only in SSIF "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    if (description.size() > maxDescriptionLength)
    {
        return ipmi::responseReqDataLenExceeded();
    }
    if (!description.empty())
    {
        // check the string is null terminated
        if (description[description.size() - 1])
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }
    uint8_t byteData;
    for (auto index = 0; index < description.size(); index++)
    {
        byteData = description[index];
        // Checking the byte contain control characters
        if (byteData > 0x0 && byteData < 0x1f)
        {
            return ipmi::responseInvalidFieldRequest();
        }
        messageData.push_back(byteData);
    }

    // Form the message format
    std::stringstream hexCode;
    hexCode << "0x" << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(codeClass) << std::setw(2) << std::setfill('0')
            << static_cast<int>(subClass) << std::setw(2) << std::setfill('0')
            << static_cast<int>(operation2nd) << std::setw(2)
            << std::setfill('0') << static_cast<int>(operation1st);
    std::string eventMessage;
    std::string eventSeverity;
    switch (statuscode)
    {
        case bootProgressCode:
            eventMessage.assign("Progress Code ");
            eventSeverity.assign(
                "xyz.openbmc_project.Logging.Entry.Level.Informational");
            break;
        case bootErrorCode:
            eventMessage.assign("Error Code ");
            if (severity == bootErrorMinor)
            {
                eventMessage += "Minor ";
            }
            else if (severity == bootErrorMajor)
            {
                eventMessage += "Major ";
            }
            else if (severity == bootErrorUnrecoverd)
            {
                eventMessage += "Unrecovered ";
            }
            else if (severity == bootErrorUncontained)
            {
                eventMessage += "Uncontained ";
            }

            if (severity == bootErrorMinor)
            {
                eventSeverity.assign(
                    "xyz.openbmc_project.Logging.Entry.Level.Warning");
            }
            else
            {
                eventSeverity.assign(
                    "xyz.openbmc_project.Logging.Entry.Level.Error");
            }

            break;
        case bootDebugCode:
            eventMessage.assign("Debug Code ");
            eventSeverity.assign(
                "xyz.openbmc_project.Logging.Entry.Level.Debug");
            break;
        default:
            log<level::ERR>("ipmiOemSbmrSendDescription:Invalid Status Code");
            return ipmi::responseInvalidFieldRequest();
    }
    eventMessage += hexCode.str();
    eventMessage = eventMessage + ":" + messageData;
    // Log event
    try
    {
        std::map<std::string, std::string> additionData = {};
        auto method = ctx->bus->new_method_call(loggingService, loggingObject,
                                                loggingInterface, "Create");
        method.append(eventMessage);
        method.append(eventSeverity);
        method.append(additionData);
        auto reply = ctx->bus->call(method);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
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
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemNV),
        entry("Cmd:[%02Xh]", ipmi::nvidia::cmdSbmrSendDescription));
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemNV,
                          ipmi::nvidia::cmdSbmrSendDescription,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiOemSbmrSendDescription);
#endif
}
