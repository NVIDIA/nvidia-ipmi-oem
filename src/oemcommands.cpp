/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#include "oemcommands.hpp"

#include <ipmid/api.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <vector>
#include <array>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>

// Network object in dbus
const char* networkService = "xyz.openbmc_project.Network";
const char* networkObj = "/xyz/openbmc_project/network";
const char* networkResetIntf = "xyz.openbmc_project.Common.FactoryReset";

// Software BMC Updater object in dbus
const char* sftBMCService = "xyz.openbmc_project.Software.BMC.Updater";
const char* sftBMCObj = "/xyz/openbmc_project/software";
const char* sftBMCResetIntf = "xyz.openbmc_project.Common.FactoryReset";

void registerNvOemFunctions() __attribute__((constructor));

using namespace phosphor::logging;

namespace ipmi
{

ipmi::RspType<> ipmiSystemFactoryReset(boost::asio::yield_context yield)
{
    /*
     * BMC factory reset must be use to restore the BMC to its
     * original manufacturer settings.
     * IPMI performs below 2 steps:
     * 1. The network factory reset, it overwrites the configuration
     *    for all configured network interfaces to a DHCP setting.
     * 2. The BMC software updater factory reset, it clears any
     *    volumes and persistence files created by the BMC processes.
     *    This reset occurs only on the next BMC reboot.
     */

    auto sdbusp = getSdBus();
    boost::system::error_code ec;

    // Network factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            networkService,
            networkObj,
            networkResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on network reset");
            return ipmi::responseUnspecifiedError();
        }

    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    // BMC software updater factory reset
    try
    {
        sdbusp->yield_method_call<void>(
            yield, ec,
            sftBMCService,
            sftBMCObj,
            sftBMCResetIntf,
            "Reset");
        if (ec)
        {
            phosphor::logging::log<level::ERR>("Unspecified Error on BMC software reset");
            return ipmi::responseUnspecifiedError();
        }
    }
    catch (...)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::Cc i2cSMBusWriteRead(int i2cdev, const uint8_t slaveAddr, uint8_t devAddr,
                           uint8_t read_write, uint8_t* buf)
{
    struct i2c_smbus_ioctl_data ioctl_data;
    union i2c_smbus_data smbus_data;
    int rc;
    uint8_t len = buf[0];

    if (len > (I2C_SMBUS_BLOCK_MAX+1))
    {
        log<level::ERR>("Invalid length",
                        phosphor::logging::entry("read_write= %u, len=%u",
                        read_write, len));
        return ipmi::ccReqDataLenInvalid;
    }

    if ((rc = ::ioctl(i2cdev, I2C_SLAVE, slaveAddr)) < 0)
    {
        log<level::ERR>("Failed to acquire bus access",
                        phosphor::logging::entry("read_write=%u, len=%u, slaveAddr=0x%x, rc=%d",
                        read_write, len, slaveAddr, rc));
        return ipmi::ccDestinationUnavailable;
    }

    smbus_data.block[0] = len;

    if (read_write != I2C_SMBUS_READ)
    {
        for(int i = 1; i < (len+1); i++)
        {
            smbus_data.block[i] = buf[i];
        }
    }

    ioctl_data.read_write = read_write;
    ioctl_data.command = devAddr;
    ioctl_data.size = I2C_SMBUS_I2C_BLOCK_DATA;
    ioctl_data.data = &smbus_data;

    rc = ::ioctl(i2cdev, I2C_SMBUS, &ioctl_data);
    if (rc < 0)
    {
        log<level::ERR>("Failed to access I2C_SMBUS Read/Write",
                        phosphor::logging::entry("read_write=%u, len=%u, slaveAddr=0x%x, devAddr=0x%x, rc=%d",
                        read_write, len, slaveAddr, devAddr, rc));
        return ipmi::ccDestinationUnavailable;
    }

    if (read_write == I2C_SMBUS_READ)
    {
        buf[0] = smbus_data.block[0];
        for(int i = 1; i < (len+1); i++)
        {
            // Skip the first byte, which is the length of the rest of the block.
            buf[i] = smbus_data.block[i];
        }
    }

    return ipmi::ccSuccess;
}

ipmi::RspType<uint8_t, std::vector<uint8_t>>
ipmiPSUInventoryInfo(uint8_t psuNum, uint8_t psuInfoSelector)
{

    std::array<uint8_t, 4> psuCmd = {0x9E, 0x9A, 0x99, 0x9B};
    std::array<uint8_t, 4> psuInfoLen = {0x0D, 0x0C, 0x06, 0x06};
    std::array<uint8_t, 3> slaveAddress = {0x40, 0x41, 0x42};
    std::vector<uint8_t> dataReceived;
    int size = I2C_SMBUS_I2C_BLOCK_DATA;
    uint8_t bus = 3;

    if (psuNum > 5)
    {
        log<level::ERR>("Invalid psuNum",
                        phosphor::logging::entry("psuNum=%u", psuNum));
        return ipmi::responseInvalidFieldRequest();
    }
    else
    {
        if (psuNum < 3)
        {
            bus = 4;
        }
        else
        {
            bus = 3;
        }
    }

    // psuInfoSelector
    // 0 = Serial Number
    // 1 = Part Number
    // 2 = Vendor
    // 3 = Model
    if (psuInfoSelector > 3)
    {
        log<level::ERR>("Invalid psuInfoSelector",
                        phosphor::logging::entry("psuInfoSelector=%u",
                        psuInfoSelector));
        return ipmi::responseInvalidFieldRequest();
    }

    std::string i2cBus = "/dev/i2c-" + std::to_string(bus);

    // Open the i2c device, for low-level combined data write/read
    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        log<level::ERR>("Failed to open i2c bus",
                        phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
        return ipmi::responseInvalidFieldRequest();
    }

    // psuNum range is 0 to 5.  Under each mux channel number is 0 to 2
    // Select mux channel first: i2cMux@0x70 device_address@0x04
    // chanel_number is bit 0 and 1 ith bit 2 as enable bit in data_byte=000001xx
    uint8_t muxData[2] = {0};
    muxData[0] = 1;
    muxData[1] = (0x04 | (psuNum % 3));
    auto retI2C = i2cSMBusWriteRead(i2cDev, 0x70, 0x04, I2C_SMBUS_WRITE,
                                    muxData);
    if (retI2C != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed doing i2c SMBus Write to set channel to the MUX",
                        phosphor::logging::entry("BUS=%s, muxData[0]=0x%x",
                        i2cBus.c_str(), muxData[0]));
        ::close(i2cDev);
        return ipmi::response(retI2C);
    }

    uint8_t psuInfoBuf[I2C_SMBUS_BLOCK_MAX+1] = {0};
    psuInfoBuf[0] = psuInfoLen[psuInfoSelector];
    retI2C = i2cSMBusWriteRead(i2cDev, slaveAddress[(psuNum % 3)],
                               psuCmd[psuInfoSelector], I2C_SMBUS_READ,
                               psuInfoBuf);
    ::close(i2cDev);

    if (retI2C != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed doing i2c SMBus Read of psu_info",
                        phosphor::logging::entry("BUS=%s, slaveAddress[%u]=0x%x, psuCmd[%u]=0x%x, psuInfoLen[%u]=%u",
                        i2cBus.c_str(), (psuNum % 3),
                        slaveAddress[(psuNum % 3)], psuInfoSelector,
                        psuCmd[psuInfoSelector], psuInfoSelector,
                        psuInfoLen[psuInfoSelector]));
        return ipmi::response(retI2C);
    }

    for (int i = 1; i < (psuInfoBuf[0] + 1); i++)
    {
        dataReceived.emplace_back(psuInfoBuf[i]);
    }

    return ipmi::responseSuccess(psuInfoSelector, dataReceived);
}

} // namespace ipmi

void registerNvOemFunctions()
{
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdSystemFactoryReset));

    // <BMC Factory Reset>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdSystemFactoryReset,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiSystemFactoryReset);

    // <PSU Inventory Info>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::nvidia::netFnOemGlobal),
        entry("Cmd:[%02Xh]", ipmi::nvidia::app::cmdPSUInventoryInfo));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::nvidia::netFnOemGlobal,
                          ipmi::nvidia::app::cmdPSUInventoryInfo,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiPSUInventoryInfo);
    return;
}

