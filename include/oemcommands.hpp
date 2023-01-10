/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#pragma once

#include <cstdint>

namespace ipmi
{
namespace nvidia
{
constexpr auto netFnOemGlobal = 0x32;
constexpr auto netFnOemNV = 0x3C;
constexpr auto netFnOemPost = 0x30;
constexpr auto netGroupExt = 0x52;

namespace app
{
constexpr auto cmdSetBiosVersion = 0x10;
constexpr auto cmdSystemFactoryReset = 0x66;
constexpr auto cmdSetVendorFieldModeConfig = 0x67;
constexpr auto cmdGetVendorFieldModeConfig = 0x68;
constexpr auto cmdGetRshimState = 0x69;
constexpr auto cmdSetRshimState = 0x6A;
constexpr auto cmdPSUInventoryInfo = 0x0E;
constexpr auto cmdGetSELPolicy = 0x7E;
constexpr auto cmdSetSELPolicy = 0x7F;
constexpr auto cmdGetNTPConfig = 0xA7;
constexpr auto cmdSetNTPConfig = 0xA8;
constexpr auto cmdGetDNSConfig = 0x6B;
constexpr auto cmdSetDNSConfig = 0x6C;
constexpr auto cmdSetFanMode = 0x73;
constexpr auto cmdAllFanZonesPWMDuty = 0x74;
constexpr auto cmdSetFanZonePWMDuty = 0x75;
constexpr auto cmdGetBiosPostStatus = 0x25;
constexpr auto cmdGetBiosPostCode = 0xE9;
constexpr auto cmdI2CMasterReadWrite = 0x81;
constexpr auto cmdGetBiosPostCodeToIpmiMaxSize = 945;

} // namespace app

namespace misc
{
constexpr auto cmdGetOEMVersion = 0x01;
constexpr auto cmdGetFwBootupSlot = 0x03;
constexpr auto cmdSoftPowerCycle = 0x04;
constexpr auto cmdGetBMCBootComplete = 0x05;
constexpr auto cmdSMBPBIPassthrough = 0x09;
constexpr auto cmdSMBPBIPassthroughExtended = 0x0A;
constexpr auto cmdGetPSUInventory = 0x0E;
constexpr auto cmdGetDeviceFirmwareVersion = 0x0F;
constexpr auto cmdSensorScanEnable = 0x85;
constexpr auto cmdSetSSDLed = 0x63;
constexpr auto cmdGetSSDLed = 0x64;
constexpr auto cmdGetLedStatus = 0x65;
constexpr auto cmdGetWpStatus = 0x8A;
constexpr auto cmdSetWpStatus = 0x8B;
constexpr auto cmdGetPsuPower = 0x78;
constexpr auto cmdGetBiosBootupImage = 0x1E;
constexpr auto cmdGetBiosConfig = 0x21;
constexpr auto cmdGetBiosNextImage = 0x22;
constexpr auto cmdSetBiosNextImage = 0x23;
constexpr auto cmdGetBiosVerions = 0x24;
constexpr auto cmdSetBiosConfig = 0x25;
constexpr auto cmdGetUsbDescription = 0x30;
constexpr auto cmdGetUsbSerialNum = 0x31;
constexpr auto cmdGetRedfishHostName = 0x32;
constexpr auto cmdGetipmiChannelRfHi = 0x33;
constexpr auto cmdGetRedfishServiceUuid = 0x34;
constexpr auto cmdGetRedfishServicePort = 0x35;
constexpr auto cmdGetManagerCertFingerPrint = 0x01;
constexpr auto cmdGetBootStrapAcc = 0x02;
constexpr auto cmdGetMaxPMaxQConfiguration = 0x90;
constexpr auto cmdSetMaxPMaxQConfiguration = 0x91;

constexpr auto getFirmwareVersionDeviceMBFPGA = 0x00;
constexpr auto getFirmwareVersionDeviceGBFPGA = 0x01;
constexpr auto getFirmwareVersionDevicePSU0 = 0x02;
constexpr auto getFirmwareVersionDevicePSU1 = 0x03;
constexpr auto getFirmwareVersionDevicePSU2 = 0x04;
constexpr auto getFirmwareVersionDevicePSU3 = 0x05;
constexpr auto getFirmwareVersionDevicePSU4 = 0x06;
constexpr auto getFirmwareVersionDevicePSU5 = 0x07;
constexpr auto getFirmwareVersionDeviceMIDFPGA = 0x08;
constexpr auto getFirmwareVersionDeviceCEC = 0x09;
constexpr auto getFirmwareVersionDeviceFPGACEC = 0x0A;
constexpr auto getFirmwareVersionDevicePEXSwitch0 = 0x10;
constexpr auto getFirmwareVersionDevicePEXSwitch1 = 0x11;
constexpr auto getFirmwareVersionDevicePEXSwitch2 = 0x12;
constexpr auto getFirmwareVersionDevicePEXSwitch3 = 0x13;
constexpr auto getFirmwareVersionDeviceBMCActive = 0x20;
constexpr auto getFirmwareVersionDeviceBMCInactive = 0x21;

constexpr auto getWPTypePEX = 0x00;
constexpr auto getWPTypeFRU = 0x01;

constexpr auto getWPIdPexSW0 = 0x00;
constexpr auto getWPIdPexSW1 = 0x01;
constexpr auto getWPIdPexSW2 = 0x02;
constexpr auto getWPIdPexSW3 = 0x03;

constexpr auto getWPIdMB = 0x00;
constexpr auto getWPIdMid = 0x01;
constexpr auto getWPIdIOEL = 0x02;
constexpr auto getWpIdIOER = 0x03;
constexpr auto getWpIdPDB = 0x04;
constexpr auto getWpIdGB = 0x05;
constexpr auto getWPIdM2 = 0x06;
constexpr auto getWpIdSW = 0x07;

constexpr auto getSSDLedTypeReadyMove = 0x30;
constexpr auto getSSDLedTypeActivity = 0x31;
constexpr auto getSSDLedTypeFault = 0x32;

constexpr auto getSSDLedNLed = 8;

constexpr auto getLedStatusPowerLed = 0x00;
constexpr auto getLedStatusFaultLed = 0x01;
constexpr auto getLedStatusMotherBoardLed = 0x10;

constexpr auto biosConfigTypeNetwork = 0x01;
constexpr auto biosConfigTypeRedFish = 0x02;

constexpr auto getMaxPMaxQConfigurationMode = 0x00;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimit = 0x01;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitP = 0x02;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitQ = 0x03;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitMax = 0x04;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitMin = 0x05;
constexpr auto getMaxPMaxQConfigurationRestOfSytemPower = 0x06;

constexpr auto setMaxPMaxQConfigurationMode = 0x00;
constexpr auto setMaxPMaxQConfigurationCurrentPowerLimit = 0x01;

constexpr auto staticMode = 0x01;
constexpr auto maximumPerformanceMode = 0x01;
constexpr auto powerSavingMode = 0x02;
constexpr auto OemMode = 0x03;

constexpr uint8_t getMaskdata(int data, int position)
{
    return (data >> position * 8) & 0xff;
}

} // namespace misc

namespace chassis
{
} // namespace chassis
} // namespace nvidia
} // namespace ipmi

