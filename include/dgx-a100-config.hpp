/**
 * Copyright © 2020 NVIDIA Corporation
 *
 * License Information here...
 */

#pragma once

#include <unistd.h>

namespace ipmi
{
namespace nvidia
{
/* PSU Information */
constexpr auto psuNumber = 6;
constexpr uint8_t psuAddr[psuNumber] = {0x40, 0x41, 0x42, 0x40, 0x41, 0x42};
constexpr uint8_t psuBus[psuNumber]  = {215, 216, 217, 218, 219, 220};

constexpr auto psuRegSerialNumber       = 0x9e;
constexpr auto psuRegSerialNumberLen    = 0x0D;
constexpr auto psuRegPartNumber         = 0x9A;
constexpr auto psuRegPartNumberLen      = 0x0C;
constexpr auto psuRegVendor             = 0x99;
constexpr auto psuRegVendorLen          = 0x06;
constexpr auto psuRegModel              = 0x9B;
constexpr auto psuRegModelLen           = 0x06;
constexpr auto psuRegFWVersion          = 0xE2;

constexpr auto fpgaI2cAddress           = 0x3c;
constexpr auto fpgaMbI2cBus             = 1;
constexpr auto fpgaMidI2cBus            = 2;
constexpr auto fpgaMbVersionAddr        = 0x00;
constexpr auto fpgaMidVersionAddr       = 0x2d;
constexpr auto fpgaMidWpReg             = 0x30;
constexpr auto fpgaMidPexSwWpReg        = 0x21;
constexpr auto fpgaMidWpMidBit          = 1;
constexpr auto fpgaMidWpIOELBit         = 4;
constexpr auto fpgaMidWpIOERBit         = 3;
constexpr auto fpgaMidWpPDB             = 0;
constexpr auto fpgaMidWpSw              = 2;
constexpr auto cecI2cAddress            = 0x55;
constexpr auto cecI2cBus                = 1;
constexpr auto cecI2cFwSlotReg          = 0x9B;
constexpr auto cecI2cVersionRegister    = 0x9c;
constexpr auto cecFpgaI2cBus            = 10;
constexpr auto cecFpgaI2cVersionRegister = 0x01;

constexpr uint8_t pexSwitchI2CBus[]     = {7, 9, 7, 9};
constexpr uint8_t pexSwitchI2CVersionAddress[] = {0x48, 0x49, 0x48, 0x49};
constexpr uint8_t pexSwitchVersionWrite[] = {0x04, 0x00, 0x3C, 0x84};

constexpr auto gpFpgaSmbpbiDeviceId         = 0; /* 0 indexed */
constexpr auto gbFpgaSmbpbiVersionOpcode    = 0x05;
constexpr auto gbFpgaSmbpbiVersionArg1      = 0x88;
constexpr auto gbFpgaSmbpbiWpOpcode         = 0xb4;
constexpr auto gbFpgaSmbpbiWpReadArg1       = 0xff;
constexpr auto gbFpgaSmbpbiWpMask           = 0x02;
constexpr auto gbFpgaSmbpbiWpWriteArg1      = 0x81;

constexpr auto mbWpGpioId                   = 55;
constexpr auto mbWpGpioChip                 = "gpiochip792";

} //namespace nvidia
} //namespace ipmi
