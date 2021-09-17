#include "smbus.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <iostream>
#include <mutex>

#include "i2c.h"

#define MAX_I2C_BUS 30

static int fd[MAX_I2C_BUS] = {0};

namespace phosphor
{
namespace smbus
{

std::mutex gMutex;

int phosphor::smbus::Smbus::open_i2c_dev(int i2cbus, char* filename,
                                         size_t size, int quiet)
{
    int file;

    snprintf(filename, size, "/dev/i2c/%d", i2cbus);
    filename[size - 1] = '\0';
    file = open(filename, O_RDWR);

    if (file < 0 && (errno == ENOENT || errno == ENOTDIR))
    {
        sprintf(filename, "/dev/i2c-%d", i2cbus);
        file = open(filename, O_RDWR);
    }

    if (file < 0 && !quiet)
    {
        if (errno == ENOENT)
        {
            fprintf(stderr,
                    "Error: Could not open file "
                    "`/dev/i2c-%d' or `/dev/i2c/%d': %s\n",
                    i2cbus, i2cbus, strerror(ENOENT));
        }
        else
        {
            fprintf(stderr,
                    "Error: Could not open file "
                    "`%s': %s\n",
                    filename, strerror(errno));
            if (errno == EACCES)
                fprintf(stderr, "Run as root?\n");
        }
    }

    return file;
}

int phosphor::smbus::Smbus::smbusInit(int smbus_num)
{
    int res = 0;
    char filename[20];

    gMutex.lock();

    fd[smbus_num] = open_i2c_dev(smbus_num, filename, sizeof(filename), 0);
    if (fd[smbus_num] < 0)
    {
        gMutex.unlock();

        return -1;
    }

    res = fd[smbus_num];

    gMutex.unlock();

    return res;
}

void phosphor::smbus::Smbus::smbusClose(int smbus_num)
{
    close(fd[smbus_num]);
}

int phosphor::smbus::Smbus::set_slave_addr(int file, int address, int force)
{
    /* With force, let the user read from/write to the registers
       even when a driver is also running */
    if (ioctl(file, force ? I2C_SLAVE_FORCE : I2C_SLAVE, address) < 0)
    {
        fprintf(stderr, "Error: Could not set address to 0x%02x: %s\n", address,
                strerror(errno));
        return -errno;
    }

    return 0;
}

int phosphor::smbus::Smbus::SetSmbusCmdByte(int smbus_num, int8_t device_addr,
                                            int8_t smbuscmd, int8_t data)
{
    int res;

    gMutex.lock();
    if (fd[smbus_num] > 0)
    {
        res = set_slave_addr(fd[smbus_num], device_addr, I2C_SLAVE_FORCE);
        if (res < 0)
        {
            fprintf(stderr,
                    "set PMBUS BUS%d to slave address 0x%02X failed (%s)\n",
                    smbus_num, device_addr, strerror(errno));
            close(fd[smbus_num]);

            gMutex.unlock();
            return -1;
        }
    }

    res = i2c_smbus_write_byte_data(fd[smbus_num], smbuscmd, data);
    if (res < 0)
    {
        fprintf(stderr, "Error: Read failed\n");
        gMutex.unlock();

        return -1;
    }

    gMutex.unlock();
    return res;
}

int phosphor::smbus::Smbus::GetSmbusCmdByte(int smbus_num, int8_t device_addr,
                                            int8_t smbuscmd)
{
    int res;

    gMutex.lock();
    if (fd[smbus_num] > 0)
    {
        res = set_slave_addr(fd[smbus_num], device_addr, I2C_SLAVE_FORCE);

        if (res < 0)
        {
            fprintf(stderr,
                    "set PMBUS BUS%d to slave address 0x%02X failed (%s)\n",
                    smbus_num, device_addr, strerror(errno));
            close(fd[smbus_num]);

            gMutex.unlock();
            return -1;
        }
    }

    res = i2c_smbus_read_byte_data(fd[smbus_num], smbuscmd);
    if (res < 0)
    {
        fprintf(stderr, "Error: Read failed\n");
        gMutex.unlock();

        return -1;
    }

    gMutex.unlock();
    return res;
}

} // namespace smbus
} // namespace phosphor
