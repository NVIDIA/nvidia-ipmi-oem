#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/types.h>
#include <stddef.h>
#include <sys/ioctl.h>

/*
 * Data for SMBus Messages
 */
#define I2C_SMBUS_BLOCK_MAX 32 /* As specified in SMBus standard */
#define I2C_DATA_MAX 256

/* smbus_access read or write markers */
#define I2C_SMBUS_READ 1
#define I2C_SMBUS_WRITE 0

/* SMBus transaction types (size parameter in the above functions)
   Note: these no longer correspond to the (arbitrary) PIIX4 internal codes! */
#define I2C_SMBUS_BYTE_DATA 2

/* NOTE: Slave address is 7 or 10 bits, but 10-bit addresses
 * are NOT supported! (due to code brokenness)
 */
#define I2C_SLAVE 0x0703 /* Use this slave address */
#define I2C_SLAVE_FORCE 0x0706
#define I2C_SMBUS 0x0720 /* SMBus transfer */

static inline __s32 i2c_smbus_access(int file, char read_write, __u8 command,
                                     int size, union i2c_smbus_data* data)
{
    struct i2c_smbus_ioctl_data args;

    args.read_write = read_write;
    args.command = command;
    args.size = size;
    args.data = data;
    return ioctl(file, I2C_SMBUS, &args);
}

static inline __s32 i2c_smbus_write_byte_data(int file, __u8 command,
                                              __u8 value)
{
    union i2c_smbus_data data;
    data.byte = value;
    return i2c_smbus_access(file, I2C_SMBUS_WRITE, command, I2C_SMBUS_BYTE_DATA,
                            &data);
}

static inline __s32 i2c_smbus_read_byte_data(int file, __u8 command)
{
    union i2c_smbus_data data;
    if (i2c_smbus_access(file, I2C_SMBUS_READ, command, I2C_SMBUS_BYTE_DATA,
                         &data))
        return -1;
    else
        return 0x0FF & data.byte;
}
