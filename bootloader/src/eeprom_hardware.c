#include <stdio.h>
#include "pico/stdlib.h"
#include <stdlib.h>
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "task.h"
#include "headers/essential.h"
#include "hardware/watchdog.h"
#include "headers/communication.h"
#include "headers/i2c.h"
#include "headers/debug.h"
#include "headers/flash.h"
#include "headers/atecc.h"
#include "headers/eeprom_hardware.h"
#include <string.h>
#include "headers/essential.h"

int eeprom_hardware_write_zeroes() {
    return SW_OK;
}

int eeprom_hardware_write_byte(uint16_t addr, uint8_t data)
{
    if (addr > 4095)
    {
        return -1;
    }
    uint8_t command[3];
    command[0] = (addr >> 8) & 0xff;
    command[1] = (addr >> 0) & 0xff;
    command[2] = data;

    int err;
    err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, command, 3);

    return err;
}

int eeprom_hardware_write_block(uint16_t addr, uint8_t *data, uint8_t data_len)
{
    if (addr > 4095)
    {
        return -1;
    }

    if (data_len > 32)
    {
        return -1;
    }

    if (addr % 32 != 0)
    {
        return -1;
    }

    uint8_t *final_command;
    final_command = (uint8_t *)calloc(data_len + 2, sizeof(uint8_t));

    final_command[0] = (addr >> 8) & 0xff;
    final_command[1] = (addr >> 0) & 0xff;
    memcpy(final_command + 2, data, data_len);

    int err;
    err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, final_command, 2 + data_len);

    free(final_command);

    return SW_OK;
}

int eeprom_hardware_read_byte(uint8_t *data)
{
    uint8_t ret[1];
    int err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, ret, 1);
    if (err)
    {
        return err;
    }
    *data = ret[0];
    return SW_OK;
}

int eeprom_hardware_read_random_byte(uint16_t addr, uint8_t *data)
{
    if (addr > 4095)
    {
        return -1;
    }
    uint8_t command[2];
    command[0] = (addr >> 8) & 0xff;
    command[1] = (addr >> 0) & 0xff;
    int err;
    err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, command, 2);
    if (err)
    {
        return err;
    }
    uint8_t ret[1];
    err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, ret, 1);
    if (err)
    {
        return err;
    }
    *data = ret[0];
    return SW_OK;
}

int eeprom_hardware_read_block(uint16_t addr, uint8_t *data, uint8_t data_len)
{
    if (addr > 4095)
    {
        return -1;
    }

    if (addr % 32 != 0)
    {
        return -1;
    }

    uint8_t command[2];
    command[0] = (addr >> 8) & 0xff;
    command[1] = (addr >> 0) & 0xff;
    int err;
    err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, command, 2);
    if (err)
    {
        return err;
    }
    err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, data, data_len);
    if (err)
    {
        return err;
    }
    return SW_OK;
}

int eeprom_hardware_read_byte_retry(uint8_t *data, uint16_t retries, uint16_t delay)
{
    uint8_t ret[1];
    int err;
    while (retries--)
    {
        err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, ret, 1);
        if (err)
        {
            sleep_ms(delay);
            continue;
        }
        *data = ret[0];
        return SW_OK;
    }
    return err;
}

int eeprom_hardware_read_random_byte_retry(uint16_t addr, uint8_t *data, uint16_t retries, uint16_t delay)
{
    if (addr > 4095)
    {
        return -1;
    }

    int err;
    bool write_done = false;
    while (retries--)
    {
        uint8_t command[2];
        command[0] = (addr >> 8) & 0xff;
        command[1] = (addr >> 0) & 0xff;
        if (!write_done)
        {
            err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, command, 2);
            if (err)
            {
                sleep_ms(delay);
                continue;
            }
            write_done = true;
        }
        uint8_t ret[1];
        err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, ret, 1);
        if (err)
        {
            sleep_ms(delay);
            continue;
        }
        *data = ret[0];
        return SW_OK;
    }
    return err;
}

int eeprom_hardware_read_block_retry(uint16_t addr, uint8_t *data, uint8_t data_len, uint16_t retries, uint16_t delay)
{
    if (addr > 4095)
    {
        return -1;
    }

    if (addr % 32 != 0)
    {
        return -1;
    }

    int err;
    bool write_done = false;

    while (retries--)
    {
        uint8_t command[2];
        command[0] = (addr >> 8) & 0xff;
        command[1] = (addr >> 0) & 0xff;
        if (!write_done)
        {
            err = i2c_write(EEPROM_HARDWARE_DEVICE_ADDRESS, command, 2);
            if (err)
            {
                sleep_ms(delay);
                continue;
            }
            write_done = true;
        }
        err = i2c_read(EEPROM_HARDWARE_DEVICE_ADDRESS, data, data_len);
        if (err)
        {
            sleep_ms(delay);
            continue;
        }
        return SW_OK;
    }
    return err;
}
