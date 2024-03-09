#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hardware/flash.h>
#include <hardware/sync.h>
#include <inttypes.h>
#include <stdint.h>

#include "../headers/defines.h"
#include "../headers/eeprom_emulation.h"
#include "../headers/eeprom_emulation.h"
#include "../headers/eeprom_hardware.h"
#include "../headers/storage.h"
#include "../headers/log.h"


int storage_init()
{
    int err;
    uint8_t ret;

#ifdef STORAGE_SDCARD_ENABLED
    err = sdcard_init();
    if (err)
    {
        log_loge(STORAGE_TAG, "failed to init sd card");
        return;
    }
#else
    /* check if its first run */
    err = storage_read_u8(STORAGE_FIRST_RUN_INIT_ADDRESS, &ret);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "First run read failed");
        return SW_ERROR;
    }
    if (ret == '1')
    {
        log_logi(STORAGE_TAG, "storage already initialised");
        return SW_OK;
    }
    /* if its first run then write zeroes on the entire eeprom */
    err = storage_write_zeroes();
    if (err)
    {
        log_loge(STORAGE_TAG, "storage failed!");
        return err;
    }

    /* now write to mark that storage has been initialised */
    err = storage_write_u8(STORAGE_FIRST_RUN_INIT_ADDRESS, '1');
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "First run write failed");
        return SW_ERROR;
    }
#endif

    return SW_OK;
}

int storage_write_zeroes()
{
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_zeroes();
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_zeroes();
    return err;
#endif
    return SW_OK;
}

int storage_write_u8(uint32_t addr, uint8_t val)
{
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_byte(addr, val);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_byte((uint16_t)addr, val);
    return err;
#endif

    return SW_ERROR;
}

int storage_write_u16(uint32_t addr, uint16_t val)
{
    uint8_t data[] = {(val >> 8) & 0xff, val & 0xff};

    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_block(addr, data, 2);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_block((uint16_t)addr, data, 2);
    return err;
#endif

    return SW_ERROR;
}

int storage_write_u32(uint32_t addr, uint32_t val)
{

    uint8_t data[] = {(val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff};

    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_block(addr, data, 4);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_block((uint16_t)addr, data, 4);
    return err;
#endif

    return SW_ERROR;
}

int storage_write_u64(uint32_t addr, uint64_t val)
{

    uint8_t data[] = {(val >> 56) & 0xff, (val >> 48) & 0xff, (val >> 40) & 0xff, (val >> 32) & 0xff, (val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff};

    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_block(addr, data, 8);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_block((uint16_t)addr, data, 8);
    return err;
#endif

    return SW_ERROR;
}

int storage_read_u8(uint32_t addr, uint8_t *val)
{
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_read_byte(addr, val);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_read_random_byte((uint16_t)addr, val);
    return err;
#endif
    return SW_OK;
}

int storage_read_u16(uint32_t addr, uint16_t *val)
{

    uint8_t data[2];

    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_read_block(addr, data, 2);
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_read_block((uint16_t)addr, data, 2);
#endif

    if (err)
    {
        return err;
    }

    *val = ((uint16_t)data[0] << 8) | ((uint16_t)data[1]);
    return SW_OK;
}

int storage_read_u32(uint32_t addr, uint32_t *val)
{
    uint8_t data[4];
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_read_block(addr, data, 4);
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_read_block((uint16_t)addr, data, 4);
#endif

    if (err)
    {
        return err;
    }
    *val = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | (uint32_t)(data[3]);
    return SW_OK;
}

int storage_read_u64(uint32_t addr, uint64_t *val)
{

    uint8_t data[8];
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_read_block(addr, data, 8);
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_read_block((uint16_t)addr, data, 8);
#endif

    if (err)
    {
        return err;
    }
    *val = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | (uint64_t)(data[7]);
    return SW_OK;
}

int storage_write_block(uint32_t addr, uint8_t *data, uint32_t data_size)
{
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_write_block(addr, data, data_size);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_write_block((uint16_t)addr, data, data_size);
    return err;
#endif

    return SW_ERROR;
}

int storage_read_block(uint32_t addr, uint8_t *buff, uint32_t buff_size)
{
    int err;
#ifdef STORAGE_USE_EMULATION
    err = eeprom_emulation_read_block(addr, buff, buff_size);
    return err;
#endif
#ifdef STORAGE_USE_HARDWARE
    err = eeprom_hardware_read_block((uint16_t)addr, buff, buff_size);
    return err;
#endif

    return SW_ERROR;
}

int storage_counter_write_u8(uint32_t addr, uint32_t counter_addr, uint8_t val)
{

    /*
     * first 8 bytes after address is data
     * second 8 bytes after data end are counter of 4 bytes each
     */

    //
    uint32_t i = 0, err;

    uint32_t lowest_counter_index = 0;
    uint32_t lowest_counter = 4294967295;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, L: %" PRIu32 "", i, counter, lowest_counter);
        if (counter < lowest_counter)
        {
            lowest_counter = counter;
            lowest_counter_index = i;
        }
    }

    /* increment the counter */
    err = storage_write_u32(counter_addr + (lowest_counter_index * 4), lowest_counter + 1);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing counter %" PRIu32 "", lowest_counter + 1);
        return err;
    }

    err = storage_write_u8(addr + (lowest_counter_index), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_write_u16(uint32_t addr, uint32_t counter_addr, uint16_t val)
{

    /*
     * first 8 bytes after address is data
     * second 8 bytes after data end are counter of 4 bytes each
     */

    //
    uint32_t i = 0, err;

    uint32_t lowest_counter_index = 0;
    uint32_t lowest_counter = 4294967295;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, L: %" PRIu32 "", i, counter, lowest_counter);
        if (counter < lowest_counter)
        {
            lowest_counter = counter;
            lowest_counter_index = i;
        }
    }

    /* increment the counter */
    err = storage_write_u32(counter_addr + (lowest_counter_index * 4), lowest_counter + 1);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing counter %" PRIu32 "", lowest_counter + 1);
        return err;
    }

    err = storage_write_u16(addr + (lowest_counter_index * 2), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_read_u8(uint32_t addr, uint32_t counter_addr, uint8_t *val)
{

    uint32_t i = 0, err;

    uint32_t highest_counter_index = 0;
    uint32_t highest_counter = 0;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, H: %" PRIu32 "", i, counter, highest_counter);
        if (counter >= highest_counter)
        {
            highest_counter = counter;
            highest_counter_index = i;
        }
    }

    log_logv(STORAGE_TAG, "Reading from index %d", highest_counter_index);

    /* get the value */
    log_logv(STORAGE_TAG, "READING: %d", addr + (highest_counter_index));

    err = storage_read_u8(addr + (highest_counter_index), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while reading FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_read_u16(uint32_t addr, uint32_t counter_addr, uint16_t *val)
{

    uint32_t i = 0, err;

    uint32_t highest_counter_index = 0;
    uint32_t highest_counter = 0;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, H: %" PRIu32 "", i, counter, highest_counter);
        if (counter >= highest_counter)
        {
            highest_counter = counter;
            highest_counter_index = i;
        }
    }

    log_logv(STORAGE_TAG, "Reading from index %d", highest_counter_index);

    /* get the value */

    err = storage_read_u16(addr + (highest_counter_index * 2), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while reading FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_write_u32(uint32_t addr, uint32_t counter_addr, uint32_t val)
{

    /*
     * first 8 bytes after address is data
     * second 8 bytes after data end are counter of 4 bytes each
     */

    //
    uint32_t i = 0, err;

    uint32_t lowest_counter_index = 0;
    uint32_t lowest_counter = 4294967295;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, L: %" PRIu32 "", i, counter, lowest_counter);
        if (counter < lowest_counter)
        {
            lowest_counter = counter;
            lowest_counter_index = i;
        }
    }

    /* increment the counter */
    err = storage_write_u32(counter_addr + (lowest_counter_index * 4), lowest_counter + 1);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing counter %" PRIu32 "", lowest_counter + 1);
        return err;
    }

    err = storage_write_u32(addr + (lowest_counter_index * 4), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_write_u64(uint32_t addr, uint32_t counter_addr, uint64_t val)
{

    /*
     * first 8 bytes after address is data
     * second 8 bytes after data end are counter of 4 bytes each
     */

    //
    uint32_t i = 0, err;

    uint32_t lowest_counter_index = 0;
    uint32_t lowest_counter = 4294967295;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, L: %" PRIu32 "", i, counter, lowest_counter);
        if (counter < lowest_counter)
        {
            lowest_counter = counter;
            lowest_counter_index = i;
        }
    }

    /* increment the counter */
    err = storage_write_u32(counter_addr + (lowest_counter_index * 4), lowest_counter + 1);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing counter %" PRIu32 "", lowest_counter + 1);
        return err;
    }

    err = storage_write_u64(addr + (lowest_counter_index * 8), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while writing FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_read_u32(uint32_t addr, uint32_t counter_addr, uint32_t *val)
{

    uint32_t i = 0, err;

    uint32_t highest_counter_index = 0;
    uint32_t highest_counter = 0;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, H: %" PRIu32 "", i, counter, highest_counter);
        if (counter >= highest_counter)
        {
            highest_counter = counter;
            highest_counter_index = i;
        }
    }

    log_logv(STORAGE_TAG, "Reading from index %d", highest_counter_index);

    /* get the value */

    err = storage_read_u32(addr + (highest_counter_index * 4), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while reading FM");
        return err;
    }

    return SW_OK;
}

int storage_counter_read_u64(uint32_t addr, uint32_t counter_addr, uint64_t *val)
{

    uint32_t i = 0, err;

    uint32_t highest_counter_index = 0;
    uint32_t highest_counter = 0;
    uint32_t counter;

    for (i = 0; i < 8; i++)
    {
        err = storage_read_u32(counter_addr + (i * 4), &counter);
        if (err != SW_OK)
        {
            log_loge(STORAGE_TAG, "error while reading");
            return err;
        }
        log_logv(STORAGE_TAG, "i: %d, C: %d, H: %" PRIu32 "", i, counter, highest_counter);
        if (counter >= highest_counter)
        {
            highest_counter = counter;
            highest_counter_index = i;
        }
    }

    log_logv(STORAGE_TAG, "Reading from index %d", highest_counter_index);

    /* get the value */

    err = storage_read_u64(addr + (highest_counter_index * 8), val);
    if (err != SW_OK)
    {
        log_loge(STORAGE_TAG, "error while reading FM");
        return err;
    }

    return SW_OK;
}

// add checksum based storage functions for counter and non counter methods