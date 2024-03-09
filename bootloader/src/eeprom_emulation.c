#include <hardware/flash.h>
#include <hardware/sync.h>
#include <stdint.h>
#include "headers/essential.h"
#include "headers/eeprom_emulation.h"
#include <string.h>
#include "headers/random.h"
#include <stdio.h>
#include <stdlib.h>
#include "headers/log.h"

/*
Thanks
https://github.com/earlephilhower/arduino-pico/blob/1fd0b0404d9b1e21ee803c39fb560652b9f8b1ac/libraries/EEPROM/EEPROM.cpp
for inspiration
*/

/* have to have this size */
// uint8_t EEPROM_EMULATION_DATA[EEPROM_EMULATION_END_ADDRESS-EEPROM_EMULATION_START_ADDRESS];
uint8_t EEPROM_EMULATION_DATA[FLASH_SECTOR_SIZE];
/**/

const uint8_t *eeprom_target_contents = (const uint8_t *)(XIP_BASE + EEPROM_EMULATION_START_ADDRESS);

int eeprom_emulation_get_size()
{
    return EEPROM_EMULATION_END_ADDRESS - EEPROM_EMULATION_START_ADDRESS;
}

int eeprom_emulation_write_byte(uint32_t address, uint8_t data)
{
    uint8_t data_[1] = {data};
    int err = eeprom_emulation_write_block(address, data_, 1);
    if (err)
    {
        return err;
    }
    // int err;
    // /* get page of that address and rewrite the page */

    // /* get page's number */

    // uint32_t sector_number = address / FLASH_SECTOR_SIZE;

    // /* read page */
    // // char aa[256];
    // err = eeprom_emulation_read_sector(sector_number, EEPROM_EMULATION_DATA);
    // // err = eeprom_emulation_read_page(page_number,aa);
    // if (err)
    // {
    //     return err;
    // }

    // /* write data to address */
    // // EEPROM_EMULATION_DATA[address&0xff] = data;
    // EEPROM_EMULATION_DATA[address % FLASH_SECTOR_SIZE] = data;
    // // EEPROM_EMULATION_DATA[address] = data;
    // // aa[address&0xff] = data;

    // err = eeprom_emulation_write_sector(sector_number, EEPROM_EMULATION_DATA);
    // // err = eeprom_emulation_write_page(page_number,aa);
    // if (err)
    // {
    //     return err;
    // }
    return SW_OK;
}

int eeprom_emulation_read_byte(uint32_t address, uint8_t *data)
{
    int err;
    *data = eeprom_target_contents[address];
    return SW_OK;
}

int eeprom_emulation_read_block(uint32_t address, uint8_t *out, uint32_t size)
{
    memcpy(out, eeprom_target_contents + address, size);
    return SW_OK;
}

int eeprom_emulation_write_block(uint32_t address, uint8_t *data, uint32_t d_size)
{

    if (d_size > eeprom_emulation_get_size())
    {
        log_loge(EEPROM_EMULATION_TAG,"block size is not allowed to be more than eeprom size");
        return SW_ERROR;
    }

    /* get total pages */

    // uint32_t total_sectors = (d_size / FLASH_SECTOR_SIZE) + 1;

    uint32_t total_sectors;

    /* get remaning bytes in the sector */

    uint32_t sector_boundary_address = address + (FLASH_SECTOR_SIZE - (address % FLASH_SECTOR_SIZE)) - 1;

    log_logv(EEPROM_EMULATION_TAG,"sector_boundary_address: %d", sector_boundary_address);

    if ((sector_boundary_address - address + 1) < d_size)
    {
        total_sectors = 2 + ((d_size - (sector_boundary_address - address + 1)) / FLASH_SECTOR_SIZE);
    }
    else
    {
        total_sectors = 1;
    }

    /* if theres offset than adjust sector numbers accordinly */
    // if (address + d_size > FLASH_SECTOR_SIZE) {
    //     total_sectors = ((address + d_size) / FLASH_SECTOR_SIZE) + 1;
    // }
    log_logv(EEPROM_EMULATION_TAG,"total sectors: %d", total_sectors);
    int i, err;
    uint32_t address_ = address;
    uint32_t page_number = address_ / FLASH_PAGE_SIZE;
    uint32_t sector_number = address_ / FLASH_SECTOR_SIZE;
    uint32_t size_to_execute = d_size;
    uint32_t size_executed = 0;
    /* write sector by sector */
    for (i = sector_number; i < sector_number + total_sectors; i++)
    {

        log_logv(EEPROM_EMULATION_TAG,"writing sector: %d", i);
        /* prepare size to execute */

        // if (((address % FLASH_SECTOR_SIZE) + size_to_execute) > FLASH_SECTOR_SIZE)
        if ((d_size - size_executed) > (((i + 1) * FLASH_SECTOR_SIZE) - address_))
        {
            size_to_execute = ((i + 1) * FLASH_SECTOR_SIZE) - address_;
            // size_to_execute = address + (FLASH_SECTOR_SIZE-(address%FLASH_SECTOR_SIZE)) - 1;
        }

        log_logv(EEPROM_EMULATION_TAG,"size to execute: %d", size_to_execute);

        /* read sector */
        err = eeprom_emulation_read_sector(i, EEPROM_EMULATION_DATA);
        if (err)
        {
            return err;
        }

        log_logv(EEPROM_EMULATION_TAG,"executed: %d", size_executed);
        log_logv(EEPROM_EMULATION_TAG,"address_: %d", address_);

        /* write data to address */
        memcpy(EEPROM_EMULATION_DATA + (address_ % FLASH_SECTOR_SIZE), data + (size_executed), size_to_execute);
        /* flash erase*/

        err = eeprom_emulation_write_sector(i, EEPROM_EMULATION_DATA);
        if (err)
        {
            return err;
        }
        /* change address and size */
        // address_ = (i + 1) * FLASH_SECTOR_SIZE;
        address_ += size_to_execute;
        // data += (uint8_t*)size_to_execute;
        size_executed += size_to_execute;
        size_to_execute = d_size - size_to_execute;
    }

    /**/

    return SW_OK;
}

int eeprom_emulation_write_page(uint32_t page_number, uint8_t *data)
{

    /* get sector number */
    uint32_t sector_number = page_number / (FLASH_SECTOR_SIZE / FLASH_PAGE_SIZE);

    /* */
    int i, err;

    /* copy all pages in sector to RAM */
    for (i = 0; i < (FLASH_SECTOR_SIZE / FLASH_PAGE_SIZE); i++)
    {
        if (page_number % (FLASH_SECTOR_SIZE / FLASH_PAGE_SIZE) == i)
        {
            
            continue;
        }
        err = eeprom_emulation_read_page(sector_number + i, EEPROM_EMULATION_DATA + (i * FLASH_PAGE_SIZE));
        if (err)
        {
            return err;
        }
    }
    /**/

    // erase sectors
    flash_range_erase(EEPROM_EMULATION_START_ADDRESS + (sector_number * FLASH_SECTOR_SIZE), FLASH_SECTOR_SIZE);
    /**/

    /* copy new page */

    // memcpy(EEPROM_EMULATION_DATA+((page_number%(FLASH_SECTOR_SIZE/FLASH_PAGE_SIZE))*FLASH_PAGE_SIZE),data,FLASH_PAGE_SIZE);

    /* copy all pages */

    for (i = 0; i < (FLASH_SECTOR_SIZE / FLASH_PAGE_SIZE); i++)
    {
        flash_range_program(EEPROM_EMULATION_START_ADDRESS + (sector_number * FLASH_SECTOR_SIZE) + (i * FLASH_PAGE_SIZE), EEPROM_EMULATION_DATA + (i * FLASH_PAGE_SIZE), FLASH_PAGE_SIZE);
    }

    // noInterrupts();

    return SW_OK;
}

int eeprom_emulation_read_page(uint32_t page_number, uint8_t *out)
{
    memcpy(out, (const uint8_t *)(XIP_BASE + EEPROM_EMULATION_START_ADDRESS) + (page_number * FLASH_PAGE_SIZE), FLASH_PAGE_SIZE);
    return SW_OK;
}

int eeprom_emulation_erase_page(uint32_t page_number)
{
    memset(EEPROM_EMULATION_DATA, 0xff, FLASH_PAGE_SIZE);
    flash_range_program(EEPROM_EMULATION_START_ADDRESS + (page_number * FLASH_PAGE_SIZE), EEPROM_EMULATION_DATA, FLASH_PAGE_SIZE);
    return SW_OK;
}

int eeprom_emulation_erase_sector(uint32_t sector_number)
{
    flash_range_erase(EEPROM_EMULATION_START_ADDRESS + (sector_number * FLASH_SECTOR_SIZE), FLASH_SECTOR_SIZE);
    return SW_OK;
}

int eeprom_emulation_read_sector(uint32_t sector_number, uint8_t *out)
{
    memcpy(out, (const uint8_t *)(XIP_BASE + EEPROM_EMULATION_START_ADDRESS) + (sector_number * FLASH_SECTOR_SIZE), FLASH_SECTOR_SIZE);
    return SW_OK;
}

int eeprom_emulation_write_sector(uint32_t sector_number, uint8_t *data)
{

    int i;
    uint32_t ints = save_and_disable_interrupts();

    log_logv(EEPROM_EMULATION_TAG,"erasing flash sector: %d", i);
    flash_range_erase(EEPROM_EMULATION_START_ADDRESS + (sector_number * FLASH_SECTOR_SIZE), FLASH_SECTOR_SIZE);
    log_logv(EEPROM_EMULATION_TAG,"flash erased");

    for (i = 0; i < (FLASH_SECTOR_SIZE / FLASH_PAGE_SIZE); i++)
    {
        flash_range_program(EEPROM_EMULATION_START_ADDRESS + (sector_number * FLASH_SECTOR_SIZE) + (i * FLASH_PAGE_SIZE), data + (i * FLASH_PAGE_SIZE), FLASH_PAGE_SIZE);
    }
    restore_interrupts(ints);
    return SW_OK;
}

int eeprom_emulation_write_zeroes()
{
    int err;
    log_logv(EEPROM_EMULATION_TAG,"writing 0s on eeprom");
    memset(EEPROM_EMULATION_DATA, 0, FLASH_SECTOR_SIZE);
    uint32_t number_of_sectors = (eeprom_emulation_get_size() / FLASH_SECTOR_SIZE) + 1;
    int i;
    for (i = 0; i < number_of_sectors; i++)
    {
        err = eeprom_emulation_write_sector(i, EEPROM_EMULATION_DATA);
        if (err)
        {
            return err;
        }
    }
    log_logv(EEPROM_EMULATION_TAG,"writing 0s on eeprom DONE!");
    return SW_OK;
}

int eeprom_emulation_test()
{

    int eeprom_size = eeprom_emulation_get_size();
    int EEPROM_BUFF[eeprom_size];
    int i;
    uint32_t seed_ = random_get_uint32();
    log_logv(EEPROM_EMULATION_TAG,"using seed: %d", seed_);
    srand(seed_);

    log_logv(EEPROM_EMULATION_TAG,"now writing eeprom");
    for (i = 0; i < eeprom_size; i++)
    {
        uint8_t randn = rand();
        log_logv(EEPROM_EMULATION_TAG,"writing at address: %d with %d", i, randn);
        EEPROM_BUFF[i] = randn;
        eeprom_emulation_write_byte(i, EEPROM_BUFF[i]);
    }
    log_logv(EEPROM_EMULATION_TAG,"now verifing eeprom");
    int err = 0;
    uint8_t out;
    for (i = 0; i < eeprom_size; i++)
    {
        eeprom_emulation_read_byte(i, &out);
        log_logv(EEPROM_EMULATION_TAG,"reading at address: %d read: %d", i, out);
        if (out != EEPROM_BUFF[i])
        {
            err = 1;
            break;
        }
    }
    if (err)
    {
        log_loge(EEPROM_EMULATION_TAG,"eeprom emulation verify failed!!");
        return SW_ERROR;
    }
    log_logv(EEPROM_EMULATION_TAG,"eeprom emulation successfully verified!!");
    return SW_OK;
}