#include <stdint.h>

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#define BOOTLOADER_TAG "BOOTLOADER"
#define BOOTLOADER_APP_NUM 3 // 0 the main app 1 and 2 OTA updates




// OPTIONS BITS
#define OPTIONS_APP_SIGNED_BIT 0


extern uint32_t __bootloader_start__;
extern uint32_t __bootloader_size__;
extern uint32_t __app_main_start__;
extern uint32_t __app_main_size__;
extern uint32_t __flash_start__;

typedef struct bootloader_image_header
{
    uint32_t options;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t build_number;
    uint8_t hash[32];
    uint8_t sign[64];
    uint32_t size;
    uint32_t variables;
    uint32_t time_unix;
    uint32_t crc32;
    uint32_t calc_crc32;
    

} bootloader_image_header_t;

typedef struct bootloader_image
{
    uint32_t address;
    bootloader_image_header_t image_header;
    uint8_t app_id;

} bootloader_image_t;

#endif