#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/stdio.h"
#include "pico/time.h"

#include "hardware/structs/dma.h"
#include "hardware/structs/watchdog.h"
#include "hardware/gpio.h"
#include "hardware/resets.h"
#include "hardware/uart.h"
#include "hardware/watchdog.h"
#include "hardware/structs/scb.h"

#include "../headers/bootloader.h"
#include "../headers/debug.h"
#include "../headers/log.h"
#include "../headers/time.h"
#include "../headers/defines.h"
#include "../headers/crc32.h"
#include "../headers/crypto.h"

#define FLASH_SIZE 4 * 1024 // in KB
#define NUM_APPS 3          // including main/0th app
#define APP_SIZE 1024       // in KB

/* The default flash size if 4MB */
/* check which app to start for the three apps */
uint32_t BOOTLOADER_APP_0 = (XIP_BASE + 0x20000);              // hardcoded default APP
uint32_t BOOTLOADER_APP_1 = (XIP_BASE + (0x20000 + 0x100000)); // 1MB per app OTA APP
uint32_t BOOTLOADER_APP_2 = (XIP_BASE + (0x20000 + 0x200000)); // 1MB per app OTA APP
/**/

#define default_header_size 0x1000

static void jump_to_vtor(uint32_t vtor)
{
    // Derived from the Leaf Labs Cortex-M3 bootloader.
    // Copyright (c) 2010 LeafLabs LLC.
    // Modified 2021 Brian Starkey <stark3y@gmail.com>
    // Originally under The MIT License
    uint32_t reset_vector = *(volatile uint32_t *)(vtor + 0x04);

    scb_hw->vtor = (volatile uint32_t)(vtor);

    asm volatile("msr msp, %0" ::"g"(*(volatile uint32_t *)vtor));
    asm volatile("bx %0" ::"r"(reset_vector));
}

int bootloader_boot_image(bootloader_image_t *image)
{

    uint32_t image_address = image->address + default_header_size;

    log_logi(BOOTLOADER_TAG, "booting app: %d at address %lX", image->app_id, image_address);

    sleep_ms(50);

    jump_to_vtor(image_address);

    return SW_OK;
}

int bootloader_get_image_header(uint32_t image_address, bootloader_image_header_t *image_header)
{
    const uint8_t *image_address_start = (const uint8_t *)image_address;

    /* options */
    image_header->options = (((uint32_t)image_address_start[0]) << 0) | (((uint32_t)image_address_start[1]) << 8) | (((uint32_t)image_address_start[2]) << 16) | (((uint32_t)image_address_start[3]) << 24);
    /**/

    /* major version */
    image_header->major_version = (((uint32_t)image_address_start[4]) << 0) | (((uint32_t)image_address_start[5]) << 8) | (((uint32_t)image_address_start[6]) << 16) | (((uint32_t)image_address_start[7]) << 24);
    /**/

    /* minor version */
    image_header->minor_version = (((uint32_t)image_address_start[8]) << 0) | (((uint32_t)image_address_start[9]) << 8) | (((uint32_t)image_address_start[10]) << 16) | (((uint32_t)image_address_start[11]) << 24);
    /**/

    /* build number */
    image_header->build_number = (((uint32_t)image_address_start[12]) << 0) | (((uint32_t)image_address_start[13]) << 8) | (((uint32_t)image_address_start[14]) << 16) | (((uint32_t)image_address_start[15]) << 24);
    /**/

    /* hash */
    memcpy(image_header->hash, image_address_start + 16, 32);
    /**/

    /* sign */
    memcpy(image_header->sign, image_address_start + 48, 64);
    /**/

    /* size */
    image_header->size = (((uint32_t)image_address_start[112]) << 0) | (((uint32_t)image_address_start[113]) << 8) | (((uint32_t)image_address_start[114]) << 16) | (((uint32_t)image_address_start[115]) << 24);
    /**/

    /* variables */
    image_header->variables = (((uint32_t)image_address_start[116]) << 0) | (((uint32_t)image_address_start[117]) << 8) | (((uint32_t)image_address_start[118]) << 16) | (((uint32_t)image_address_start[119]) << 24);
    /**/

    /* time */
    image_header->time_unix = (((uint32_t)image_address_start[120]) << 0) | (((uint32_t)image_address_start[121]) << 8) | (((uint32_t)image_address_start[122]) << 16) | (((uint32_t)image_address_start[123]) << 24);
    /**/

    /* crc32 */
    image_header->crc32 = (((uint32_t)image_address_start[124]) << 0) | (((uint32_t)image_address_start[125]) << 8) | (((uint32_t)image_address_start[126]) << 16) | (((uint32_t)image_address_start[127]) << 24);
    /**/

    /* calculated crc32 */
    image_header->calc_crc32 = crc32c(image_address_start, 124);
    /**/

    return SW_OK;
}

int bootloader_verify_image_header(bootloader_image_header_t *image_header)
{

    if (image_header->time_unix == 0)
    {
        log_loge(BOOTLOADER_TAG, "verify: timeunix %u", image_header->time_unix);
        return BOOTLOADER_IMAGE_HEADER_INVALID;
    }

    log_logi(BOOTLOADER_TAG, "timeunix %u", image_header->time_unix);

    // if (image_header->options == 0)
    // {
    //     log_loge(BOOTLOADER_TAG, "verify: options %lu", image_header->options);
    //     return BOOTLOADER_IMAGE_HEADER_INVALID;
    // }

    log_logi(BOOTLOADER_TAG, "options %u", image_header->options);

    if (image_header->size == 0)
    {
        log_loge(BOOTLOADER_TAG, "verify: size %u", image_header->size);
        return BOOTLOADER_IMAGE_HEADER_INVALID;
    }

    log_logi(BOOTLOADER_TAG, "size %u", image_header->size);

    /* check crc */

    if (image_header->calc_crc32 != image_header->crc32)
    {
        log_loge(BOOTLOADER_TAG, "crc error: %u != %u", image_header->calc_crc32, image_header->crc32);

        return BOOTLOADER_IMAGE_HEADER_INVALID;
    }

    log_logi(BOOTLOADER_TAG, "Version: %d.%d.%d", image_header->major_version, image_header->minor_version, image_header->build_number);

    return BOOTLOADER_IMAGE_HEADER_VALID;
}

int bootloader_verify_image_at_address(uint32_t image_address, bootloader_image_t *image)
{
    int err;
    bootloader_image_header_t image_header;

    /* get image header */
    err = bootloader_get_image_header(image_address, &image_header);
    if (err != SW_OK)
    {
        return err;
    }
    /**/

    /* verify image header */
    err = bootloader_verify_image_header(&image_header);
    if (err != BOOTLOADER_IMAGE_HEADER_VALID)
    {
        return err;
    }
    /**/

    image->image_header = image_header;
    image->address = image_address;

    /* get image hash */
    uint8_t hash_sum[32];
    err = crypto_sha256(image_address + default_header_size, image_header.size, hash_sum, 32);
    if (err != SW_OK)
    {
        log_loge(BOOTLOADER_TAG, "failed to calculate sha256 sum for app");
        return err;
    }
    /**/

    /* check image hash is valid */

    if (memcmp(hash_sum, image->image_header.hash, 32) != 0)
    {
        printHexArray(hash_sum, 32);
        printHexArray(image->image_header.hash, 32);
        log_loge(BOOTLOADER_TAG, "hash did not match");
        err = SW_ERROR;
        return err;
    }

    /**/

    /* verify image sign */
    if (image->image_header.options & (1 << OPTIONS_APP_SIGNED_BIT))
    {
        log_logd(BOOTLOADER_TAG, "app is signed");
        log_logd(BOOTLOADER_TAG, "checking signature...");

        err = crypto_verify_sign_from_hash(hash_sum, 32, image->image_header.sign, 64);
        if (err != SW_OK)
        {
            log_loge(BOOTLOADER_TAG, "failed to verify sign");
            return err;
        }
    }
    /**/

    /* check for any previous failure and take action according to the kind of failure*/

    return BOOTLOADER_IMAGE_VALID;
}

int bootloader_get_image_to_boot(bootloader_image_t *image_to_boot)
{
    int err;
    bootloader_image_t image;

    /* app 0 - has to be correct */

    err = bootloader_verify_image_at_address(BOOTLOADER_APP_0, &image);
    if (err != BOOTLOADER_IMAGE_VALID)
    {
        log_loge(BOOTLOADER_TAG, "failed to get image 0");
        return err;
    }
    image.app_id = 0;
    *image_to_boot = image;

    /**/

    if (NUM_APPS == 1)
    {
        log_logi(BOOTLOADER_TAG, "only one image is present");
        return SW_OK;
    }

    /* now iterate over other images */
    int i = 1;

    for (i = 1; i < NUM_APPS; i++)
    {
        err = bootloader_verify_image_at_address(BOOTLOADER_APP_0 + (i * APP_SIZE * 1024), &image);
        if (err != BOOTLOADER_IMAGE_VALID)
        {
            log_loge(BOOTLOADER_TAG, "failed to get image %d", i);
            continue;
        }

        /* check if image is latest using time */
        if (image.image_header.time_unix > image_to_boot->image_header.time_unix)
        {
            log_logd(BOOTLOADER_TAG, "using app %d", i);
            image.app_id = i;
            *image_to_boot = image;
        }
    }

    return SW_OK;
}

void printHexArray(unsigned char *array, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02X ", array[i]);
    }
    printf("\n");
}

void main()
{
    int err;

    debug_uart_init();

    /* init time */
    err = time_function_init();
    if (err)
    {
        log_loge(BOOTLOADER_TAG, "time functions init failed");
        return;
    }

    /* crypto init */
    err = crypto_init();
    if (err)
    {
        log_loge(BOOTLOADER_TAG, "crypto init failed");
        return;
    }

    if (NUM_APPS == 0)
    {
        log_loge(BOOTLOADER_TAG, "No images present to boot.");
        return;
    }

    int i = 0;
    for (i = 0; i < NUM_APPS; i++)
    {
        log_logi(BOOTLOADER_TAG, "App %d Address: %lX", i, BOOTLOADER_APP_0 + (i * APP_SIZE * 1024));
    }

    /* check which app to use */

    bootloader_image_t image_to_boot;

    err = bootloader_get_image_to_boot(&image_to_boot);
    if (err != SW_OK)
    {
        log_loge(BOOTLOADER_TAG, "Failed to get image");
        return;
    }
    /**/

    err = bootloader_boot_image(&image_to_boot);
    if (err != SW_OK)
    {
        log_loge(BOOTLOADER_TAG, "Failed to boot image");
        return;
    }

    while (1)
        ;

    return;
}