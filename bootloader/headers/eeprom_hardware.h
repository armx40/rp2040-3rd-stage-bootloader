#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"


#ifndef HARDWARE_EEPROM_H
#define HARDWARE_EEPROM_H

#define EEPROM_HARDWARE_DEVICE_ADDRESS 0x50

int eeprom_hardware_write_zeroes();
int eeprom_hardware_write_byte(uint16_t addr, uint8_t data);
int eeprom_hardware_write_block(uint16_t addr, uint8_t *data, uint8_t data_len);
int eeprom_hardware_read_byte(uint8_t *data);
int eeprom_hardware_read_random_byte(uint16_t addr, uint8_t *data);
int eeprom_hardware_read_block(uint16_t addr, uint8_t *data, uint8_t data_len);
int eeprom_hardware_read_byte_retry(uint8_t *data, uint16_t retries, uint16_t delay);
int eeprom_hardware_read_random_byte_retry(uint16_t addr, uint8_t *data, uint16_t retries, uint16_t delay);
int eeprom_hardware_read_block_retry(uint16_t addr, uint8_t *data, uint8_t data_len, uint16_t retries, uint16_t delay);

#endif