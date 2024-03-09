#ifndef EEPROMEMULATION_H
#define	EEPROMEMULATION_H

#define EEPROM_EMULATION_START_ADDRESS 0x100000 // after 1MB
#define EEPROM_EMULATION_END_ADDRESS 0x101000
#define EEPROM_EMULATION_FLASH_PAGE_SIZE 256
#define EEPROM_EMULATION_TAG "EEPROM_EMULATION"

int eeprom_emulation_write_page(uint32_t page_number, uint8_t *data);
int eeprom_emulation_read_page(uint32_t page_number, uint8_t *out);
int eeprom_emulation_read_byte(uint32_t address, uint8_t *data);
int eeprom_emulation_write_byte(uint32_t address, uint8_t data);
int eeprom_emulation_get_size();
int eeprom_emulation_test();
int eeprom_emulation_read_sector(uint32_t sector_number,uint8_t *out);
int eeprom_emulation_write_block(uint32_t address, uint8_t *data, uint32_t d_size);
int eeprom_emulation_read_block(uint32_t address, uint8_t *out, uint32_t size);
int eeprom_emulation_write_sector(uint32_t sector_number, uint8_t *data);
int eeprom_emulation_write_zeroes();
#endif