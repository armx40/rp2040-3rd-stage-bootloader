
#include "pico/stdlib.h"

#define LOCAL_DEBUG_UART uart0
// #define DEBUG_UART_TX_PIN 0
// #define DEBUG_UART_RX_PIN 1

/* for now only these pins are for i2c */
#define DEBUG_UART_TX_PIN 0
#define DEBUG_UART_RX_PIN 1
/**/

void debug_uart_init();