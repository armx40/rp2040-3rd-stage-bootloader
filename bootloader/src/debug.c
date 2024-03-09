#include "pico/stdlib.h"
#include "../headers/debug.h"

void debug_uart_init() {
     // gpio_put(LED_PIN, 1);
    stdio_uart_init_full(LOCAL_DEBUG_UART, 115200,DEBUG_UART_TX_PIN,DEBUG_UART_RX_PIN);
 
    // Set the GPIO pin mux to the UART - 16 is TX, 17 is RX
    gpio_set_function(DEBUG_UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(DEBUG_UART_RX_PIN, GPIO_FUNC_UART);
}
