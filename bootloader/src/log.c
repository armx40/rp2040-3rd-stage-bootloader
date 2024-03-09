#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> 

#include "pico/stdlib.h"

#include "../headers/log.h"
#include "../headers/defines.h"

// little inspiration from esp idf

int log_log(log_level_t level,const char *tag,const char *format, ...)
{

    /* prepare tag */

    /* printf */
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);

    return SW_OK;
}


