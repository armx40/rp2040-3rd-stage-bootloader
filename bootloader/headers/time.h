#include "pico/util/datetime.h"
#include <time.h>

#ifndef TIME_H
#define TIME_H

#define DEVICE_TIMEZONE_OFFSET 19800
#define TIME_TAG "TIME"

int time_function_init();
int time_init_epoch_timer();
int time_init_rtc_system();
int time_get_epoch_seconds(uint8_t *out);
int time_epoch_from_datetime(datetime_t *dt);
int time_epoch_from_rtc();
int time_rtc_set_datetime(datetime_t *dt);
int time_rtc_set_datetime_from_tm(struct tm *timer);
int time_rtc_set_datetime_from_epoch(int epoch);
int time_get_uptime();
int time_get_utc_offset();
int time_set_utc_offset(int offset);
int time_settings_init();
int time_get_datetime_from_seconds(datetime_t *dt, uint64_t seconds);
uint32_t time_get_time_set_counter();
int time_get_day_of_week_from_unix(time_t epoch_seconds);
int time_get_unix_from_datetime(struct tm *timeptr, time_t *unix_time);

#endif