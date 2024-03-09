#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include <time.h>

#include "pico/stdlib.h"
#include "pico/util/datetime.h"

#include "hardware/watchdog.h"
#include "hardware/rtc.h"

#include "../headers/defines.h"
#include "../headers/time.h"
#include "../headers/storage.h"
#include "../headers/log.h"

int UPTIME_TIMESTAMP = 0;
int TIMEZONE_OFFSET = DEVICE_TIMEZONE_OFFSET;

uint32_t TIME_TIME_SET_COUNTER = 0;

int time_function_init()
{

    int err = time_init_rtc_system();
    return err;
}

int time_init_epoch_timer()
{
}

int time_init_rtc_system()
{
    if (rtc_running())
    {
        return SW_OK;
    }
    log_logi(TIME_TAG, "initing RTC");
    datetime_t t = {
        .year = 2022,
        .month = 7,
        .day = 1,
        .dotw = 5, // 0 is Sunday, so 5 is Friday
        .hour = 0,
        .min = 0,
        .sec = 00,
    };

    // Start the RTC
    rtc_init();
    rtc_set_datetime(&t);

    // clk_sys is >2000x faster than clk_rtc, so datetime is not updated immediately when rtc_get_datetime() is called.
    // tbe delay is up to 3 RTC clock cycles (which is 64us with the default clock settings)
    sleep_us(64);

    UPTIME_TIMESTAMP = time_epoch_from_rtc();

    log_logi(TIME_TAG, "RTC inited");
    return SW_OK;
}

int time_get_epoch_seconds(uint8_t *out)
{
}

int time_rtc_set_datetime(datetime_t *dt)
{
    /* curr time tmp */

    int curr_time_epoch = time_epoch_from_rtc();
    sleep_us(64);
    bool ret = rtc_set_datetime(dt);
    sleep_us(64);
    if (ret)
    {
        /* transform uptime */
        /* add difference of epochs to uptime timestamp */
        UPTIME_TIMESTAMP += (time_epoch_from_rtc() - curr_time_epoch);
        TIME_TIME_SET_COUNTER++;
        return SW_OK;
    }
    return SW_ERROR;
}

int time_rtc_set_datetime_from_tm(struct tm *timer)
{
    datetime_t dt;
    dt.hour = timer->tm_hour;
    dt.day = timer->tm_mday;
    dt.dotw = timer->tm_wday;
    dt.sec = timer->tm_sec;
    dt.year = timer->tm_year + 1900;
    dt.month = timer->tm_mon + 1;
    dt.min = timer->tm_min;

    int err = time_rtc_set_datetime(&dt);
    if (err)
    {
        return err;
    }

    return SW_OK;
}

int time_rtc_set_datetime_from_epoch(int epoch)
{
    log_logi(TIME_TAG, "setting time from epoch: %d", epoch);
    struct tm *timer;
    time_t epoch_ = (time_t)epoch;
    timer = localtime(&epoch_);

    int err = time_rtc_set_datetime_from_tm(timer);
    if (err)
    {
        return err;
    }
    return SW_OK;
}

int time_epoch_from_datetime(datetime_t *dt)
{
    int seconds = 0;

    struct tm time_str;
    time_str.tm_hour = dt->hour;
    time_str.tm_mday = dt->day;
    time_str.tm_wday = dt->dotw;
    time_str.tm_min = dt->min;
    time_str.tm_mon = dt->month - 1;
    time_str.tm_sec = dt->sec;
    time_str.tm_year = dt->year - 1900;
    time_t epoch = mktime(&time_str);
    seconds = (int)epoch;
    return seconds;
}

int time_epoch_from_rtc()
{
    int seconds = 0;
    datetime_t dt;
    rtc_get_datetime(&dt);
    struct tm time_str;
    time_str.tm_hour = dt.hour;
    time_str.tm_mday = dt.day;
    time_str.tm_wday = dt.dotw;
    time_str.tm_min = dt.min;
    time_str.tm_mon = dt.month - 1;
    time_str.tm_sec = dt.sec;
    time_str.tm_year = dt.year - 1900;

    time_t epoch = mktime(&time_str);
    seconds = (int)epoch & 0xffffffff;

    return seconds;
}

int time_get_datetime_from_seconds(datetime_t *dt, uint64_t seconds)
{

    struct tm *timer;
    time_t epoch_ = (time_t)seconds;
    timer = localtime(&epoch_);

    dt->dotw = timer->tm_wday;

    dt->hour = timer->tm_hour;
    dt->sec = timer->tm_sec;
    dt->min = timer->tm_min;

    dt->year = timer->tm_year + 1900;
    dt->month = timer->tm_mon + 1;
    dt->day = timer->tm_mday;
    return SW_OK;
}

int time_get_uptime()
{
    return time_epoch_from_rtc() - UPTIME_TIMESTAMP;
}

int time_get_utc_offset()
{
    return TIMEZONE_OFFSET;
}

int time_set_utc_offset(int offset)
{
    return SW_OK;
}

int time_settings_init()
{

    int err;

    uint16_t storage_utc_offset;
    /* read time zone offset from storage */
    err = storage_counter_read_u16(STORAGE_TIME_UTC_OFFSET_ADDRESS_1, STORAGE_TIME_UTC_OFFSET_ADDRESS_COUNTER_1, &storage_utc_offset);
    if (err)
    {
        return SW_ERROR;
    }

    /* if offset is zero, set it to IST(Device Country) offset */
    if (storage_utc_offset == 0)
    {
        log_logi(TIME_TAG, "TIME: setting offset to DEVICE TZ: %d", DEVICE_TIMEZONE_OFFSET);
        TIMEZONE_OFFSET = DEVICE_TIMEZONE_OFFSET;
    }
    else
    {
        log_logi(TIME_TAG, "TIME: setting offset from storage: %d", storage_utc_offset);
        TIMEZONE_OFFSET = storage_utc_offset;
    }

    return SW_OK;
}

uint32_t time_get_time_set_counter()
{
    return TIME_TIME_SET_COUNTER;
}

int time_get_day_of_week_from_unix(time_t epoch_seconds)
{

    return (((int)epoch_seconds / 86400) + 4) % 7;
}

int time_get_unix_from_datetime(struct tm *timeptr, time_t *unix_time)
{
    *unix_time = mktime(timeptr);
    return SW_OK;
}