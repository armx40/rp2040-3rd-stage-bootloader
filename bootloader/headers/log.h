#include "time.h"

#ifndef LOG_H
#define LOG_H

// inspired and copied little from esp-idf log library

#define MAX_LOG_LEVEL 4

typedef enum
{
    LOG_NONE,  /*!< No log output */
    LOG_ERROR, /*!< Critical errors, software module can not recover on its own */
    LOG_WARN,  /*!< Error conditions from which recovery measures have been taken */
    LOG_INFO,  /*!< Information messages which describe normal flow of events */
    LOG_DEBUG, /*!< Extra information which is not necessary for normal use (values, pointers, sizes, etc). */
    LOG_VERBOSE
} log_level_t;

#define LOG_COLOR_BLACK "30"
#define LOG_COLOR_RED "31"
#define LOG_COLOR_GREEN "32"
#define LOG_COLOR_BROWN "33"
#define LOG_COLOR_BLUE "34"
#define LOG_COLOR_PURPLE "35"
#define LOG_COLOR_CYAN "36"
#define LOG_COLOR(COLOR) "\033[0;" COLOR "m"
#define LOG_BOLD(COLOR) "\033[1;" COLOR "m"
#define LOG_RESET_COLOR "\033[0m"
#define LOG_COLOR_E LOG_COLOR(LOG_COLOR_RED)
#define LOG_COLOR_W LOG_COLOR(LOG_COLOR_BROWN)
#define LOG_COLOR_I LOG_COLOR(LOG_COLOR_GREEN)
#define LOG_COLOR_D LOG_COLOR(LOG_COLOR_CYAN)
#define LOG_COLOR_V LOG_COLOR(LOG_COLOR_PURPLE)

int log_log(log_level_t level, const char *tag, const char *format, ...);

#define LOG_FORMAT(letter, format) LOG_COLOR_##letter #letter " (%u) %s: " format LOG_RESET_COLOR "\r\n"
#define LOG_SYSTEM_TIME_FORMAT(letter, format) LOG_COLOR_##letter #letter " (%s) %s: " format LOG_RESET_COLOR "\r\n"

#define LOG_LEVEL(level, tag, format, ...)                                                                           \
    do                                                                                                               \
    {                                                                                                                \
        if (level > MAX_LOG_LEVEL) {}                                                                                                                   \
        else if (level == LOG_ERROR)                                                                                 \
        {                                                                                                            \
            log_log(LOG_ERROR, tag, LOG_FORMAT(E, format), time_epoch_from_rtc(), tag __VA_OPT__(, ) __VA_ARGS__);   \
        }                                                                                                            \
        else if (level == LOG_WARN)                                                                                  \
        {                                                                                                            \
            log_log(LOG_WARN, tag, LOG_FORMAT(W, format), time_epoch_from_rtc(), tag __VA_OPT__(, ) __VA_ARGS__);    \
        }                                                                                                            \
        else if (level == LOG_INFO)                                                                                  \
        {                                                                                                            \
            log_log(LOG_INFO, tag, LOG_FORMAT(I, format), time_epoch_from_rtc(), tag __VA_OPT__(, ) __VA_ARGS__);    \
        }                                                                                                            \
        else if (level == LOG_DEBUG)                                                                                 \
        {                                                                                                            \
            log_log(LOG_DEBUG, tag, LOG_FORMAT(D, format), time_epoch_from_rtc(), tag __VA_OPT__(, ) __VA_ARGS__);   \
        }                                                                                                            \
        else if (level == LOG_VERBOSE)                                                                               \
        {                                                                                                            \
            log_log(LOG_VERBOSE, tag, LOG_FORMAT(V, format), time_epoch_from_rtc(), tag __VA_OPT__(, ) __VA_ARGS__); \
        }                                                                                                            \
        else                                                                                                         \
        {                                                                                                            \
        }                                                                                                            \
    } while (0)

#define LOG_LEVEL_LOCAL(level, tag, format, ...)      \
    do                                                \
    {                                                 \
        LOG_LEVEL(level, tag, format, ##__VA_ARGS__); \
    } while (0)

#define log_logn(tag, format, ...) LOG_LEVEL_LOCAL(LOG_NONE, tag, format __VA_OPT__(, ) __VA_ARGS__)
#define log_loge(tag, format, ...) LOG_LEVEL_LOCAL(LOG_ERROR, tag, format __VA_OPT__(, ) __VA_ARGS__)
#define log_logw(tag, format, ...) LOG_LEVEL_LOCAL(LOG_WARN, tag, format __VA_OPT__(, ) __VA_ARGS__)
#define log_logi(tag, format, ...) LOG_LEVEL_LOCAL(LOG_INFO, tag, format __VA_OPT__(, ) __VA_ARGS__)
#define log_logd(tag, format, ...) LOG_LEVEL_LOCAL(LOG_DEBUG, tag, format __VA_OPT__(, ) __VA_ARGS__)
#define log_logv(tag, format, ...) LOG_LEVEL_LOCAL(LOG_VERBOSE, tag, format __VA_OPT__(, ) __VA_ARGS__)

#endif