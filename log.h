/**
 * @author lijk@infosec.com.cn
 * @version 0.0.1
 * @date 2016-10-12 13:41:51
 */
#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <syslog.h>

enum log_level
{
    LOG_LEVEL_CRIT,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_NOTICE,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_NUM
};

extern enum log_level _log_level;

#define _log_message(level, priority, format, ...)                                                                              \
do{                                                                                                                             \
    level > _log_level ? 0 : syslog(priority, #priority" [%s - %s:%u] "format, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__);\
}while(0)

void print_hex_dump(enum log_level level, const void *buf, size_t len);

#define log_crit(format, ...)       _log_message(LOG_LEVEL_CRIT, LOG_LOCAL5|LOG_CRIT, format, ##__VA_ARGS__)
#define log_err(format, ...)        _log_message(LOG_LEVEL_ERR, LOG_LOCAL4|LOG_ERR, format, ##__VA_ARGS__)
#define log_warning(format, ...)    _log_message(LOG_LEVEL_WARNING, LOG_LOCAL3|LOG_WARNING, format, ##__VA_ARGS__)
#define log_notice(format, ...)     _log_message(LOG_LEVEL_NOTICE, LOG_LOCAL2|LOG_NOTICE, format, ##__VA_ARGS__)
#define log_info(format, ...)       _log_message(LOG_LEVEL_INFO, LOG_LOCAL1|LOG_INFO, format, ##__VA_ARGS__)
#define log_debug(format, ...)      _log_message(LOG_LEVEL_DEBUG, LOG_LOCAL0|LOG_DEBUG, format, ##__VA_ARGS__)

#define log_dump(buf, len)          print_hex_dump(LOG_LEVEL_INFO, buf, len)
#define log_print(buf, len)         print_hex_dump(LOG_LEVEL_NUM, buf, len)

void log_open(const char *ident, bool tostderr);

// level: crit, err, warning, notice, info, debug
enum log_level log_get_level(const char *level);

void log_set_level(enum log_level level);

void log_close(void);

#endif
