#ifndef WR_LOG_H
#define WR_LOG_H

#include "wr/base.h"
#include <stdarg.h>

typedef enum {
    WR_LOG_NONE = 0,
    WR_LOG_ERROR,
    WR_LOG_WARN,
    WR_LOG_INFO,
    WR_LOG_DEBUG,
    WR_LOG_TRACE
} wr_log_level;

typedef void (*wr_log_sink)(void *ctx, wr_log_level lvl, const char *module,
                            const char *fmt, va_list ap);

void wr_log_set_sink(wr_log_sink sink, void *ctx, wr_log_level min_level);
wr_log_level wr_log_get_level(void);
void wr_log_write(const char *module, wr_log_level lvl, const char *fmt, ...)
    WR_PRINTF(3, 4);

#define WR_LOG_ERROR(mod, ...) wr_log_write(mod, WR_LOG_ERROR, __VA_ARGS__)
#define WR_LOG_WARN(mod, ...)  wr_log_write(mod, WR_LOG_WARN, __VA_ARGS__)
#define WR_LOG_INFO(mod, ...)  wr_log_write(mod, WR_LOG_INFO, __VA_ARGS__)
#define WR_LOG_DEBUG(mod, ...) wr_log_write(mod, WR_LOG_DEBUG, __VA_ARGS__)

#endif /* WR_LOG_H */