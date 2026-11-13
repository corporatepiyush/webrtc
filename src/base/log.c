#include "wr/log.h"

#include <stdio.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

typedef struct {
    wr_log_sink sink;
    void *ctx;
    wr_log_level min_level;
} wr_log_state;

static wr_log_state g_log = {
    NULL, NULL, WR_LOG_WARN
};

static const char *level_name(wr_log_level l)
{
    switch (l) {
    case WR_LOG_NONE:  return "NONE";
    case WR_LOG_ERROR: return "ERROR";
    case WR_LOG_WARN:  return "WARN";
    case WR_LOG_INFO:  return "INFO";
    case WR_LOG_DEBUG: return "DEBUG";
    case WR_LOG_TRACE: return "TRACE";
    default:           return "?";
    }
}

static void default_sink(void *ctx, wr_log_level lvl, const char *module,
                         const char *fmt, va_list ap)
{
    WR_UNUSED(ctx);
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) {
        return;
    }
    fprintf(stderr, "[%s] %s: %s\n", level_name(lvl), module, buf);
}

void wr_log_set_sink(wr_log_sink sink, void *ctx, wr_log_level min_level)
{
    g_log.sink = sink;
    g_log.ctx = ctx;
    g_log.min_level = min_level;
}

wr_log_level wr_log_get_level(void)
{
    return g_log.min_level;
}

void wr_log_write(const char *module, wr_log_level lvl, const char *fmt, ...)
{
    if (lvl > g_log.min_level || !fmt) {
        return;
    }
    wr_log_sink sink = g_log.sink ? g_log.sink : default_sink;
    va_list ap;
    va_start(ap, fmt);
    sink(g_log.ctx, lvl, module ? module : "?", fmt, ap);
    va_end(ap);
}