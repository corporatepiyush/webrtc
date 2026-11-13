#include "wr/stun.h"

#include <string.h>

wr_status wr_turn_channel_parse(wr_span_c raw, uint16_t *num, wr_span_c *data)
{
    if (!raw.ptr || raw.len < 4u) {
        return WR_ERR_TRUNCATED;
    }
    uint16_t n = wr_load_be16(raw.ptr);
    uint16_t len = wr_load_be16(raw.ptr + 2);
    if (n < 0x4000u || n > 0x7fffu) {
        return WR_ERR_INVAL;
    }
    if ((size_t)len > raw.len - 4u) {
        return WR_ERR_TRUNCATED;
    }
    if (num) {
        *num = n;
    }
    if (data) {
        *data = wr_span_c_sub(raw, 4u, len);
    }
    return WR_OK;
}

wr_status wr_turn_channel_serialize(char *buf, size_t cap, uint16_t num,
                                    wr_span_c data, size_t *out_len)
{
    if (!buf || num < 0x4000u || num > 0x7fffu || data.len > UINT16_MAX) {
        return WR_ERR_INVAL;
    }
    size_t total = 4u + data.len;
    total = (total + 3u) & ~(size_t)3u;
    if (cap < total) {
        return WR_ERR_OVERFLOW;
    }
    wr_store_be16((uint8_t *)buf, num);
    wr_store_be16((uint8_t *)buf + 2, (uint16_t)data.len);
    if (data.len) {
        memcpy(buf + 4, data.ptr, data.len);
    }
    memset(buf + 4 + data.len, 0, total - 4u - data.len);
    if (out_len) {
        *out_len = total;
    }
    return WR_OK;
}