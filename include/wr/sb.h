#ifndef WR_SB_H
#define WR_SB_H

#include "wr/base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bounded byte sink shared by text/protocol serializers. Writes are clamped
 * to cap; len still tracks the intended length so callers can detect
 * overflow with wr_sb_ok() after building. */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
} wr_sb;

static inline void wr_sb_init(wr_sb *s, void *buf, size_t cap)
{
    s->buf = (uint8_t *)buf;
    s->cap = cap;
    s->len = 0u;
}

static inline bool wr_sb_ok(const wr_sb *s)
{
    return s->len <= s->cap;
}

static inline void wr_sb_put_n(wr_sb *s, const void *p, size_t n)
{
    if (s->len < s->cap && n) {
        size_t room = s->cap - s->len;
        size_t copy = n < room ? n : room;
        if (copy) {
            memcpy(s->buf + s->len, p, copy);
        }
    }
    s->len += n;
}

static inline void wr_sb_put_u8(wr_sb *s, uint8_t v)
{
    if (s->len < s->cap) {
        s->buf[s->len] = v;
    }
    s->len++;
}

static inline void wr_sb_put_be16(wr_sb *s, uint16_t v)
{
    if (s->cap >= 2u && s->len <= s->cap - 2u) {
        wr_store_be16(s->buf + s->len, v);
        s->len += 2u;
        return;
    }
    uint8_t tmp[2];
    wr_store_be16(tmp, v);
    wr_sb_put_n(s, tmp, sizeof(tmp));
}

static inline void wr_sb_put_be32(wr_sb *s, uint32_t v)
{
    if (s->cap >= 4u && s->len <= s->cap - 4u) {
        wr_store_be32(s->buf + s->len, v);
        s->len += 4u;
        return;
    }
    uint8_t tmp[4];
    wr_store_be32(tmp, v);
    wr_sb_put_n(s, tmp, sizeof(tmp));
}

static inline void wr_sb_put_be64(wr_sb *s, uint64_t v)
{
    if (s->cap >= 8u && s->len <= s->cap - 8u) {
        wr_store_be64(s->buf + s->len, v);
        s->len += 8u;
        return;
    }
    uint8_t tmp[8];
    wr_store_be64(tmp, v);
    wr_sb_put_n(s, tmp, sizeof(tmp));
}

static inline void wr_sb_put(wr_sb *s, const char *str)
{
    if (str) {
        wr_sb_put_n(s, str, strlen(str));
    }
}

static inline void wr_sb_put_span(wr_sb *s, wr_span_c v)
{
    wr_sb_put_n(s, v.ptr, v.len);
}

static inline void wr_sb_crlf(wr_sb *s)
{
    wr_sb_put_n(s, "\r\n", 2u);
}

/* Decimal and dotted-quad formatting avoid snprintf/inet_ntop on hot paths. */
void wr_sb_put_u64(wr_sb *s, uint64_t v);
void wr_sb_put_ipv4(wr_sb *s, const uint8_t v4[4]);

#ifdef __cplusplus
}
#endif

#endif /* WR_SB_H */
