#ifndef WR_BASE_H
#define WR_BASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WR_API_VERSION 1u

/* ------------------------------------------------------------------------- */
/* Status                                                                    */
/* ------------------------------------------------------------------------- */

typedef uint32_t wr_status;

#define WR_MOD_BASE 0x01u
#define WR_MOD_NET  0x02u
#define WR_MOD_SDP  0x03u
#define WR_MOD_STUN 0x04u
#define WR_MOD_ICE  0x05u
#define WR_MOD_DTLS 0x06u
#define WR_MOD_SRTP 0x07u
#define WR_MOD_RTP  0x08u
#define WR_MOD_SCTP 0x09u
#define WR_MOD_DCEP 0x0au
#define WR_MOD_PC   0x0bu

#define WR_STATUS(mod, code) ((wr_status)(((uint32_t)(mod) << 16) | (uint32_t)(code)))

enum {
    WR_OK = 0,
    WR_ERR_INVAL     = WR_STATUS(WR_MOD_BASE, 0x01),
    WR_ERR_NOMEM     = WR_STATUS(WR_MOD_BASE, 0x02),
    WR_ERR_TRUNCATED = WR_STATUS(WR_MOD_BASE, 0x03),
    WR_ERR_OVERFLOW  = WR_STATUS(WR_MOD_BASE, 0x04),
    WR_ERR_NOT_FOUND = WR_STATUS(WR_MOD_BASE, 0x05),
    WR_ERR_EXISTS    = WR_STATUS(WR_MOD_BASE, 0x06),
    WR_ERR_STATE     = WR_STATUS(WR_MOD_BASE, 0x07),
    WR_ERR_AUTH      = WR_STATUS(WR_MOD_BASE, 0x08),
    WR_ERR_TIMEOUT   = WR_STATUS(WR_MOD_BASE, 0x09),
    WR_ERR_IO        = WR_STATUS(WR_MOD_BASE, 0x0a),
    WR_ERR_LIMIT     = WR_STATUS(WR_MOD_BASE, 0x0b),
    WR_ERR_CRYPTO    = WR_STATUS(WR_MOD_BASE, 0x0c),
    WR_ERR_CLOSED    = WR_STATUS(WR_MOD_BASE, 0x0d),
    WR_ERR_AGAIN     = WR_STATUS(WR_MOD_BASE, 0x0e),
    WR_ERR_UNSUPPORTED = WR_STATUS(WR_MOD_BASE, 0x0f),
};

const char *wr_status_str(wr_status st);
const char *wr_status_module(wr_status st);

/* ------------------------------------------------------------------------- */
/* Spans                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct { uint8_t *ptr; size_t len; } wr_span;
typedef struct { const uint8_t *ptr; size_t len; } wr_span_c;

static inline wr_span wr_span_make(void *ptr, size_t len)
{
    wr_span s;
    s.ptr = (uint8_t *)ptr;
    s.len = len;
    return s;
}

static inline wr_span_c wr_span_c_make(const void *ptr, size_t len)
{
    wr_span_c s;
    s.ptr = (const uint8_t *)ptr;
    s.len = len;
    return s;
}

static inline wr_span_c wr_span_upcast(wr_span s)
{
    return wr_span_c_make(s.ptr, s.len);
}

static inline bool wr_span_c_empty(wr_span_c s) { return s.len == 0u; }

static inline wr_span_c wr_span_c_sub(wr_span_c s, size_t off, size_t len)
{
    if (off > s.len || len > s.len - off) {
        return wr_span_c_make(NULL, 0);
    }
    return wr_span_c_make(s.ptr + off, len);
}

static inline wr_span wr_span_sub(wr_span s, size_t off, size_t len)
{
    if (off > s.len || len > s.len - off) {
        return wr_span_make(NULL, 0);
    }
    return wr_span_make(s.ptr + off, len);
}

static inline wr_span_c wr_span_c_take(wr_span_c *s, size_t n)
{
    wr_span_c out;
    if (n > s->len) {
        n = s->len;
    }
    out.ptr = s->ptr;
    out.len = n;
    s->ptr += n;
    s->len -= n;
    return out;
}

static inline wr_span_c wr_span_c_drop(wr_span_c *s, size_t n)
{
    if (n > s->len) {
        n = s->len;
    }
    s->ptr += n;
    s->len -= n;
    return *s;
}

static inline bool wr_span_c_eq(wr_span_c a, wr_span_c b)
{
    return a.len == b.len &&
           (a.len == 0u || memcmp(a.ptr, b.ptr, a.len) == 0);
}

static inline bool wr_span_c_starts_with(wr_span_c s, wr_span_c prefix)
{
    return s.len >= prefix.len &&
           (prefix.len == 0u || memcmp(s.ptr, prefix.ptr, prefix.len) == 0);
}

static inline bool wr_span_c_case_eq(wr_span_c a, wr_span_c b)
{
    if (a.len != b.len) {
        return false;
    }
    for (size_t i = 0; i < a.len; ++i) {
        uint8_t ca = a.ptr[i];
        uint8_t cb = b.ptr[i];
        if (ca >= (uint8_t)'A' && ca <= (uint8_t)'Z') ca = (uint8_t)(ca + 32);
        if (cb >= (uint8_t)'A' && cb <= (uint8_t)'Z') cb = (uint8_t)(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

static inline wr_span_c wr_span_c_from_str(const char *s)
{
    return wr_span_c_make(s, strlen(s));
}

/* Parse an unsigned decimal into *out. Returns false on overflow/empty. */
bool wr_parse_u64(wr_span_c s, uint64_t *out);
bool wr_parse_u32(wr_span_c s, uint32_t *out);
bool wr_parse_u16(wr_span_c s, uint16_t *out);

/* ------------------------------------------------------------------------- */
/* Byte-order helpers (boundary conversions only)                            */
/* ------------------------------------------------------------------------- */

static inline uint16_t wr_load_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t wr_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t wr_load_be64(const uint8_t *p)
{
    return ((uint64_t)wr_load_be32(p) << 32) | (uint64_t)wr_load_be32(p + 4);
}

static inline void wr_store_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xffu);
}

static inline void wr_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xffu);
}

static inline void wr_store_be64(uint8_t *p, uint64_t v)
{
    wr_store_be32(p, (uint32_t)(v >> 32));
    wr_store_be32(p + 4, (uint32_t)(v & 0xffffffffu));
}

/* ------------------------------------------------------------------------- */
/* Misc                                                                      */
/* ------------------------------------------------------------------------- */

#define WR_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define WR_MIN(a, b) ((a) < (b) ? (a) : (b))
#define WR_MAX(a, b) ((a) > (b) ? (a) : (b))
#define WR_UNUSED(x) (void)(x)

#if defined(__GNUC__) || defined(__clang__)
#define WR_LIKELY(x)   __builtin_expect(!!(x), 1)
#define WR_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define WR_LIKELY(x)   (x)
#define WR_UNLIKELY(x) (x)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WR_INLINE static inline __attribute__((unused))
#define WR_NORETURN __attribute__((noreturn))
#define WR_PRINTF(a, b) __attribute__((format(printf, a, b)))
#define WR_PACKED __attribute__((packed))
#else
#define WR_INLINE static inline
#define WR_NORETURN
#define WR_PRINTF(a, b)
#define WR_PACKED
#endif

void wr_secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WR_BASE_H */