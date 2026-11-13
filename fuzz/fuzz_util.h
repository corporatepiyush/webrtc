#ifndef WR_FUZZ_UTIL_H
#define WR_FUZZ_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wr/base.h"

/* Deterministic splitmix64 used by structured targets. The fuzz input seeds
 * it, so a crashing input replays the exact same schedule. */
typedef struct {
    uint64_t state;
} wr_fuzz_rng;

static inline uint64_t wr_fuzz_next(wr_fuzz_rng *r)
{
    uint64_t z = (r->state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static inline uint32_t wr_fuzz_below(wr_fuzz_rng *r, uint32_t n)
{
    return n ? (uint32_t)(wr_fuzz_next(r) % n) : 0u;
}

static inline uint8_t wr_fuzz_u8(wr_fuzz_rng *r)
{
    return (uint8_t)wr_fuzz_next(r);
}

static inline bool wr_fuzz_bool(wr_fuzz_rng *r)
{
    return (wr_fuzz_next(r) & 1u) != 0u;
}

/* Read up to 8 bytes as a big-endian integer without reading past the
 * input. Missing bytes are zero. */
static inline uint64_t wr_fuzz_u64(const uint8_t *data, size_t size)
{
    uint64_t v = 0u;
    size_t n = size < 8u ? size : 8u;
    for (size_t i = 0; i < 8u; ++i) {
        v = (v << 8) | (i < n ? data[i] : 0u);
    }
    return v;
}

/* Consume a byte string as a stream of bounded integers. */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
    uint64_t state;
} wr_fuzz_stream;

static inline void wr_fuzz_stream_init(wr_fuzz_stream *s, const uint8_t *data,
                                       size_t size)
{
    s->p = data;
    s->len = size;
    s->pos = 0u;
    s->state = UINT64_C(0x243f6a8885a308d3);
    for (size_t i = 0; i < size && i < 64u; ++i) {
        s->state ^= (uint64_t)data[i] << ((i & 7u) * 8u);
    }
    if (!s->state) {
        s->state = 1u;
    }
}

static inline uint64_t wr_fuzz_stream_next(wr_fuzz_stream *s)
{
    uint64_t z = (s->state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    s->state = z ^ (z >> 31);
    if (s->pos < s->len) {
        s->state ^= (uint64_t)s->p[s->pos++] << ((s->pos & 7u) * 8u);
    }
    return s->state;
}

static inline uint32_t wr_fuzz_stream_below(wr_fuzz_stream *s, uint32_t n)
{
    return n ? (uint32_t)(wr_fuzz_stream_next(s) % n) : 0u;
}

static inline uint8_t wr_fuzz_stream_u8(wr_fuzz_stream *s)
{
    return (uint8_t)wr_fuzz_stream_next(s);
}

static inline bool wr_fuzz_stream_bool(wr_fuzz_stream *s)
{
    return (wr_fuzz_stream_next(s) & 1u) != 0u;
}

/* Deterministic slice of the input. */
static inline wr_span_c wr_fuzz_slice(const uint8_t *data, size_t size,
                                      size_t *pos, size_t max)
{
    size_t left = size - (pos ? *pos : 0u);
    size_t n = left < max ? left : max;
    const uint8_t *p = data + (pos ? *pos : 0u);
    if (pos) {
        *pos += n;
    }
    return wr_span_c_make(p, n);
}

#endif