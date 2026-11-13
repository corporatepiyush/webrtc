#include "wr/hash.h"

static inline uint64_t read64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t read32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return (uint64_t)v;
}

uint64_t wr_hash64(const void *p, size_t n, uint64_t seed)
{
    const uint8_t *b = (const uint8_t *)p;
    uint64_t h = seed ^ (uint64_t)n * UINT64_C(0x9e3779b97f4a7c15);
    size_t i = 0;
    for (; i + 8u <= n; i += 8u) {
        h ^= read64(b + i);
        h = wr_mix64(h);
    }
    if (i + 4u <= n) {
        h ^= read32(b + i);
        h *= UINT64_C(0xff51afd7ed558ccd);
        h ^= h >> 29;
        i += 4u;
    }
    if (i < n) {
        uint64_t tail = 0u;
        for (size_t k = 0; i + k < n; ++k) {
            tail |= (uint64_t)b[i + k] << (8u * k);
        }
        h ^= tail;
        h = wr_mix64(h);
    }
    h ^= (uint64_t)n;
    return wr_mix64(h) | 1u; /* 0 is the map's empty-slot marker */
}

uint32_t wr_hash32(const void *p, size_t n, uint32_t seed)
{
    uint64_t h = wr_hash64(p, n, (uint64_t)seed << 1);
    return (uint32_t)(h ^ (h >> 32));
}

uint32_t wr_hash_span(wr_span_c s)
{
    return wr_hash32(s.ptr, s.len, 0u);
}

uint32_t wr_hash_span_ci(wr_span_c s)
{
    /* ASCII case fold without allocation; non-letters are left as-is. */
    uint64_t h = (uint64_t)s.len * UINT64_C(0x9e3779b97f4a7c15);
    for (size_t i = 0; i < s.len; ++i) {
        uint8_t c = s.ptr[i];
        if (c >= (uint8_t)'A' && c <= (uint8_t)'Z') {
            c = (uint8_t)(c + 32u);
        }
        h ^= c;
        h = wr_mix64(h);
    }
    return (uint32_t)(h ^ (h >> 32)) | 1u;
}