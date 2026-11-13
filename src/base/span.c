#include "wr/base.h"

#include <string.h>

/* Parse exactly eight ASCII digits with SWAR: validate all bytes in
 * parallel, then fold base-10 -> base-100 -> base-10000 -> base-1e8. */
static bool parse8_swar(const uint8_t *p, uint64_t *out)
{
    uint64_t x;
    memcpy(&x, p, sizeof(x));
    /* Valid bytes are exactly 0x30..0x39. The two SWAR tests reject bytes
     * below '0' and bytes above '9' without a per-byte branch. */
    if (((x + UINT64_C(0x5050505050505050)) &
         UINT64_C(0x8080808080808080)) != UINT64_C(0x8080808080808080) ||
        ((x + UINT64_C(0x4646464646464646)) &
         UINT64_C(0x8080808080808080)) != 0u) {
        return false;
    }
    uint64_t y = x - UINT64_C(0x3030303030303030);
    uint64_t v = y & UINT64_C(0x0f0f0f0f0f0f0f0f);
    v = (v * 10u + (v >> 8)) & UINT64_C(0x00ff00ff00ff00ff);
    v = (v * 100u + (v >> 16)) & UINT64_C(0x0000ffff0000ffff);
    v = (v * 10000u + (v >> 32)) & UINT64_C(0x00000000ffffffff);
    *out = v;
    return true;
}

bool wr_parse_u64(wr_span_c s, uint64_t *out)
{
    if (!s.ptr || s.len == 0u || out == NULL) {
        return false;
    }
    uint64_t v = 0;
    size_t i = 0u;
    if (s.len >= 16u) {
        uint64_t hi = 0u;
        uint64_t lo = 0u;
        if (!parse8_swar(s.ptr, &hi) || !parse8_swar(s.ptr + 8u, &lo)) {
            return false;
        }
        v = hi * UINT64_C(100000000) + lo;
        i = 16u;
    } else if (s.len >= 8u) {
        if (!parse8_swar(s.ptr, &v)) {
            return false;
        }
        i = 8u;
    }
    for (; i < s.len; ++i) {
        uint8_t c = s.ptr[i];
        if (c < (uint8_t)'0' || c > (uint8_t)'9') {
            return false;
        }
        uint64_t d = (uint64_t)(c - (uint8_t)'0');
        if (v > (UINT64_MAX - d) / 10u) {
            return false;
        }
        v = v * 10u + d;
    }
    *out = v;
    return true;
}

bool wr_parse_u32(wr_span_c s, uint32_t *out)
{
    uint64_t v;
    if (!wr_parse_u64(s, &v) || v > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

bool wr_parse_u16(wr_span_c s, uint16_t *out)
{
    uint64_t v;
    if (!wr_parse_u64(s, &v) || v > UINT16_MAX) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

void wr_secure_zero(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) {
        *q++ = 0;
    }
}