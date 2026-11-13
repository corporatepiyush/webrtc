#include "wr/crc32.h"

#include <pthread.h>
#include <string.h>

#if defined(__ARM_FEATURE_CRC32)
#include <arm_acle.h>
#define WR_CRC32_HW 1
#endif

#if !defined(__ARM_FEATURE_CRC32)
static uint32_t table[8][256];
static pthread_once_t once = PTHREAD_ONCE_INIT;

static void init_tables(void)
{
    for (uint32_t i = 0; i < 256u; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        }
        table[0][i] = c;
    }
    for (uint32_t s = 1u; s < 8u; ++s) {
        for (uint32_t i = 0; i < 256u; ++i) {
            uint32_t v = table[s - 1u][i];
            table[s][i] = (v >> 8) ^ table[0][v & 0xffu];
        }
    }
}
#endif

static inline uint32_t load32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4u);
    return v;
}

#if defined(__ARM_FEATURE_CRC32)
static uint32_t crc32_hw(uint32_t crc, const uint8_t *p, size_t len)
{
    crc = ~crc;
    while (len >= 8u) {
        uint64_t v;
        memcpy(&v, p, 8u);
        crc = __crc32d(crc, v);
        p += 8u;
        len -= 8u;
    }
    if (len >= 4u) {
        crc = __crc32w(crc, load32(p));
        p += 4u;
        len -= 4u;
    }
    while (len--) {
        crc = __crc32b(crc, *p++);
    }
    return ~crc;
}
#endif

uint32_t wr_crc32(uint32_t crc, const void *buf, size_t len)
{
    if (!buf || len == 0u) {
        return crc;
    }
    const uint8_t *p = (const uint8_t *)buf;
#if defined(__ARM_FEATURE_CRC32)
    return crc32_hw(crc, p, len);
#else
    (void)pthread_once(&once, init_tables);
    crc = ~crc;
    while (len >= 8u) {
        uint32_t a = load32(p) ^ crc;
        uint32_t b = load32(p + 4u);
        crc = table[7][a & 0xffu] ^ table[6][(a >> 8) & 0xffu] ^
              table[5][(a >> 16) & 0xffu] ^ table[4][(a >> 24) & 0xffu] ^
              table[3][b & 0xffu] ^ table[2][(b >> 8) & 0xffu] ^
              table[1][(b >> 16) & 0xffu] ^ table[0][(b >> 24) & 0xffu];
        p += 8u;
        len -= 8u;
    }
    while (len--) {
        crc = table[0][(crc ^ *p++) & 0xffu] ^ (crc >> 8);
    }
    return ~crc;
#endif
}