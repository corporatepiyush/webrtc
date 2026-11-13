#ifndef WR_HASH_H
#define WR_HASH_H

#include "wr/base.h"

/*
 * Non-cryptographic hashes tuned for protocol keys and short strings.
 * The 64-bit variant is a wyhash-style multiply/xor mix over 8-byte
 * chunks; the 32-bit variant is its high half folded with the length.
 * These are for hash tables, not for integrity: use CRC/HMAC for that.
 */

static inline uint64_t wr_mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x *= UINT64_C(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    return x;
}

uint64_t wr_hash64(const void *p, size_t n, uint64_t seed);
uint32_t wr_hash32(const void *p, size_t n, uint32_t seed);
uint32_t wr_hash_span(wr_span_c s);
uint32_t wr_hash_span_ci(wr_span_c s);

#endif /* WR_HASH_H */