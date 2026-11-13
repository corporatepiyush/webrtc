#include "wr/rng.h"

#include <openssl/rand.h>
#include <stdlib.h>

struct wr_rng {
    bool deterministic;
    uint64_t s[4];
};

static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static uint64_t rotl64(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static uint64_t xoshiro_next(wr_rng *r)
{
    uint64_t result = rotl64(r->s[1] * 5u, 7) * 9u;
    uint64_t t = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl64(r->s[3], 45);
    return result;
}

wr_rng *wr_rng_create(void)
{
    wr_rng *r = (wr_rng *)calloc(1, sizeof(*r));
    return r;
}

void wr_rng_destroy(wr_rng *rng)
{
    if (rng) {
        wr_secure_zero(rng, sizeof(*rng));
        free(rng);
    }
}

void wr_rng_seed(wr_rng *rng, uint64_t seed)
{
    if (!rng) {
        return;
    }
    rng->deterministic = true;
    for (int i = 0; i < 4; ++i) {
        rng->s[i] = splitmix64(&seed);
    }
    if ((rng->s[0] | rng->s[1] | rng->s[2] | rng->s[3]) == 0u) {
        rng->s[0] = 1u;
    }
}

wr_status wr_rng_fill(wr_rng *rng, uint8_t *out, size_t len)
{
    if (!rng || (!out && len != 0u)) {
        return WR_ERR_INVAL;
    }
    if (rng->deterministic) {
        size_t i = 0;
        while (i < len) {
            uint64_t v = xoshiro_next(rng);
            for (int b = 0; b < 8 && i < len; ++b) {
                out[i++] = (uint8_t)(v >> (b * 8));
            }
        }
        return WR_OK;
    }
    if (len != 0u && RAND_bytes(out, (int)len) != 1) {
        return WR_ERR_CRYPTO;
    }
    return WR_OK;
}

uint64_t wr_rng_u64(wr_rng *rng)
{
    uint64_t v = 0;
    if (!rng) {
        return 0u;
    }
    if (rng->deterministic) {
        return xoshiro_next(rng);
    }
    if (RAND_bytes((uint8_t *)&v, (int)sizeof(v)) != 1) {
        return 0u;
    }
    return v;
}