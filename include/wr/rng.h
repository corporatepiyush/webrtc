#ifndef WR_RNG_H
#define WR_RNG_H

#include "wr/base.h"

typedef struct wr_rng wr_rng;

wr_rng *wr_rng_create(void);
void wr_rng_destroy(wr_rng *rng);
wr_status wr_rng_fill(wr_rng *rng, uint8_t *out, size_t len);
uint64_t wr_rng_u64(wr_rng *rng);
void wr_rng_seed(wr_rng *rng, uint64_t seed); /* deterministic mode */

#endif /* WR_RNG_H */