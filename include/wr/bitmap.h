#ifndef WR_BITMAP_H
#define WR_BITMAP_H

#include "wr/arena.h"

typedef struct {
    uint64_t *words;
    uint32_t nwords;
    uint32_t nbits;
} wr_bitmap;

wr_status wr_bitmap_init(wr_arena *a, wr_bitmap *bm, uint32_t nbits);

static inline void wr_bitmap_set(wr_bitmap *bm, uint32_t i)
{
    if (i < bm->nbits) {
        bm->words[i >> 6] |= (UINT64_C(1) << (i & 63u));
    }
}

static inline void wr_bitmap_clear(wr_bitmap *bm, uint32_t i)
{
    if (i < bm->nbits) {
        bm->words[i >> 6] &= ~(UINT64_C(1) << (i & 63u));
    }
}

static inline bool wr_bitmap_test(const wr_bitmap *bm, uint32_t i)
{
    if (i >= bm->nbits) {
        return false;
    }
    return (bm->words[i >> 6] & (UINT64_C(1) << (i & 63u))) != 0u;
}

void wr_bitmap_set_range(wr_bitmap *bm, uint32_t first, uint32_t count);
void wr_bitmap_clear_all(wr_bitmap *bm);
uint32_t wr_bitmap_count(const wr_bitmap *bm);
uint32_t wr_bitmap_find_first(const wr_bitmap *bm);

typedef struct {
    const wr_bitmap *bm;
    uint32_t next;
} wr_bitmap_iter;

void wr_bitmap_iter_init(wr_bitmap_iter *it, const wr_bitmap *bm);
bool wr_bitmap_iter_next(wr_bitmap_iter *it, uint32_t *out);

#endif /* WR_BITMAP_H */