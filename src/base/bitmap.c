#include "wr/bitmap.h"

wr_status wr_bitmap_init(wr_arena *a, wr_bitmap *bm, uint32_t nbits)
{
    if (!a || !bm || nbits == 0u || nbits > UINT32_MAX - 63u) {
        return WR_ERR_INVAL;
    }
    uint32_t nwords = (nbits + 63u) / 64u;
    bm->words = (uint64_t *)wr_arena_calloc(a, nwords, sizeof(uint64_t));
    if (!bm->words) {
        return WR_ERR_NOMEM;
    }
    bm->nwords = nwords;
    bm->nbits = nbits;
    return WR_OK;
}

void wr_bitmap_set_range(wr_bitmap *bm, uint32_t first, uint32_t count)
{
    if (!bm || count == 0u || first >= bm->nbits) {
        return;
    }
    uint32_t last = first + count;
    if (last < first || last > bm->nbits) {
        last = bm->nbits;
    }
    uint32_t head = first & 63u;
    uint32_t tail = last & 63u;
    uint32_t fi = first >> 6;
    uint32_t li = (last - 1u) >> 6;
    if (fi == li) {
        uint32_t bits = last - first;
        uint64_t mask = bits >= 64u ? UINT64_MAX
                                    : ((UINT64_C(1) << bits) - 1u) << head;
        bm->words[fi] |= mask;
        return;
    }
    bm->words[fi] |= UINT64_MAX << head;
    for (uint32_t i = fi + 1u; i < li; ++i) {
        bm->words[i] = UINT64_MAX;
    }
    bm->words[li] |= tail ? ((UINT64_C(1) << tail) - 1u) : UINT64_MAX;
}

void wr_bitmap_clear_all(wr_bitmap *bm)
{
    if (bm && bm->words) {
        memset(bm->words, 0, (size_t)bm->nwords * sizeof(uint64_t));
    }
}

uint32_t wr_bitmap_count(const wr_bitmap *bm)
{
    if (!bm) {
        return 0u;
    }
    uint32_t n = 0u;
    for (uint32_t i = 0; i < bm->nwords; ++i) {
        n += (uint32_t)__builtin_popcountll(bm->words[i]);
    }
    return n;
}

uint32_t wr_bitmap_find_first(const wr_bitmap *bm)
{
    if (!bm) {
        return UINT32_MAX;
    }
    for (uint32_t i = 0; i < bm->nwords; ++i) {
        uint64_t w = bm->words[i];
        if (w) {
            return i * 64u + (uint32_t)__builtin_ctzll(w);
        }
    }
    return UINT32_MAX;
}

void wr_bitmap_iter_init(wr_bitmap_iter *it, const wr_bitmap *bm)
{
    it->bm = bm;
    it->next = 0u;
}

bool wr_bitmap_iter_next(wr_bitmap_iter *it, uint32_t *out)
{
    const wr_bitmap *bm = it->bm;
    if (!bm) {
        return false;
    }
    while (it->next < bm->nbits) {
        uint32_t wi = it->next >> 6;
        uint64_t w = bm->words[wi] >> (it->next & 63u);
        if (w) {
            uint32_t bit = (uint32_t)__builtin_ctzll(w);
            it->next += bit + 1u;
            *out = it->next - 1u;
            return true;
        }
        it->next = (wi + 1u) << 6;
    }
    return false;
}