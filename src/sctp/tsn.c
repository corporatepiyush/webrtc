#include "wr/sctp.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* TSN receive window                                                        */
/* ------------------------------------------------------------------------- */

void wr_tsn_set_init(wr_tsn_set *s, uint32_t cum)
{
    if (!s) {
        return;
    }
    memset(s, 0, sizeof(*s));
    s->cum = cum;
}

#define WR_TSN_WORDS (WR_SCTP_RX_WINDOW / 64u)
#define WR_TSN_WORD_MASK (WR_TSN_WORDS - 1u)

/* Logical bit d (0 = cum+1) maps to physical bit s->off+d. Rotating the base
 * instead of shifting the 1 KiB window makes in-order delivery O(1). */
static inline size_t tsn_word_of(const wr_tsn_set *s, uint32_t d)
{
    return (size_t)(((s->off + d) >> 6) & WR_TSN_WORD_MASK);
}

static inline uint64_t tsn_mask_of(const wr_tsn_set *s, uint32_t d)
{
    return UINT64_C(1) << ((s->off + d) & 63u);
}

static inline uint64_t tsn_logical_word(const wr_tsn_set *s, uint32_t lw)
{
    uint32_t p = s->off + lw * 64u;
    size_t wi = (size_t)((p >> 6) & WR_TSN_WORD_MASK);
    uint32_t sh = p & 63u;
    if (sh == 0u) {
        return s->w[wi];
    }
    return (s->w[wi] >> sh) |
           (s->w[(wi + 1u) & WR_TSN_WORD_MASK] << (64u - sh));
}

bool wr_tsn_set_has(const wr_tsn_set *s, uint32_t tsn)
{
    if (!s || tsn <= s->cum) {
        return true; /* already consumed */
    }
    uint32_t d = tsn - (s->cum + 1u);
    if (d >= WR_SCTP_RX_WINDOW) {
        return false;
    }
    return (s->w[tsn_word_of(s, d)] & tsn_mask_of(s, d)) != 0u;
}

bool wr_tsn_set_add(wr_tsn_set *s, uint32_t tsn)
{
    if (!s || tsn <= s->cum) {
        return false;
    }
    uint32_t d = tsn - (s->cum + 1u);
    if (d >= WR_SCTP_RX_WINDOW) {
        return false;
    }
    size_t wi = tsn_word_of(s, d);
    uint64_t bit = tsn_mask_of(s, d);
    if (s->w[wi] & bit) {
        return false;
    }
    s->w[wi] |= bit;
    s->count++;
    return true;
}

bool wr_tsn_set_pop_next(wr_tsn_set *s, uint32_t *tsn)
{
    if (!s || !tsn) {
        return false;
    }
    uint64_t bit = UINT64_C(1) << (s->off & 63u);
    size_t wi = (size_t)((s->off >> 6) & WR_TSN_WORD_MASK);
    if ((s->w[wi] & bit) == 0u) {
        return false;
    }
    s->w[wi] &= ~bit;
    *tsn = s->cum + 1u;
    s->cum++;
    s->off = (s->off + 1u) & (WR_SCTP_RX_WINDOW - 1u);
    s->count--;
    return true;
}

uint32_t wr_tsn_set_advance(wr_tsn_set *s)
{
    if (!s) {
        return 0u;
    }
    uint32_t tsn;
    while (wr_tsn_set_pop_next(s, &tsn)) {
    }
    return s->cum;
}

/* First logical index >= from whose bit is set, or WR_SCTP_RX_WINDOW. */
static uint32_t tsn_next_set(const wr_tsn_set *s, uint32_t from)
{
    uint32_t i = from;
    while (i < WR_SCTP_RX_WINDOW) {
        uint32_t wi = i >> 6;
        uint64_t w = tsn_logical_word(s, wi) & (~UINT64_C(0) << (i & 63u));
        if (w) {
            return wi * 64u + (uint32_t)__builtin_ctzll(w);
        }
        i = (wi + 1u) * 64u;
    }
    return WR_SCTP_RX_WINDOW;
}

/* First logical index >= from whose bit is clear, or WR_SCTP_RX_WINDOW. */
static uint32_t tsn_next_clear(const wr_tsn_set *s, uint32_t from)
{
    uint32_t i = from;
    while (i < WR_SCTP_RX_WINDOW) {
        uint32_t wi = i >> 6;
        uint64_t w = ~tsn_logical_word(s, wi) & (~UINT64_C(0) << (i & 63u));
        if (w) {
            return wi * 64u + (uint32_t)__builtin_ctzll(w);
        }
        i = (wi + 1u) * 64u;
    }
    return WR_SCTP_RX_WINDOW;
}

static uint32_t tsn_popcount_range(const wr_tsn_set *s, uint32_t start,
                                   uint32_t end)
{
    uint32_t n = 0u;
    uint32_t first = start >> 6;
    uint32_t last = (end - 1u) >> 6;
    for (uint32_t wi = first; wi <= last; ++wi) {
        uint64_t w = tsn_logical_word(s, wi);
        uint64_t mask = ~UINT64_C(0);
        if (wi == first) {
            mask &= ~UINT64_C(0) << (start & 63u);
        }
        if (wi == last && (end & 63u) != 0u) {
            mask &= (UINT64_C(1) << (end & 63u)) - 1u;
        }
        n += (uint32_t)__builtin_popcountll(w & mask);
    }
    return n;
}

uint32_t wr_tsn_set_gaps(const wr_tsn_set *s, wr_tsn_gap *gaps, size_t max)
{
    if (!s || !gaps || max == 0u || s->count == 0u) {
        return 0u;
    }
    uint32_t n = 0u;
    uint32_t i = 0u;
    uint32_t left = s->count;
    while (i < WR_SCTP_RX_WINDOW && n < max && left > 0u) {
        uint32_t start = tsn_next_set(s, i);
        if (start >= WR_SCTP_RX_WINDOW) {
            break;
        }
        uint32_t end = tsn_next_clear(s, start);
        gaps[n].start = s->cum + 1u + start;
        gaps[n].end = s->cum + end; /* end is exclusive; -1 then +1. */
        n++;
        left -= tsn_popcount_range(s, start, end);
        i = end;
    }
    return n;
}
