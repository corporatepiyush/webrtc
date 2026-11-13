#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/bitmap.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    if (!a) {
        return 0;
    }
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint32_t nbits = 1u + wr_fuzz_stream_below(&fs, 512u);
    wr_bitmap bm;
    if (wr_bitmap_init(a, &bm, nbits) != WR_OK) {
        wr_arena_destroy(a);
        return 0;
    }
    uint8_t model[64];
    memset(model, 0, sizeof(model));

    for (int i = 0; i < 128; ++i) {
        uint32_t op = wr_fuzz_stream_below(&fs, 5u);
        uint32_t bit = wr_fuzz_stream_below(&fs, nbits);
        switch (op) {
        case 0:
            wr_bitmap_set(&bm, bit);
            model[bit >> 3] |= (uint8_t)(1u << (bit & 7u));
            break;
        case 1:
            wr_bitmap_clear(&bm, bit);
            model[bit >> 3] &= (uint8_t)~(1u << (bit & 7u));
            break;
        case 2: {
            uint32_t first = wr_fuzz_stream_below(&fs, nbits);
            uint32_t count = wr_fuzz_stream_below(&fs, nbits + 1u);
            wr_bitmap_set_range(&bm, first, count);
            for (uint32_t k = first; k < nbits && k < first + count; ++k) {
                model[k >> 3] |= (uint8_t)(1u << (k & 7u));
            }
            break;
        }
        case 3:
            wr_bitmap_clear_all(&bm);
            memset(model, 0, sizeof(model));
            break;
        case 4: {
            uint32_t got = wr_bitmap_count(&bm);
            uint32_t want = 0;
            for (uint32_t k = 0; k < nbits; ++k) {
                want += (model[k >> 3] >> (k & 7u)) & 1u;
            }
            if (got != want) {
                __builtin_trap();
            }
            break;
        }
        default:
            break;
        }
    }

    uint32_t want_first = UINT32_MAX;
    for (uint32_t k = 0; k < nbits; ++k) {
        if ((model[k >> 3] >> (k & 7u)) & 1u) {
            want_first = k;
            break;
        }
    }
    uint32_t got_first = wr_bitmap_find_first(&bm);
    if (want_first == UINT32_MAX ? got_first != UINT32_MAX
                                 : got_first != want_first) {
        __builtin_trap();
    }

    wr_bitmap_iter it;
    wr_bitmap_iter_init(&it, &bm);
    uint32_t prev = 0;
    bool first = true;
    uint32_t out = 0;
    uint32_t seen = 0;
    while (wr_bitmap_iter_next(&it, &out)) {
        if (out >= nbits || (!first && out <= prev)) {
            __builtin_trap();
        }
        if (!((model[out >> 3] >> (out & 7u)) & 1u)) {
            __builtin_trap();
        }
        prev = out;
        first = false;
        seen++;
    }
    uint32_t want_count = 0;
    for (uint32_t k = 0; k < nbits; ++k) {
        want_count += (model[k >> 3] >> (k & 7u)) & 1u;
    }
    if (seen != want_count) {
        __builtin_trap();
    }

    /* OOB set/clear/test must be no-ops/false, not memory corruption. */
    wr_bitmap_set(&bm, nbits + 1u);
    wr_bitmap_clear(&bm, nbits + 1u);
    if (wr_bitmap_test(&bm, nbits + 1u)) {
        __builtin_trap();
    }
    wr_arena_destroy(a);
    return 0;
}