#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/pool.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    if (!a) {
        return 0;
    }
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint32_t cap = 1u + wr_fuzz_stream_below(&fs, 32u);
    size_t elem = 8u + wr_fuzz_stream_below(&fs, 64u);
    wr_pool p;
    if (!wr_pool_init(&p, a, cap, elem, 16u)) {
        wr_arena_destroy(a);
        return 0;
    }
    if (wr_pool_capacity(&p) != cap) {
        __builtin_trap();
    }

    void *live[64];
    memset(live, 0, sizeof(live));
    uint32_t in_use = 0;
    for (int i = 0; i < 256; ++i) {
        uint32_t slot = wr_fuzz_stream_below(&fs, cap);
        if (wr_fuzz_stream_bool(&fs)) {
            void *obj = wr_pool_alloc(&p);
            if (obj) {
                if ((uintptr_t)wr_pool_at(&p, 0u) % 16u != 0u) {
                    __builtin_trap();
                }
                uint32_t idx = wr_pool_index(&p, obj);
                if (idx >= cap || wr_pool_at(&p, idx) != obj) {
                    __builtin_trap();
                }
                if (live[slot] != NULL) {
                    wr_pool_free(&p, live[slot]);
                    in_use--;
                }
                live[slot] = obj;
                in_use++;
            }
        } else if (live[slot]) {
            void *obj = live[slot];
            uint32_t idx = wr_pool_index(&p, obj);
            if (wr_pool_at(&p, idx) != obj) {
                __builtin_trap();
            }
            wr_pool_free(&p, obj);
            live[slot] = NULL;
            in_use--;
        }
        if (wr_pool_in_use(&p) != in_use) {
            __builtin_trap();
        }
        if (in_use > cap) {
            __builtin_trap();
        }
    }

    /* Drain and ensure the pool is reusable. */
    for (uint32_t i = 0; i < cap; ++i) {
        if (live[i]) {
            wr_pool_free(&p, live[i]);
            live[i] = NULL;
            in_use--;
        }
    }
    if (wr_pool_in_use(&p) != 0u) {
        __builtin_trap();
    }
    for (uint32_t i = 0; i < cap; ++i) {
        void *obj = wr_pool_alloc(&p);
        if (!obj) {
            __builtin_trap();
        }
    }
    if (wr_pool_alloc(&p) != NULL) {
        __builtin_trap();
    }
    wr_pool_destroy(&p);
    wr_arena_destroy(a);
    return 0;
}