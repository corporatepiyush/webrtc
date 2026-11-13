#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/map.h"

#include <string.h>

typedef struct {
    uint64_t key;
    uint32_t val;
} u64_ent;

typedef struct {
    char key[24];
    uint32_t val;
} str_ent;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    if (!a) {
        return 0;
    }
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);

    wr_u64_map m;
    u64_ent model[128];
    size_t mlen = 0;
    if (!wr_u64_map_init(&m, a, 8u)) {
        wr_arena_destroy(a);
        return 0;
    }

    for (int i = 0; i < 256; ++i) {
        uint64_t key = wr_fuzz_stream_next(&fs);
        if (key == 0u) {
            key = 1u;
        }
        uint32_t val = (uint32_t)wr_fuzz_stream_next(&fs);
        uint32_t op = wr_fuzz_stream_below(&fs, 3u);
        size_t idx = mlen;
        for (size_t k = 0; k < mlen; ++k) {
            if (model[k].key == key) {
                idx = k;
                break;
            }
        }
        if (op == 0u) {
            if (!wr_u64_map_put(&m, key, val)) {
                __builtin_trap();
            }
            if (idx == mlen) {
                if (mlen < WR_ARRAY_LEN(model)) {
                    model[mlen].key = key;
                    model[mlen].val = val;
                    mlen++;
                }
            } else {
                model[idx].val = val;
            }
        } else if (op == 1u) {
            bool erased = wr_u64_map_erase(&m, key);
            if (idx == mlen ? erased : !erased) {
                __builtin_trap();
            }
            if (erased) {
                for (size_t k = idx; k + 1u < mlen; ++k) {
                    model[k] = model[k + 1u];
                }
                mlen--;
            }
        } else {
            uint32_t *got = wr_u64_map_find(&m, key);
            if (idx == mlen) {
                if (got) {
                    __builtin_trap();
                }
            } else if (!got || *got != model[idx].val) {
                __builtin_trap();
            }
        }
        if (wr_u64_map_len(&m) != mlen) {
            __builtin_trap();
        }
    }

    /* Every surviving model entry must be findable. */
    for (size_t k = 0; k < mlen; ++k) {
        uint32_t *got = wr_u64_map_find(&m, model[k].key);
        if (!got || *got != model[k].val) {
            __builtin_trap();
        }
    }
    wr_u64_map_destroy(&m);

    /* String map with bounded fuzz keys. */
    wr_str_map sm;
    str_ent smodel[64];
    size_t slen = 0;
    if (!wr_str_map_init(&sm, a, 8u)) {
        wr_arena_destroy(a);
        return 0;
    }
    for (int i = 0; i < 128; ++i) {
        char key[24];
        size_t klen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(key));
        for (size_t k = 0; k < klen; ++k) {
            key[k] = (char)(wr_fuzz_stream_u8(&fs) | 1u);
        }
        key[klen] = '\0';
        uint32_t val = (uint32_t)wr_fuzz_stream_next(&fs);
        size_t idx = slen;
        for (size_t k = 0; k < slen; ++k) {
            if (strcmp(smodel[k].key, key) == 0) {
                idx = k;
                break;
            }
        }
        bool do_put = wr_fuzz_stream_bool(&fs);
        if (do_put && idx == slen && slen >= WR_ARRAY_LEN(smodel)) {
            do_put = false;
        }
        if (do_put) {
            if (!wr_str_map_put(&sm, wr_span_c_make(key, klen), val)) {
                __builtin_trap();
            }
            if (idx == slen && slen < WR_ARRAY_LEN(smodel)) {
                memcpy(smodel[slen].key, key, klen + 1u);
                smodel[slen].val = val;
                slen++;
            } else if (idx < slen) {
                smodel[idx].val = val;
            } else if (idx >= WR_ARRAY_LEN(smodel)) {
                __builtin_trap();
            }
        } else {
            uint32_t *got = wr_str_map_find(&sm, wr_span_c_make(key, klen));
            if (idx == slen) {
                if (got) {
                    __builtin_trap();
                }
            } else if (!got || *got != smodel[idx].val) {
                __builtin_trap();
            }
        }
        if (wr_str_map_len(&sm) != slen) {
            __builtin_trap();
        }
    }
    wr_str_map_destroy(&sm);
    wr_arena_destroy(a);
    return 0;
}