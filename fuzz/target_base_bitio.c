#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/bitio.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint8_t buf[128];
    wr_bitwr w;
    wr_bitwr_init(&w, wr_span_make(buf, sizeof(buf)));

    /* Write a deterministic sequence: bits, bytes, 16/24/32-bit words. */
    for (int i = 0; i < 64 && !w.overrun; ++i) {
        uint32_t op = wr_fuzz_stream_below(&fs, 6u);
        switch (op) {
        case 0: {
            uint8_t bit = (uint8_t)wr_fuzz_stream_below(&fs, 2u);
            (void)wr_bitwr_u1(&w, bit);
            break;
        }
        case 1:
            (void)wr_bitwr_u8(&w, wr_fuzz_stream_u8(&fs));
            break;
        case 2:
            (void)wr_bitwr_u16(&w, (uint16_t)wr_fuzz_stream_next(&fs));
            break;
        case 3:
            (void)wr_bitwr_u24(&w, (uint32_t)wr_fuzz_stream_next(&fs));
            break;
        case 4:
            (void)wr_bitwr_u32(&w, (uint32_t)wr_fuzz_stream_next(&fs));
            break;
        default: {
            uint8_t raw[8];
            size_t n = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(raw));
            for (size_t k = 0; k < n; ++k) {
                raw[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_bitwr_bytes(&w, wr_span_c_make(raw, n));
            break;
        }
        }
    }
    (void)wr_bitwr_align_zero(&w);
    size_t used = wr_bitwr_used(&w);
    size_t bytes = (used + 7u) / 8u;
    if (bytes > sizeof(buf)) {
        __builtin_trap();
    }

    /* Read the whole buffer back; values must not be required to match
     * because the sequence above is not recorded, but reads must stay in
     * bounds and overrun must be sticky. */
    wr_bitrd r;
    wr_bitrd_init(&r, wr_span_c_make(buf, bytes));
    for (int i = 0; i < 128 && !r.overrun; ++i) {
        uint32_t op = wr_fuzz_stream_below(&fs, 5u);
        switch (op) {
        case 0: {
            uint8_t v = 0;
            (void)wr_bitrd_u1(&r, &v);
            break;
        }
        case 1: {
            uint8_t v = 0;
            (void)wr_bitrd_u8(&r, &v);
            break;
        }
        case 2: {
            uint16_t v = 0;
            (void)wr_bitrd_u16(&r, &v);
            break;
        }
        case 3: {
            uint32_t v = 0;
            (void)wr_bitrd_u24(&r, &v);
            break;
        }
        default: {
            uint32_t v = 0;
            (void)wr_bitrd_u32(&r, &v);
            break;
        }
        }
        (void)wr_bitrd_left(&r);
    }
    (void)wr_bitrd_align(&r);
    (void)wr_bitrd_skip(&r, wr_fuzz_stream_below(&fs, 128u));

    /* Every truncation length must be handled safely. */
    for (size_t n = 0; n <= sizeof(buf); ++n) {
        wr_bitrd tr;
        wr_bitrd_init(&tr, wr_span_c_make(buf, n));
        for (int i = 0; i < 16; ++i) {
            uint8_t v8 = 0;
            uint16_t v16 = 0;
            uint32_t v32 = 0;
            (void)wr_bitrd_u1(&tr, &v8);
            (void)wr_bitrd_u8(&tr, &v8);
            (void)wr_bitrd_u16(&tr, &v16);
            (void)wr_bitrd_u24(&tr, &v32);
            (void)wr_bitrd_u32(&tr, &v32);
            (void)wr_bitrd_left(&tr);
        }
    }
    return 0;
}