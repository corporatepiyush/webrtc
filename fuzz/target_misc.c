#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/base.h"
#include "wr/crc32.h"
#include "wr/crc32c.h"
#include "wr/hash.h"

#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_span_c s = wr_span_c_make(data, size);
    if (!wr_span_c_eq(s, s) || !wr_span_c_starts_with(s, wr_span_c_make(data, 0))) {
        __builtin_trap();
    }
    if (!wr_span_c_case_eq(s, s)) {
        __builtin_trap();
    }

    /* take/drop/sub consistency. */
    size_t cut = size / 3u;
    wr_span_c rest = s;
    wr_span_c a = wr_span_c_take(&rest, cut);
    if (a.len != cut || rest.len != size - cut) {
        __builtin_trap();
    }
    wr_span_c b = wr_span_c_take(&rest, size);
    if (rest.len != 0u) {
        __builtin_trap();
    }
    if (a.len + b.len != size) {
        __builtin_trap();
    }
    wr_span_c sub = wr_span_c_sub(s, cut, size - cut);
    if (!wr_span_c_eq(sub, b)) {
        __builtin_trap();
    }
    /* Invalid offsets are empty, not out of bounds. */
    if (wr_span_c_sub(s, size + 1u, 1u).ptr != NULL ||
        wr_span_c_sub(s, 0u, size + 1u).ptr != NULL) {
        __builtin_trap();
    }

    /* Decimal parsing: round trip and reject junk. */
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    for (int i = 0; i < 16; ++i) {
        uint64_t v = wr_fuzz_stream_next(&fs);
        char tmp[32];
        int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
        if (n <= 0 || (size_t)n >= sizeof(tmp)) {
            __builtin_trap();
        }
        uint64_t got = 0;
        if (!wr_parse_u64(wr_span_c_make(tmp, (size_t)n), &got) ||
            got != v) {
            __builtin_trap();
        }
    }
    {
        uint64_t v = 0;
        if (wr_parse_u64(wr_span_c_from_str(""), &v) ||
            wr_parse_u64(wr_span_c_from_str("-1"), &v) ||
            wr_parse_u64(wr_span_c_from_str("12x"), &v) ||
            wr_parse_u64(wr_span_c_from_str("99999999999999999999999"), &v)) {
            __builtin_trap();
        }
    }

    /* Hash stability and case-insensitive equality. */
    uint64_t h1 = wr_hash64(data, size, 0u);
    uint64_t h2 = wr_hash64(data, size, 0u);
    if (h1 != h2 || h1 == 0u) {
        __builtin_trap();
    }
    (void)wr_hash32(data, size, 0u);
    (void)wr_hash_span(s);
    (void)wr_hash_span_ci(s);
    if (!wr_span_c_case_eq(wr_span_c_from_str("AbC"),
                           wr_span_c_from_str("aBc"))) {
        __builtin_trap();
    }

    /* Known CRC vectors. */
    if (wr_crc32(0u, "123456789", 9) != 0xcbf43926u) {
        __builtin_trap();
    }
    if (wr_crc32c(0u, "123456789", 9) != 0xe3069283u) {
        __builtin_trap();
    }
    if (wr_crc32(0u, data, 0) != 0u || wr_crc32c(0u, data, 0) != 0u) {
        __builtin_trap();
    }

    /* Status strings are total. */
    static const wr_status codes[] = {
        WR_OK, WR_ERR_INVAL, WR_ERR_NOMEM, WR_ERR_TRUNCATED,
        WR_ERR_OVERFLOW, WR_ERR_NOT_FOUND, WR_ERR_EXISTS, WR_ERR_STATE,
        WR_ERR_AUTH, WR_ERR_TIMEOUT, WR_ERR_IO, WR_ERR_LIMIT, WR_ERR_CRYPTO,
        WR_ERR_CLOSED, WR_ERR_AGAIN, WR_ERR_UNSUPPORTED,
    };
    for (size_t i = 0; i < WR_ARRAY_LEN(codes); ++i) {
        if (!wr_status_str(codes[i]) || !wr_status_module(codes[i])) {
            __builtin_trap();
        }
    }
    return 0;
}