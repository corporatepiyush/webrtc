#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/net.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);

    /* Parse arbitrary text as endpoint (bounded to a line). */
    char text[160];
    size_t tlen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(text));
    for (size_t i = 0; i < tlen; ++i) {
        text[i] = (char)(wr_fuzz_stream_u8(&fs) | 1u);
    }
    text[tlen] = '\0';
    wr_endpoint ep;
    (void)wr_endpoint_parse(wr_span_c_make(text, tlen), 1234u, &ep);

    /* IPv4 round trip through text and sockaddr. */
    uint8_t v4[4];
    for (size_t i = 0; i < sizeof(v4); ++i) {
        v4[i] = wr_fuzz_stream_u8(&fs);
    }
    wr_endpoint e4;
    wr_endpoint_v4(&e4, v4, (uint16_t)wr_fuzz_stream_next(&fs));
    char buf[128];
    size_t n = wr_endpoint_format(&e4, buf, sizeof(buf));
    if (n == 0u || n >= sizeof(buf)) {
        __builtin_trap();
    }
    wr_endpoint back4;
    if (!wr_endpoint_parse(wr_span_c_make(buf, n), 0u, &back4) ||
        !wr_endpoint_eq(&e4, &back4)) {
        __builtin_trap();
    }

    /* IPv6 round trip (scope is not represented in text). */
    uint8_t v6[16];
    for (size_t i = 0; i < sizeof(v6); ++i) {
        v6[i] = wr_fuzz_stream_u8(&fs);
    }
    wr_endpoint e6;
    wr_endpoint_v6(&e6, v6, 0u, (uint16_t)wr_fuzz_stream_next(&fs));
    n = wr_endpoint_format(&e6, buf, sizeof(buf));
    if (n == 0u || n >= sizeof(buf)) {
        __builtin_trap();
    }
    wr_endpoint back6;
    if (!wr_endpoint_parse(wr_span_c_make(buf, n), 0u, &back6) ||
        !wr_endpoint_eq(&e6, &back6)) {
        __builtin_trap();
    }

    /* Truncated format buffers must never write out of bounds. */
    for (size_t cap = 0; cap < 16u; ++cap) {
        char small[16];
        memset(small, 0x7f, sizeof(small));
        (void)wr_endpoint_format(&e4, small, cap);
    }

    struct sockaddr_storage ss;
    if (wr_endpoint_to_sockaddr(&e4, &ss) != 0u) {
        wr_endpoint from_ss;
        if (!wr_endpoint_from_sockaddr((const struct sockaddr *)&ss,
                                       &from_ss) ||
            !wr_endpoint_eq(&e4, &from_ss)) {
            __builtin_trap();
        }
    }
    if (wr_endpoint_to_sockaddr(&e6, &ss) != 0u) {
        wr_endpoint from_ss;
        if (!wr_endpoint_from_sockaddr((const struct sockaddr *)&ss,
                                       &from_ss) ||
            !wr_endpoint_eq(&e6, &from_ss)) {
            __builtin_trap();
        }
    }

    (void)wr_endpoint_is_loopback(&e4);
    (void)wr_endpoint_is_unspec(&e4);
    return 0;
}