#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/rtp.h"
#include "wr/rtp_stream.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_rtp_hdr h;
    if (!wr_rtp_parse(wr_span_c_make(data, size), &h)) {
        return 0;
    }

    /* Header length helper must agree with the parser for the same fields. */
    uint16_t ext_words = (uint16_t)(h.ext_raw.len / 4u);
    size_t expect = wr_rtp_header_len(h.cc, h.ext != 0u, ext_words);
    if (expect != h.header_len) {
        __builtin_trap();
    }

    /* Serialize the parsed header with a fuzzed payload and reparse. */
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint8_t payload[512];
    size_t plen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(payload));
    for (size_t i = 0; i < plen; ++i) {
        payload[i] = wr_fuzz_stream_u8(&fs);
    }
    char buf[1024];
    size_t n = 0;
    if (wr_rtp_serialize(&h, wr_span_c_make(payload, plen), buf, sizeof(buf),
                         &n) == WR_OK) {
        wr_rtp_hdr h2;
        if (!wr_rtp_parse(wr_span_c_make(buf, n), &h2)) {
            __builtin_trap();
        }
        if (h2.seq != h.seq || h2.timestamp != h.timestamp ||
            h2.ssrc != h.ssrc || h2.pt != h.pt || h2.marker != h.marker ||
            h2.cc != h.cc) {
            __builtin_trap();
        }
    }

    /* Extension parser over arbitrary bytes and lengths. */
    uint16_t ids[8];
    wr_span_c ext_data[8];
    size_t count = 0;
    (void)wr_rtp_ext_parse(wr_span_c_make(data, size), ids, ext_data, 8u,
                           &count);

    /* SSRC-indexed stream table exercises map + pool + SoA. */
    wr_arena *a = wr_arena_create(64u * 1024u);
    if (!a) {
        return 0;
    }
    uint32_t max_streams = 1u + wr_fuzz_stream_below(&fs, 32u);
    wr_rtp_stream_table *t = wr_rtp_stream_table_create(a, max_streams);
    if (t) {
        for (int i = 0; i < 32; ++i) {
            wr_rtp_stream *s = wr_rtp_stream_get_or_create(
                t, (uint32_t)wr_fuzz_stream_next(&fs));
            if (s) {
                wr_rtp_stream_update(s, &h, plen, wr_fuzz_stream_next(&fs));
            }
            (void)wr_rtp_stream_find(t, (uint32_t)wr_fuzz_stream_next(&fs));
            if (wr_fuzz_stream_bool(&fs)) {
                (void)wr_rtp_stream_remove(
                    t, (uint32_t)wr_fuzz_stream_next(&fs));
            }
            (void)wr_rtp_stream_count(t);
        }
        if (wr_rtp_stream_count(t) > wr_rtp_stream_capacity(t)) {
            __builtin_trap();
        }
        wr_rtp_stream_table_destroy(t);
    }
    wr_arena_destroy(a);
    return 0;
}