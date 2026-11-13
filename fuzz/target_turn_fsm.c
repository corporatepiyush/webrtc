#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/turn.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(256u * 1024u);
    if (!a) {
        return 0;
    }
    wr_rng *rng = wr_rng_create();
    if (!rng) {
        wr_arena_destroy(a);
        return 0;
    }
    wr_rng_seed(rng, size ? wr_fuzz_u64(data, size) : 1u);

    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io = wr_io_udp_create(&lo, true);
    if (!io) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_endpoint server;
    wr_endpoint_loopback(&server, 3478u);

    wr_turn *t = wr_turn_create(a, rng, io, &server,
                                wr_span_c_from_str("user"),
                                wr_span_c_from_str("password"));
    if (!t) {
        wr_io_destroy(io);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }

    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    (void)wr_turn_start(t, 0u);

    uint8_t buf[1024];
    uint64_t now = 0u;
    for (int i = 0; i < 80; ++i) {
        now += 5u + wr_fuzz_stream_below(&fs, 50u);
        (void)wr_turn_step(t, now);

        uint32_t inject = wr_fuzz_stream_below(&fs, 6u);
        if (inject == 0u) {
            size_t n = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(buf));
            for (size_t k = 0; k < n; ++k) {
                buf[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_turn_input(t, now, wr_span_c_make(buf, n));
        }

        if (wr_fuzz_stream_below(&fs, 12u) == 0u) {
            wr_endpoint peer;
            wr_endpoint_loopback(&peer, (uint16_t)(50000u +
                                                   wr_fuzz_stream_below(&fs, 100u)));
            (void)wr_turn_connect(t, &peer,
                                  (uint16_t)(0x4000u +
                                             wr_fuzz_stream_below(&fs, 100u)));
        }
        if (wr_fuzz_stream_below(&fs, 8u) == 0u) {
            uint8_t app[128];
            size_t alen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(app));
            for (size_t k = 0; k < alen; ++k) {
                app[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_turn_send(t, wr_span_c_make(app, alen));
        }
        wr_span_c out;
        while (wr_turn_recv(t, &out)) {
        }
        (void)wr_turn_get_status(t);
        (void)wr_turn_relayed(t);
    }

    wr_turn_destroy(t);
    wr_io_destroy(io);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}