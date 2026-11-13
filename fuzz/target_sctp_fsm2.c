#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/sctp.h"

#include <string.h>

static int pump(wr_sctp_assoc *dst, wr_io *src, uint64_t now,
                wr_fuzz_stream *fs, uint8_t *buf, size_t cap)
{
    int delivered = 0;
    for (int i = 0; i < 16; ++i) {
        bool ready = false;
        (void)wr_io_wait(src, 0u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(src, &from, wr_span_make(buf, cap), &data) != WR_OK) {
            break;
        }
        uint32_t choice = wr_fuzz_stream_below(fs, 10u);
        if (choice == 0u) {
            continue; /* drop */
        }
        (void)wr_sctp_input(dst, now, wr_span_upcast(data));
        delivered++;
        if (choice == 1u) {
            (void)wr_sctp_input(dst, now, wr_span_upcast(data)); /* dup */
        }
    }
    return delivered;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    if (!a) {
        return 0;
    }
    wr_rng *rng = wr_rng_create();
    if (!rng) {
        wr_arena_destroy(a);
        return 0;
    }
    wr_rng_seed(rng, size ? wr_fuzz_u64(data, size) : 1u);

    wr_endpoint lo_a, lo_b;
    wr_endpoint_loopback(&lo_a, 0u);
    wr_endpoint_loopback(&lo_b, 0u);
    wr_io *ia = wr_io_udp_create(&lo_a, true);
    wr_io *ib = wr_io_udp_create(&lo_b, true);
    if (!ia || !ib) {
        wr_io_destroy(ia);
        wr_io_destroy(ib);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_endpoint ea, eb;
    if (!wr_io_local_addr(ia, &ea) || !wr_io_local_addr(ib, &eb)) {
        wr_io_destroy(ia);
        wr_io_destroy(ib);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }

    wr_sctp_assoc *a1 = wr_sctp_create(a, ea.port, eb.port, rng);
    wr_sctp_assoc *b1 = wr_sctp_create(a, eb.port, ea.port, rng);
    if (!a1 || !b1) {
        wr_sctp_close(a1);
        wr_sctp_close(b1);
        wr_io_destroy(ia);
        wr_io_destroy(ib);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_sctp_attach_io(a1, ia, &eb);
    wr_sctp_attach_io(b1, ib, &ea);
    wr_sctp_start_established(a1, 1000u, 2000u, 2000u);
    wr_sctp_start_established(b1, 2000u, 1000u, 1000u);

    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint8_t buf[2048];
    uint64_t now = 0u;

    for (int i = 0; i < 48; ++i) {
        now += 1u + wr_fuzz_stream_below(&fs, 50u);

        /* Fuzzed application writes in both directions. */
        if (wr_fuzz_stream_below(&fs, 3u) == 0u) {
            uint8_t payload[128];
            size_t plen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(payload));
            for (size_t k = 0; k < plen; ++k) {
                payload[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_sctp_send_data(a1, (uint16_t)wr_fuzz_stream_below(&fs, 4u),
                                    (uint32_t)wr_fuzz_stream_next(&fs),
                                    wr_span_c_make(payload, plen), now);
        }
        (void)wr_sctp_step(a1, now);
        (void)wr_sctp_step(b1, now);
        (void)pump(b1, ib, now, &fs, buf, sizeof(buf));
        (void)pump(a1, ia, now, &fs, buf, sizeof(buf));
        (void)wr_sctp_step(a1, now);
        (void)wr_sctp_step(b1, now);

        /* Inject malformed datagrams at both ends. */
        if (wr_fuzz_stream_below(&fs, 8u) == 0u) {
            size_t n = wr_fuzz_stream_below(&fs, 128u);
            uint8_t junk[128];
            for (size_t k = 0; k < n; ++k) {
                junk[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_sctp_input(a1, now, wr_span_c_make(junk, n));
        }
        if (wr_fuzz_stream_below(&fs, 16u) == 0u) {
            wr_sctp_delivery d;
            while (wr_sctp_recv(b1, &d)) {
                if (d.data.len == 5u &&
                    memcmp(d.data.ptr, "lossy", 5u) == 0) {
                    /* expected payload observed */
                }
            }
            while (wr_sctp_recv(a1, &d)) {
            }
        }
        (void)wr_sctp_last_ack(a1);
        (void)wr_sctp_last_ack(b1);
    }

    (void)wr_sctp_get_state(a1);
    (void)wr_sctp_get_state(b1);
    wr_sctp_close(a1);
    wr_sctp_close(b1);
    wr_io_destroy(ia);
    wr_io_destroy(ib);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}