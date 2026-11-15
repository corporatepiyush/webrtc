#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/dtls.h"

#include <string.h>

static void pump(wr_io *from, wr_dtls *to, wr_fuzz_stream *fs,
                 uint8_t *buf, size_t cap)
{
    for (int i = 0; i < 16; ++i) {
        bool ready = false;
        (void)wr_io_wait(from, 0u, &ready);
        if (!ready) {
            return;
        }
        wr_endpoint src;
        wr_span data;
        if (wr_io_recv(from, &src, wr_span_make(buf, cap), &data) != WR_OK) {
            return;
        }
        uint32_t choice = wr_fuzz_stream_below(fs, 8u);
        if (choice == 0u) {
            continue; /* drop */
        }
        (void)wr_dtls_input(to, NULL, wr_span_upcast(data));
        if (choice == 1u) {
            (void)wr_dtls_input(to, NULL, wr_span_upcast(data)); /* duplicate */
        } else if (choice == 2u) {
            /* replay an older copy by rewinding the length is not possible;
             * re-input the same bytes after a step is enough for replay. */
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(2u * 1024u * 1024u);
    if (!a) {
        return 0;
    }
    wr_rng *rng_a = wr_rng_create();
    wr_rng *rng_b = wr_rng_create();
    if (!rng_a || !rng_b) {
        wr_rng_destroy(rng_a);
        wr_rng_destroy(rng_b);
        wr_arena_destroy(a);
        return 0;
    }
    wr_rng_seed(rng_a, size ? wr_fuzz_u64(data, size) : 1u);
    wr_rng_seed(rng_b, size > 8u ? wr_fuzz_u64(data + 8u, size - 8u) : 2u);

    wr_endpoint ep_a, ep_b;
    wr_endpoint_loopback(&ep_a, 0u);
    wr_endpoint_loopback(&ep_b, 0u);
    wr_io *io_a = wr_io_udp_create(&ep_a, true);
    wr_io *io_b = wr_io_udp_create(&ep_b, true);
    if (!io_a || !io_b || !wr_io_local_addr(io_a, &ep_a) ||
        !wr_io_local_addr(io_b, &ep_b)) {
        wr_io_destroy(io_a);
        wr_io_destroy(io_b);
        wr_rng_destroy(rng_a);
        wr_rng_destroy(rng_b);
        wr_arena_destroy(a);
        return 0;
    }

    wr_dtls *client = wr_dtls_create(a, rng_a, WR_DTLS_ROLE_CLIENT, io_a,
                                     &ep_b);
    wr_dtls *server = wr_dtls_create(a, rng_b, WR_DTLS_ROLE_SERVER, io_b,
                                     &ep_a);
    if (!client || !server) {
        wr_dtls_destroy(client);
        wr_dtls_destroy(server);
        wr_io_destroy(io_a);
        wr_io_destroy(io_b);
        wr_rng_destroy(rng_a);
        wr_rng_destroy(rng_b);
        wr_arena_destroy(a);
        return 0;
    }

    size_t fp_len = 0;
    const uint8_t *fp = wr_dtls_fingerprint(server, &fp_len);
    (void)wr_dtls_set_peer_fingerprint(client, fp, fp_len);
    fp = wr_dtls_fingerprint(client, &fp_len);
    (void)wr_dtls_set_peer_fingerprint(server, fp, fp_len);

    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    uint32_t start_role = wr_fuzz_stream_below(&fs, 2u);
    if (start_role == 0u) {
        (void)wr_dtls_start(client, 0u);
    } else {
        (void)wr_dtls_start(server, 0u);
    }

    uint8_t buf[2048];
    uint64_t now = 0u;
    for (int i = 0; i < 80; ++i) {
        now += 5u + wr_fuzz_stream_below(&fs, 40u);
        (void)wr_dtls_step(client, now);
        (void)wr_dtls_step(server, now);
        pump(io_a, client, &fs, buf, sizeof(buf));
        pump(io_b, server, &fs, buf, sizeof(buf));
        if (wr_fuzz_stream_below(&fs, 16u) == 0u) {
            wr_span_c junk = wr_span_c_make(data, size < 64u ? size : 64u);
            (void)wr_dtls_input(client, NULL, junk);
        }
        if (wr_dtls_ready(client) && wr_dtls_ready(server)) {
            break;
        }
    }

    if (wr_dtls_ready(client) && wr_dtls_ready(server)) {
        uint8_t app[256];
        size_t alen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(app));
        for (size_t i = 0; i < alen; ++i) {
            app[i] = wr_fuzz_stream_u8(&fs);
        }
        if (wr_dtls_send(client, wr_span_c_make(app, alen)) == WR_OK) {
            pump(io_b, server, &fs, buf, sizeof(buf));
            wr_span_c out;
            if (wr_dtls_recv(server, &out) &&
                (out.len != alen || memcmp(out.ptr, app, alen) != 0)) {
                __builtin_trap();
            }
        }
        (void)wr_dtls_send(server, wr_span_c_from_str("pong"));
        pump(io_a, client, &fs, buf, sizeof(buf));
        wr_span_c out;
        if (wr_dtls_recv(client, &out) &&
            !wr_span_c_eq(out, wr_span_c_from_str("pong"))) {
            __builtin_trap();
        }
    }

    (void)wr_dtls_state(client);
    (void)wr_dtls_state(server);
    wr_dtls_destroy(client);
    wr_dtls_destroy(server);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng_a);
    wr_rng_destroy(rng_b);
    wr_arena_destroy(a);
    return 0;
}