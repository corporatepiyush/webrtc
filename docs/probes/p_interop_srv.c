/* Acceptance probe for the DTLS cookie exchange + extensions (docs/GAPS.md
 * gap 2), direction 2: wr DTLS SERVER interoperating with OpenSSL s_client
 * -dtls1_2. The handshake must survive the HelloVerifyRequest cookie round
 * (OpenSSL answers the cookieless ClientHello with one), negotiate
 * ECDHE-ECDSA-AES128-GCM-SHA256 with extended_master_secret, and complete
 * with both Finished messages accepted. After the handshake the server
 * echoes the first application-data line s_client sends.
 *
 * Usage:
 *   mkfifo /tmp/wr_fifo
 *   printf 'ping\n' > /tmp/in.txt
 *   openssl s_client -dtls1_2 -connect 127.0.0.1:4433 \
 *     -cert /tmp/wr_cert.pem -key /tmp/wr_key.pem \
 *     -cipher ECDHE-ECDSA-AES128-GCM-SHA256 \
 *     < /tmp/in.txt > /tmp/scl.log 2>&1 &
 *   ./p_interop_srv 4433
 *
 * PASS requires our server to complete the handshake, receive s_client's
 * "ping" and echo it; grep the s_client log for the echoed line.
 *
 * Build:
 *   clang -O2 -Iinclude docs/probes/p_interop_srv.c build-rel/libwr.a \
 *     -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o /tmp/p_interop_srv
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/dtls.h"
#include "wr/net.h"
#include "wr/rng.h"

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned port = 4433u;
    if (argc > 1) {
        port = (unsigned)atoi(argv[1]);
    }
    wr_arena *a = wr_arena_create(4u << 20);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 78);
    wr_endpoint bind_ep;
    wr_endpoint_loopback(&bind_ep, (uint16_t)port);
    wr_io *io = wr_io_udp_create(&bind_ep, true);
    if (!io) {
        printf("FAIL: no socket\n");
        return 1;
    }

    /* The s_client source port is ephemeral; learn the peer from its first
     * datagram, then start the association against it. */
    uint8_t buf[4096];
    wr_endpoint from;
    wr_span data;
    bool got = false;
    for (int i = 0; i < 2000 && !got; ++i) {
        bool r = false;
        if (wr_io_wait(io, 10u, &r) != WR_OK || !r) {
            continue;
        }
        if (wr_io_recv(io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            continue;
        }
        got = data.len > 0u;
    }
    if (!got) {
        printf("FAIL: no first datagram from s_client\n");
        return 1;
    }

    wr_dtls *srv = wr_dtls_create(a, rng, WR_DTLS_ROLE_SERVER, io, &from);
    if (!srv) {
        printf("FAIL: create\n");
        return 1;
    }
    /* Fingerprint checking stays off: s_client uses the same self-signed
     * test certificate. */
    uint64_t now = 1000u;
    wr_status st = wr_dtls_input(srv, NULL, wr_span_upcast(data));
    printf("first input st=%d\n", st);

    bool ready = false;
    for (int i = 0; i < 2000 && !ready; ++i) {
        now += 10u;
        (void)wr_dtls_step(srv, now);
        bool r = false;
        while (wr_io_wait(io, 10u, &r) == WR_OK && r) {
            wr_endpoint f2;
            wr_span d2;
            if (wr_io_recv(io, &f2, wr_span_make(buf, sizeof(buf)), &d2) !=
                WR_OK) {
                break;
            }
            wr_status ist = wr_dtls_input(srv, NULL, wr_span_upcast(d2));
            if (ist != WR_OK && ist != WR_ERR_AUTH) {
                printf("input err %d at i=%d\n", ist, i);
            }
        }
        ready = wr_dtls_ready(srv);
    }
    printf("ready=%d state=%d\n", (int)ready, (int)wr_dtls_state(srv));
    if (!ready) {
        printf("RESULT: FAIL (handshake incomplete)\n");
        return 1;
    }

    /* Echo the first application-data line s_client sends. */
    bool echoed = false;
    for (int i = 0; i < 2000 && !echoed; ++i) {
        now += 10u;
        (void)wr_dtls_step(srv, now);
        bool r = false;
        while (wr_io_wait(io, 10u, &r) == WR_OK && r) {
            wr_endpoint f2;
            wr_span d2;
            if (wr_io_recv(io, &f2, wr_span_make(buf, sizeof(buf)), &d2) !=
                WR_OK) {
                break;
            }
            (void)wr_dtls_input(srv, NULL, wr_span_upcast(d2));
        }
        wr_span_c out;
        if (wr_dtls_recv(srv, &out)) {
            printf("got '%.*s' (%zu B)\n", (int)out.len, out.ptr, out.len);
            if (out.len == 5u && memcmp(out.ptr, "ping\n", 5u) == 0) {
                st = wr_dtls_send(srv, out);
                echoed = st == WR_OK;
                printf("echo st=%d\n", st);
            }
        }
    }
    printf(echoed ? "RESULT: PASS (echo sent)\n"
                  : "RESULT: FAIL (no app data)\n");
    return echoed ? 0 : 1;
}
