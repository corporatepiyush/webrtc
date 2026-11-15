/* Acceptance probe for the DTLS cookie exchange + extensions (docs/GAPS.md
 * gap 2), direction 1: wr DTLS CLIENT interoperating with OpenSSL s_server
 * -dtls1_2. The handshake must survive the HelloVerifyRequest cookie round
 * (OpenSSL sends one by default), negotiate ECDHE-ECDSA-AES128-GCM-SHA256
 * with extended_master_secret, and complete with both Finished messages
 * accepted. After the handshake an application-data echo round-trip runs.
 *
 * Usage:
 *   mkfifo /tmp/wr_fifo
 *   openssl s_server -dtls1_2 -accept 4433 \
 *     -cert /tmp/wr_cert.pem -key /tmp/wr_key.pem -naccept 1 \
 *     < /tmp/wr_fifo &
 *   exec 9>/tmp/wr_fifo      # keep s_server's stdin open
 *   ./p_interop_cli 4433
 *
 * Build:
 *   clang -O2 -Iinclude docs/probes/p_interop_cli.c build-rel/libwr.a \
 *     -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o /tmp/p_interop_cli
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
    wr_rng_seed(rng, 77);
    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0u);
    wr_io *io = wr_io_udp_create(&loop, true);
    if (!io) {
        printf("FAIL: no socket\n");
        return 1;
    }
    wr_endpoint peer;
    char target[64];
    snprintf(target, sizeof(target), "127.0.0.1:%u", port);
    if (!wr_endpoint_parse(wr_span_c_from_str(target), (uint16_t)port,
                           &peer)) {
        printf("FAIL: parse\n");
        return 1;
    }
    wr_dtls *cli = wr_dtls_create(a, rng, WR_DTLS_ROLE_CLIENT, io, &peer);
    if (!cli) {
        printf("FAIL: create\n");
        return 1;
    }
    /* Peer fingerprint checking is optional; s_server uses a self-signed
     * test certificate, so the check is skipped here. */
    uint64_t now = 1000u;
    wr_status st = wr_dtls_start(cli, now);
    printf("start st=%d\n", st);

    uint8_t buf[4096];
    bool ready = false;
    for (int i = 0; i < 2000 && !ready; ++i) {
        now += 10u;
        (void)wr_dtls_step(cli, now);
        bool r = false;
        while (wr_io_wait(io, 10u, &r) == WR_OK && r) {
            wr_endpoint from;
            wr_span data;
            if (wr_io_recv(io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
                WR_OK) {
                break;
            }
            wr_status ist = wr_dtls_input(cli, NULL, wr_span_upcast(data));
            if (ist != WR_OK && ist != WR_ERR_AUTH) {
                printf("input err %d at i=%d\n", ist, i);
            }
        }
        ready = wr_dtls_ready(cli);
    }
    printf("ready=%d state=%d\n", (int)ready, (int)wr_dtls_state(cli));
    if (!ready) {
        printf("RESULT: FAIL (handshake incomplete)\n");
        return 1;
    }

    st = wr_dtls_send(cli, wr_span_c_from_str("ping\n"));
    printf("send ping st=%d\n", st);
    bool echoed = false;
    for (int i = 0; i < 2000 && !echoed; ++i) {
        now += 10u;
        (void)wr_dtls_step(cli, now);
        bool r = false;
        while (wr_io_wait(io, 10u, &r) == WR_OK && r) {
            wr_endpoint from;
            wr_span data;
            if (wr_io_recv(io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
                WR_OK) {
                break;
            }
            (void)wr_dtls_input(cli, NULL, wr_span_upcast(data));
        }
        wr_span_c out;
        if (wr_dtls_recv(cli, &out)) {
            printf("echo '%.*s' (%zu B)\n", (int)out.len, out.ptr, out.len);
            echoed = out.len == 5u && memcmp(out.ptr, "ping\n", 5u) == 0;
        }
    }
    printf(echoed ? "RESULT: PASS (echo verified)\n"
                  : "RESULT: FAIL (no echo)\n");
    return echoed ? 0 : 1;
}
