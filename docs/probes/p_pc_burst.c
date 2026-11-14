/* Acceptance probe for DTLS record framing (docs/GAPS.md gaps 3 and 4).
 *
 * Before the fix: three back-to-back data-channel messages through the full
 * wr_pc + ICE + DTLS + SCTP stack delivered 0 of 3, because two DTLS records
 * in flight were concatenated and SCTP's parser dropped the whole datagram.
 * After the fix the acceptance is 3 of 3.
 *
 * Build:
 *   clang -O2 -Iinclude docs/probes/p_pc_burst.c build-rel/libwr.a \
 *     -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o /tmp/p_pc_burst
 */
#include <stdio.h>
#include <string.h>
#include "wr/arena.h"
#include "wr/net.h"
#include "wr/pc.h"
#include "wr/rng.h"

int main(void)
{
    wr_arena *a1 = wr_arena_create(4u << 20), *a2 = wr_arena_create(4u << 20);
    wr_rng *r1 = wr_rng_create(), *r2 = wr_rng_create();
    wr_rng_seed(r1, 101);
    wr_rng_seed(r2, 103);
    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *i1 = wr_io_udp_create(&loop, true), *i2 = wr_io_udp_create(&loop, true);
    wr_endpoint e1, e2;
    wr_io_local_addr(i1, &e1);
    wr_io_local_addr(i2, &e2);
    wr_pc *a = wr_pc_create(a1, r1, i1, &e1, &e2, WR_ICE_ROLE_CONTROLLING);
    wr_pc *b = wr_pc_create(a2, r2, i2, &e2, &e1, WR_ICE_ROLE_CONTROLLED);
    wr_pc_set_credentials(a, wr_span_c_from_str("uA"),
                          wr_span_c_from_str("pA"),
                          wr_span_c_from_str("uB"),
                          wr_span_c_from_str("pB"));
    wr_pc_set_credentials(b, wr_span_c_from_str("uB"),
                          wr_span_c_from_str("pB"),
                          wr_span_c_from_str("uA"),
                          wr_span_c_from_str("pA"));
    wr_pc_enable_dtls(a);
    wr_pc_enable_dtls(b);
    const uint8_t *fa, *fb;
    size_t la, lb;
    wr_pc_local_fingerprint(a, &fa, &la);
    wr_pc_local_fingerprint(b, &fb, &lb);
    wr_pc_set_peer_fingerprint(a, fb, lb);
    wr_pc_set_peer_fingerprint(b, fa, la);
    uint64_t now = 1000;
    wr_pc_start(a, now);
    wr_pc_start(b, now);
    for (int i = 0; i < 1000; i++) {
        now += 5;
        wr_pc_step(a, now);
        wr_pc_step(b, now);
        if (wr_pc_ready(a) && wr_pc_ready(b)) {
            break;
        }
    }
    printf("ready a=%d b=%d\n", wr_pc_ready(a), wr_pc_ready(b));
    if (!wr_pc_ready(a) || !wr_pc_ready(b)) {
        return 1;
    }

    static const char *m[3] = {"one", "two", "three"};
    for (int k = 0; k < 3; k++) {
        wr_status st = wr_pc_send(a, wr_span_c_from_str(m[k]));
        printf("send %s -> %d\n", m[k], st);
        if (st != WR_OK) {
            return 1;
        }
    }
    int got = 0;
    wr_sctp_delivery d;
    for (int i = 0; i < 400 && got < 3; i++) {
        now += 5;
        wr_pc_step(a, now);
        wr_pc_step(b, now);
        while (wr_pc_recv(b, &d)) {
            printf("recv: '%.*s'\n", (int)d.data.len, d.data.ptr);
            got++;
        }
    }
    printf("delivered %d of 3\n", got);
    return got == 3 ? 0 : 1;
}
