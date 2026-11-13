#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/pc.h"

#include <stdlib.h>
#include <string.h>

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

    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io = wr_io_udp_create(&lo, true);
    if (!io) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_endpoint local, remote;
    wr_endpoint_loopback(&local, 40000u);
    wr_endpoint_loopback(&remote, 40001u);
    wr_ice_role role = (size & 1u) ? WR_ICE_ROLE_CONTROLLING
                                   : WR_ICE_ROLE_CONTROLLED;
    wr_pc *pc = wr_pc_create(a, rng, io, &local, &remote, role);
    if (!pc) {
        wr_io_destroy(io);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }

    wr_pc_set_credentials(pc, wr_span_c_from_str("abcd"),
                          wr_span_c_from_str(
                              "abcdefghijklmnopqrstuvwx"),
                          wr_span_c_from_str("efgh"),
                          wr_span_c_from_str(
                              "zyxwvutsrqponmlkjihgfedcba"));
    /* Certificate generation is expensive; exercise DTLS on a subset of
     * inputs so the fuzzer keeps a useful throughput. */
    if ((size & 31u) == 0u) {
        wr_pc_enable_dtls(pc);
        const uint8_t *fp = NULL;
        size_t fp_len = 0;
        (void)wr_pc_local_fingerprint(pc, &fp, &fp_len);
        if (fp_len == 32u) {
            (void)wr_pc_set_peer_fingerprint(pc, fp, fp_len);
        }
    }

    char sdp[4096];
    size_t n = 0;
    if (wr_pc_create_offer(pc, sdp, sizeof(sdp), &n) == WR_OK) {
        char answer[4096];
        size_t an = 0;
        if (wr_pc_create_answer(pc, wr_span_c_make(sdp, n), answer,
                                sizeof(answer), &an) == WR_OK) {
            (void)wr_pc_set_remote_description(pc, wr_span_c_make(answer, an));
        }
    }

    /* Arbitrary remote descriptions must be rejected or ignored, never
     * crash. */
    if (size > 0u) {
        (void)wr_pc_set_remote_description(pc, wr_span_c_make(data, size));
    }

    (void)wr_pc_start(pc, 0u);
    /* wr_pc_step pumps the UDP socket with a 10 ms poll per drain pass.
     * Exercise it on a subset of inputs; the full ICE/DTLS/SCTP integration
     * is covered by tests/test_pc.c. */
    if ((size & 15u) == 0u) {
        (void)wr_pc_step(pc, 5u);
    }
    (void)wr_pc_send(pc, wr_span_c_from_str("hello"));
    wr_sctp_delivery d;
    (void)wr_pc_recv(pc, &d);

    (void)wr_pc_ready(pc);
    (void)wr_pc_dtls_ready(pc);
    (void)wr_pc_ice_state(pc);
    (void)wr_pc_ice(pc);
    (void)wr_pc_sctp(pc);
    wr_pc_close(pc);
    wr_pc_destroy(pc);
    wr_io_destroy(io);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}