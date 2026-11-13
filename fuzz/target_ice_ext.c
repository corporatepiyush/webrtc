#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/ice.h"
#include "wr/stun.h"

#include <stdio.h>
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

    /* Endpoint text parser over the raw input (truncated to a line). */
    char text[256];
    size_t tlen = size < sizeof(text) - 1u ? size : sizeof(text) - 1u;
    memcpy(text, data, tlen);
    text[tlen] = '\0';
    wr_endpoint ep;
    (void)wr_endpoint_parse(wr_span_c_make(text, tlen), 3478u, &ep);

    wr_ice_config cfg;
    wr_ice_config_defaults(&cfg);
    cfg.role = (size & 1u) ? WR_ICE_ROLE_CONTROLLING : WR_ICE_ROLE_CONTROLLED;
    cfg.max_pairs = 64u;
    cfg.check_rto_ms = 50u;
    cfg.max_retransmits = 3u;
    cfg.consent_freshness = true;
    cfg.consent_interval_ms = 100u;
    cfg.consent_timeout_ms = 500u;
    wr_ice_agent *ag = wr_ice_create(a, &cfg, rng);
    if (!ag) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }

    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io = wr_io_udp_create(&lo, true);
    if (io) {
        wr_ice_attach_io(ag, io, &lo);
    }

    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    for (int i = 0; i < 4; ++i) {
        wr_endpoint cand;
        wr_endpoint_loopback(&cand, (uint16_t)(40000u + i));
        if (wr_fuzz_stream_bool(&fs)) {
            (void)wr_ice_add_local_candidate(ag, cand, WR_ICE_CAND_HOST,
                                             (uint16_t)(i + 1u));
        } else {
            (void)wr_ice_add_remote_candidate(ag, cand, WR_ICE_CAND_HOST,
                                              (uint16_t)(i + 1u));
        }
    }
    (void)wr_ice_end_of_remote_candidates(ag);

    wr_span_c ufrag = wr_span_c_from_str("abcd");
    wr_span_c pwd = wr_span_c_from_str("abcdefghijklmnopqrstuvwx");
    wr_ice_set_local_credentials(ag, ufrag, pwd);
    wr_ice_set_remote_credentials(ag, wr_span_c_from_str("efgh"),
                                  wr_span_c_from_str(
                                      "zyxwvutsrqponmlkjihgfedcba"));

    (void)wr_ice_start(ag, 0u);
    uint8_t buf[512];
    uint64_t now = 0u;
    for (int i = 0; i < 40; ++i) {
        now += 10u + wr_fuzz_stream_below(&fs, 30u);
        (void)wr_ice_step(ag, now);
        if (wr_fuzz_stream_below(&fs, 3u) == 0u) {
            wr_endpoint from;
            wr_endpoint_loopback(&from, 40000u);
            size_t n = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(buf));
            for (size_t k = 0; k < n; ++k) {
                buf[k] = wr_fuzz_stream_u8(&fs);
            }
            (void)wr_ice_input(ag, now, &from, wr_span_c_make(buf, n));
        }
        if (wr_fuzz_stream_below(&fs, 10u) == 0u) {
            size_t lc = 0, rc = 0;
            (void)wr_ice_local_candidates(ag, &lc);
            (void)wr_ice_remote_candidates(ag, &rc);
            (void)wr_ice_pair_count(ag);
        }
    }

    wr_endpoint la, ra;
    (void)wr_ice_selected(ag, &la, &ra);
    (void)wr_ice_is_complete(ag);
    (void)wr_ice_get_state(ag);

    if (wr_fuzz_stream_bool(&fs)) {
        (void)wr_ice_restart(ag, wr_span_c_from_str("ijkl"),
                             wr_span_c_from_str(
                                 "abcdefghijklmnopqrstuvwxyz"));
        (void)wr_ice_start(ag, now);
        for (int i = 0; i < 8; ++i) {
            now += 20u;
            (void)wr_ice_step(ag, now);
        }
    }

    wr_ice_close(ag);
    wr_ice_destroy(ag);
    if (io) {
        wr_io_destroy(io);
    }
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}