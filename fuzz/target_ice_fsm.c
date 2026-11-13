#include "fuzz.h"

#include "wr/arena.h"
#include "wr/ice.h"
#include "wr/rng.h"

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
    wr_ice_config cfg;
    wr_ice_config_defaults(&cfg);
    cfg.role = (size >= 1u && (data[0] & 1u)) ? WR_ICE_ROLE_CONTROLLING
                                              : WR_ICE_ROLE_CONTROLLED;
    wr_ice_agent *ag = wr_ice_create(a, &cfg, rng);
    if (!ag) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0u);
    wr_io *io = wr_io_udp_create(&loop, true);
    if (io) {
        wr_ice_attach_io(ag, io, &loop);
    }
    wr_endpoint local, remote;
    wr_endpoint_loopback(&local, 40000u);
    wr_endpoint_loopback(&remote, 40001u);
    (void)wr_ice_add_local_candidate(ag, local, WR_ICE_CAND_HOST, 1u);
    (void)wr_ice_add_remote_candidate(ag, remote, WR_ICE_CAND_HOST, 1u);
    wr_ice_set_local_credentials(ag, wr_span_c_from_str("abcd"),
                                 wr_span_c_from_str("abcdefghijklmnopqrstuvwx"));
    wr_ice_set_remote_credentials(ag, wr_span_c_from_str("efgh"),
                                  wr_span_c_from_str("zyxwvutsrqponmlkjihgfedcba"));
    (void)wr_ice_start(ag, 0u);

    if (size >= 4u) {
        wr_endpoint from;
        wr_endpoint_loopback(&from, 40001u);
        (void)wr_ice_input(ag, 1u, &from, wr_span_c_make(data + 4u, size - 4u));
    }
    for (int i = 0; i < 4; ++i) {
        (void)wr_ice_step(ag, (uint64_t)(10u + i));
    }
    wr_endpoint la, ra;
    (void)wr_ice_selected(ag, &la, &ra);
    (void)wr_ice_is_complete(ag);
    if (io) {
        wr_io_destroy(io);
    }
    wr_ice_close(ag);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}