#include "test_util.h"

#include "wr/arena.h"
#include "wr/ice.h"
#include "wr/net.h"
#include "wr/rng.h"

static void drain(wr_ice_agent *dst, wr_io *src, uint64_t now_ms)
{
    uint8_t buf[2048];
    for (int k = 0; k < 20; ++k) {
        wr_endpoint from;
        wr_span data;
        wr_status st = wr_io_recv(src, &from, wr_span_make(buf, sizeof(buf)),
                                  &data);
        if (st != WR_OK) {
            break;
        }
        (void)wr_ice_input(dst, now_ms, &from, wr_span_upcast(data));
    }
}

static void test_loopback(void)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 7);

    wr_ice_config ca;
    wr_ice_config_defaults(&ca);
    ca.role = WR_ICE_ROLE_CONTROLLING;

    wr_ice_config cb;
    wr_ice_config_defaults(&cb);
    cb.role = WR_ICE_ROLE_CONTROLLED;
    cb.consent_interval_ms = 1000;
    cb.consent_timeout_ms = 5000;

    wr_ice_agent *a1 = wr_ice_create(a, &ca, rng);
    wr_ice_agent *b1 = wr_ice_create(a, &cb, rng);
    WR_TEST_CHECK(a1 && b1);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    WR_TEST_CHECK(io_a && io_b);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));
    WR_TEST_CHECK(ep_a.port != 0 && ep_b.port != 0);

    wr_ice_attach_io(a1, io_a, &ep_a);
    wr_ice_attach_io(b1, io_b, &ep_b);

    wr_ice_set_local_credentials(a1, wr_span_c_from_str("ufragA"),
                                 wr_span_c_from_str("pwdA"));
    wr_ice_set_remote_credentials(a1, wr_span_c_from_str("ufragB"),
                                  wr_span_c_from_str("pwdB"));
    wr_ice_set_local_credentials(b1, wr_span_c_from_str("ufragB"),
                                 wr_span_c_from_str("pwdB"));
    wr_ice_set_remote_credentials(b1, wr_span_c_from_str("ufragA"),
                                  wr_span_c_from_str("pwdA"));

    WR_TEST_CHECK(wr_ice_add_local_candidate(a1, ep_a, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_local_candidate(b1, ep_b, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_remote_candidate(a1, ep_b, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_remote_candidate(b1, ep_a, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_EQ_U64(wr_ice_pair_count(a1), 1);
    WR_TEST_EQ_U64(wr_ice_pair_count(b1), 1);

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_ice_start(a1, now), WR_OK);
    WR_TEST_EQ_U64(wr_ice_start(b1, now), WR_OK);

    bool ok = false;
    for (int i = 0; i < 400; ++i) {
        now += 5;
        (void)wr_ice_step(a1, now);
        (void)wr_ice_step(b1, now);
        drain(b1, io_b, now);
        drain(a1, io_a, now);
        if (wr_ice_get_state(a1) == WR_ICE_COMPLETED &&
            wr_ice_get_state(b1) == WR_ICE_COMPLETED) {
            ok = true;
            break;
        }
        if (wr_ice_get_state(a1) == WR_ICE_FAILED ||
            wr_ice_get_state(b1) == WR_ICE_FAILED) {
            break;
        }
    }
    WR_TEST_CHECK(ok);
    WR_TEST_EQ_U64(wr_ice_get_state(a1), WR_ICE_COMPLETED);
    WR_TEST_EQ_U64(wr_ice_get_state(b1), WR_ICE_COMPLETED);

    wr_endpoint la, ra;
    WR_TEST_CHECK(wr_ice_selected(a1, &la, &ra));
    WR_TEST_CHECK(wr_endpoint_eq(&la, &ep_a));
    WR_TEST_CHECK(wr_endpoint_eq(&ra, &ep_b));

    wr_ice_close(a1);
    wr_ice_close(b1);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

static void test_priority(void)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_ice_config cfg;
    wr_ice_config_defaults(&cfg);
    wr_ice_agent *ag = wr_ice_create(a, &cfg, rng);
    WR_TEST_CHECK(ag != NULL);

    wr_endpoint e1, e2;
    uint8_t b1[4] = { 192, 0, 2, 1 };
    uint8_t b2[4] = { 192, 0, 2, 2 };
    wr_endpoint_v4(&e1, b1, 1000);
    wr_endpoint_v4(&e2, b2, 2000);
    (void)wr_ice_add_local_candidate(ag, e1, WR_ICE_CAND_HOST, 1);
    (void)wr_ice_add_remote_candidate(ag, e2, WR_ICE_CAND_HOST, 1);
    (void)wr_ice_add_remote_candidate(ag, e2, WR_ICE_CAND_SRFLX, 1);
    WR_TEST_EQ_U64(wr_ice_pair_count(ag), 2);

    wr_ice_destroy(ag);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

void test_ice(void)
{
    test_loopback();
    test_priority();
}