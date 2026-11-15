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

/* Two agents that both believe they are controlling must resolve the conflict:
 * one of them answers 487 and switches to controlled (RFC 8445 7.3.1.1). */
static void test_role_conflict(void)
{
    wr_arena *a = wr_arena_create(256u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 77);

    wr_ice_config ca;
    wr_ice_config_defaults(&ca);
    ca.role = WR_ICE_ROLE_CONTROLLING;
    wr_ice_config cb;
    wr_ice_config_defaults(&cb);
    cb.role = WR_ICE_ROLE_CONTROLLING;

    wr_ice_agent *a1 = wr_ice_create(a, &ca, rng);
    wr_ice_agent *b1 = wr_ice_create(a, &cb, rng);
    WR_TEST_CHECK(a1 && b1);
    /* Distinct tie-breakers: the one with the smaller value must yield. */
    /* (tie-breakers are random here; only the outcome is asserted) */

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    WR_TEST_CHECK(io_a && io_b);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_ice_attach_io(a1, io_a, &ep_a);
    wr_ice_attach_io(b1, io_b, &ep_b);
    wr_ice_set_local_credentials(a1, wr_span_c_from_str("uaf"),
                                 wr_span_c_from_str("paf"));
    wr_ice_set_remote_credentials(a1, wr_span_c_from_str("ubf"),
                                  wr_span_c_from_str("pbf"));
    wr_ice_set_local_credentials(b1, wr_span_c_from_str("ubf"),
                                 wr_span_c_from_str("pbf"));
    wr_ice_set_remote_credentials(b1, wr_span_c_from_str("uaf"),
                                  wr_span_c_from_str("paf"));

    WR_TEST_CHECK(wr_ice_add_local_candidate(a1, ep_a, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_local_candidate(b1, ep_b, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_remote_candidate(a1, ep_b, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);
    WR_TEST_CHECK(wr_ice_add_remote_candidate(b1, ep_a, WR_ICE_CAND_HOST, 1) !=
                  UINT32_MAX);

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_ice_start(a1, now), WR_OK);
    WR_TEST_EQ_U64(wr_ice_start(b1, now), WR_OK);

    bool saw_error = false;
    bool any_role_changed = false;
    for (int i = 0; i < 200; ++i) {
        now += 5;
        (void)wr_ice_step(a1, now);
        (void)wr_ice_step(b1, now);
        /* pass 0 drains the socket the *other* agent writes to, and vice
         * versa: a datagram read from io_b was sent by a1. */
        for (int pass = 0; pass < 2; ++pass) {
            wr_io *from = pass == 0 ? io_b : io_a;
            wr_ice_agent *dst = pass == 0 ? b1 : a1;
            uint8_t buf[2048];
            for (int k = 0; k < 16; ++k) {
                bool ready = false;
                if (wr_io_wait(from, 0u, &ready) != WR_OK || !ready) {
                    break;
                }
                wr_endpoint src;
                wr_span data;
                if (wr_io_recv(from, &src, wr_span_make(buf, sizeof(buf)),
                               &data) != WR_OK) {
                    break;
                }
                /* Observe the response type before the agent consumes it. */
                wr_stun_msg m;
                if (wr_stun_parse(a, wr_span_upcast(data), WR_STUN_LIBERAL,
                                  &m) == WR_OK &&
                    m.type == wr_stun_type(WR_STUN_METHOD_BINDING,
                                           WR_STUN_CLASS_ERROR)) {
                    saw_error = true;
                }
                (void)wr_ice_input(dst, now, &src, wr_span_upcast(data));
            }
        }
        if (wr_ice_get_role(a1) != WR_ICE_ROLE_CONTROLLING ||
            wr_ice_get_role(b1) != WR_ICE_ROLE_CONTROLLING) {
            any_role_changed = true;
        }
        if (wr_ice_get_state(a1) == WR_ICE_CONNECTED &&
            wr_ice_get_state(b1) == WR_ICE_CONNECTED) {
            break;
        }
    }
    WR_TEST_CHECK(saw_error);
    WR_TEST_CHECK(any_role_changed);
    /* Exactly one agent must have yielded. */
    int changed = (wr_ice_get_role(a1) != WR_ICE_ROLE_CONTROLLING ? 1 : 0) +
                  (wr_ice_get_role(b1) != WR_ICE_ROLE_CONTROLLING ? 1 : 0);
    WR_TEST_EQ_U64((uint64_t)changed, 1u);

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
    test_role_conflict();
}