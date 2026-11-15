#include "test_util.h"

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/pc.h"
#include "wr/rng.h"

static void test_loopback(void)
{
    wr_arena *a1 = wr_arena_create(1024u * 1024u);
    wr_arena *a2 = wr_arena_create(1024u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 99);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_pc *a = wr_pc_create(a1, rng, io_a, &ep_a, &ep_b,
                            WR_ICE_ROLE_CONTROLLING);
    wr_pc *b = wr_pc_create(a2, rng, io_b, &ep_b, &ep_a,
                            WR_ICE_ROLE_CONTROLLED);
    WR_TEST_CHECK(a && b);
    wr_pc_set_credentials(a, wr_span_c_from_str("uA"),
                          wr_span_c_from_str("pA"),
                          wr_span_c_from_str("uB"),
                          wr_span_c_from_str("pB"));
    wr_pc_set_credentials(b, wr_span_c_from_str("uB"),
                          wr_span_c_from_str("pB"),
                          wr_span_c_from_str("uA"),
                          wr_span_c_from_str("pA"));
    /* This test exercises the plaintext path deliberately: without DTLS the
     * verification tags are predictable and both peers must agree on them. */
    wr_pc_disable_dtls(a);
    wr_pc_disable_dtls(b);

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_pc_start(a, now), WR_OK);
    WR_TEST_EQ_U64(wr_pc_start(b, now), WR_OK);

    bool ready = false;
    for (int i = 0; i < 400; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_ready(a) && wr_pc_ready(b)) {
            ready = true;
            break;
        }
        if (wr_pc_ice_state(a) == WR_ICE_FAILED ||
            wr_pc_ice_state(b) == WR_ICE_FAILED) {
            break;
        }
    }
    WR_TEST_CHECK(ready);

    WR_TEST_EQ_U64(wr_pc_send(a, wr_span_c_from_str("hello")), WR_OK);
    wr_sctp_delivery d;
    bool got = false;
    for (int i = 0; i < 200; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_recv(b, &d)) {
            got = true;
            break;
        }
    }
    WR_TEST_CHECK(got);
    WR_TEST_EQ_U64(d.ppid, 54);
    WR_TEST_EQ_U64(d.data.len, 5);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "hello", 5), 0);

    WR_TEST_EQ_U64(wr_pc_send(b, wr_span_c_from_str("world")), WR_OK);
    /* wr_pc_step no longer blocks in recv: the datagram may not have arrived
     * yet, so the caller drives steps until it is delivered. */
    bool got2 = false;
    for (int i = 0; i < 100 && !got2; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        got2 = wr_pc_recv(a, &d);
    }
    WR_TEST_CHECK(got2);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "world", 5), 0);

    wr_pc_close(a);
    wr_pc_close(b);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng);
    wr_arena_destroy(a1);
    wr_arena_destroy(a2);
}


static void test_pc_dtls(void)
{
    wr_arena *a1 = wr_arena_create(2u * 1024u * 1024u);
    wr_arena *a2 = wr_arena_create(2u * 1024u * 1024u);
    wr_rng *rng1 = wr_rng_create();
    wr_rng *rng2 = wr_rng_create();
    wr_rng_seed(rng1, 101);
    wr_rng_seed(rng2, 103);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_pc *a = wr_pc_create(a1, rng1, io_a, &ep_a, &ep_b,
                            WR_ICE_ROLE_CONTROLLING);
    wr_pc *b = wr_pc_create(a2, rng2, io_b, &ep_b, &ep_a,
                            WR_ICE_ROLE_CONTROLLED);
    WR_TEST_CHECK(a && b);
    if (!a || !b) {
        return;
    }
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
    size_t fla = 0, flb = 0;
    WR_TEST_CHECK(wr_pc_local_fingerprint(a, &fa, &fla));
    WR_TEST_CHECK(wr_pc_local_fingerprint(b, &fb, &flb));
    WR_TEST_CHECK(wr_pc_set_peer_fingerprint(a, fb, flb));
    WR_TEST_CHECK(wr_pc_set_peer_fingerprint(b, fa, fla));

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_pc_start(a, now), WR_OK);
    WR_TEST_EQ_U64(wr_pc_start(b, now), WR_OK);

    bool ready = false;
    for (int i = 0; i < 1000; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_ready(a) && wr_pc_ready(b)) {
            ready = true;
            break;
        }
        if (wr_pc_ice_state(a) == WR_ICE_FAILED ||
            wr_pc_ice_state(b) == WR_ICE_FAILED) {
            break;
        }
    }
    WR_TEST_CHECK(ready);
    WR_TEST_CHECK(wr_pc_dtls_ready(a));
    WR_TEST_CHECK(wr_pc_dtls_ready(b));

    WR_TEST_EQ_U64(wr_pc_send(a, wr_span_c_from_str("secure")), WR_OK);
    wr_sctp_delivery d;
    bool got = false;
    for (int i = 0; i < 200; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_recv(b, &d)) {
            got = true;
            break;
        }
    }
    WR_TEST_CHECK(got);
    WR_TEST_EQ_U64(d.data.len, 6);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "secure", 6), 0);

    wr_pc_close(a);
    wr_pc_close(b);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng1);
    wr_rng_destroy(rng2);
    wr_arena_destroy(a1);
    wr_arena_destroy(a2);
}

static void test_pc_burst(void)
{
    wr_arena *a1 = wr_arena_create(2u * 1024u * 1024u);
    wr_arena *a2 = wr_arena_create(2u * 1024u * 1024u);
    wr_rng *rng1 = wr_rng_create();
    wr_rng *rng2 = wr_rng_create();
    wr_rng_seed(rng1, 301);
    wr_rng_seed(rng2, 303);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_pc *a = wr_pc_create(a1, rng1, io_a, &ep_a, &ep_b,
                            WR_ICE_ROLE_CONTROLLING);
    wr_pc *b = wr_pc_create(a2, rng2, io_b, &ep_b, &ep_a,
                            WR_ICE_ROLE_CONTROLLED);
    WR_TEST_CHECK(a && b);
    if (!a || !b) {
        return;
    }
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
    size_t fla = 0, flb = 0;
    WR_TEST_CHECK(wr_pc_local_fingerprint(a, &fa, &fla));
    WR_TEST_CHECK(wr_pc_local_fingerprint(b, &fb, &flb));
    WR_TEST_CHECK(wr_pc_set_peer_fingerprint(a, fb, flb));
    WR_TEST_CHECK(wr_pc_set_peer_fingerprint(b, fa, fla));

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_pc_start(a, now), WR_OK);
    WR_TEST_EQ_U64(wr_pc_start(b, now), WR_OK);

    bool ready = false;
    for (int i = 0; i < 1000; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_ready(a) && wr_pc_ready(b)) {
            ready = true;
            break;
        }
        if (wr_pc_ice_state(a) == WR_ICE_FAILED ||
            wr_pc_ice_state(b) == WR_ICE_FAILED) {
            break;
        }
    }
    WR_TEST_CHECK(ready);

    /* Three back-to-back sends: each SCTP packet rides its own DTLS record
     * and every one must be delivered, in order. */
    static const char *expect[3] = {"msg-one", "msg-two", "msg-three"};
    for (int k = 0; k < 3; ++k) {
        WR_TEST_EQ_U64(wr_pc_send(a, wr_span_c_from_str(expect[k])), WR_OK);
    }

    int got = 0;
    wr_sctp_delivery d;
    for (int i = 0; i < 400 && got < 3; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        while (wr_pc_recv(b, &d)) {
            WR_TEST_CHECK(got < 3);
            WR_TEST_EQ_U64(d.data.len, strlen(expect[got]));
            WR_TEST_EQ_U64(memcmp(d.data.ptr, expect[got], d.data.len), 0);
            got++;
        }
    }
    WR_TEST_EQ_U64((uint64_t)got, 3u);

    wr_pc_close(a);
    wr_pc_close(b);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng1);
    wr_rng_destroy(rng2);
    wr_arena_destroy(a1);
    wr_arena_destroy(a2);
}

static void test_jsep(void)
{
    wr_arena *a1 = wr_arena_create(2u * 1024u * 1024u);
    wr_arena *a2 = wr_arena_create(2u * 1024u * 1024u);
    wr_rng *rng1 = wr_rng_create();
    wr_rng *rng2 = wr_rng_create();
    wr_rng_seed(rng1, 201);
    wr_rng_seed(rng2, 203);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_pc *a = wr_pc_create(a1, rng1, io_a, &ep_a, &ep_b,
                            WR_ICE_ROLE_CONTROLLING);
    wr_pc *b = wr_pc_create(a2, rng2, io_b, &ep_b, &ep_a,
                            WR_ICE_ROLE_CONTROLLED);
    WR_TEST_CHECK(a && b);
    if (!a || !b) {
        return;
    }
    char offer[2048], answer[2048];
    size_t offer_len = 0, answer_len = 0;
    WR_TEST_EQ_U64(wr_pc_create_offer(a, offer, sizeof(offer), &offer_len),
                   WR_OK);
    WR_TEST_CHECK(offer_len > 0u);
    WR_TEST_EQ_U64(wr_pc_set_remote_description(b, wr_span_c_make(offer, offer_len)),
                   WR_OK);
    WR_TEST_EQ_U64(wr_pc_create_answer(b, wr_span_c_make(offer, offer_len),
                                       answer, sizeof(answer), &answer_len),
                   WR_OK);
    WR_TEST_EQ_U64(wr_pc_set_remote_description(a, wr_span_c_make(answer, answer_len)),
                   WR_OK);

    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_pc_start(a, now), WR_OK);
    WR_TEST_EQ_U64(wr_pc_start(b, now), WR_OK);
    bool ready = false;
    for (int i = 0; i < 1000; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_ready(a) && wr_pc_ready(b)) {
            ready = true;
            break;
        }
    }
    WR_TEST_CHECK(ready);

    WR_TEST_EQ_U64(wr_pc_send(a, wr_span_c_from_str("sdp")), WR_OK);
    wr_sctp_delivery d;
    bool got = false;
    for (int i = 0; i < 200; ++i) {
        now += 5;
        (void)wr_pc_step(a, now);
        (void)wr_pc_step(b, now);
        if (wr_pc_recv(b, &d)) {
            got = true;
            break;
        }
    }
    WR_TEST_CHECK(got);
    WR_TEST_EQ_U64(d.data.len, 3);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "sdp", 3), 0);

    wr_pc_close(a);
    wr_pc_close(b);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng1);
    wr_rng_destroy(rng2);
    wr_arena_destroy(a1);
    wr_arena_destroy(a2);
}
void test_pc(void)
{
    test_loopback();
    test_pc_dtls();
    test_pc_burst();
    test_jsep();
}
