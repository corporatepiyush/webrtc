#include "test_util.h"

#include "wr/dtls.h"

static bool capture_one(wr_io *from, uint8_t *buf, size_t cap, size_t *out_len)
{
    for (int i = 0; i < 100; ++i) {
        bool ready = false;
        if (wr_io_wait(from, 1u, &ready) != WR_OK || !ready) {
            continue;
        }
        wr_endpoint src;
        wr_span data;
        if (wr_io_recv(from, &src, wr_span_make(buf, cap), &data) != WR_OK) {
            continue;
        }
        if (data.len > cap) {
            return false;
        }
        memcpy(buf, data.ptr, data.len);
        *out_len = data.len;
        return true;
    }
    return false;
}

static void pump(wr_io *from, wr_dtls *to)
{
    uint8_t buf[2048];
    for (int i = 0; i < 32; ++i) {
        bool ready = false;
        (void)wr_io_wait(from, 1u, &ready);
        if (!ready) {
            return;
        }
        wr_endpoint src;
        wr_span data;
        if (wr_io_recv(from, &src, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            return;
        }
        (void)wr_dtls_input(to, wr_span_upcast(data));
    }
}

void test_dtls_hs(void)
{
    wr_arena *a = wr_arena_create(2u * 1024u * 1024u);
    wr_rng *rng_a = wr_rng_create();
    wr_rng *rng_b = wr_rng_create();
    wr_rng_seed(rng_a, 7);
    wr_rng_seed(rng_b, 9);

    wr_endpoint ep_a, ep_b;
    wr_endpoint_loopback(&ep_a, 0u);
    wr_endpoint_loopback(&ep_b, 0u);
    wr_io *io_a = wr_io_udp_create(&ep_a, true);
    wr_io *io_b = wr_io_udp_create(&ep_b, true);
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_dtls *client = wr_dtls_create(a, rng_a, WR_DTLS_ROLE_CLIENT, io_a, &ep_b);
    wr_dtls *server = wr_dtls_create(a, rng_b, WR_DTLS_ROLE_SERVER, io_b, &ep_a);
    WR_TEST_CHECK(client && server);
    if (!client || !server) {
        return;
    }

    size_t fp_len = 0u;
    const uint8_t *fp = wr_dtls_fingerprint(server, &fp_len);
    WR_TEST_EQ_U64(fp_len, 32u);
    WR_TEST_CHECK(wr_dtls_set_peer_fingerprint(client, fp, fp_len));
    fp = wr_dtls_fingerprint(client, &fp_len);
    WR_TEST_CHECK(wr_dtls_set_peer_fingerprint(server, fp, fp_len));

    WR_TEST_EQ_U64(wr_dtls_start(client, 0u), WR_OK);
    for (int i = 0; i < 100 && !(wr_dtls_ready(client) && wr_dtls_ready(server));
         ++i) {
        pump(io_b, server);
        (void)wr_dtls_step(server, (uint64_t)i);
        (void)wr_dtls_step(client, (uint64_t)i);
        pump(io_a, client);
        (void)wr_dtls_step(server, (uint64_t)i);
        (void)wr_dtls_step(client, (uint64_t)i);
    }
    WR_TEST_CHECK(wr_dtls_ready(client));
    WR_TEST_CHECK(wr_dtls_ready(server));

    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("hello dtls")), WR_OK);
    pump(io_b, server);
    wr_span_c out;
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 10u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "hello dtls", 10), 0);

    WR_TEST_EQ_U64(wr_dtls_send(server, wr_span_c_from_str("reply")), WR_OK);
    pump(io_a, client);
    WR_TEST_CHECK(wr_dtls_recv(client, &out));
    WR_TEST_EQ_U64(out.len, 5u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "reply", 5), 0);

    /* Duplicate application-data records must be delivered once. */
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("dup")), WR_OK);
    uint8_t dup[2048];
    size_t dup_len = 0u;
    WR_TEST_CHECK(capture_one(io_b, dup, sizeof(dup), &dup_len));
    WR_TEST_EQ_U64(wr_dtls_input(server, wr_span_c_make(dup, dup_len)), WR_OK);
    WR_TEST_EQ_U64(wr_dtls_input(server, wr_span_c_make(dup, dup_len)), WR_OK);
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 3u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "dup", 3), 0);
    WR_TEST_CHECK(!wr_dtls_recv(server, &out));

    /* An unauthenticated record must not advance the replay window. */
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("bad")), WR_OK);
    uint8_t good[2048];
    size_t good_len = 0u;
    WR_TEST_CHECK(capture_one(io_b, good, sizeof(good), &good_len));
    uint8_t bad[2048];
    memcpy(bad, good, good_len);
    uint64_t seq = 0u;
    for (int i = 0; i < 6; ++i) {
        seq = (seq << 8) | good[5u + (size_t)i];
    }
    seq += 100u;
    for (int i = 0; i < 6; ++i) {
        bad[10u - (size_t)i] = (uint8_t)(seq >> (8u * (unsigned)i));
    }
    (void)wr_dtls_input(server, wr_span_c_make(bad, good_len));
    WR_TEST_EQ_U64(wr_dtls_input(server, wr_span_c_make(good, good_len)), WR_OK);
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 3u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "bad", 3), 0);

    wr_dtls_destroy(client);
    wr_dtls_destroy(server);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng_a);
    wr_rng_destroy(rng_b);
    wr_arena_destroy(a);
}