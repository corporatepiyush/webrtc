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
        (void)wr_dtls_input(to, NULL, wr_span_upcast(data));
    }
}

/* Collects (type, msg_seq) of every full handshake message inside a datagram
 * by walking its DTLS records with the public parsers. */
typedef struct {
    uint8_t type[8];
    uint16_t seq[8];
    unsigned count;
    bool encrypted_tail;
} hs_walk;

static void walk_hs(wr_span_c pkt, hs_walk *w, bool *is_ccs, bool *has_epoch1)
{
    memset(w, 0, sizeof(*w));
    *is_ccs = false;
    *has_epoch1 = false;
    size_t off = 0u;
    while (off < pkt.len) {
        wr_dtls_record r;
        if (wr_dtls_record_parse(wr_span_c_sub(pkt, off, pkt.len - off), &r) !=
            WR_OK) {
            break;
        }
        if (r.epoch != 0u) {
            *has_epoch1 = true;
        }
        if (r.type == WR_DTLS_CCS) {
            *is_ccs = true;
        } else if (r.type == WR_DTLS_HANDSHAKE && !*has_epoch1) {
            wr_dtls_hs h;
            if (wr_dtls_hs_parse(r.body, &h) == WR_OK &&
                w->count < 8u) {
                w->type[w->count] = h.type;
                w->seq[w->count] = h.msg_seq;
                w->count++;
            }
        }
        off += r.header_len + r.body.len;
    }
}

/* The full HelloVerifyRequest dance at the wire level: every flight is
 * captured from the socket and asserted byte-wise before being fed to the
 * peer, so the message sequence numbers, the cookie field, and the extension
 * block are all verified against RFC 6347 / the offered parameters. */
void test_dtls_dance(void)
{
    wr_arena *a = wr_arena_create(2u * 1024u * 1024u);
    wr_rng *rng_a = wr_rng_create();
    wr_rng *rng_b = wr_rng_create();
    wr_rng_seed(rng_a, 21);
    wr_rng_seed(rng_b, 22);

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
    WR_TEST_CHECK(wr_dtls_set_peer_fingerprint(client, fp, fp_len));
    fp = wr_dtls_fingerprint(client, &fp_len);
    WR_TEST_CHECK(wr_dtls_set_peer_fingerprint(server, fp, fp_len));

    uint8_t pkt[4096];
    size_t n = 0u;
    wr_span_c got;

    /* Flight 1: ClientHello without a cookie, message_seq 0. */
    WR_TEST_EQ_U64(wr_dtls_start(client, 1000u), WR_OK);
    WR_TEST_CHECK(capture_one(io_b, pkt, sizeof(pkt), &n));
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        WR_TEST_EQ_U64(n, 104u);
        WR_TEST_EQ_U64(pkt[0], WR_DTLS_HANDSHAKE);
        WR_TEST_EQ_U64(w.count, 1u);
        WR_TEST_EQ_U64(w.type[0], WR_DTLS_HIERARCHY_CLIENT_HELLO);
        WR_TEST_EQ_U64(w.seq[0], 0u);
        /* ClientHello body: version(2) random(32) sid_len cookie_len ... */
        WR_TEST_EQ_U64(pkt[59], 0u); /* session id len */
        WR_TEST_EQ_U64(pkt[60], 0u); /* cookie len */
        uint16_t ext_len = (uint16_t)((pkt[67] << 8) | pkt[68]);
        WR_TEST_EQ_U64(ext_len, 35u); /* 5 extensions */
        WR_TEST_EQ_U64((uint64_t)((pkt[69] << 8) | pkt[70]),
                       UINT64_C(0x000e)); /* use_srtp first */
    }

    /* Flight 2: HelloVerifyRequest, message_seq 0, 16-byte cookie. */
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(capture_one(io_a, pkt, sizeof(pkt), &n));
    uint8_t cookie[32];
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        WR_TEST_EQ_U64(n, 44u);
        WR_TEST_EQ_U64(w.count, 1u);
        WR_TEST_EQ_U64(w.type[0], WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST);
        WR_TEST_EQ_U64(w.seq[0], 0u);
        WR_TEST_EQ_U64(pkt[27], 16u); /* cookie len */
        memcpy(cookie, pkt + 28u, 16u);
    }

    /* Flight 3: ClientHello with the echoed cookie, message_seq 1. */
    WR_TEST_EQ_U64(wr_dtls_input(client, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(capture_one(io_b, pkt, sizeof(pkt), &n));
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        WR_TEST_EQ_U64(n, 120u);
        WR_TEST_EQ_U64(w.count, 1u);
        WR_TEST_EQ_U64(w.type[0], WR_DTLS_HIERARCHY_CLIENT_HELLO);
        WR_TEST_EQ_U64(w.seq[0], 1u);
        WR_TEST_EQ_U64(pkt[59], 0u);
        WR_TEST_EQ_U64(pkt[60], 16u);
        WR_TEST_EQ_U64(memcmp(pkt + 61, cookie, 16), 0);
    }

    /* Flight 4: ServerHello, Certificate, ServerKeyExchange,
     * ServerHelloDone as message_seq 1..4. */
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(capture_one(io_a, pkt, sizeof(pkt), &n));
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        const uint8_t expect_t[4] = {2u, 11u, 12u, 14u};
        const uint16_t expect_s[4] = {1u, 2u, 3u, 4u};
        WR_TEST_EQ_U64(w.count, 4u);
        for (unsigned i = 0; i < 4u; ++i) {
            WR_TEST_EQ_U64(w.type[i], expect_t[i]);
            WR_TEST_EQ_U64(w.seq[i], expect_s[i]);
        }
        WR_TEST_CHECK(!ccs);
        WR_TEST_CHECK(!ep1);
    }

    /* Flight 5: ClientKeyExchange (epoch 0), plaintext ChangeCipherSpec
     * (epoch 0), encrypted Finished (epoch 1). */
    WR_TEST_EQ_U64(wr_dtls_input(client, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(capture_one(io_b, pkt, sizeof(pkt), &n));
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        WR_TEST_EQ_U64(w.count, 1u);
        WR_TEST_EQ_U64(w.type[0], WR_DTLS_HIERARCHY_CLIENT_KEY_EXCHANGE);
        WR_TEST_EQ_U64(w.seq[0], 2u);
        WR_TEST_CHECK(ccs);
        WR_TEST_CHECK(ep1);
    }

    /* Flight 6: server ChangeCipherSpec + encrypted Finished. */
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(capture_one(io_a, pkt, sizeof(pkt), &n));
    {
        hs_walk w;
        bool ccs = false, ep1 = false;
        walk_hs(wr_span_c_make(pkt, n), &w, &ccs, &ep1);
        WR_TEST_EQ_U64(w.count, 0u);
        WR_TEST_CHECK(ccs);
        WR_TEST_CHECK(ep1);
    }
    WR_TEST_EQ_U64(wr_dtls_input(client, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(wr_dtls_ready(client));
    WR_TEST_CHECK(wr_dtls_ready(server));

    /* Encrypted application data round-trip. */
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("dance")), WR_OK);
    WR_TEST_CHECK(capture_one(io_b, pkt, sizeof(pkt), &n));
    WR_TEST_EQ_U64(pkt[0], WR_DTLS_APPDATA);
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(pkt, n)), WR_OK);
    WR_TEST_CHECK(wr_dtls_recv(server, &got));
    WR_TEST_EQ_U64(got.len, 5u);
    WR_TEST_EQ_U64(memcmp(got.ptr, "dance", 5), 0);

    /* Once the handshake is done, unprotected epoch-0 records must be
     * ignored: an off-path attacker who can send a datagram to the socket can
     * otherwise fail an established session with a forged alert. */
    uint8_t alert[13 + 2];
    memset(alert, 0, sizeof(alert));
    alert[0] = WR_DTLS_ALERT;
    wr_store_be16(alert + 1, UINT16_C(0xfefd));
    wr_store_be16(alert + 11, 2u); /* length */
    alert[13] = 2u; /* fatal */
    alert[14] = 40u; /* handshake_failure */
    WR_TEST_EQ_U64(wr_dtls_input(client, NULL, wr_span_c_make(alert, sizeof(alert))),
                   WR_OK);
    WR_TEST_CHECK(wr_dtls_ready(client));
    WR_TEST_EQ_U64(wr_dtls_state(client), WR_DTLS_DONE);
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("still")), WR_OK);

    wr_dtls_destroy(client);
    wr_dtls_destroy(server);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng_a);
    wr_rng_destroy(rng_b);
    wr_arena_destroy(a);
}

/* DTLS is point-to-point: a record that arrives from any other source address
 * must be dropped before it is parsed, because the socket is shared with ICE. */
static void test_dtls_source_filter(void)
{
    wr_arena *a = wr_arena_create(1u << 20);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 55);
    wr_endpoint ep_c, ep_s, ep_other;
    wr_endpoint_loopback(&ep_c, 0u);
    wr_endpoint_loopback(&ep_s, 0u);
    wr_endpoint_loopback(&ep_other, 0u);
    wr_io *io_c = wr_io_udp_create(&ep_c, true);
    wr_io *io_s = wr_io_udp_create(&ep_s, true);
    WR_TEST_CHECK(io_c && io_s);
    WR_TEST_CHECK(wr_io_local_addr(io_c, &ep_c));
    WR_TEST_CHECK(wr_io_local_addr(io_s, &ep_s));
    if (!io_c || !io_s) {
        return;
    }
    uint8_t oip[4] = { 10, 1, 2, 3 };
    wr_endpoint_v4(&ep_other, oip, 4444);

    wr_dtls *client = wr_dtls_create(a, rng, WR_DTLS_ROLE_CLIENT, io_c, &ep_s);
    wr_dtls *server = wr_dtls_create(a, rng, WR_DTLS_ROLE_SERVER, io_s, &ep_c);
    WR_TEST_CHECK(client && server);
    if (!client || !server) {
        return;
    }
    size_t fp_len = 0u;
    const uint8_t *fp = wr_dtls_fingerprint(server, &fp_len);
    (void)wr_dtls_set_peer_fingerprint(client, fp, fp_len);
    fp = wr_dtls_fingerprint(client, &fp_len);
    (void)wr_dtls_set_peer_fingerprint(server, fp, fp_len);

    WR_TEST_EQ_U64(wr_dtls_start(client, 1000u), WR_OK);
    uint8_t pkt[2048];
    size_t n = 0u;
    WR_TEST_CHECK(capture_one(io_s, pkt, sizeof(pkt), &n));

    /* A record from a different address must not advance the handshake. */
    WR_TEST_EQ_U64(wr_dtls_input(server, &ep_other, wr_span_c_make(pkt, n)),
                   WR_ERR_AUTH);
    /* The legitimate source is accepted. */
    WR_TEST_EQ_U64(wr_dtls_input(server, &ep_c, wr_span_c_make(pkt, n)),
                   WR_OK);

    wr_dtls_destroy(client);
    wr_dtls_destroy(server);
    wr_io_destroy(io_c);
    wr_io_destroy(io_s);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

/* A client whose peer never answers must give up after the retransmit budget
 * instead of retransmitting forever. */
static void test_dtls_retx_cap(void)
{
    wr_arena *a = wr_arena_create(1u << 20);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 41);
    wr_endpoint ep_c, ep_s;
    wr_endpoint_loopback(&ep_c, 0u);
    wr_endpoint_loopback(&ep_s, 0u);
    wr_io *io_c = wr_io_udp_create(&ep_c, true);
    wr_io *io_s = wr_io_udp_create(&ep_s, true);
    WR_TEST_CHECK(io_c && io_s);
    if (!io_c || !io_s) {
        return;
    }
    wr_dtls *c = wr_dtls_create(a, rng, WR_DTLS_ROLE_CLIENT, io_c, &ep_s);
    WR_TEST_CHECK(c != NULL);
    if (!c) {
        return;
    }
    WR_TEST_EQ_U64(wr_dtls_start(c, 1000u), WR_OK);

    uint64_t now = 1000u;
    wr_status st = WR_OK;
    int steps = 0;
    uint8_t sink[2048];
    while (st == WR_OK && steps < 64) {
        now += 5000u;
        st = wr_dtls_step(c, now);
        steps++;
        /* Drain the sink so the client's socket never blocks. */
        for (int i = 0; i < 4; ++i) {
            bool ready = false;
            if (wr_io_wait(io_s, 0u, &ready) != WR_OK || !ready) {
                break;
            }
            wr_endpoint from;
            wr_span data;
            (void)wr_io_recv(io_s, &from, wr_span_make(sink, sizeof(sink)),
                             &data);
        }
        if (wr_dtls_state(c) == WR_DTLS_FAILED) {
            break;
        }
    }
    WR_TEST_EQ_U64(st, WR_ERR_TIMEOUT);
    WR_TEST_EQ_U64(wr_dtls_state(c), WR_DTLS_FAILED);
    WR_TEST_CHECK(!wr_dtls_ready(c));
    WR_TEST_CHECK(steps < 64);

    wr_dtls_destroy(c);
    wr_io_destroy(io_c);
    wr_io_destroy(io_s);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
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
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(dup, dup_len)), WR_OK);
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(dup, dup_len)), WR_OK);
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
    (void)wr_dtls_input(server, NULL, wr_span_c_make(bad, good_len));
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(good, good_len)), WR_OK);
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 3u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "bad", 3), 0);

    /* Two application-data records coalesced into one datagram must be
     * delivered as two separate records, never as one concatenated span. */
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("AAAA")), WR_OK);
    WR_TEST_EQ_U64(wr_dtls_send(client, wr_span_c_from_str("BBBB")), WR_OK);
    uint8_t rec1[2048], rec2[2048];
    size_t rn1 = 0u, rn2 = 0u;
    WR_TEST_CHECK(capture_one(io_b, rec1, sizeof(rec1), &rn1));
    WR_TEST_CHECK(capture_one(io_b, rec2, sizeof(rec2), &rn2));
    uint8_t joined[4096];
    memcpy(joined, rec1, rn1);
    memcpy(joined + rn1, rec2, rn2);
    WR_TEST_EQ_U64(wr_dtls_input(server, NULL, wr_span_c_make(joined, rn1 + rn2)),
                   WR_OK);
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 4u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "AAAA", 4), 0);
    WR_TEST_CHECK(wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(out.len, 4u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "BBBB", 4), 0);
    WR_TEST_CHECK(!wr_dtls_recv(server, &out));
    WR_TEST_EQ_U64(wr_dtls_recv_drops(server), 0u);

    wr_dtls_destroy(client);
    wr_dtls_destroy(server);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng_a);
    wr_rng_destroy(rng_b);
    wr_arena_destroy(a);

    test_dtls_source_filter();
    test_dtls_retx_cap();
}