#include "test_util.h"

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"

static void test_codec(void)
{
    char body[128];
    size_t blen = 0;
    WR_TEST_EQ_U64(wr_sctp_data_body(42u, 3u, 7u, 54u,
                                     wr_span_c_from_str("hello"), body,
                                     sizeof(body), &blen), WR_OK);

    char chunk[160];
    size_t clen = 0;
    WR_TEST_EQ_U64(wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                           wr_span_c_make(body, blen), chunk,
                                           sizeof(chunk), &clen), WR_OK);

    wr_sctp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_port = 5000;
    pkt.dst_port = 6000;
    pkt.vtag = 0x11223344u;
    char raw[256];
    size_t raw_len = 0;
    WR_TEST_EQ_U64(wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen), raw,
                                     sizeof(raw), &raw_len), WR_OK);

    wr_arena *a = wr_arena_create(64 * 1024);
    wr_sctp_msg m;
    WR_TEST_EQ_U64(wr_sctp_parse(a, wr_span_c_make(raw, raw_len), &m), WR_OK);
    WR_TEST_EQ_U64(m.hdr.src_port, 5000);
    WR_TEST_EQ_U64(m.hdr.dst_port, 6000);
    WR_TEST_EQ_U64(m.hdr.vtag, 0x11223344);
    WR_TEST_EQ_U64(m.chunks.len, 1);
    WR_TEST_EQ_U64(m.chunks.data[0].type, WR_SCTP_DATA);
    WR_TEST_EQ_U64(m.chunks.data[0].body.len, blen);
    WR_TEST_EQ_U64(wr_load_be32(m.chunks.data[0].body.ptr), 42);
    WR_TEST_EQ_U64(wr_load_be16(m.chunks.data[0].body.ptr + 4u), 3);
    WR_TEST_EQ_U64(wr_load_be16(m.chunks.data[0].body.ptr + 6u), 7);
    WR_TEST_EQ_U64(wr_load_be32(m.chunks.data[0].body.ptr + 8u), 54);

    raw[12] ^= 1u;
    WR_TEST_CHECK(wr_sctp_parse(a, wr_span_c_make(raw, raw_len), &m) ==
                  WR_ERR_AUTH);
    wr_arena_destroy(a);
}

static void test_chunk_limits(void)
{
    char body[70000];
    memset(body, 0x41, sizeof(body));
    char chunk[70016];
    size_t n = 0u;
    WR_TEST_CHECK(wr_sctp_chunk_serialize(WR_SCTP_DATA, 0u,
                                          wr_span_c_make(body, sizeof(body)),
                                          chunk, sizeof(chunk), &n) ==
                  WR_ERR_OVERFLOW);
    WR_TEST_CHECK(wr_sctp_chunk_serialize(WR_SCTP_DATA, 0u,
                                          wr_span_c_make(body, 65531u),
                                          chunk, sizeof(chunk), &n) == WR_OK);
    WR_TEST_EQ_U64(n, 65536u);

    uint32_t gaps[2 * 8191];
    for (size_t i = 0; i < 8191u; ++i) {
        gaps[2u * i] = 1u;
        gaps[2u * i + 1u] = 1u;
    }
    char sbuf[12 + 8u * 8191 + 4u];
    WR_TEST_CHECK(wr_sctp_sack_body(1u, 1u, gaps, 8191u, NULL, 0u, sbuf,
                                    sizeof(sbuf), &n) == WR_ERR_OVERFLOW);
    WR_TEST_CHECK(wr_sctp_sack_body(1u, 1u, gaps, 8189u, NULL, 0u, sbuf,
                                    sizeof(sbuf), &n) == WR_OK);
}

static void test_send_limits(void)
{
    /* DATA body + chunk + packet header must fit the 2048-byte send buffer;
     * 2020 bytes is the largest payload, 2021 must be rejected before any
     * copy into that buffer. */
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_rng *rng = wr_rng_create();
    WR_TEST_CHECK(a && rng);
    if (!a || !rng) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_assoc *as = wr_sctp_create(a, 5000u, 6000u, rng);
    WR_TEST_CHECK(as != NULL);
    if (as) {
        wr_sctp_start_established(as, 0x11111111u, 0x22222222u, 100u);
        static char payload[2021];
        memset(payload, 'x', sizeof(payload));
        WR_TEST_EQ_U64(wr_sctp_send_data(as, 0u, 0u,
                                         wr_span_c_make(payload, 2021u), 0u),
                       WR_ERR_OVERFLOW);
        /* 2020 passes the length guard; without attached I/O the send then
         * reports WR_ERR_STATE rather than silently truncating. */
        WR_TEST_EQ_U64(wr_sctp_send_data(as, 0u, 0u,
                                         wr_span_c_make(payload, 2020u), 0u),
                       WR_ERR_STATE);
    }
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

static void test_dcep(void)
{
    char buf[128];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_dcep_open_serialize(wr_span_c_from_str("chat"),
                                           wr_span_c_from_str(""),
                                           0u, 0u, 0u, buf, sizeof(buf), &n),
                   WR_OK);
    WR_TEST_EQ_U64(buf[0], WR_DCEP_OPEN);
    wr_dcep_msg m;
    WR_TEST_EQ_U64(wr_dcep_parse(wr_span_c_make(buf, n), &m), WR_OK);
    WR_TEST_EQ_U64(m.type, WR_DCEP_OPEN);
    WR_TEST_EQ_U64(m.label.len, 4);
    WR_TEST_EQ_U64(memcmp(m.label.ptr, "chat", 4), 0);

    WR_TEST_EQ_U64(wr_dcep_ack_serialize(buf, sizeof(buf), &n), WR_OK);
    WR_TEST_EQ_U64(wr_dcep_parse(wr_span_c_make(buf, n), &m), WR_OK);
    WR_TEST_EQ_U64(m.type, WR_DCEP_ACK);
}

static void drain(wr_sctp_assoc *dst, wr_io *src, uint64_t now)
{
    uint8_t buf[2048];
    for (int i = 0; i < 20; ++i) {
        bool ready = false;
        (void)wr_io_wait(src, 10u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        wr_status st = wr_io_recv(src, &from, wr_span_make(buf, sizeof(buf)),
                                  &data);
        if (st != WR_OK) {
            break;
        }
        (void)wr_sctp_input(dst, now, &from, wr_span_upcast(data));
    }
}

static void test_loopback(void)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 11);

    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_sctp_assoc *a1 = wr_sctp_create(a, ep_a.port, ep_b.port, rng);
    wr_sctp_assoc *b1 = wr_sctp_create(a, ep_b.port, ep_a.port, rng);
    WR_TEST_CHECK(a1 && b1);
    wr_sctp_attach_io(a1, io_a, &ep_b);
    wr_sctp_attach_io(b1, io_b, &ep_a);
    wr_sctp_start_established(a1, 1000, 2000, 2000);
    wr_sctp_start_established(b1, 2000, 1000, 1000);

    char dcep[64];
    size_t dcep_len = 0;
    WR_TEST_EQ_U64(wr_dcep_open_serialize(wr_span_c_from_str("chat"),
                                           wr_span_c_from_str(""),
                                           0u, 0u, 0u, dcep,
                                           sizeof(dcep), &dcep_len), WR_OK);
    uint64_t now = 1000;
    WR_TEST_EQ_U64(wr_sctp_send_data(a1, 0u, 50u,
                                     wr_span_c_make(dcep, dcep_len), now),
                   WR_OK);

    drain(b1, io_b, now);
    wr_sctp_delivery d;
    WR_TEST_CHECK(wr_sctp_recv(b1, &d));
    WR_TEST_EQ_U64(d.stream, 0);
    WR_TEST_EQ_U64(d.ppid, 50);
    WR_TEST_EQ_U64(wr_sctp_last_ack(b1), 1000);
    wr_dcep_msg dm;
    WR_TEST_EQ_U64(wr_dcep_parse(d.data, &dm), WR_OK);
    WR_TEST_EQ_U64(dm.type, WR_DCEP_OPEN);
    WR_TEST_EQ_U64(dm.label.len, 4);

    char ack[4];
    size_t ack_len = 0;
    WR_TEST_EQ_U64(wr_dcep_ack_serialize(ack, sizeof(ack), &ack_len), WR_OK);
    WR_TEST_EQ_U64(wr_sctp_send_data(b1, 0u, 51u,
                                     wr_span_c_make(ack, ack_len), now), WR_OK);

    drain(a1, io_a, now);
    WR_TEST_CHECK(wr_sctp_recv(a1, &d));
    WR_TEST_EQ_U64(d.ppid, 51);

    WR_TEST_EQ_U64(wr_sctp_send_data(a1, 0u, 54u,
                                     wr_span_c_from_str("hello"), now), WR_OK);
    drain(b1, io_b, now);
    WR_TEST_CHECK(wr_sctp_recv(b1, &d));
    WR_TEST_EQ_U64(d.ppid, 54);
    WR_TEST_EQ_U64(d.data.len, 5);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "hello", 5), 0);

    WR_TEST_EQ_U64(wr_sctp_send_data(b1, 0u, 54u,
                                     wr_span_c_from_str("world"), now), WR_OK);
    drain(a1, io_a, now);
    WR_TEST_CHECK(wr_sctp_recv(a1, &d));
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "world", 5), 0);

    /* Retransmit after RTO. */
    WR_TEST_EQ_U64(wr_sctp_send_data(a1, 0u, 54u,
                                     wr_span_c_from_str("retry"), now), WR_OK);
    now += 1100;
    WR_TEST_EQ_U64(wr_sctp_step(a1, now), WR_OK);
    drain(b1, io_b, now);
    WR_TEST_CHECK(wr_sctp_recv(b1, &d));
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "retry", 5), 0);

    wr_sctp_close(a1);
    wr_sctp_close(b1);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}


static void feed_data(wr_sctp_assoc *as, uint32_t tsn, uint16_t seq,
                      const char *data)
{
    char body[128];
    size_t blen = 0;
    wr_sctp_data_body(tsn, 0u, seq, 42u, wr_span_c_from_str(data), body,
                      sizeof(body), &blen);
    char chunk[192];
    size_t clen = 0;
    wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u, wr_span_c_make(body, blen),
                            chunk, sizeof(chunk), &clen);
    wr_sctp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_port = 2000;
    pkt.dst_port = 1000;
    pkt.vtag = 2000; /* wr_sctp_start_established(as, 2000, ...) */
    char raw[256];
    size_t raw_len = 0;
    WR_TEST_EQ_U64(wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen), raw,
                                     sizeof(raw), &raw_len), WR_OK);
    (void)wr_sctp_input(as, 1000u, NULL, wr_span_c_make(raw, raw_len));
}

/* A DATA chunk that arrives before the association is established must be
 * discarded: an off-path host can otherwise seed the receive TSN window and
 * desynchronise the handshake. */
static void test_state_gating(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 12);
    wr_sctp_assoc *as = wr_sctp_create(a, 1000, 2000, rng);
    WR_TEST_CHECK(as != NULL);
    if (!as) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_start_established(as, 2000, 1000, 1000);
    wr_sctp_delivery d;
    WR_TEST_CHECK(wr_sctp_recv(as, &d) == false);

    /* Force the association out of ESTABLISHED and inject. */
    wr_sctp_close(as);
    feed_data(as, 1001u, 0u, "early");
    WR_TEST_CHECK(!wr_sctp_recv(as, &d));

    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

/* A packet whose source address is not the association's peer must be
 * rejected, whatever it contains: SCTP has no cryptographic protection of its
 * own, so this is the only thing standing between the association and an
 * off-path injector. */
static void test_source_filter(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 13);
    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0);
    wr_io *io = wr_io_udp_create(&lo, true);
    wr_sctp_assoc *as = wr_sctp_create(a, 1000, 2000, rng);
    WR_TEST_CHECK(as != NULL && io != NULL);
    if (!as || !io) {
            wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_endpoint peer, other;
    uint8_t pip[4] = { 10, 0, 0, 1 };
    uint8_t oip[4] = { 10, 0, 0, 2 };
    wr_endpoint_v4(&peer, pip, 5000);
    wr_endpoint_v4(&other, oip, 5000);
    wr_sctp_attach_io(as, io, &peer);
    wr_sctp_start_established(as, 2000, 1000, 1000);

    char body[128];
    size_t blen = 0;
    wr_sctp_data_body(1000u, 0u, 0u, 42u, wr_span_c_from_str("spoof"), body,
                      sizeof(body), &blen);
    char chunk[192];
    size_t clen = 0;
    wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u, wr_span_c_make(body, blen),
                            chunk, sizeof(chunk), &clen);
    char raw[256];
    size_t raw_len = 0;
    wr_sctp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_port = 2000;
    pkt.dst_port = 1000;
    pkt.vtag = 2000;
    WR_TEST_EQ_U64(wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen), raw,
                                     sizeof(raw), &raw_len),
                   WR_OK);

    WR_TEST_EQ_U64(wr_sctp_input(as, 1u, &other, wr_span_c_make(raw, raw_len)),
                   WR_ERR_AUTH);
    wr_sctp_delivery d;
    WR_TEST_CHECK(!wr_sctp_recv(as, &d));

    WR_TEST_EQ_U64(wr_sctp_input(as, 1u, &peer, wr_span_c_make(raw, raw_len)),
                   WR_OK);
    WR_TEST_CHECK(wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(d.data.len, 5u);
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "spoof", 5), 0);

    wr_io_destroy(io);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

static void test_reassembly(void)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 3);
    wr_sctp_assoc *as = wr_sctp_create(a, 1000, 2000, rng);
    WR_TEST_CHECK(as != NULL);
    if (!as) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_start_established(as, 2000, 1000, 1000);
    wr_sctp_delivery d;

    /* Out of order: 1001 arrives before 1000. */
    feed_data(as, 1001u, 1u, "B");
    WR_TEST_CHECK(!wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(wr_sctp_last_ack(as), 999u);

    feed_data(as, 1000u, 0u, "A");
    WR_TEST_CHECK(wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(d.data.len, 1u);
    WR_TEST_EQ_U64(d.data.ptr[0], 'A');
    WR_TEST_CHECK(wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(d.data.ptr[0], 'B');
    WR_TEST_EQ_U64(wr_sctp_last_ack(as), 1001u);

    /* Duplicate is ignored. */
    feed_data(as, 1000u, 0u, "A");
    WR_TEST_CHECK(!wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(wr_sctp_last_ack(as), 1001u);

    feed_data(as, 1002u, 2u, "C");
    WR_TEST_CHECK(wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(d.data.ptr[0], 'C');
    WR_TEST_EQ_U64(wr_sctp_last_ack(as), 1002u);

    wr_sctp_close(as);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}


/* RFC 4960 3.3.4: gap ack blocks are runs of received TSNs above cum, not
 * the missing TSNs in between. Verify what actually goes on the wire. */
static void test_sack_gaps(void)
{
    wr_arena *a = wr_arena_create(256u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 31);
    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io = wr_io_udp_create(&lo, true);
    wr_endpoint self;
    WR_TEST_CHECK(io != NULL);
    if (!io || !wr_io_local_addr(io, &self)) {
        wr_io_destroy(io);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_assoc *as = wr_sctp_create(a, self.port, self.port, rng);
    WR_TEST_CHECK(as != NULL);
    if (!as) {
        wr_io_destroy(io);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_attach_io(as, io, &self);
    wr_sctp_start_established(as, 2000, 1000, 1000);

    /* Receive 1001 and 1003 out of order: cum stays 999, two received runs. */
    feed_data(as, 1001u, 0u, "B");
    feed_data(as, 1003u, 1u, "D");

    uint8_t wire[2048];
    bool verified = false;
    for (int attempt = 0; attempt < 4 && !verified; ++attempt) {
        bool ready = false;
        (void)wr_io_wait(io, 2u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(io, &from, wr_span_make(wire, sizeof(wire)), &data) !=
            WR_OK) {
            break;
        }
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_sctp_msg msg;
        if (wr_sctp_parse(a, wr_span_upcast(data), &msg) == WR_OK) {
            for (size_t i = 0; i < msg.chunks.len; ++i) {
                const wr_sctp_chunk *c = &msg.chunks.data[i];
                if (c->type != WR_SCTP_SACK || c->body.len < 12u) {
                    continue;
                }
                uint32_t cum = wr_load_be32(c->body.ptr);
                uint16_t ngaps = wr_load_be16(c->body.ptr + 8u);
                uint16_t ndups = wr_load_be16(c->body.ptr + 10u);
                if (cum != 999u || ngaps != 2u || ndups != 0u ||
                    c->body.len < 28u) {
                    continue;
                }
                uint32_t s0 = wr_load_be32(c->body.ptr + 12u);
                uint32_t e0 = wr_load_be32(c->body.ptr + 16u);
                uint32_t s1 = wr_load_be32(c->body.ptr + 20u);
                uint32_t e1 = wr_load_be32(c->body.ptr + 24u);
                if (s0 == 1001u && e0 == 1001u && s1 == 1003u &&
                    e1 == 1003u) {
                    verified = true;
                }
            }
        }
        wr_arena_mark_release(a, mk);
    }
    WR_TEST_CHECK(verified);

    wr_sctp_delivery d;
    WR_TEST_CHECK(!wr_sctp_recv(as, &d));
    WR_TEST_EQ_U64(wr_sctp_last_ack(as), 999u);

    wr_sctp_close(as);
    wr_io_destroy(io);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

static void sctp_pump(wr_sctp_assoc *dst, wr_io *src, uint64_t now)
{
    uint8_t buf[2048];
    for (int i = 0; i < 20; ++i) {
        bool ready = false;
        (void)wr_io_wait(src, 1u, &ready);
        if (!ready) {
            return;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(src, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            return;
        }
        (void)wr_sctp_input(dst, now, &from, wr_span_upcast(data));
    }
}

static void test_handshake(void)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 21);
    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io_a = wr_io_udp_create(&lo, true);
    wr_io *io_b = wr_io_udp_create(&lo, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_sctp_assoc *a1 = wr_sctp_create(a, ep_a.port, ep_b.port, rng);
    wr_sctp_assoc *b1 = wr_sctp_create(a, ep_b.port, ep_a.port, rng);
    WR_TEST_CHECK(a1 && b1);
    wr_sctp_attach_io(a1, io_a, &ep_b);
    wr_sctp_attach_io(b1, io_b, &ep_a);
    WR_TEST_EQ_U64(wr_sctp_start(a1, 0u), WR_OK);

    for (int i = 0; i < 20; ++i) {
        sctp_pump(b1, io_b, (uint64_t)i);
        (void)wr_sctp_step(b1, (uint64_t)i);
        (void)wr_sctp_step(a1, (uint64_t)i);
        sctp_pump(a1, io_a, (uint64_t)i);
        (void)wr_sctp_step(b1, (uint64_t)i);
        (void)wr_sctp_step(a1, (uint64_t)i);
    }
    WR_TEST_EQ_U64(wr_sctp_get_state(a1), WR_SCTP_ST_ESTABLISHED);
    WR_TEST_EQ_U64(wr_sctp_get_state(b1), WR_SCTP_ST_ESTABLISHED);

    uint64_t allocs_before = wr_arena_alloc_count(a);
    WR_TEST_EQ_U64(wr_sctp_send_data(a1, 0u, 50u,
                                     wr_span_c_from_str("hi"), 0u), WR_OK);
    sctp_pump(b1, io_b, 0u);
    uint64_t allocs_after = wr_arena_alloc_count(a);
    /* Bounded: TX/RX slots plus the payload copy; no per-chunk arena vector. */
    WR_TEST_CHECK(allocs_after - allocs_before <= 16u);
    wr_sctp_delivery d;
    WR_TEST_CHECK(wr_sctp_recv(b1, &d));
    WR_TEST_EQ_U64(memcmp(d.data.ptr, "hi", 2), 0);

    wr_sctp_close(a1);
    wr_sctp_close(b1);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}


/* Independent model: runs of received TSNs above cum, per RFC 4960 3.3.4. */
static uint32_t naive_gaps(const wr_tsn_set *s, wr_tsn_gap *gaps, size_t max)
{
    uint32_t n = 0u;
    size_t i = 0u;
    while (i < WR_SCTP_RX_WINDOW) {
        if (!wr_tsn_set_has(s, s->cum + 1u + (uint32_t)i)) {
            i++;
            continue;
        }
        size_t run = i;
        while (run < WR_SCTP_RX_WINDOW &&
               wr_tsn_set_has(s, s->cum + 1u + (uint32_t)run)) {
            run++;
        }
        if (n < max) {
            gaps[n].start = s->cum + 1u + (uint32_t)i;
            gaps[n].end = s->cum + (uint32_t)run;
            n++;
        }
        i = run + 1u;
    }
    return n;
}

static void test_tsn_gaps(void)
{
    wr_tsn_set s;
    wr_tsn_set_init(&s, 100u);
    const uint32_t bits[] = { 0, 1, 2, 30, 31, 32, 63, 64, 65, 200,
                              8191 };
    for (size_t i = 0; i < WR_ARRAY_LEN(bits); ++i) {
        (void)wr_tsn_set_add(&s, s.cum + 1u + bits[i]);
    }
    wr_tsn_gap fast[16];
    wr_tsn_gap slow[16];
    uint32_t nf = wr_tsn_set_gaps(&s, fast, WR_ARRAY_LEN(fast));
    uint32_t ns = naive_gaps(&s, slow, WR_ARRAY_LEN(slow));
    WR_TEST_EQ_U64(nf, ns);
    WR_TEST_EQ_U64(nf, 5u);
    for (uint32_t i = 0; i < nf; ++i) {
        WR_TEST_EQ_U64(fast[i].start, slow[i].start);
        WR_TEST_EQ_U64(fast[i].end, slow[i].end);
    }

    /* Empty window: no gap ack blocks. */
    wr_tsn_set empty;
    wr_tsn_set_init(&empty, 7u);
    wr_tsn_gap eg[2];
    WR_TEST_EQ_U64(wr_tsn_set_gaps(&empty, eg, WR_ARRAY_LEN(eg)), 0u);

    /* Fully populated window: one block covering it. */
    for (uint32_t i = 0; i < WR_SCTP_RX_WINDOW; ++i) {
        (void)wr_tsn_set_add(&empty, 8u + i);
    }
    uint32_t en = wr_tsn_set_gaps(&empty, eg, WR_ARRAY_LEN(eg));
    WR_TEST_EQ_U64(en, 1u);
    WR_TEST_EQ_U64(eg[0].start, 8u);
    WR_TEST_EQ_U64(eg[0].end, 7u + WR_SCTP_RX_WINDOW);
}

static void test_tsn_rotation(void)
{
    enum { REF = 65536 };
    static uint8_t present[REF];
    wr_tsn_set s;
    wr_tsn_set_init(&s, 0u);
    uint64_t x = UINT64_C(0x123456789abcdef0);
    uint32_t bad = 0u;

    for (uint32_t step = 0; step < 20000u; ++step) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        uint32_t d = (uint32_t)(x % WR_SCTP_RX_WINDOW);
        uint32_t tsn = s.cum + 1u + d;
        if (tsn >= REF) {
            bad++;
            break;
        }
        bool want_add = !present[tsn];
        bool got_add = wr_tsn_set_add(&s, tsn);
        if (got_add != want_add) {
            bad++;
        }
        if (got_add) {
            present[tsn] = 1u;
        }
        bool want_has = tsn <= s.cum || present[tsn];
        if (wr_tsn_set_has(&s, tsn) != want_has) {
            bad++;
        }

        if ((x & 3u) == 0u) {
            uint32_t next = s.cum + 1u;
            bool want_pop = next < REF && present[next] != 0u;
            uint32_t out = 0u;
            bool got_pop = wr_tsn_set_pop_next(&s, &out);
            if (got_pop != want_pop || (got_pop && out != next)) {
                bad++;
            }
            if (got_pop) {
                present[next] = 0u;
            }
        }

        if (step % 257u == 0u) {
            wr_tsn_gap fast[16];
            uint32_t nf = wr_tsn_set_gaps(&s, fast, WR_ARRAY_LEN(fast));
            wr_tsn_gap model[16];
            uint32_t dm = 0u;
            uint32_t nm = 0u;
            while (dm < WR_SCTP_RX_WINDOW && nm < WR_ARRAY_LEN(model)) {
                uint32_t t = s.cum + 1u + dm;
                if (t >= REF || !present[t]) {
                    dm++;
                    continue;
                }
                uint32_t start = dm;
                while (dm < WR_SCTP_RX_WINDOW) {
                    t = s.cum + 1u + dm;
                    if (t >= REF || !present[t]) {
                        break;
                    }
                    dm++;
                }
                model[nm].start = s.cum + 1u + start;
                model[nm].end = s.cum + dm;
                nm++;
            }
            if (nf != nm) {
                bad++;
            } else {
                for (uint32_t i = 0; i < nf; ++i) {
                    if (fast[i].start != model[i].start ||
                        fast[i].end != model[i].end) {
                        bad++;
                    }
                }
            }
        }
    }
    WR_TEST_EQ_U64(bad, 0u);
}

static void test_lossy(void);

void test_sctp(void)
{
    test_codec();
    test_chunk_limits();
    test_send_limits();
    test_dcep();
    test_loopback();
    test_reassembly();
    test_sack_gaps();
    test_handshake();
    test_lossy();
    test_tsn_gaps();
    test_tsn_rotation();
    test_state_gating();
    test_source_filter();
}
static int lossy_pump(wr_sctp_assoc *dst, wr_io *src, uint64_t now, int step)
{
    uint8_t buf[2048];
    int delivered = 0;
    for (int i = 0; i < 8; ++i) {
        bool ready = false;
        (void)wr_io_wait(src, 1u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(src, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            break;
        }
        if (step % 5 == 0) {
            continue; /* drop */
        }
        (void)wr_sctp_input(dst, now, &from, wr_span_upcast(data));
        delivered++;
        if (step % 7 == 0) {
            (void)wr_sctp_input(dst, now, &from, wr_span_upcast(data)); /* duplicate */
        }
    }
    return delivered;
}

static void test_lossy(void)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 31);
    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *ia = wr_io_udp_create(&lo, true);
    wr_io *ib = wr_io_udp_create(&lo, true);
    wr_endpoint ea, eb;
    WR_TEST_CHECK(ia && ib);
    WR_TEST_CHECK(wr_io_local_addr(ia, &ea));
    WR_TEST_CHECK(wr_io_local_addr(ib, &eb));
    wr_sctp_assoc *a1 = wr_sctp_create(a, ea.port, eb.port, rng);
    wr_sctp_assoc *b1 = wr_sctp_create(a, eb.port, ea.port, rng);
    WR_TEST_CHECK(a1 && b1);
    wr_sctp_attach_io(a1, ia, &eb);
    wr_sctp_attach_io(b1, ib, &ea);
    wr_sctp_start_established(a1, 1000, 2000, 2000);
    wr_sctp_start_established(b1, 2000, 1000, 1000);
    WR_TEST_EQ_U64(wr_sctp_send_data(a1, 0u, 60u,
                                     wr_span_c_from_str("lossy"), 0u), WR_OK);

    wr_sctp_delivery d;
    bool got = false;
    for (int i = 0; i < 1200 && !got; ++i) {
        (void)lossy_pump(b1, ib, (uint64_t)i, i);
        (void)wr_sctp_step(b1, (uint64_t)i);
        (void)wr_sctp_step(a1, (uint64_t)i);
        (void)lossy_pump(b1, ib, (uint64_t)i, i + 1);
        if (wr_sctp_recv(b1, &d)) {
            got = true;
        }
    }
    WR_TEST_CHECK(got);
    if (got) {
        WR_TEST_EQ_U64(d.data.len, 5);
        WR_TEST_EQ_U64(memcmp(d.data.ptr, "lossy", 5), 0);
    }
    wr_sctp_close(a1);
    wr_sctp_close(b1);
    wr_io_destroy(ia);
    wr_io_destroy(ib);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}
