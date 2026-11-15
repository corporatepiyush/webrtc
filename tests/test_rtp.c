#include "test_util.h"

#include "wr/rtp.h"

static void test_rtp_basic(void)
{
    /* A minimal extension body: one-byte headers 0x10 (id 1, len 1) + 0xAA and
     * 0x20 (id 2, len 1) + 0xBB = four bytes, one 32-bit word. */
    static const uint8_t ext_body[4] = { 0x10, 0xaa, 0x20, 0xbb };
    uint8_t pkt[64];
    pkt[0] = 0x80;
    pkt[1] = 0x00;
    wr_store_be16(pkt + 2, 1000);
    wr_store_be32(pkt + 4, 123456);
    wr_store_be32(pkt + 8, 0x11223344);
    memcpy(pkt + 12, "abc", 3);

    wr_rtp_hdr h;
    WR_TEST_CHECK(wr_rtp_parse(wr_span_c_make(pkt, 15), &h));
    WR_TEST_EQ_U64(h.version, 2);
    WR_TEST_EQ_U64(h.seq, 1000);
    WR_TEST_EQ_U64(h.timestamp, 123456);
    WR_TEST_EQ_U64(h.ssrc, 0x11223344);
    WR_TEST_EQ_U64(h.header_len, 12);
    WR_TEST_EQ_U64(h.payload_len, 3);

    char out[64];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_rtp_serialize(&h, wr_span_c_from_str("abc"),
                                    out, sizeof(out), &n), WR_OK);
    WR_TEST_EQ_U64(n, 15);
    WR_TEST_EQ_U64(memcmp(out, pkt, 15), 0);

    WR_TEST_CHECK(!wr_rtp_parse(wr_span_c_make(pkt, 8), &h));
    pkt[0] = 0x00;
    WR_TEST_CHECK(!wr_rtp_parse(wr_span_c_make(pkt, 15), &h));

    /* Serializer refuses layouts it cannot emit: a CSRC list and padding are
     * not modelled by wr_rtp_hdr. */
    wr_rtp_hdr h2;
    memset(&h2, 0, sizeof(h2));
    h2.pt = 96;
    h2.seq = 1;
    h2.cc = 1;
    WR_TEST_CHECK(wr_rtp_serialize(&h2, wr_span_c_from_str("x"), out,
                                   sizeof(out), &n) == WR_ERR_UNSUPPORTED);
    h2.cc = 0;
    h2.padding = 1;
    WR_TEST_CHECK(wr_rtp_serialize(&h2, wr_span_c_from_str("x"), out,
                                   sizeof(out), &n) == WR_ERR_UNSUPPORTED);

    /* Header extensions are emitted with the 0xBEDE profile; a body that is
     * not a whole number of 32-bit words is rejected. */
    wr_rtp_hdr h3;
    memset(&h3, 0, sizeof(h3));
    h3.pt = 96;
    h3.seq = 1;
    h3.ext = 1;
    h3.ext_raw = wr_span_c_make(ext_body, sizeof(ext_body));
    WR_TEST_EQ_U64(wr_rtp_serialize(&h3, wr_span_c_from_str("x"), out,
                                    sizeof(out), &n),
                   WR_OK);
    wr_rtp_hdr rt;
    WR_TEST_CHECK(wr_rtp_parse(wr_span_c_make(out, n), &rt));
    WR_TEST_EQ_U64(rt.ext, 1);
    WR_TEST_EQ_U64(rt.header_len, 20);
    WR_TEST_EQ_U64(rt.payload_len, 1);
    h3.ext_raw = wr_span_c_make(ext_body, 3u); /* not word-aligned */
    WR_TEST_CHECK(wr_rtp_serialize(&h3, wr_span_c_from_str("x"), out,
                                   sizeof(out), &n) == WR_ERR_INVAL);
}

static void test_rtp_ext(void)
{
    uint8_t pkt[64];
    pkt[0] = 0x90; /* V=2, X=1 */
    pkt[1] = 0x00;
    wr_store_be16(pkt + 2, 7);
    wr_store_be32(pkt + 4, 0);
    wr_store_be32(pkt + 8, 0x55667788);
    wr_store_be16(pkt + 12, 0xBEDE);
    wr_store_be16(pkt + 14, 1);
    pkt[16] = 0x10;
    pkt[17] = 0xaa;
    pkt[18] = 0x20;
    pkt[19] = 0xbb;
    pkt[20] = 'z';

    wr_rtp_hdr h;
    WR_TEST_CHECK(wr_rtp_parse(wr_span_c_make(pkt, 21), &h));
    WR_TEST_EQ_U64(h.ext, 1);
    WR_TEST_EQ_U64(h.header_len, 20);
    WR_TEST_EQ_U64(h.payload_len, 1);
    WR_TEST_EQ_U64(h.ext_raw.len, 4);

    uint16_t ids[4];
    wr_span_c data[4];
    size_t count = 0;
    (void)wr_rtp_ext_parse(h.ext_raw, ids, data, 4, &count);
    WR_TEST_EQ_U64(count, 2);
    WR_TEST_EQ_U64(ids[0], 1);
    WR_TEST_EQ_U64(data[0].len, 1);
    WR_TEST_EQ_U64(data[0].ptr[0], 0xaa);
    WR_TEST_EQ_U64(ids[1], 2);
    WR_TEST_EQ_U64(data[1].ptr[0], 0xbb);

    /* Two-byte form (RFC 8285 4.3): 8-bit id, 8-bit length, no padding.
     * id 3 len 2 "hi", id 4 len 1 "!", then a zero id terminating. */
    uint8_t two[8] = { 3u, 2u, 'h', 'i', 4u, 1u, '!', 0u };
    count = 0;
    (void)wr_rtp_ext_parse_form(wr_span_c_make(two, sizeof(two)), true, ids,
                                data, 4, &count);
    WR_TEST_EQ_U64(count, 2);
    WR_TEST_EQ_U64(ids[0], 3);
    WR_TEST_EQ_U64(data[0].len, 2);
    WR_TEST_EQ_U64(memcmp(data[0].ptr, "hi", 2), 0);
    WR_TEST_EQ_U64(ids[1], 4);
    WR_TEST_EQ_U64(data[1].ptr[0], '!');
    /* The same bytes are not valid one-byte elements: the leading 3 means
     * "id 0, length 4", which is a padding/terminator. */
    count = 0;
    (void)wr_rtp_ext_parse_form(wr_span_c_make(two, sizeof(two)), false, ids,
                                data, 4, &count);
    WR_TEST_EQ_U64(count, 0);
    /* A truncated two-byte element stops the walk. */
    uint8_t two_trunc[3] = { 9u, 16u, 0u };
    count = 0;
    (void)wr_rtp_ext_parse_form(wr_span_c_make(two_trunc, sizeof(two_trunc)),
                                true, ids, data, 4, &count);
    WR_TEST_EQ_U64(count, 0);
}

static void test_rtcp_sr(void)
{
    wr_rtcp_rr_block rb;
    memset(&rb, 0, sizeof(rb));
    rb.ssrc = 0xdeadbeefu;
    rb.fraction = 20;
    rb.lost = 5;
    rb.seq = 100;
    rb.jitter = 9;
    rb.lsr = 1;
    rb.dlsr = 2;

    char buf[128];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_rtcp_sr_serialize(0x11223344u, 0x8877665544332211ULL,
                                        999u, 10u, 100u, &rb, 1, buf,
                                        sizeof(buf), &n), WR_OK);

    wr_rtcp_hdr hdr;
    size_t used = 0;
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    WR_TEST_EQ_U64(used, n);
    WR_TEST_EQ_U64(hdr.pt, 200);
    WR_TEST_EQ_U64(hdr.count, 1);

    wr_rtcp_sr_info info;
    wr_rtcp_rr_block blocks[2];
    size_t count = 0;
    WR_TEST_EQ_U64(wr_rtcp_sr_parse(&hdr, &info, blocks, 2, &count), WR_OK);
    WR_TEST_EQ_U64(info.ssrc, 0x11223344);
    WR_TEST_EQ_U64(info.ntp, 0x8877665544332211ULL);
    WR_TEST_EQ_U64(info.pkt_count, 10);
    WR_TEST_EQ_U64(count, 1);
    WR_TEST_EQ_U64(blocks[0].ssrc, 0xdeadbeef);
    WR_TEST_EQ_U64(blocks[0].lost, 5);
}

static void test_rtcp_compound(void)
{
    wr_rtcp_rr_block rb;
    memset(&rb, 0, sizeof(rb));
    rb.ssrc = 1;

    char buf[256];
    size_t sr_n = 0;
    WR_TEST_EQ_U64(wr_rtcp_sr_serialize(0x11223344u, 1, 2, 3, 4, &rb, 1,
                                        buf, sizeof(buf), &sr_n), WR_OK);

    size_t off = sr_n;
    buf[off + 0] = 0x81;
    buf[off + 1] = (char)202;
    wr_store_be16((uint8_t *)buf + off + 2, 4);
    wr_store_be32((uint8_t *)buf + off + 4, 0xaabbccdd);
    buf[off + 8] = 1;
    buf[off + 9] = 5;
    memcpy(buf + off + 10, "cname", 5);
    buf[off + 15] = 0;
    buf[off + 16] = 0;
    size_t total = off + 20;

    wr_rtcp_hdr pkts[4];
    size_t count = 0;
    WR_TEST_EQ_U64(wr_rtcp_compound_parse(wr_span_c_make(buf, total), 4, pkts,
                                          &count), WR_OK);
    WR_TEST_EQ_U64(count, 2);
    WR_TEST_EQ_U64(pkts[0].pt, 200);
    WR_TEST_EQ_U64(pkts[1].pt, 202);

    wr_span_c cname;
    WR_TEST_EQ_U64(wr_rtcp_sdes_cname(&pkts[1], &cname), WR_OK);
    WR_TEST_EQ_U64(cname.len, 5);
    WR_TEST_EQ_U64(memcmp(cname.ptr, "cname", 5), 0);
}

static void test_rtcp_length_limits(void)
{
    /* The 16-bit RTCP length field must not wrap at the maximum packet size.
     * NACK fits 65534 4-byte FCIs; FIR fits 32767 8-byte FCIs. */
    size_t nack_max = 65534u;
    uint32_t *pids = (uint32_t *)malloc(nack_max * sizeof(*pids));
    uint16_t *blps = (uint16_t *)malloc(nack_max * sizeof(*blps));
    char *buf = (char *)malloc(262144u);
    WR_TEST_CHECK(pids && blps && buf);
    if (!pids || !blps || !buf) {
        free(pids);
        free(blps);
        free(buf);
        return;
    }
    for (size_t i = 0; i < nack_max; ++i) {
        pids[i] = (uint32_t)(i & 0x7fffu);
        blps[i] = 1u;
    }
    size_t n = 0u;
    WR_TEST_EQ_U64(wr_rtcp_nack_serialize(1u, pids, blps, nack_max, buf,
                                          262144u, &n),
                   WR_OK);
    WR_TEST_EQ_U64(n, 262144u);
    wr_rtcp_hdr hdr;
    size_t used = 0u;
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    WR_TEST_EQ_U64(hdr.length, 65535u);
    WR_TEST_EQ_U64(wr_rtcp_nack_serialize(1u, pids, blps, nack_max + 1u, buf,
                                          262144u, &n),
                   WR_ERR_OVERFLOW);
    free(pids);
    free(blps);
    free(buf);

    size_t fir_max = 32767u;
    uint32_t *targets = (uint32_t *)malloc(fir_max * sizeof(*targets));
    uint8_t *seqs = (uint8_t *)malloc(fir_max * sizeof(*seqs));
    buf = (char *)malloc(262144u);
    WR_TEST_CHECK(targets && seqs && buf);
    if (!targets || !seqs || !buf) {
        free(targets);
        free(seqs);
        free(buf);
        return;
    }
    for (size_t i = 0; i < fir_max; ++i) {
        targets[i] = (uint32_t)i;
        seqs[i] = (uint8_t)i;
    }
    WR_TEST_EQ_U64(wr_rtcp_fir_serialize(1u, targets, seqs, fir_max, buf,
                                         262144u, &n),
                   WR_OK);
    WR_TEST_EQ_U64(n, 262144u);
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    WR_TEST_EQ_U64(hdr.length, 65535u);
    WR_TEST_EQ_U64(wr_rtcp_fir_serialize(1u, targets, seqs, fir_max + 1u, buf,
                                         262144u, &n),
                   WR_ERR_OVERFLOW);
    free(targets);
    free(seqs);
    free(buf);
}

static void test_feedback(void)
{
    char buf[64];
    size_t n = 0;
    uint32_t pids[2] = { 10, 20 };
    uint16_t blps[2] = { 0, 3 };
    WR_TEST_EQ_U64(wr_rtcp_nack_serialize(0x1234u, pids, blps, 2, buf,
                                          sizeof(buf), &n), WR_OK);
    wr_rtcp_hdr hdr;
    size_t used = 0;
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    WR_TEST_EQ_U64(hdr.pt, 205);
    uint32_t pid[2];
    uint16_t blp[2];
    size_t count = 0;
    WR_TEST_EQ_U64(wr_rtcp_nack_parse(&hdr, pid, blp, 2, &count), WR_OK);
    WR_TEST_EQ_U64(count, 2);
    WR_TEST_EQ_U64(pid[0], 10);
    WR_TEST_EQ_U64(blp[1], 3);

    WR_TEST_EQ_U64(wr_rtcp_pli_serialize(0x1234u, buf, sizeof(buf), &n),
                   WR_OK);
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    uint32_t ssrc = 0;
    WR_TEST_EQ_U64(wr_rtcp_pli_parse(&hdr, &ssrc), WR_OK);
    WR_TEST_EQ_U64(ssrc, 0x1234);

    uint32_t targets[1] = { 0x99u };
    uint8_t seqs[1] = { 7u };
    WR_TEST_EQ_U64(wr_rtcp_fir_serialize(0x1234u, targets, seqs, 1, buf,
                                         sizeof(buf), &n), WR_OK);
    WR_TEST_EQ_U64(wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &hdr),
                   WR_OK);
    uint8_t seq = 0;
    uint32_t fir_ssrc = 0;
    uint32_t fir_targets[1] = { 0 };
    WR_TEST_EQ_U64(wr_rtcp_fir_parse(&hdr, &fir_ssrc, &seq, 1, &count), WR_OK);
    WR_TEST_EQ_U64(fir_ssrc, 0x99);
    WR_TEST_EQ_U64(seq, 7);
    (void)ssrc;
    (void)fir_targets;
}

void test_rtp(void)
{
    test_rtp_basic();
    test_rtp_ext();
    test_rtcp_sr();
    test_rtcp_compound();
    test_rtcp_length_limits();
    test_feedback();
}