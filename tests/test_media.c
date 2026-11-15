#include "test_util.h"

#include "wr/media.h"
#include "wr/rtp.h"

static wr_rtp_hdr parse_only(wr_span_c pkt)
{
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    if (!wr_rtp_parse(pkt, &h)) {
        memset(&h, 0, sizeof(h));
    }
    return h;
}

static void test_h264(void)
{
    uint8_t sps[] = { 0x67, 0x42, 0x00, 0x1f };
    uint8_t pps[] = { 0x68, 0xce, 0x38, 0x80 };
    uint8_t idr[300];
    idr[0] = 0x65;
    for (size_t i = 1; i < sizeof(idr); ++i) idr[i] = (uint8_t)(i * 7u);

    uint8_t annexb[512];
    size_t off = 0;
    const uint8_t sc[4] = { 0, 0, 0, 1 };
    memcpy(annexb + off, sc, 4); off += 4;
    memcpy(annexb + off, sps, sizeof(sps)); off += sizeof(sps);
    memcpy(annexb + off, sc, 4); off += 4;
    memcpy(annexb + off, pps, sizeof(pps)); off += sizeof(pps);
    memcpy(annexb + off, sc, 4); off += 4;
    memcpy(annexb + off, idr, sizeof(idr)); off += sizeof(idr);

    wr_rtp_pay_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mtu = 64u;
    cfg.pt = 96u;
    cfg.seq = 1u;
    cfg.ts = 1000u;
    cfg.ssrc = 0x11223344u;
    cfg.marker = true;

    enum { MAXP = 24 };
    uint8_t bufs[MAXP][128];
    wr_rtp_out out[MAXP];
    for (int i = 0; i < MAXP; ++i) {
        out[i].ptr = bufs[i];
        out[i].cap = sizeof(bufs[i]);
    }
    uint32_t n = 0;
    WR_TEST_EQ_U64(wr_h264_packetize(wr_span_c_make(annexb, off), &cfg, out,
                                     MAXP, &n), WR_OK);
    WR_TEST_CHECK(n >= 4u);
    WR_TEST_CHECK(out[n - 1u].len > 0u);

    uint8_t nalbuf[512];
    wr_h264_depay d;
    wr_h264_depay_init(&d, nalbuf, sizeof(nalbuf));
    wr_span_c got[8];
    size_t ngot = 0;
    uint16_t last_seq = 0u;
    bool saw_marker = false;
    for (uint32_t i = 0; i < n; ++i) {
        wr_rtp_hdr h = parse_only(wr_span_c_make(out[i].ptr, out[i].len));
        WR_TEST_EQ_U64(h.version, 2u);
        WR_TEST_EQ_U64(h.pt, 96u);
        if (i == 0) {
            last_seq = h.seq;
        } else {
            WR_TEST_EQ_U64(h.seq, (uint16_t)(last_seq + 1u));
            last_seq = h.seq;
        }
        saw_marker = saw_marker || h.marker != 0u;
        wr_span_c payload = wr_span_c_sub(
            wr_span_c_make(out[i].ptr, out[i].len), h.payload_off,
            h.payload_len);
        wr_span_c nal;
        wr_status st = wr_h264_depay_input(&d, payload, &nal);
        if (st == WR_OK) {
            WR_TEST_CHECK(ngot < WR_ARRAY_LEN(got));
            got[ngot++] = nal;
        } else {
            WR_TEST_EQ_U64(st, WR_ERR_AGAIN);
        }
    }
    WR_TEST_CHECK(saw_marker);
    WR_TEST_EQ_U64(ngot, 3u);
    if (ngot == 3u) {
        WR_TEST_EQ_U64(got[0].len, sizeof(sps));
        WR_TEST_EQ_U64(memcmp(got[0].ptr, sps, sizeof(sps)), 0);
        WR_TEST_EQ_U64(got[1].len, sizeof(pps));
        WR_TEST_EQ_U64(memcmp(got[1].ptr, pps, sizeof(pps)), 0);
        WR_TEST_EQ_U64(got[2].len, sizeof(idr));
        WR_TEST_EQ_U64(memcmp(got[2].ptr, idr, sizeof(idr)), 0);
    }

    /* Truncated FU-A is rejected, not delivered. */
    uint8_t bad[2] = { 0x7c, 0x81 };
    wr_span_c x;
    WR_TEST_EQ_U64(wr_h264_depay_input(&d, wr_span_c_make(bad, 2), &x),
                   WR_ERR_AGAIN);
    WR_TEST_EQ_U64(wr_h264_depay_input(&d, wr_span_c_make(bad, 1), &x),
                   WR_ERR_TRUNCATED);

    /* A middle fragment that announces a different NAL type than the start
     * fragment must be rejected (RFC 6184 5.8). */
    wr_h264_depay d2;
    wr_h264_depay_init(&d2, nalbuf, sizeof(nalbuf));
    uint8_t fu_start[3] = { 0x7c, 0x85, 0xaa }; /* S=1, type 5 */
    WR_TEST_EQ_U64(wr_h264_depay_input(&d2, wr_span_c_make(fu_start, 3), &x),
                   WR_ERR_AGAIN);
    uint8_t fu_mid[3] = { 0x7c, 0x01, 0xbb }; /* no S/E, type 1: mismatch */
    WR_TEST_EQ_U64(wr_h264_depay_input(&d2, wr_span_c_make(fu_mid, 3), &x),
                   WR_ERR_INVAL);
    /* A non-fragmentable NAL type (24-31) is malformed in an FU-A. */
    uint8_t fu_bad_type[3] = { 0x7c, 0x19, 0x00 }; /* type 25 */
    WR_TEST_EQ_U64(wr_h264_depay_input(&d2, wr_span_c_make(fu_bad_type, 3), &x),
                   WR_ERR_INVAL);
    /* A non-VCL but fragmentable type (e.g. SEI, 6) is accepted as a start
     * fragment. */
    uint8_t fu_sei[3] = { 0x7c, 0x86, 0x00 }; /* S=1, type 6 */
    WR_TEST_EQ_U64(wr_h264_depay_input(&d2, wr_span_c_make(fu_sei, 3), &x),
                   WR_ERR_AGAIN);
}

static void test_vp8(void)
{
    uint8_t frame[300];
    for (size_t i = 0; i < sizeof(frame); ++i) frame[i] = (uint8_t)(i * 3u);
    wr_rtp_pay_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mtu = 64u;
    cfg.pt = 97u;
    cfg.seq = 10u;
    cfg.ts = 9000u;
    cfg.ssrc = 0x55667788u;
    cfg.marker = true;

    enum { MAXP = 16 };
    uint8_t bufs[MAXP][128];
    wr_rtp_out out[MAXP];
    for (int i = 0; i < MAXP; ++i) {
        out[i].ptr = bufs[i];
        out[i].cap = sizeof(bufs[i]);
    }
    uint32_t n = 0;
    WR_TEST_EQ_U64(wr_vp8_packetize(wr_span_c_make(frame, sizeof(frame)), &cfg,
                                    out, MAXP, &n), WR_OK);
    WR_TEST_CHECK(n >= 5u);

    uint8_t reasm[512];
    wr_vp8_depay d;
    wr_vp8_depay_init(&d, reasm, sizeof(reasm));
    wr_span_c got;
    size_t got_len = 0u;
    for (uint32_t i = 0; i < n; ++i) {
        wr_rtp_hdr h = parse_only(wr_span_c_make(out[i].ptr, out[i].len));
        wr_span_c payload = wr_span_c_sub(
            wr_span_c_make(out[i].ptr, out[i].len), h.payload_off,
            h.payload_len);
        wr_status st = wr_vp8_depay_input(&d, payload, h.marker != 0u, &got);
        if (st == WR_OK) {
            got_len = got.len;
        } else {
            WR_TEST_EQ_U64(st, WR_ERR_AGAIN);
        }
    }
    WR_TEST_EQ_U64(got_len, sizeof(frame));
    if (got_len == sizeof(frame)) {
        WR_TEST_EQ_U64(memcmp(got.ptr, frame, sizeof(frame)), 0);
    }

    /* VP8 payload descriptor: the extension header presence bits are I, L, T
     * and K (RFC 7741 4.2). A packet with I and K set but not L/T used to be
     * parsed with a two-byte offset, so the frame was misaligned. */
    {
        uint8_t reasm2[64];
        wr_vp8_depay d2;
        wr_vp8_depay_init(&d2, reasm2, sizeof(reasm2));
        wr_span_c out2;
        /* Descriptor: X=1 (0x80) | S=1 (0x10); ext byte: I|K = 0x90;
         * PictureID (1 byte, high bit clear) = 0x7f; KEYIDX = 0x2a. */
        uint8_t p1[6] = { 0x90u, 0x90u, 0x7fu, 0x2au, 0xde, 0xad };
        WR_TEST_EQ_U64(wr_vp8_depay_input(&d2, wr_span_c_make(p1, 2), false,
                                          &out2),
                       WR_ERR_TRUNCATED);
        WR_TEST_EQ_U64(wr_vp8_depay_input(&d2, wr_span_c_make(p1, sizeof(p1)),
                                          false, &out2),
                       WR_ERR_AGAIN);
        /* The two payload bytes must be the frame bytes, not the descriptor. */
        uint8_t p2[3] = { 0x00u, 0xbe, 0xef };
        WR_TEST_EQ_U64(wr_vp8_depay_input(&d2, wr_span_c_make(p2, 3), true,
                                          &out2),
                       WR_OK);
        WR_TEST_EQ_U64(out2.len, 4u);
        WR_TEST_EQ_U64(memcmp(out2.ptr, "\xde\xad\xbe\xef", 4), 0);
    }
    /* A 16-bit PictureID (high bit set) occupies two octets. */
    {
        uint8_t reasm3[64];
        wr_vp8_depay d3;
        wr_vp8_depay_init(&d3, reasm3, sizeof(reasm3));
        wr_span_c out3;
        uint8_t p[7] = { 0x90u, 0x90u, 0xffu, 0xffu, 0x2au, 0x11, 0x22 };
        WR_TEST_EQ_U64(wr_vp8_depay_input(&d3, wr_span_c_make(p, sizeof(p)),
                                          true, &out3),
                       WR_OK);
        WR_TEST_EQ_U64(out3.len, 2u);
        WR_TEST_EQ_U64(memcmp(out3.ptr, "\x11\x22", 2), 0);
    }
}

static void test_opus(void)
{
    uint8_t frame[80];
    for (size_t i = 0; i < sizeof(frame); ++i) frame[i] = (uint8_t)(0xffu - i);
    wr_rtp_pay_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mtu = 1000u;
    cfg.pt = 111u;
    cfg.seq = 1u;
    cfg.ts = 48000u;
    cfg.ssrc = 1u;
    cfg.marker = true;
    uint8_t buf[256];
    wr_rtp_out out = { buf, sizeof(buf), 0u };
    uint32_t n = 0;
    WR_TEST_EQ_U64(wr_opus_packetize(wr_span_c_make(frame, sizeof(frame)),
                                     &cfg, &out, 1u, &n), WR_OK);
    WR_TEST_EQ_U64(n, 1u);
    wr_rtp_hdr h = parse_only(wr_span_c_make(out.ptr, out.len));
    wr_span_c payload = wr_span_c_sub(wr_span_c_make(out.ptr, out.len),
                                      h.payload_off, h.payload_len);
    WR_TEST_EQ_U64(payload.len, sizeof(frame));
    WR_TEST_EQ_U64(memcmp(payload.ptr, frame, sizeof(frame)), 0);
}

void test_media(void)
{
    test_h264();
    test_vp8();
    test_opus();
}