#include "test_util.h"

#include "wr/media.h"
#include "wr/media_codec.h"
#include "wr/rtp.h"

#include <math.h>
#include <stdlib.h>

static void fill_yuv(uint8_t *p, int w, int h, int frame)
{
    for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
            p[y * w + x] = (uint8_t)((x * 3 + y * 5 + frame * 7) & 0xff);
        }
    }
    uint8_t *u = p + w * h;
    uint8_t *v = u + (w / 2) * (h / 2);
    for (int i = 0; i < (w / 2) * (h / 2); ++i) {
        u[i] = (uint8_t)(128 + ((i + frame) & 0x1f) - 16);
        v[i] = (uint8_t)(128 - ((i + frame) & 0x1f) + 16);
    }
}

static bool decode_all(wr_media_dec *d, wr_media_packet *pkts, uint32_t n,
                       int *w, int *h)
{
    int frames = 0;
    for (uint32_t i = 0; i < n; ++i) {
        wr_media_frame f;
        bool got = false;
        if (wr_media_dec_push(d, pkts[i].data, &f, &got) != WR_OK) {
            return false;
        }
        if (got) {
            *w = f.width;
            *h = f.height;
            frames++;
        }
    }
    return frames > 0;
}

static void test_h264(void)
{
    enum { W = 320, H = 240 };
    wr_arena *a = wr_arena_create(4u * 1024u * 1024u);
    wr_media_enc_config cfg = {
        WR_MEDIA_H264, (uint16_t)W, (uint16_t)H, 30, 500, 30, 0, 0
    };
    wr_media_enc *e = wr_media_enc_create(a, &cfg);
    WR_TEST_CHECK(e != NULL);
    if (!e) {
        wr_arena_destroy(a);
        return;
    }

    wr_media_packet pkts[64];
    uint32_t n = 0;
    uint8_t *frame = (uint8_t *)malloc((size_t)W * H * 3 / 2);
    WR_TEST_CHECK(frame != NULL);
    for (int f = 0; f < 8 && n < 64; ++f) {
        fill_yuv(frame, W, H, f);
        uint32_t got = 0;
        WR_TEST_EQ_U64(wr_media_enc_push(e, wr_span_c_make(frame, (size_t)W * H * 3 / 2),
                                         (uint64_t)f * 33u, &pkts[n], 64 - n, &got), WR_OK);
        n += got;
    }
    uint32_t got = 0;
    (void)wr_media_enc_flush(e, &pkts[n], 64 - n, &got);
    n += got;
    free(frame);
    WR_TEST_CHECK(n > 0u);

    int dw = 0, dh = 0;
    wr_media_dec *d = wr_media_dec_create(a, WR_MEDIA_H264);
    WR_TEST_CHECK(d != NULL);
    if (d) {
        WR_TEST_CHECK(decode_all(d, pkts, n, &dw, &dh));
        WR_TEST_EQ_U64((uint32_t)dw, W);
        WR_TEST_EQ_U64((uint32_t)dh, H);
        wr_media_dec_destroy(d);
    }

    /* The encoded access unit must be Annex B, and must survive RTP
     * packetization/depacketization. */
    wr_span_c first = pkts[0].data;
    bool annexb = first.len > 4u &&
                  ((first.ptr[0] == 0 && first.ptr[1] == 0 &&
                    first.ptr[2] == 0 && first.ptr[3] == 1) ||
                   (first.ptr[0] == 0 && first.ptr[1] == 0 && first.ptr[2] == 1));
    WR_TEST_CHECK(annexb);

    wr_rtp_pay_cfg pc;
    memset(&pc, 0, sizeof(pc));
    pc.mtu = 128u;
    pc.pt = 96u;
    pc.seq = 1u;
    pc.ts = 1000u;
    pc.ssrc = 1u;
    pc.marker = true;
    enum { MAXP = 128 };
    uint8_t bufs[MAXP][192];
    wr_rtp_out out[MAXP];
    for (int i = 0; i < MAXP; ++i) {
        out[i].ptr = bufs[i];
        out[i].cap = sizeof(bufs[i]);
    }

    uint8_t nalbuf[8192];
    wr_h264_depay dp;
    wr_h264_depay_init(&dp, nalbuf, sizeof(nalbuf));
    uint8_t reasm[16384];
    size_t roff = 0;
    const uint8_t sc[4] = { 0, 0, 0, 1 };
    for (uint32_t p = 0; p < n; ++p) {
        uint32_t np = 0;
        WR_TEST_EQ_U64(wr_h264_packetize(pkts[p].data, &pc, out, MAXP, &np),
                       WR_OK);
        WR_TEST_CHECK(np > 0u);
        for (uint32_t i = 0; i < np; ++i) {
            wr_rtp_hdr h;
            WR_TEST_CHECK(wr_rtp_parse(wr_span_c_make(out[i].ptr, out[i].len),
                                       &h));
            wr_span_c payload = wr_span_c_sub(
                wr_span_c_make(out[i].ptr, out[i].len), h.payload_off,
                h.payload_len);
            wr_span_c nal;
            wr_status st = wr_h264_depay_input(&dp, payload, &nal);
            if (st == WR_OK) {
                WR_TEST_CHECK(roff + 4u + nal.len <= sizeof(reasm));
                memcpy(reasm + roff, sc, 4u);
                roff += 4u;
                memcpy(reasm + roff, nal.ptr, nal.len);
                roff += nal.len;
            } else {
                WR_TEST_EQ_U64(st, WR_ERR_AGAIN);
            }
        }
        pc.seq = (uint16_t)(pc.seq + np);
        pc.ts += 3000u;
    }

    wr_media_dec *d2 = wr_media_dec_create(a, WR_MEDIA_H264);
    WR_TEST_CHECK(d2 != NULL);
    if (d2) {
        wr_media_frame f;
        bool gotf = false;
        WR_TEST_EQ_U64(wr_media_dec_push(d2, wr_span_c_make(reasm, roff), &f,
                                         &gotf), WR_OK);
        WR_TEST_CHECK(gotf);
        if (gotf) {
            WR_TEST_EQ_U64((uint32_t)f.width, W);
            WR_TEST_EQ_U64((uint32_t)f.height, H);
            /* A YUV420p frame exposes all three planes and a real stride. */
            WR_TEST_CHECK(f.data != NULL);
            WR_TEST_CHECK(f.data_u != NULL && f.data_v != NULL);
            WR_TEST_CHECK(f.linesize >= (size_t)W);
        }
        wr_media_dec_destroy(d2);
    }

    wr_media_enc_destroy(e);
    wr_arena_destroy(a);
}

static void test_vp8(void)
{
    enum { W = 320, H = 240 };
    wr_arena *a = wr_arena_create(4u * 1024u * 1024u);
    wr_media_enc_config cfg = {
        WR_MEDIA_VP8, (uint16_t)W, (uint16_t)H, 30, 500, 30, 0, 0
    };
    wr_media_enc *e = wr_media_enc_create(a, &cfg);
    WR_TEST_CHECK(e != NULL);
    if (!e) {
        wr_arena_destroy(a);
        return;
    }
    uint8_t *frame = (uint8_t *)malloc((size_t)W * H * 3 / 2);
    WR_TEST_CHECK(frame != NULL);
    wr_media_packet pkts[64];
    uint32_t n = 0;
    for (int f = 0; f < 6; ++f) {
        fill_yuv(frame, W, H, f);
        uint32_t got = 0;
        (void)wr_media_enc_push(e, wr_span_c_make(frame, (size_t)W * H * 3 / 2),
                                (uint64_t)f * 33u, &pkts[n], 64 - n, &got);
        n += got;
    }
    uint32_t got = 0;
    (void)wr_media_enc_flush(e, &pkts[n], 64 - n, &got);
    n += got;
    free(frame);
    WR_TEST_CHECK(n > 0u);

    wr_media_dec *d = wr_media_dec_create(a, WR_MEDIA_VP8);
    WR_TEST_CHECK(d != NULL);
    if (d) {
        int dw = 0, dh = 0;
        WR_TEST_CHECK(decode_all(d, pkts, n, &dw, &dh));
        WR_TEST_EQ_U64((uint32_t)dw, W);
        WR_TEST_EQ_U64((uint32_t)dh, H);
        wr_media_dec_destroy(d);
    }
    wr_media_enc_destroy(e);
    wr_arena_destroy(a);
}


static void test_opus(void)
{
    wr_arena *a = wr_arena_create(1u * 1024u * 1024u);
    wr_media_enc_config cfg = {
        WR_MEDIA_OPUS, 0, 0, 0, 64, 0, 48000, 2
    };
    wr_media_enc *e = wr_media_enc_create(a, &cfg);
    WR_TEST_CHECK(e != NULL);
    if (!e) {
        wr_arena_destroy(a);
        return;
    }
    enum { N = 960 };
    float planar[2 * N];
    for (int i = 0; i < N; ++i) {
        float v = (float)sin(2.0 * 3.14159265358979 * 440.0 * i / 48000.0);
        planar[i] = v * 0.5f;
        planar[N + i] = v * 0.5f;
    }
    wr_media_packet pkts[4];
    uint32_t n = 0;
    WR_TEST_EQ_U64(wr_media_enc_push_audio(e, planar, N, pkts, 4, &n), WR_OK);
    WR_TEST_CHECK(n > 0u);
    (void)wr_media_enc_flush(e, &pkts[n], 4 - n, &n);

    wr_media_dec *d = wr_media_dec_create(a, WR_MEDIA_OPUS);
    WR_TEST_CHECK(d != NULL);
    if (d) {
        wr_media_frame f;
        bool got = false;
        WR_TEST_EQ_U64(wr_media_dec_push(d, pkts[0].data, &f, &got), WR_OK);
        WR_TEST_CHECK(got);
        if (got) {
            WR_TEST_EQ_U64((uint32_t)f.sample_rate, 48000u);
            WR_TEST_EQ_U64((uint32_t)f.channels, 2u);
            WR_TEST_EQ_U64((uint32_t)f.nb_samples, N);
        }
        wr_media_dec_destroy(d);
    }
    wr_media_enc_destroy(e);
    wr_arena_destroy(a);
}
void test_media_codec(void)
{
    test_h264();
    test_vp8();
    test_opus();
}