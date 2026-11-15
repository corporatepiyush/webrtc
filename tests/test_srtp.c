#include "test_util.h"

#include "wr/srtp.h"

static void make_rtp(uint8_t *buf, uint16_t seq, uint32_t ssrc,
                     const char *payload, size_t *out_len)
{
    size_t n = strlen(payload);
    buf[0] = 0x80;
    buf[1] = 0x00;
    wr_store_be16(buf + 2, seq);
    wr_store_be32(buf + 4, 12345);
    wr_store_be32(buf + 8, ssrc);
    memcpy(buf + 12, payload, n);
    *out_len = 12 + n;
}

static void test_aes_cm(void)
{
    uint8_t key[16];
    uint8_t salt[14];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 14; ++i) salt[i] = (uint8_t)(0xa0 + i);

    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&c, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key,
                                salt, 0x12345678u), WR_OK);
    WR_TEST_EQ_U64(c.tag_len, 10);
    WR_TEST_EQ_U64(wr_srtp_get_roc(&c), 0);

    uint8_t in[64], out[64], back[64];
    size_t in_len = 0;
    make_rtp(in, 1000, 0x12345678u, "hello srtp", &in_len);
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(in, in_len),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    WR_TEST_CHECK(out[12] != in[12]); /* payload encrypted */
    WR_TEST_EQ_U64(out[0], in[0]);    /* header not encrypted */

    wr_srtp_ctx d;
    WR_TEST_EQ_U64(wr_srtp_init(&d, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key,
                                salt, 0x12345678u), WR_OK);
    wr_span back_span = wr_span_make(back, sizeof(back));
    WR_TEST_EQ_U64(wr_srtp_unprotect(&d, wr_span_c_make(out, in_len + 10),
                                     back_span), WR_OK);
    WR_TEST_EQ_U64(memcmp(in, back, in_len), 0);

    /* Replay. */
    WR_TEST_CHECK(wr_srtp_unprotect(&d, wr_span_c_make(out, in_len + 10),
                                    back_span) == WR_ERR_AUTH);

    /* Tamper. */
    out[20] ^= 1u;
    WR_TEST_CHECK(wr_srtp_unprotect(&d, wr_span_c_make(out, in_len + 10),
                                    back_span) == WR_ERR_AUTH);
    wr_srtp_fini(&c);
    wr_srtp_fini(&d);
}

static void test_roc_wrap(void)
{
    uint8_t key[16] = { 1 };
    uint8_t salt[14] = { 2 };
    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&c, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt,
                                0x11223344u), WR_OK);

    uint8_t in[32], out[32];
    size_t n = 0;
    make_rtp(in, 65535, 0x11223344u, "x", &n);
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(in, n),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    WR_TEST_EQ_U64(wr_srtp_get_roc(&c), 0);
    make_rtp(in, 0, 0x11223344u, "y", &n);
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(in, n),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    WR_TEST_EQ_U64(wr_srtp_get_roc(&c), 1);

    wr_srtp_ctx d;
    WR_TEST_EQ_U64(wr_srtp_init(&d, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt,
                                0x11223344u), WR_OK);
    make_rtp(in, 65535, 0x11223344u, "x", &n);
    uint8_t pkt[64];
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(in, n),
                                   wr_span_make(pkt, sizeof(pkt))), WR_OK);
    WR_TEST_EQ_U64(wr_srtp_get_roc(&c), 1);
    wr_srtp_fini(&c);
    wr_srtp_fini(&d);
}

static void test_gcm(void)
{
    uint8_t key[16] = { 0 };
    uint8_t salt[14] = { 0 };
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(0xf0 - i);
    for (int i = 0; i < 14; ++i) salt[i] = (uint8_t)(0x30 + i);

    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&c, WR_SRTP_AES_GCM_128, key, salt,
                                0xdeadbeefu), WR_OK);
    WR_TEST_EQ_U64(c.tag_len, 16);

    uint8_t in[64], out[64], back[64];
    size_t n = 0;
    make_rtp(in, 42, 0xdeadbeefu, "gcm payload", &n);
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(in, n),
                                   wr_span_make(out, sizeof(out))), WR_OK);

    wr_srtp_ctx d;
    WR_TEST_EQ_U64(wr_srtp_init(&d, WR_SRTP_AES_GCM_128, key, salt,
                                0xdeadbeefu), WR_OK);
    wr_span bs = wr_span_make(back, sizeof(back));
    WR_TEST_EQ_U64(wr_srtp_unprotect(&d, wr_span_c_make(out, n + 16), bs),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(in, back, n), 0);

    out[12] ^= 1u;
    WR_TEST_CHECK(wr_srtp_unprotect(&d, wr_span_c_make(out, n + 16), bs) ==
                  WR_ERR_AUTH);
}

static void test_kdf_vector(void)
{
    /* RFC 3711 Appendix B.3 */
    static const uint8_t mk[16] = {
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
        0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39
    };
    static const uint8_t ms[14] = {
        0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe,
        0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
    };
    static const uint8_t key[16] = {
        0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee,
        0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7, 0xa0, 0x87
    };
    static const uint8_t salt[14] = {
        0x30, 0xcb, 0xbc, 0x08, 0x86, 0x3d, 0x8c,
        0x85, 0xd4, 0x9d, 0xb3, 0x4a, 0x9a, 0xe1
    };
    static const uint8_t auth[20] = {
        0xce, 0xbe, 0x32, 0x1f, 0x6f, 0xf7, 0x71, 0x6b, 0x6f, 0xd4,
        0xab, 0x49, 0xaf, 0x25, 0x6a, 0x15, 0x6d, 0x38, 0xba, 0xa4
    };
    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&c, WR_SRTP_AES_CM_128_HMAC_SHA1_80, mk, ms,
                                0x12345678u), WR_OK);
    WR_TEST_EQ_U64(memcmp(c.key, key, 16), 0);
    WR_TEST_EQ_U64(memcmp(c.salt, salt, 14), 0);
    WR_TEST_EQ_U64(memcmp(c.auth, auth, 20), 0);
    wr_srtp_fini(&c);
}

static void test_gcm_vector(void)
{
    /* RFC 7714 Section 16.1.1 */
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t salt[12] = {
        0x51, 0x75, 0x69, 0x64, 0x20, 0x70,
        0x72, 0x6f, 0x20, 0x71, 0x75, 0x6f
    };
    static const char *pt = "Gallia est omnis divisa in partes tres";
    static const uint8_t expected[] = {
        0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2,
        0xf2, 0x4d, 0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c,
        0x9d, 0x7e, 0x4b, 0xca, 0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f,
        0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7, 0xd1, 0x9b, 0x36, 0xde, 0x3a, 0xdf,
        0x88, 0x33, 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1, 0x6a, 0x91, 0x52, 0xcf,
        0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce
    };
    uint8_t pkt[128];
    memcpy(pkt, expected, 12);
    memcpy(pkt + 12, pt, strlen(pt));

    wr_srtp_ctx c;
    memset(&c, 0, sizeof(c));
    c.profile = WR_SRTP_AES_GCM_128;
    c.tag_len = 16;
    c.ssrc = 0x5501a0b2u;
    c.roc = 0;
    memcpy(c.key, key, 16);
    memcpy(c.salt, salt, 12);
    c.initialized = true;

    uint8_t out[128];
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(pkt, 12 + strlen(pt)),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    WR_TEST_EQ_U64(memcmp(out, expected, sizeof(expected)), 0);

    wr_srtp_ctx d;
    memset(&d, 0, sizeof(d));
    d.profile = WR_SRTP_AES_GCM_128;
    d.tag_len = 16;
    d.ssrc = 0x5501a0b2u;
    memcpy(d.key, key, 16);
    memcpy(d.salt, salt, 12);
    d.initialized = true;
    uint8_t back[128];
    wr_span bs = wr_span_make(back, sizeof(back));
    WR_TEST_EQ_U64(wr_srtp_unprotect(&d, wr_span_c_make(out, sizeof(expected)), bs),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(back + 12, pt, strlen(pt)), 0);
}

static void test_aes_cm_keystream(void)
{
    /* RFC 3711 Appendix B.2, first keystream block. */
    static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    static const uint8_t salt[14] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
        0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
    };
    static const uint8_t ks[16] = {
        0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80,
        0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b, 0x4e, 0xb4
    };
    wr_srtp_ctx c;
    memset(&c, 0, sizeof(c));
    c.profile = WR_SRTP_AES_CM_128_HMAC_SHA1_80;
    c.tag_len = 10;
    c.ssrc = 0;
    memcpy(c.key, key, 16);
    memcpy(c.salt, salt, 14);
    c.initialized = true;

    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x80;
    uint8_t out[64];
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(pkt, sizeof(pkt)),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    WR_TEST_EQ_U64(memcmp(out + 12, ks, 16), 0);
}

/* SRTCP AEAD_AES_128_GCM round trip, using the packet from RFC 7714 17.1. */
static void test_srtcp_gcm_roundtrip(void)
{
    /* RTCP packet: length 0x000d, SSRC "Mars", PT=200 (SR), ... */
    uint8_t pt[32];
    static const uint8_t hex[] = {
        0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54,
        0x50, 0x31, 0x4e, 0x54, 0x50, 0x32, 0x52, 0x54, 0x50, 0x20,
        0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30, 0x4c, 0x75,
        0x6e, 0x61,
    };
    /* The RFC appends three "deadbeef" words; this packet is 32 octets. */
    memcpy(pt, hex, sizeof(hex));
    const size_t pt_len = sizeof(hex);

    uint8_t key[16];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)i;
    uint8_t salt[12];
    for (int i = 0; i < 12; ++i) salt[i] = (uint8_t)(0xa0 + i);

    wr_srtp_ctx enc;
    WR_TEST_EQ_U64(wr_srtcp_init(&enc, WR_SRTP_AES_GCM_128, key, salt,
                                 0x4d617273u),
                   WR_OK);
    uint8_t out[128];
    WR_TEST_EQ_U64(wr_srtcp_protect(&enc, wr_span_c_make(pt, pt_len),
                                    wr_span_make(out, sizeof(out)), 0x5d4u),
                   WR_OK);
    /* The ESRTCP word must be E=1 with index 0x5d4. */
    uint32_t e = wr_load_be32(out + 8 + (pt_len - 8u));
    WR_TEST_EQ_U64(e, (1u << 31) | 0x5d4u);
    /* The 8-octet header stays in the clear. */
    WR_TEST_EQ_U64(memcmp(out, pt, 8), 0);

    /* Round trip through an independent context. */
    wr_srtp_ctx dec;
    WR_TEST_EQ_U64(wr_srtcp_init(&dec, WR_SRTP_AES_GCM_128, key, salt,
                                 0x4d617273u),
                   WR_OK);
    uint8_t back[128];
    uint32_t idx = 0u;
    WR_TEST_EQ_U64(wr_srtcp_unprotect(&dec, wr_span_c_make(out, 8u + (pt_len - 8u) + 4u + 16u),
                                      wr_span_make(back, sizeof(back)), &idx),
                   WR_OK);
    WR_TEST_EQ_U64(idx, 0x5d4u);
    WR_TEST_EQ_U64(memcmp(back, pt, pt_len), 0);
    /* Replay of the same index must be rejected. */
    WR_TEST_EQ_U64(wr_srtcp_unprotect(&dec, wr_span_c_make(out, 8u + (pt_len - 8u) + 4u + 16u),
                                      wr_span_make(back, sizeof(back)), &idx),
                   WR_ERR_AUTH);
}

/* AES-CM SRTCP uses labels 3/4/5, so its key material must differ from the
 * SRTP context derived from the same master key. */
static void test_srtcp_key_labels(void)
{
    uint8_t key[16];
    uint8_t salt[14];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 14; ++i) salt[i] = (uint8_t)(0x60 + i);

    wr_srtp_ctx s;
    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&s, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key,
                                salt, 0x11223344u),
                   WR_OK);
    WR_TEST_EQ_U64(wr_srtcp_init(&c, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key,
                                 salt, 0x11223344u),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(s.key, c.key, 16) != 0, 1);
    WR_TEST_EQ_U64(memcmp(s.auth, c.auth, 20) != 0, 1);
    WR_TEST_EQ_U64(memcmp(s.salt, c.salt, 14) != 0, 1);

    /* The SRTCP index is 31 bits: the E flag must not leak into it. */
    uint8_t rtcp[32];
    memset(rtcp, 0x11, sizeof(rtcp));
    rtcp[0] = 0x81;
    rtcp[1] = 0xc8;
    uint8_t out[128];
    WR_TEST_EQ_U64(wr_srtcp_protect(&c, wr_span_c_make(rtcp, sizeof(rtcp)),
                                    wr_span_make(out, sizeof(out)),
                                    UINT32_C(0x7fffffff)),
                   WR_OK);
    uint32_t idx = 0u;
    uint8_t back[128];
    WR_TEST_EQ_U64(wr_srtcp_unprotect(&c, wr_span_c_make(out, sizeof(rtcp) + 4u + 10u),
                                      wr_span_make(back, sizeof(back)), &idx),
                   WR_OK);
    WR_TEST_EQ_U64(idx, UINT32_C(0x7fffffff));
}

/* AES-256 profiles (RFC 6188 AES_256_CM_HMAC_SHA1_80 and RFC 7714
 * AEAD_AES_256_GCM) derive a 32-octet session key. The master key supplied to
 * this API is 16 octets; the KDF expands it to 32 by running the AES-CM key
 * derivation with a 32-octet output, which is exactly what the 256-bit
 * profiles specify. */
static void test_aes_256(void)
{
    uint8_t key[16];
    uint8_t salt[14];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 14; ++i) salt[i] = (uint8_t)(0x70 + i);

    wr_srtp_ctx c;
    WR_TEST_EQ_U64(wr_srtp_init(&c, WR_SRTP_AES_CM_256_HMAC_SHA1_80, key,
                                salt, 0x22334455u),
                   WR_OK);
    WR_TEST_EQ_U64(c.tag_len, 10);

    /* The KDF is a keystream: the first 16 octets of a 32-octet derivation
     * are identical to a 16-octet one, so compare the ciphertext instead. */
    wr_srtp_ctx c128;
    WR_TEST_EQ_U64(wr_srtp_init(&c128, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key,
                                salt, 0x22334455u),
                   WR_OK);

    uint8_t rtp[20];
    size_t rtp_len = 0u;
    make_rtp(rtp, 1000, 0x22334455u, "aes256", &rtp_len);
    uint8_t out[64];
    WR_TEST_EQ_U64(wr_srtp_protect(&c, wr_span_c_make(rtp, rtp_len),
                                   wr_span_make(out, sizeof(out))), WR_OK);
    uint8_t out128[64];
    WR_TEST_EQ_U64(wr_srtp_protect(&c128, wr_span_c_make(rtp, rtp_len),
                                   wr_span_make(out128, sizeof(out128))), WR_OK);
    WR_TEST_EQ_U64(memcmp(out, out128, rtp_len) != 0, 1);

    uint8_t back[64];
    WR_TEST_EQ_U64(wr_srtp_unprotect(&c,
                                     wr_span_c_make(out, rtp_len + 10u),
                                     wr_span_make(back, sizeof(back))),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(back, rtp, rtp_len), 0);

    /* GCM-256 round trip. */
    wr_srtp_ctx g;
    WR_TEST_EQ_U64(wr_srtp_init(&g, WR_SRTP_AES_GCM_256, key, salt,
                                0x22334455u),
                   WR_OK);
    WR_TEST_EQ_U64(g.tag_len, 16);
    uint8_t gout[64];
    WR_TEST_EQ_U64(wr_srtp_protect(&g, wr_span_c_make(rtp, rtp_len),
                                   wr_span_make(gout, sizeof(gout))), WR_OK);
    uint8_t gback[64];
    WR_TEST_EQ_U64(wr_srtp_unprotect(&g,
                                     wr_span_c_make(gout, rtp_len + 16u),
                                     wr_span_make(gback, sizeof(gback))),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(gback, rtp, rtp_len), 0);
}

void test_srtp(void)
{
    test_aes_cm();
    test_roc_wrap();
    test_gcm();
    test_kdf_vector();
    test_gcm_vector();
    test_aes_cm_keystream();
    test_srtcp_key_labels();
    test_srtcp_gcm_roundtrip();
    test_aes_256();
}