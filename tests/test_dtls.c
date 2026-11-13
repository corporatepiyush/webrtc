#include "test_util.h"

#include "wr/dtls.h"

static void test_record(void)
{
    wr_dtls_record r;
    memset(&r, 0, sizeof(r));
    r.type = WR_DTLS_APPDATA;
    r.version = 0xfefd;
    r.epoch = 3;
    for (int i = 0; i < 6; ++i) r.seq[i] = (uint8_t)(i + 1);
    r.body = wr_span_c_from_str("hello");

    char buf[64];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_dtls_record_serialize(&r, buf, sizeof(buf), &n), WR_OK);
    wr_dtls_record p;
    WR_TEST_EQ_U64(wr_dtls_record_parse(wr_span_c_make(buf, n), &p), WR_OK);
    WR_TEST_EQ_U64(p.type, WR_DTLS_APPDATA);
    WR_TEST_EQ_U64(p.epoch, 3);
    WR_TEST_EQ_U64(p.body.len, 5);
    WR_TEST_EQ_U64(memcmp(p.body.ptr, "hello", 5), 0);
    WR_TEST_CHECK(wr_dtls_record_parse(wr_span_c_make(buf, 12), &p) ==
                  WR_ERR_TRUNCATED);
}

static void test_encrypt(void)
{
    wr_dtls_cipher c;
    memset(&c, 0, sizeof(c));
    for (int i = 0; i < 16; ++i) c.key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 4; ++i) c.salt[i] = (uint8_t)(0x90 + i);

    uint8_t seq[6] = { 0, 0, 0, 0, 0, 42 };
    char buf[128];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_dtls_encrypt(&c, WR_DTLS_APPDATA, 1, seq,
                                   wr_span_c_from_str("secret payload"), buf,
                                   sizeof(buf), &n), WR_OK);

    uint8_t out[64];
    wr_span os = wr_span_make(out, sizeof(out));
    wr_dtls_record meta;
    WR_TEST_EQ_U64(wr_dtls_decrypt(&c, wr_span_c_make(buf, n), &os, &meta),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(out, "secret payload", 14), 0);
    WR_TEST_EQ_U64(meta.epoch, 1);
    WR_TEST_EQ_U64(meta.seq[5], 42);

    buf[20] ^= 1u;
    WR_TEST_CHECK(wr_dtls_decrypt(&c, wr_span_c_make(buf, n), &os, &meta) ==
                  WR_ERR_AUTH);
}

static void test_hs(void)
{
    wr_dtls_hs h;
    memset(&h, 0, sizeof(h));
    h.type = WR_DTLS_HIERARCHY_CLIENT_HELLO;
    h.length = 100;
    h.msg_seq = 2;
    h.frag_off = 10;
    h.frag_len = 5;
    h.body = wr_span_c_from_str("abcde");

    char buf[64];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_dtls_hs_serialize(&h, buf, sizeof(buf), &n), WR_OK);
    wr_dtls_hs p;
    WR_TEST_EQ_U64(wr_dtls_hs_parse(wr_span_c_make(buf, n), &p), WR_OK);
    WR_TEST_EQ_U64(p.type, WR_DTLS_HIERARCHY_CLIENT_HELLO);
    WR_TEST_EQ_U64(p.length, 100);
    WR_TEST_EQ_U64(p.msg_seq, 2);
    WR_TEST_EQ_U64(p.frag_off, 10);
    WR_TEST_EQ_U64(p.frag_len, 5);
    WR_TEST_EQ_U64(memcmp(p.body.ptr, "abcde", 5), 0);

    h.frag_len = 200;
    WR_TEST_EQ_U64(wr_dtls_hs_serialize(&h, buf, sizeof(buf), &n), WR_OK);
    WR_TEST_CHECK(wr_dtls_hs_parse(wr_span_c_make(buf, n), &p) == WR_ERR_INVAL);
}

static void test_prf(void)
{
    uint8_t secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = (uint8_t)(i + 3);
    uint8_t seed[64];
    for (int i = 0; i < 64; ++i) seed[i] = (uint8_t)(0x40 + i);
    uint8_t a[48], b[48];
    wr_dtls_prf(secret, sizeof(secret), wr_span_c_from_str("master secret"),
                wr_span_c_make(seed, sizeof(seed)), a, sizeof(a));
    wr_dtls_prf(secret, sizeof(secret), wr_span_c_from_str("master secret"),
                wr_span_c_make(seed, sizeof(seed)), b, sizeof(b));
    WR_TEST_EQ_U64(memcmp(a, b, sizeof(a)), 0);
    WR_TEST_CHECK(a[0] != 0);
}

void test_dtls(void)
{
    test_record();
    test_encrypt();
    test_hs();
    test_prf();
}
