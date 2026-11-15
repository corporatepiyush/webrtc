#include "test_util.h"

#include "wr/arena.h"
#include "wr/crypto.h"
#include "wr/stun.h"

static void test_type(void)
{
    WR_TEST_EQ_U64(wr_stun_type(WR_STUN_METHOD_BINDING, WR_STUN_CLASS_REQUEST),
                   0x0001);
    WR_TEST_EQ_U64(wr_stun_type(WR_STUN_METHOD_BINDING, WR_STUN_CLASS_SUCCESS),
                   0x0101);
    WR_TEST_EQ_U64(wr_stun_type(WR_STUN_METHOD_BINDING, WR_STUN_CLASS_ERROR),
                   0x0111);
    WR_TEST_EQ_U64(wr_stun_type(WR_STUN_METHOD_ALLOCATE, WR_STUN_CLASS_REQUEST),
                   0x0003);
    WR_TEST_EQ_U64(wr_stun_type(WR_STUN_METHOD_CHANNEL_BIND,
                                WR_STUN_CLASS_SUCCESS), 0x0109);

    wr_stun_method m;
    wr_stun_class c;
    wr_stun_type_decode(0x0111, &m, &c);
    WR_TEST_EQ_U64(m, WR_STUN_METHOD_BINDING);
    WR_TEST_EQ_U64(c, WR_STUN_CLASS_ERROR);
    WR_TEST_CHECK(wr_stun_is_response(0x0101));
    WR_TEST_CHECK(!wr_stun_is_response(0x0001));
}

static void test_address(void)
{
    uint8_t txid[12];
    for (int i = 0; i < 12; ++i) {
        txid[i] = (uint8_t)(i + 1);
    }
    wr_endpoint e;
    uint8_t b[4] = { 192, 0, 2, 1 };
    wr_endpoint_v4(&e, b, 12345);

    uint8_t buf[20];
    size_t n = 0;
    WR_TEST_CHECK(wr_stun_addr_encode(buf, sizeof(buf), &e, true, txid, &n));
    WR_TEST_EQ_U64(n, 8);
    WR_TEST_EQ_U64(buf[1], 1);

    wr_endpoint out;
    WR_TEST_CHECK(wr_stun_addr_decode(wr_span_c_make(buf, n), true, txid, &out));
    WR_TEST_EQ_U64(out.port, 12345);
    WR_TEST_EQ_U64(out.af, WR_AF_INET);
    WR_TEST_EQ_U64(out.ip.b.v4[0], 192);

    uint8_t v6[16] = { 0x20, 0x01, 0x0d, 0xb8 };
    wr_endpoint_v6(&e, v6, 0, 3478);
    WR_TEST_CHECK(wr_stun_addr_encode(buf, sizeof(buf), &e, true, txid, &n));
    WR_TEST_EQ_U64(n, 20);
    WR_TEST_CHECK(wr_stun_addr_decode(wr_span_c_make(buf, n), true, txid, &out));
    WR_TEST_EQ_U64(out.port, 3478);
    WR_TEST_EQ_U64(out.af, WR_AF_INET6);
    WR_TEST_EQ_U64(out.ip.b.v6[0], 0x20);
    WR_TEST_EQ_U64(out.ip.b.v6[1], 0x01);

    WR_TEST_CHECK(!wr_stun_addr_decode(wr_span_c_make(buf, 4), true, txid, &out));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void clobber_stack(void)
{
    volatile uint8_t junk[512];
    for (size_t i = 0; i < sizeof(junk); ++i) {
        junk[i] = (uint8_t)(i * 131u + 7u);
    }
}

static void test_roundtrip(void)
{
    wr_arena *a = wr_arena_create(64 * 1024);
    wr_stun_msg m;
    char username[16];
    memcpy(username, "user:pass", 9u);
    WR_TEST_EQ_U64(wr_stun_build_binding_request(
                       &m, a, 0x1122334455667788ULL, 0x99aabbccddeeff00ULL,
                       wr_span_c_make(username, 9u), 0x6e0001ffu,
                       0x0f1e2d3c4b5a6978ULL, true, true),
                   WR_OK);

    /* The builder must not leave attribute spans pointing at its own stack
     * frame; overwrite the stale frame before serializing. */
    clobber_stack();

    char buf[512];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_stun_append_integrity(&m, (const uint8_t *)"password",
                                            8, buf, sizeof(buf), &n), WR_OK);

    wr_stun_msg p;
    WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(buf, n), WR_STUN_STRICT, &p),
                   WR_OK);
    WR_TEST_EQ_U64(p.type, wr_stun_type(WR_STUN_METHOD_BINDING,
                                        WR_STUN_CLASS_REQUEST));
    WR_TEST_EQ_U64(p.attr.len, m.attr.len + 2u);
    const wr_stun_attr *u = wr_stun_attr_find(&p, WR_STUN_ATTR_USERNAME);
    WR_TEST_CHECK(u && wr_span_c_eq(u->value, wr_span_c_from_str("user:pass")));
    const wr_stun_attr *pri = wr_stun_attr_find(&p, WR_STUN_ATTR_PRIORITY);
    WR_TEST_CHECK(pri && pri->value.len == 4u);
    if (pri) {
        WR_TEST_EQ_U64(wr_load_be32(pri->value.ptr), 0x6e0001ffu);
    }
    const wr_stun_attr *tie =
        wr_stun_attr_find(&p, WR_STUN_ATTR_ICE_CONTROLLING);
    WR_TEST_CHECK(tie && tie->value.len == 8u);
    if (tie) {
        /* The tie-breaker is the value the caller supplied, verbatim: it is
         * an independent random value, not a function of the transaction id
         * (RFC 8445 7.1.3). */
        WR_TEST_EQ_U64(wr_load_be64(tie->value.ptr), 0x0f1e2d3c4b5a6978ULL);
    }
    const wr_stun_attr *uc = wr_stun_attr_find(&p, WR_STUN_ATTR_USE_CANDIDATE);
    WR_TEST_CHECK(uc != NULL);
    WR_TEST_CHECK(wr_stun_verify_fingerprint(&p));
    WR_TEST_CHECK(wr_stun_verify_integrity(&p, (const uint8_t *)"password", 8));
    WR_TEST_CHECK(!wr_stun_verify_integrity(&p, (const uint8_t *)"wrong", 5));

    /* Controlling and controlled tie-breakers must differ; otherwise a role
     * conflict can never be resolved (RFC 8445 7.3.1.1). */
    {
        wr_stun_msg ctl;
        (void)wr_stun_build_binding_request(
            &ctl, a, 0x1122334455667788ULL, 0x99aabbccddeeff00ULL,
            wr_span_c_make(username, 9u), 0x6e0001ffu,
            0x0f1e2d3c4b5a6979ULL, false, false);
        const wr_stun_attr *ctl_tie =
            wr_stun_attr_find(&ctl, WR_STUN_ATTR_ICE_CONTROLLED);
        WR_TEST_CHECK(ctl_tie && ctl_tie->value.len == 8u);
        if (tie && ctl_tie) {
            WR_TEST_CHECK(wr_load_be64(tie->value.ptr) !=
                          wr_load_be64(ctl_tie->value.ptr));
        }
    }

    /* Flip a bit in the payload covered by the MAC. */
    uint8_t copy[512];
    memcpy(copy, buf, n);
    copy[30] ^= 0x01;
    wr_stun_msg q;
    WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(copy, n), WR_STUN_LIBERAL, &q),
                   WR_OK);
    WR_TEST_CHECK(!wr_stun_verify_integrity(&q, (const uint8_t *)"password", 8));
    wr_arena_destroy(a);
}

static void test_parse_errors(void)
{
    wr_arena *a = wr_arena_create(4096);
    wr_stun_msg m;
    uint8_t bad[20] = { 0 };
    WR_TEST_CHECK(wr_stun_parse(a, wr_span_c_make(bad, 20), WR_STUN_LIBERAL,
                                &m) == WR_ERR_INVAL);
    bad[0] = 0x00;
    bad[1] = 0x01;
    wr_store_be32(bad + 4, WR_STUN_MAGIC_COOKIE);
    WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(bad, 20), WR_STUN_LIBERAL,
                                 &m), WR_OK);
    WR_TEST_EQ_U64(m.attr.len, 0);
    wr_store_be16(bad + 2, 100);
    WR_TEST_CHECK(wr_stun_parse(a, wr_span_c_make(bad, 20), WR_STUN_LIBERAL,
                                &m) == WR_ERR_TRUNCATED);
    wr_arena_destroy(a);
}

static void test_strict_padding(void)
{
    /* Exercise every attribute length modulo 4 at the end of the message:
     * exact zero padding parses, nonzero padding is invalid, and a missing
     * padding byte is truncated without reading past the buffer. */
    wr_arena *a = wr_arena_create(4096);
    for (size_t alen = 0u; alen <= 8u; ++alen) {
        size_t pad = (4u - (alen & 3u)) & 3u;
        size_t attr = 4u + alen + pad;
        size_t n = 20u + attr;
        uint8_t p[64];
        memset(p, 0, sizeof(p));
        p[0] = 0x00; p[1] = 0x01;
        wr_store_be16(p + 2u, (uint16_t)attr);
        p[4] = 0x21; p[5] = 0x12; p[6] = 0xa4; p[7] = 0x42;
        wr_store_be16(p + 20u, 0x0001u);
        wr_store_be16(p + 22u, (uint16_t)alen);
        memset(p + 24u, 'A', alen);

        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_stun_msg m;
        WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(p, n), WR_STUN_STRICT,
                                     &m),
                       WR_OK);

        if (pad > 0u) {
            p[n - 1u] = 1u;
            WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(p, n),
                                         WR_STUN_STRICT, &m),
                           WR_ERR_INVAL);
            p[n - 1u] = 0u;
            WR_TEST_EQ_U64(wr_stun_parse(a, wr_span_c_make(p, n - 1u),
                                         WR_STUN_STRICT, &m),
                           WR_ERR_TRUNCATED);
        }
        wr_arena_mark_release(a, mk);
    }
    wr_arena_destroy(a);
}

static void test_channel(void)
{
    uint8_t packet[64];
    wr_status st = wr_turn_channel_serialize((char *)packet, sizeof(packet),
                                             0x4001,
                                             wr_span_c_from_str("hello"), NULL);
    WR_TEST_EQ_U64(st, WR_OK);
    WR_TEST_EQ_U64(wr_load_be16(packet), 0x4001);
    WR_TEST_EQ_U64(wr_load_be16(packet + 2), 5);
    WR_TEST_EQ_U64(packet[9], 0);

    uint16_t num = 0;
    wr_span_c data;
    WR_TEST_EQ_U64(wr_turn_channel_parse(wr_span_c_make(packet, 12), &num, &data),
                   WR_OK);
    WR_TEST_EQ_U64(num, 0x4001);
    WR_TEST_EQ_U64(data.len, 5);
    WR_TEST_EQ_U64(memcmp(data.ptr, "hello", 5), 0);
    WR_TEST_CHECK(wr_turn_channel_parse(wr_span_c_make(packet, 7), &num, &data) ==
                  WR_ERR_TRUNCATED);
}

void test_stun(void)
{
    test_type();
    test_address();
    test_roundtrip();
    test_parse_errors();
    test_strict_padding();
    test_channel();
}