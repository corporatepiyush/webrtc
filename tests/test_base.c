#include "test_util.h"

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/bitio.h"
#include "wr/bitmap.h"
#include "wr/crc32.h"
#include "wr/crc32c.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sb.h"

static void test_span(void)
{
    wr_span_c s = wr_span_c_from_str("hello world");
    WR_TEST_EQ_U64(wr_span_c_take(&s, 5).len, 5);
    WR_TEST_EQ_U64(s.len, 6);
    WR_TEST_EQ_U64(wr_span_c_take(&s, 1).ptr[0], ' ');
    WR_TEST_CHECK(wr_span_c_starts_with(s, wr_span_c_from_str("world")));
    WR_TEST_CHECK(wr_span_c_eq(s, wr_span_c_from_str("world")));
    WR_TEST_CHECK(!wr_span_c_eq(s, wr_span_c_from_str("worlds")));
}

static void test_parse_swar(void)
{
    static const char *ok[] = {
        "0", "7", "999999", "12345678", "00000042", "4294967295",
        "9223372036854775807", "18446744073709551615",
    };
    for (size_t i = 0; i < WR_ARRAY_LEN(ok); ++i) {
        uint64_t v = 0;
        WR_TEST_CHECK(wr_parse_u64(wr_span_c_from_str(ok[i]), &v));
    }
    static const char *bad[] = {
        "", "-", "1a", "12345678x", "99999999999999999999",
        "18446744073709551616",
    };
    for (size_t i = 0; i < WR_ARRAY_LEN(bad); ++i) {
        uint64_t v = 0;
        WR_TEST_CHECK(!wr_parse_u64(wr_span_c_from_str(bad[i]), &v));
    }
    /* Every byte in an 8- or 16-digit SWAR block must be validated. */
    for (int pos = 0; pos < 16; ++pos) {
        for (int c = 0; c < 256; ++c) {
            char buf[17];
            memset(buf, '1', sizeof(buf));
            buf[pos] = (char)c;
            uint64_t got = 0;
            bool parsed = wr_parse_u64(
                wr_span_c_make((const uint8_t *)buf, 16u), &got);
            bool want = c >= '0' && c <= '9';
            WR_TEST_EQ_U64(parsed, want);
        }
    }
    /* Cross-check every length against the value it encodes. */
    uint64_t v = 0;
    for (uint32_t d = 0; d < 100000u; ++d) {
        v = v * 1103515245u + 12345u;
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
        WR_TEST_CHECK(n > 0 && (size_t)n < sizeof(buf));
        uint64_t got = 0;
        WR_TEST_CHECK(wr_parse_u64(wr_span_c_make(buf, (size_t)n), &got));
        WR_TEST_EQ_U64(got, v);
    }
}

static void test_parse(void)
{
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    WR_TEST_CHECK(wr_parse_u64(wr_span_c_from_str("18446744073709551615"), &u64));
    WR_TEST_EQ_U64(u64, UINT64_MAX);
    WR_TEST_CHECK(!wr_parse_u64(wr_span_c_from_str("18446744073709551616"), &u64));
    WR_TEST_CHECK(wr_parse_u32(wr_span_c_from_str("4294967295"), &u32));
    WR_TEST_EQ_U64(u32, UINT32_MAX);
    WR_TEST_CHECK(wr_parse_u16(wr_span_c_from_str("65535"), &u16));
    WR_TEST_EQ_U64(u16, UINT16_MAX);
    WR_TEST_CHECK(!wr_parse_u16(wr_span_c_from_str("65536"), &u16));
    WR_TEST_CHECK(!wr_parse_u32(wr_span_c_from_str("12a"), &u32));
}

static void test_arena(void)
{
    wr_arena *a = wr_arena_create(4096);
    WR_TEST_CHECK(a != NULL);
    WR_TEST_EQ_U64(wr_arena_budget(a), 4096);

    uint8_t *p = (uint8_t *)wr_arena_alloc(a, 100);
    WR_TEST_CHECK(p != NULL);
    WR_TEST_EQ_U64(((uintptr_t)p & 7u), 0);
    memset(p, 0xab, 100);
    WR_TEST_EQ_U64(wr_arena_used(a), 100);

    wr_arena_mark m = wr_arena_mark_save(a);
    uint8_t *q = (uint8_t *)wr_arena_alloc(a, 200);
    WR_TEST_CHECK(q != NULL);
    wr_arena_mark_release(a, m);
    WR_TEST_EQ_U64(wr_arena_used(a), 100);
    WR_TEST_EQ_U64(p[0], 0xab);
    WR_TEST_EQ_U64(p[99], 0xab);

    void *big = wr_arena_alloc(a, 4096);
    WR_TEST_CHECK(big == NULL); /* budget */
    wr_arena_reset(a);
    WR_TEST_EQ_U64(wr_arena_used(a), 0);
    wr_arena_destroy(a);
}

static void test_bitmap(void)
{
    wr_arena *a = wr_arena_create(4096);
    wr_bitmap bm;
    WR_TEST_EQ_U64(wr_bitmap_init(a, &bm, 200), WR_OK);
    wr_bitmap_set(&bm, 0);
    wr_bitmap_set(&bm, 63);
    wr_bitmap_set(&bm, 64);
    wr_bitmap_set(&bm, 199);
    WR_TEST_EQ_U64(wr_bitmap_count(&bm), 4);
    WR_TEST_EQ_U64(wr_bitmap_find_first(&bm), 0);
    WR_TEST_CHECK(wr_bitmap_test(&bm, 64));
    WR_TEST_CHECK(!wr_bitmap_test(&bm, 65));
    wr_bitmap_clear(&bm, 0);
    WR_TEST_EQ_U64(wr_bitmap_count(&bm), 3);
    wr_bitmap_clear_all(&bm);
    WR_TEST_EQ_U64(wr_bitmap_count(&bm), 0);

    wr_bitmap_iter it;
    wr_bitmap_iter_init(&it, &bm);
    uint32_t v;
    WR_TEST_CHECK(!wr_bitmap_iter_next(&it, &v));

    wr_bitmap_set_range(&bm, 10, 5);
    WR_TEST_EQ_U64(wr_bitmap_count(&bm), 5);
    wr_arena_destroy(a);
}

static void test_bitmap_range(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_bitmap bm;
    WR_TEST_CHECK(wr_bitmap_init(a, &bm, 200u) == WR_OK);
    const uint32_t ranges[][2] = {
        { 0, 1 }, { 0, 64 }, { 0, 65 }, { 63, 2 }, { 64, 64 },
        { 65, 10 }, { 100, 100 }, { 199, 1 }, { 0, 200 },
    };
    for (size_t r = 0; r < WR_ARRAY_LEN(ranges); ++r) {
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_bitmap_init(a, &bm, 200u);
        wr_bitmap_set_range(&bm, ranges[r][0], ranges[r][1]);
        for (uint32_t i = 0; i < 200u; ++i) {
            bool want = i >= ranges[r][0] &&
                        i < ranges[r][0] + ranges[r][1];
            WR_TEST_EQ_U64(wr_bitmap_test(&bm, i), want);
        }
        wr_arena_mark_release(a, mk);
    }
    wr_arena_destroy(a);
}

static void test_bitio(void)
{
    uint8_t buf[16];
    wr_span s = wr_span_make(buf, sizeof(buf));
    wr_bitwr w;
    wr_bitwr_init(&w, s);
    WR_TEST_CHECK(wr_bitwr_u1(&w, 1));
    WR_TEST_CHECK(wr_bitwr_u8(&w, 0x5a));
    WR_TEST_CHECK(wr_bitwr_u16(&w, 0xbeef));
    WR_TEST_CHECK(wr_bitwr_u24(&w, 0x123456));
    WR_TEST_CHECK(wr_bitwr_u32(&w, 0x89abcdef));
    WR_TEST_CHECK(wr_bitwr_align_zero(&w));
    WR_TEST_EQ_U64(wr_bitwr_used(&w), 11);

    wr_bitrd r;
    wr_bitrd_init(&r, wr_span_upcast(s));
    uint8_t b1, b8;
    uint16_t b16;
    uint32_t b24, b32;
    WR_TEST_CHECK(wr_bitrd_u1(&r, &b1));
    WR_TEST_EQ_U64(b1, 1);
    WR_TEST_CHECK(wr_bitrd_u8(&r, &b8));
    WR_TEST_EQ_U64(b8, 0x5a);
    WR_TEST_CHECK(wr_bitrd_u16(&r, &b16));
    WR_TEST_EQ_U64(b16, 0xbeef);
    WR_TEST_CHECK(wr_bitrd_u24(&r, &b24));
    WR_TEST_EQ_U64(b24, 0x123456);
    WR_TEST_CHECK(wr_bitrd_u32(&r, &b32));
    WR_TEST_EQ_U64(b32, 0x89abcdef);
    WR_TEST_CHECK(wr_bitrd_align(&r));
    WR_TEST_EQ_U64(wr_bitrd_left(&r), 40);
    WR_TEST_CHECK(wr_bitrd_u1(&r, &b1));
}


static uint32_t ref_crc32c(uint32_t crc, const uint8_t *p, size_t n)
{
    crc = ~crc;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 8; ++k) {
            crc = (crc & 1u) ? (0x82f63b78u ^ (crc >> 1)) : (crc >> 1);
        }
    }
    return ~crc;
}

static void test_crc32c_lengths(void)
{
    uint8_t buf[256];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)(i * 13u + 5u);
    for (size_t n = 0; n <= 192u; ++n) {
        WR_TEST_EQ_U64(wr_crc32c(0u, buf, n), ref_crc32c(0u, buf, n));
    }
}

static void test_arena_counters(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    WR_TEST_CHECK(a != NULL);
    WR_TEST_EQ_U64(wr_arena_alloc_count(a), 0u);
    (void)wr_arena_alloc_array(a, 10u, 8u);
    (void)wr_arena_alloc_array(a, 20u, 4u);
    (void)wr_arena_alloc_array(a, 5u, 16u);
    WR_TEST_EQ_U64(wr_arena_alloc_count(a), 3u);
    WR_TEST_EQ_U64(wr_arena_alloc_bytes(a), 10u * 8u + 20u * 4u + 5u * 16u);
    wr_arena_destroy(a);
}
static void test_crc32c(void)
{
    WR_TEST_EQ_U64(wr_crc32(0, "123456789", 9), 0xcbf43926u);
    WR_TEST_EQ_U64(wr_crc32c(0, "123456789", 9), 0xe3069283u);
    WR_TEST_EQ_U64(wr_crc32c_span(0, wr_span_c_from_str("123456789")),
                   0xe3069283u);
}

static void test_endpoint(void)
{
    wr_endpoint e;
    WR_TEST_CHECK(wr_endpoint_parse(wr_span_c_from_str("127.0.0.1:5000"), 0, &e));
    WR_TEST_EQ_U64(e.af, WR_AF_INET);
    WR_TEST_EQ_U64(e.port, 5000);
    WR_TEST_CHECK(wr_endpoint_is_loopback(&e));

    char buf[128];
    (void)wr_endpoint_format(&e, buf, sizeof(buf));
    WR_TEST_EQ_STR(buf, "127.0.0.1:5000");

    WR_TEST_CHECK(wr_endpoint_parse(wr_span_c_from_str("[::1]:443"), 0, &e));
    WR_TEST_EQ_U64(e.af, WR_AF_INET6);
    WR_TEST_EQ_U64(e.port, 443);
    (void)wr_endpoint_format(&e, buf, sizeof(buf));
    WR_TEST_EQ_STR(buf, "[::1]:443");
    WR_TEST_CHECK(wr_endpoint_is_loopback(&e));

    WR_TEST_CHECK(wr_endpoint_parse(wr_span_c_from_str("192.0.2.1"), 9999, &e));
    WR_TEST_EQ_U64(e.port, 9999);
    WR_TEST_CHECK(!wr_endpoint_parse(wr_span_c_from_str("not-an-ip"), 0, &e));
}

static void test_sb(void)
{
    char buf[64];
    wr_sb s;

    wr_sb_init(&s, buf, sizeof(buf));
    wr_sb_put_u64(&s, 0u);
    wr_sb_put_u8(&s, ' ');
    wr_sb_put_u64(&s, 10u);
    wr_sb_put_u8(&s, ' ');
    wr_sb_put_u64(&s, 18446744073709551615ull);
    WR_TEST_CHECK(wr_sb_ok(&s));
    WR_TEST_EQ_U64(s.len, 1u + 1u + 2u + 1u + 20u);
    WR_TEST_CHECK(memcmp(buf, "0 10 18446744073709551615",
                         s.len) == 0);

    wr_sb_init(&s, buf, sizeof(buf));
    static const uint8_t ip[4] = {0u, 1u, 42u, 255u};
    wr_sb_put_ipv4(&s, ip);
    WR_TEST_EQ_U64(s.len, 10u);
    WR_TEST_CHECK(memcmp(buf, "0.1.42.255", 10u) == 0);

    wr_sb_init(&s, buf, sizeof(buf));
    wr_sb_put_be16(&s, 0x1234u);
    wr_sb_put_be32(&s, 0x89abcdefu);
    wr_sb_put_be64(&s, 0x0123456789abcdefull);
    static const uint8_t wire[14] = {
        0x12u, 0x34u, 0x89u, 0xab, 0xcdu, 0xefu, 0x01u, 0x23u,
        0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu,
    };
    WR_TEST_CHECK(wr_sb_ok(&s));
    WR_TEST_EQ_U64(s.len, sizeof(wire));
    WR_TEST_CHECK(memcmp(buf, wire, sizeof(wire)) == 0);

    /* Truncation must not write past cap, must report failure, and must keep
     * the length that a large-enough buffer would have needed. */
    wr_sb_init(&s, buf, 3u);
    wr_sb_put_u64(&s, 123456u);
    WR_TEST_CHECK(!wr_sb_ok(&s));
    WR_TEST_EQ_U64(s.len, 6u);
    WR_TEST_CHECK(memcmp(buf, "123", 3u) == 0);

    wr_sb_init(&s, buf, 3u);
    wr_sb_put_be32(&s, 0x11223344u);
    WR_TEST_CHECK(!wr_sb_ok(&s));
    WR_TEST_EQ_U64(s.len, 4u);
    WR_TEST_CHECK(memcmp(buf, "\x11\x22\x33", 3u) == 0);

    wr_sb_init(&s, buf, 0u);
    wr_sb_put_n(&s, NULL, 0u);
    wr_sb_put(&s, NULL);
    wr_sb_put_be16(&s, 0xffffu);
    WR_TEST_CHECK(!wr_sb_ok(&s));
    WR_TEST_EQ_U64(s.len, 2u);
}

static void test_rng(void)
{
    wr_rng *r = wr_rng_create();
    WR_TEST_CHECK(r != NULL);
    wr_rng_seed(r, 42);
    uint64_t a = wr_rng_u64(r);
    uint64_t b = wr_rng_u64(r);
    wr_rng_seed(r, 42);
    WR_TEST_EQ_U64(wr_rng_u64(r), a);
    WR_TEST_EQ_U64(wr_rng_u64(r), b);
    WR_TEST_CHECK(a != b);
    wr_rng_destroy(r);
}

void test_base(void)
{
    test_span();
    test_parse();
    test_parse_swar();
    test_arena();
    test_bitmap();
    test_bitmap_range();
    test_bitio();
    test_crc32c();
    test_crc32c_lengths();
    test_arena_counters();
    test_endpoint();
    test_sb();
    test_rng();
}