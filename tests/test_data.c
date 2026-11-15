#include "test_util.h"

#include "wr/hash.h"
#include "wr/map.h"
#include "wr/net.h"
#include "wr/pool.h"
#include "wr/rtp_stream.h"
#include "wr/sctp.h"

static void test_hash(void)
{
    WR_TEST_EQ_U64(wr_hash64("hello", 5, 0), wr_hash64("hello", 5, 0));
    WR_TEST_CHECK(wr_hash64("hello", 5, 0) != wr_hash64("hellp", 5, 0));
    WR_TEST_CHECK(wr_hash64("hello", 5, 0) != wr_hash64("hello", 5, 1));
    WR_TEST_CHECK(wr_hash64("", 0, 0) != 0u);
    WR_TEST_EQ_U64(wr_hash32("123456789", 9, 0), wr_hash32("123456789", 9, 0));
    WR_TEST_CHECK(wr_hash_span(wr_span_c_from_str("abc")) ==
                  wr_hash_span(wr_span_c_from_str("abc")));
    WR_TEST_CHECK(wr_hash_span_ci(wr_span_c_from_str("ABC")) ==
                  wr_hash_span_ci(wr_span_c_from_str("abc")));
}

static void test_u64_map(void)
{
    wr_arena *a = wr_arena_create(256u * 1024u);
    wr_u64_map m;
    WR_TEST_CHECK(wr_u64_map_init(&m, a, 8u));
    for (uint64_t i = 0; i < 2000u; ++i) {
        WR_TEST_CHECK(wr_u64_map_put(&m, i * 3u + 1u, (uint32_t)i));
    }
    WR_TEST_EQ_U64(wr_u64_map_len(&m), 2000u);
    for (uint64_t i = 0; i < 2000u; ++i) {
        uint32_t *v = wr_u64_map_find(&m, i * 3u + 1u);
        WR_TEST_CHECK(v != NULL);
        if (v) WR_TEST_EQ_U64(*v, (uint32_t)i);
    }
    WR_TEST_CHECK(wr_u64_map_find(&m, 2u) == NULL);

    for (uint64_t i = 0; i < 1000u; ++i) {
        WR_TEST_CHECK(wr_u64_map_erase(&m, i * 3u + 1u));
    }
    WR_TEST_EQ_U64(wr_u64_map_len(&m), 1000u);
    for (uint64_t i = 0; i < 1000u; ++i) {
        WR_TEST_CHECK(wr_u64_map_find(&m, i * 3u + 1u) == NULL);
    }
    for (uint64_t i = 1000u; i < 2000u; ++i) {
        uint32_t *v = wr_u64_map_find(&m, i * 3u + 1u);
        WR_TEST_CHECK(v != NULL);
        if (v) WR_TEST_EQ_U64(*v, (uint32_t)i);
    }
    wr_arena_destroy(a);
}

static void test_str_map(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_str_map m;
    WR_TEST_CHECK(wr_str_map_init(&m, a, 8u));
    for (uint32_t i = 0; i < 500u; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "mid-%u", i);
        WR_TEST_CHECK(wr_str_map_put(&m, wr_span_c_from_str(key), i));
    }
    WR_TEST_EQ_U64(wr_str_map_len(&m), 500u);
    for (uint32_t i = 0; i < 500u; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "mid-%u", i);
        uint32_t *v = wr_str_map_find(&m, wr_span_c_from_str(key));
        WR_TEST_CHECK(v != NULL);
        if (v) WR_TEST_EQ_U64(*v, i);
    }
    WR_TEST_CHECK(wr_str_map_find(&m, wr_span_c_from_str("nope")) == NULL);
    WR_TEST_CHECK(wr_str_map_put(&m, wr_span_c_from_str("mid-1"), 999u));
    uint32_t *v = wr_str_map_find(&m, wr_span_c_from_str("mid-1"));
    WR_TEST_CHECK(v && *v == 999u);
    wr_arena_destroy(a);
}

static void test_pool(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_pool p;
    WR_TEST_CHECK(wr_pool_init(&p, a, 16u, 128u, 64u));
    WR_TEST_EQ_U64(wr_pool_capacity(&p), 16u);
    void *objs[16];
    for (int i = 0; i < 16; ++i) {
        objs[i] = wr_pool_alloc(&p);
        WR_TEST_CHECK(objs[i] != NULL);
        WR_TEST_EQ_U64((uintptr_t)objs[i] % 64u, 0u);
        memset(objs[i], i, 128);
    }
    WR_TEST_CHECK(wr_pool_alloc(&p) == NULL);
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 16u);
    for (int i = 0; i < 16; ++i) {
        WR_TEST_EQ_U64(wr_pool_index(&p, objs[i]), (uint32_t)i);
    }
    wr_pool_free(&p, objs[5]);
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 15u);
    void *again = wr_pool_alloc(&p);
    WR_TEST_CHECK(again == objs[5]);

    /* A double free must be a no-op, not a push past free_stack[cap]: the
     * latter corrupts arena memory (the pool is bump-allocated from it). */
    wr_pool_free(&p, objs[5]);
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 15u);
    wr_pool_free(&p, objs[5]);
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 15u);
    /* A foreign pointer must be ignored as well. */
    int local_obj = 0;
    wr_pool_free(&p, &local_obj);
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 15u);

    /* Freeing every object and reallocating must hand back the same set. */
    for (int i = 0; i < 16; ++i) {
        wr_pool_free(&p, wr_pool_at(&p, (uint32_t)i));
    }
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 0u);
    for (int i = 0; i < 16; ++i) {
        WR_TEST_CHECK(wr_pool_alloc(&p) != NULL);
    }
    WR_TEST_EQ_U64(wr_pool_in_use(&p), 16u);
    wr_arena_destroy(a);
}

/* Datagrams larger than the receive buffer must be reported, not silently
 * truncated: a truncated DTLS record would simply fail to parse. */
static void test_io_datagram(void)
{
    wr_endpoint ep;
    wr_endpoint_loopback(&ep, 0u);
    wr_io *io = wr_io_udp_create(&ep, true);
    WR_TEST_CHECK(io != NULL);
    wr_endpoint local;
    WR_TEST_CHECK(wr_io_local_addr(io, &local));

    uint8_t big[4096];
    memset(big, 0x5a, sizeof(big));
    size_t sent = 0u;
    WR_TEST_EQ_U64(wr_io_send(io, &local, wr_span_c_make(big, sizeof(big)),
                              &sent), WR_OK);

    uint8_t buf[2048];
    wr_span data;
    bool ready = false;
    WR_TEST_EQ_U64(wr_io_wait(io, 100u, &ready), WR_OK);
    WR_TEST_CHECK(ready);
    /* The oversized datagram is discarded whole and reported. */
    WR_TEST_EQ_U64(wr_io_recv(io, NULL, wr_span_make(buf, sizeof(buf)), &data),
                   WR_ERR_OVERFLOW);

    /* A datagram that fits is delivered normally. */
    uint8_t small[3] = { 1, 2, 3 };
    WR_TEST_EQ_U64(wr_io_send(io, &local, wr_span_c_make(small, 3), &sent),
                   WR_OK);
    WR_TEST_EQ_U64(wr_io_wait(io, 100u, &ready), WR_OK);
    WR_TEST_CHECK(ready);
    WR_TEST_EQ_U64(wr_io_recv(io, NULL, wr_span_make(buf, sizeof(buf)), &data),
                   WR_OK);
    WR_TEST_EQ_U64(data.len, 3u);
    WR_TEST_EQ_U64(memcmp(data.ptr, small, 3), 0);

    wr_io_destroy(io);
}

static void test_rtp_streams(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_rtp_stream_table *t = wr_rtp_stream_table_create(a, 8u);
    WR_TEST_CHECK(t != NULL);
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = 2;
    h.pt = 96;
    h.ssrc = 7u;
    for (uint16_t i = 0; i < 5; ++i) {
        h.seq = i;
        wr_rtp_stream *s = wr_rtp_stream_get_or_create(t, h.ssrc);
        WR_TEST_CHECK(s != NULL);
        if (!s) continue;
        wr_rtp_stream_update(s, &h, 1200u, i);
    }
    wr_rtp_stream *s = wr_rtp_stream_find(t, 7u);
    WR_TEST_CHECK(s != NULL);
    if (s) {
        WR_TEST_EQ_U64(s->packets, 5u);
        WR_TEST_EQ_U64(s->bytes, 6000u);
        WR_TEST_EQ_U64(s->seq, 4u);
        WR_TEST_EQ_U64(s->cycles, 0u);
    }
    h.seq = 65535u;
    if (s) {
        s->seq = 65535u;
        s->packets = 1u;
        s->cycles = 0u;
        wr_rtp_stream_update(s, &h, 1200u, 99);
    }
    h.seq = 0u;
    if (s) wr_rtp_stream_update(s, &h, 1200u, 100);
    WR_TEST_EQ_U64(s->cycles, 1u);
    WR_TEST_CHECK(wr_rtp_stream_remove(t, 7u));
    WR_TEST_CHECK(wr_rtp_stream_find(t, 7u) == NULL);
    wr_arena_destroy(a);
}

static void test_tsn_set(void)
{
    wr_tsn_set s;
    wr_tsn_set_init(&s, 100u);
    WR_TEST_CHECK(!wr_tsn_set_has(&s, 101u));
    WR_TEST_CHECK(wr_tsn_set_add(&s, 103u));
    WR_TEST_CHECK(wr_tsn_set_add(&s, 102u));
    WR_TEST_CHECK(wr_tsn_set_add(&s, 101u));
    WR_TEST_CHECK(!wr_tsn_set_add(&s, 101u)); /* duplicate */
    WR_TEST_CHECK(!wr_tsn_set_add(&s, 100u)); /* consumed */

    uint32_t tsn = 0u;
    WR_TEST_CHECK(wr_tsn_set_pop_next(&s, &tsn));
    WR_TEST_EQ_U64(tsn, 101u);
    WR_TEST_CHECK(wr_tsn_set_pop_next(&s, &tsn));
    WR_TEST_EQ_U64(tsn, 102u);
    WR_TEST_CHECK(wr_tsn_set_pop_next(&s, &tsn));
    WR_TEST_EQ_U64(tsn, 103u);
    WR_TEST_CHECK(!wr_tsn_set_pop_next(&s, &tsn));
    WR_TEST_EQ_U64(s.cum, 103u);
}

void test_data(void)
{
    test_hash();
    test_u64_map();
    test_str_map();
    test_pool();
    test_io_datagram();
    test_rtp_streams();
    test_tsn_set();
}