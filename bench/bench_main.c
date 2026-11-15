#define _POSIX_C_SOURCE 200809L

#include "wr/arena.h"
#include "wr/crc32.h"
#include "wr/crc32c.h"
#include "wr/dtls.h"
#include "wr/hash.h"
#include "wr/map.h"
#include "wr/pool.h"
#include "wr/rtp_stream.h"
#include "wr/rtp.h"
#include "wr/sctp.h"
#include "wr/sdp.h"
#include "wr/srtp.h"
#include "wr/stun.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef struct {
    const char *name;
    uint64_t iters;
    uint64_t ns;
    size_t bytes;
    uint64_t allocs; /* arena bump allocations during the timed loop */
} bench_result;

static bench_result results[32];
static size_t result_count;

static void report(const char *name, uint64_t iters, uint64_t ns, size_t bytes,
                   uint64_t allocs)
{
    bench_result *r = &results[result_count++];
    r->name = name;
    r->iters = iters ? iters : 1u;
    r->ns = ns;
    r->bytes = bytes;
    r->allocs = allocs;
    double nsop = (double)ns / (double)r->iters;
    double mbps = bytes ? ((double)bytes * (double)r->iters) *
                              1000.0 / (double)ns : 0.0;
    /* Arena bump allocations per operation. This does not count allocations
     * inside OpenSSL/FFmpeg, which are outside the library's arenas. */
    double allocsop = (double)allocs / (double)r->iters;
    printf("%-28s %10.1f ns/op %10.2f MB/s  iters=%llu arena_allocs/op=%.2f\n",
           name, nsop, mbps, (unsigned long long)r->iters, allocsop);
}

static void bench_srtp(void)
{
    enum { N = 200000 };
    uint8_t key[16], salt[14];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 14; ++i) salt[i] = (uint8_t)(0xa0 + i);

    wr_srtp_ctx ctx;
    if (wr_srtp_init(&ctx, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt,
                     0x12345678u) != WR_OK) {
        printf("srtp init failed\n");
        return;
    }

    uint8_t payload[1200];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = 2;
    h.pt = 96;
    h.seq = 1;
    h.timestamp = 1000;
    h.ssrc = 0x12345678u;
    char pkt[1300];
    size_t pkt_len = 0;
    if (wr_rtp_serialize(&h, wr_span_c_make(payload, sizeof(payload)),
                         pkt, sizeof(pkt), &pkt_len) != WR_OK) {
        printf("rtp serialize failed\n");
        return;
    }

    uint8_t out[1400];
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        h.seq = (uint16_t)i;
        pkt[2] = (char)(h.seq >> 8);
        pkt[3] = (char)(h.seq & 0xffu);
        if (wr_srtp_protect(&ctx, wr_span_c_make(pkt, pkt_len),
                            wr_span_make(out, sizeof(out))) != WR_OK) {
            printf("protect failed at %d\n", i);
            return;
        }
    }
    uint64_t t1 = now_ns();
    report("srtp_aes_cm_protect", N, t1 - t0, pkt_len + 10, 0);

    wr_srtp_ctx dctx;
    wr_srtp_init(&dctx, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt, 0x12345678u);
    uint8_t back[1400];
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        /* Reset replay state so the loop measures unprotect, not replay. */
        dctx.replay_valid = false;
        dctx.seq_valid = false;
        dctx.roc = 0;
        wr_span out_span = wr_span_make(back, sizeof(back));
        if (wr_srtp_unprotect(&dctx, wr_span_c_make(out, pkt_len + 10),
                              out_span) != WR_OK) {
            printf("unprotect failed at %d\n", i);
            return;
        }
    }
    t1 = now_ns();
    report("srtp_aes_cm_unprotect", N, t1 - t0, pkt_len + 10, 0);

    /* GCM */
    wr_srtp_ctx g;
    if (wr_srtp_init(&g, WR_SRTP_AES_GCM_128, key, salt,
                     0x12345678u) != WR_OK) {
        printf("gcm init failed\n");
        return;
    }
    uint8_t gout[1400];
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        h.seq = (uint16_t)i;
        pkt[2] = (char)(h.seq >> 8);
        pkt[3] = (char)(h.seq & 0xffu);
        if (wr_srtp_protect(&g, wr_span_c_make(pkt, pkt_len),
                            wr_span_make(gout, sizeof(gout))) != WR_OK) {
            printf("gcm protect failed\n");
            return;
        }
    }
    t1 = now_ns();
    report("srtp_aes_gcm_protect", N, t1 - t0, pkt_len + 16, 0);
    wr_srtp_fini(&ctx);
    wr_srtp_fini(&dctx);
    wr_srtp_fini(&g);
}

static void bench_rtp(void)
{
    enum { N = 1000000 };
    uint8_t payload[1172];
    memset(payload, 0x5a, sizeof(payload));
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = 2;
    h.pt = 96;
    h.seq = 7;
    h.timestamp = 123456;
    h.ssrc = 0xdeadbeefu;
    char pkt[1300];
    size_t pkt_len = 0;
    wr_rtp_serialize(&h, wr_span_c_make(payload, sizeof(payload)), pkt,
                     sizeof(pkt), &pkt_len);
    wr_span_c raw = wr_span_c_make(pkt, pkt_len);

    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        wr_rtp_hdr out;
        if (!wr_rtp_parse(raw, &out)) {
            printf("rtp parse failed\n");
            return;
        }
    }
    uint64_t t1 = now_ns();
    report("rtp_parse", N, t1 - t0, raw.len, 0);

    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        h.seq = (uint16_t)i;
        size_t n = 0;
        if (wr_rtp_serialize(&h, wr_span_c_make(payload, sizeof(payload)), pkt,
                             sizeof(pkt), &n) != WR_OK) {
            printf("rtp serialize failed\n");
            return;
        }
    }
    t1 = now_ns();
    report("rtp_serialize", N, t1 - t0, sizeof(payload), 0);
}

static void bench_stun(void)
{
    wr_arena *a = wr_arena_create(256u * 1024u);
    wr_stun_msg m;
    wr_status st = wr_stun_build_binding_request(&m, a, 0x1122334455667788ull,
                                                 0x99aabbccddeeff00ull,
                                                 wr_span_c_from_str("user:pass"),
                                                 0x6e0001ffu,
                                                 0x0f1e2d3c4b5a6978ull,
                                                 true, true);
    char buf[512];
    size_t n = 0;
    wr_status st2 = wr_stun_append_integrity(&m, (const uint8_t *)"password", 8,
                                             buf, sizeof(buf), &n);
    if (st != WR_OK || st2 != WR_OK) {
        printf("stun build failed st=%u st2=%u\n", st, st2);
        return;
    }

    enum { N = 500000 };
    uint64_t a0 = wr_arena_alloc_count(a);
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_stun_msg p;
        if (wr_stun_parse(a, wr_span_c_make(buf, n), WR_STUN_LIBERAL, &p) != WR_OK) {
            printf("stun parse failed\n");
            return;
        }
        wr_arena_mark_release(a, mk);
    }
    uint64_t t1 = now_ns();
    uint64_t a1 = wr_arena_alloc_count(a);
    report("stun_parse", N, t1 - t0, n, a1 - a0);

    a0 = wr_arena_alloc_count(a);
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_stun_msg p;
        wr_stun_parse(a, wr_span_c_make(buf, n), WR_STUN_LIBERAL, &p);
        (void)wr_stun_attr_find(&p, WR_STUN_ATTR_USERNAME);
        (void)wr_stun_attr_find(&p, WR_STUN_ATTR_ICE_CONTROLLING);
        (void)wr_stun_attr_find(&p, WR_STUN_ATTR_USE_CANDIDATE);
        wr_arena_mark_release(a, mk);
    }
    t1 = now_ns();
    a1 = wr_arena_alloc_count(a);
    report("stun_parse+attr_find", N, t1 - t0, n, a1 - a0);
    wr_arena_destroy(a);
}

static const char *kSdp =
    "v=0\r\n"
    "o=- 4611731400430051454 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0 1\r\n"
    "a=msid-semantic: WMS stream\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 103 104 105 106 107 108 109 110\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:abcd\r\n"
    "a=ice-pwd:abcdefghijklmnopqrstuvwx\r\n"
    "a=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:10:20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:00\r\n"
    "a=setup:actpass\r\n"
    "a=mid:0\r\n"
    "a=sendrecv\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=rtcp-fb:111 transport-cc\r\n"
    "a=candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host generation 0 ufrag abcd\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:abcd\r\n"
    "a=ice-pwd:abcdefghijklmnopqrstuvwx\r\n"
    "a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:10:20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:00\r\n"
    "a=setup:actpass\r\n"
    "a=mid:1\r\n"
    "a=sendrecv\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=rtpmap:97 VP9/90000\r\n"
    "a=rtpmap:98 H264/90000\r\n"
    "a=rtpmap:99 red/90000\r\n"
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
    "a=candidate:2 1 UDP 1686052607 192.0.2.2 5000 typ srflx raddr 192.0.2.1 rport 5000 generation 0\r\n";


static void bench_parse(void)
{
    enum { N = 1000000 };
    const char *text = "1234567890123456789";
    wr_span_c in = wr_span_c_from_str(text);
    uint64_t sink = 0;
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        uint64_t v = 0;
        if (!wr_parse_u64(in, &v)) {
            printf("parse failed\n");
            return;
        }
        sink ^= v;
    }
    uint64_t t1 = now_ns();
    report("parse_u64_19d", N, t1 - t0, in.len, 0);
    if (sink == 0xdeadbeefu) {
        printf("unexpected\n");
    }
}

static void bench_sdp(void)
{
    wr_arena *a = wr_arena_create(512u * 1024u);
    enum { N = 100000 };
    wr_span_c in = wr_span_c_from_str(kSdp);

    uint64_t a0 = wr_arena_alloc_count(a);
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_sdp_session s;
        wr_status ps = wr_sdp_parse(a, in, WR_SDP_STRICT, &s);
        if (ps != WR_OK) {
            printf("sdp parse failed st=%u\n", ps);
            return;
        }
        wr_arena_mark_release(a, mk);
    }
    uint64_t t1 = now_ns();
    uint64_t a1 = wr_arena_alloc_count(a);
    report("sdp_parse", N, t1 - t0, in.len, a1 - a0);

    wr_sdp_session s;
    wr_sdp_parse(a, in, WR_SDP_STRICT, &s);
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        (void)wr_sdp_find_media(&s, wr_span_c_from_str("1"));
    }
    t1 = now_ns();
    report("sdp_find_media", N, t1 - t0, 0, 0);

    char out[4096];
    size_t out_len = 0;
    if (wr_sdp_serialize(&s, out, sizeof(out), &out_len) != WR_OK) {
        printf("sdp serialize failed\n");
        wr_arena_destroy(a);
        return;
    }
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        (void)wr_sdp_serialize(&s, out, sizeof(out), &out_len);
    }
    t1 = now_ns();
    report("sdp_serialize", N, t1 - t0, out_len, 0);
    wr_arena_destroy(a);
}

static void bench_sctp(void)
{
    char body[256];
    size_t blen = 0;
    wr_sctp_data_body(42u, 3u, 7u, 54u, wr_span_c_from_str("hello sctp world"),
                      body, sizeof(body), &blen);
    char chunk[320];
    size_t clen = 0;
    wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u, wr_span_c_make(body, blen),
                            chunk, sizeof(chunk), &clen);
    wr_sctp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_port = 5000;
    pkt.dst_port = 6000;
    pkt.vtag = 0x11223344u;
    char raw[384];
    size_t raw_len = 0;
    wr_status ss = wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen), raw,
                                     sizeof(raw), &raw_len);
    if (ss != WR_OK) {
        printf("sctp serialize failed st=%u\n", ss);
        return;
    }

    wr_arena *a = wr_arena_create(64u * 1024u);
    enum { N = 300000 };
    uint64_t a0 = wr_arena_alloc_count(a);
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        wr_arena_mark mk = wr_arena_mark_save(a);
        wr_sctp_msg m;
        if (wr_sctp_parse(a, wr_span_c_make(raw, raw_len), &m) != WR_OK) {
            printf("sctp parse failed\n");
            return;
        }
        wr_arena_mark_release(a, mk);
    }
    uint64_t t1 = now_ns();
    uint64_t a1 = wr_arena_alloc_count(a);
    report("sctp_parse", N, t1 - t0, raw_len, a1 - a0);
    wr_arena_destroy(a);
}


static void bench_sctp_input(void)
{
    enum { N = 20000, CAP = 64 };
    static uint8_t raws[N][CAP];
    static size_t raw_len = 0u;

    wr_arena *a = wr_arena_create(4u * 1024u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 9);
    wr_sctp_assoc *as = wr_sctp_create(a, 1000u, 2000u, rng);
    if (!as) {
        printf("sctp input setup failed\n");
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    wr_sctp_start_established(as, 2000u, 1000u, 1000u);

    char body[256];
    size_t blen = 0;
    if (wr_sctp_data_body(1000u, 0u, 0u, 42u,
                          wr_span_c_from_str("hello sctp world"), body,
                          sizeof(body), &blen) != WR_OK) {
        printf("sctp input body failed\n");
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    char chunk[320];
    size_t clen = 0;
    if (wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                wr_span_c_make(body, blen), chunk,
                                sizeof(chunk), &clen) != WR_OK) {
        printf("sctp input chunk failed\n");
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }
    for (int i = 0; i < N; ++i) {
        wr_sctp_packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.src_port = 2000u;
        pkt.dst_port = 1000u;
        pkt.vtag = 2000u;
        wr_store_be32((uint8_t *)body, (uint32_t)(1000 + i));
        wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                wr_span_c_make(body, blen), chunk,
                                sizeof(chunk), &clen);
        if (wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen),
                              (char *)raws[i], CAP, &raw_len) != WR_OK ||
            raw_len > CAP) {
            printf("sctp input serialize failed\n");
            wr_rng_destroy(rng);
            wr_arena_destroy(a);
            return;
        }
    }

    uint64_t a0 = wr_arena_alloc_count(a);
    uint64_t t0 = now_ns();
    uint64_t sink = 0u;
    for (int i = 0; i < N; ++i) {
        if (wr_sctp_input(as, (uint64_t)i, NULL,
                          wr_span_c_make(raws[i], raw_len)) != WR_OK) {
            printf("sctp input failed at %d\n", i);
            break;
        }
        wr_sctp_delivery d;
        while (wr_sctp_recv(as, &d)) {
            sink += d.data.len;
        }
    }
    uint64_t t1 = now_ns();
    uint64_t a1 = wr_arena_alloc_count(a);
    report("sctp_input_data", N, t1 - t0, raw_len, a1 - a0);
    if (sink == 0u) {
        printf("sctp input sink empty\n");
    }
    wr_sctp_close(as);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

static void bench_data(void)
{
    enum { N = 1000000 };
    static uint8_t buf[64];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)i;
    uint64_t sink = 0;
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        buf[0] = (uint8_t)i;
        sink ^= wr_hash64(buf, sizeof(buf), 0u);
    }
    uint64_t t1 = now_ns();
    report("hash64_64B", N, t1 - t0, sizeof(buf), 0);

    /* Large enough that 100k inserts plus growth copies fit. A smaller arena
     * silently stopped after ~11k inserts and turned "hit" lookups into
     * mostly misses. */
    wr_arena *a = wr_arena_create(64u * 1024u * 1024u);
    wr_u64_map m;
    wr_u64_map_init(&m, a, 131072u);
    uint64_t a0 = wr_arena_alloc_count(a);
    uint32_t put_ok = 0u;
    t0 = now_ns();
    for (uint32_t i = 0; i < 100000u; ++i) {
        if (wr_u64_map_put(&m, i * 2654435761u, i)) {
            put_ok++;
        }
    }
    t1 = now_ns();
    uint64_t a1 = wr_arena_alloc_count(a);
    report("u64_map_put", 100000u, t1 - t0, 0, a1 - a0);
    if (put_ok != 100000u) {
        printf("u64_map_put: only %u/100000 succeeded\n", put_ok);
    }
    uint32_t hit = 0u;
    t0 = now_ns();
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t *v = wr_u64_map_find(&m, i * 2654435761u);
        if (v) {
            hit++;
            sink += *v;
        }
    }
    t1 = now_ns();
    report("u64_map_find_hit", 100000u, t1 - t0, 0, 0);
    if (hit != 100000u) {
        printf("u64_map_find_hit: only %u/100000 found\n", hit);
    }

    wr_str_map sm;
    wr_str_map_init(&sm, a, 131072u);
    char key[32];
    a0 = wr_arena_alloc_count(a);
    put_ok = 0u;
    t0 = now_ns();
    for (uint32_t i = 0; i < 100000u; ++i) {
        snprintf(key, sizeof(key), "mid-%u", i);
        if (wr_str_map_put(&sm, wr_span_c_from_str(key), i)) {
            put_ok++;
        }
    }
    t1 = now_ns();
    a1 = wr_arena_alloc_count(a);
    report("str_map_put", 100000u, t1 - t0, 0, a1 - a0);
    if (put_ok != 100000u) {
        printf("str_map_put: only %u/100000 succeeded\n", put_ok);
    }
    hit = 0u;
    t0 = now_ns();
    for (uint32_t i = 0; i < 100000u; ++i) {
        snprintf(key, sizeof(key), "mid-%u", i);
        uint32_t *v = wr_str_map_find(&sm, wr_span_c_from_str(key));
        if (v) {
            hit++;
            sink += *v;
        }
    }
    t1 = now_ns();
    report("str_map_find_hit", 100000u, t1 - t0, 0, 0);
    if (hit != 100000u) {
        printf("str_map_find_hit: only %u/100000 found\n", hit);
    }

    wr_pool p;
    wr_pool_init(&p, a, 4096u, 128u, 64u);
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        void *o = wr_pool_alloc(&p);
        wr_pool_free(&p, o);
    }
    t1 = now_ns();
    report("pool_alloc_free", N, t1 - t0, 0, 0);

    wr_rtp_stream_table *st = wr_rtp_stream_table_create(a, 1024u);
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = 2;
    h.pt = 96;
    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        h.ssrc = (uint32_t)(i & 1023u);
        h.seq = (uint16_t)i;
        wr_rtp_stream *ss = wr_rtp_stream_get_or_create(st, h.ssrc);
        if (ss) wr_rtp_stream_update(ss, &h, 1200u, (uint64_t)i);
    }
    t1 = now_ns();
    report("rtp_stream_get_update", N, t1 - t0, 0, 0);

    /* Keep sink observable. */
    if (sink == 0xdeadbeefu) {
        printf("unexpected\n");
    }
    wr_arena_destroy(a);
}


static void bench_dtls(void)
{
    enum { N = 200000 };
    wr_dtls_cipher c;
    memset(&c, 0, sizeof(c));
    for (int i = 0; i < 16; ++i) c.key[i] = (uint8_t)i;
    for (int i = 0; i < 4; ++i) c.salt[i] = (uint8_t)(0x20 + i);
    if (!wr_dtls_cipher_init(&c)) {
        printf("dtls cipher init failed\n");
        return;
    }
    uint8_t seq[6] = { 0 };
    uint8_t plain[1200];
    memset(plain, 0x5a, sizeof(plain));
    uint8_t rec[1300];
    uint8_t back[1200];
    size_t n = 0u;
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        seq[5] = (uint8_t)i;
        seq[4] = (uint8_t)(i >> 8);
        if (wr_dtls_encrypt(&c, WR_DTLS_APPDATA, 1u, seq,
                            wr_span_c_make(plain, sizeof(plain)),
                            (char *)rec, sizeof(rec), &n) != WR_OK) {
            printf("dtls encrypt failed\n");
            return;
        }
    }
    uint64_t t1 = now_ns();
    report("dtls_encrypt_1200B", N, t1 - t0, sizeof(plain), 0);

    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        seq[5] = (uint8_t)i;
        seq[4] = (uint8_t)(i >> 8);
        wr_span out = wr_span_make(back, sizeof(back));
        wr_dtls_record meta;
        if (wr_dtls_decrypt(&c, wr_span_c_make(rec, n), &out, &meta) != WR_OK) {
            printf("dtls decrypt failed\n");
            return;
        }
    }
    t1 = now_ns();
    report("dtls_decrypt_1200B", N, t1 - t0, sizeof(plain), 0);
    wr_dtls_cipher_free(&c);
}


static void bench_crc(void)
{
    enum { N = 500000, LEN = 1200 };
    uint8_t buf[LEN];
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = (uint8_t)(i * 31u + 7u);
    uint32_t sink = 0;
    uint64_t t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        buf[0] = (uint8_t)i;
        sink ^= wr_crc32c(0u, buf, sizeof(buf));
    }
    uint64_t t1 = now_ns();
    report("crc32c_1200B", N, t1 - t0, sizeof(buf), 0);

    t0 = now_ns();
    for (int i = 0; i < N; ++i) {
        buf[0] = (uint8_t)i;
        sink ^= wr_crc32(0u, buf, sizeof(buf));
    }
    t1 = now_ns();
    report("crc32_1200B", N, t1 - t0, sizeof(buf), 0);
    if (sink == 0xdeadbeefu) {
        printf("unexpected crc\n");
    }
    printf("crc32c_hw=%u\n", wr_crc32c_hw_available());
}

int main(void)
{
    printf("== WebRTC protocol core benchmark ==\n");
    bench_srtp();
    bench_rtp();
    bench_stun();
    bench_sdp();
    bench_parse();
    bench_sctp();
    bench_sctp_input();
    bench_data();
    bench_dtls();
    bench_crc();
    return 0;
}