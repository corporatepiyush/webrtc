#include "test_util.h"

#include "wr/arena.h"
#include "wr/sdp.h"

static const char *kOffer =
    "v=0\r\n"
    "o=- 4611731400430051454 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0 1\r\n"
    "a=msid-semantic: WMS stream\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:abcd\r\n"
    "a=ice-pwd:abcdefghijklmnopqrstuvwx\r\n"
    "a=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 "
    "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:"
    "10:20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:00\r\n"
    "a=setup:actpass\r\n"
    "a=mid:0\r\n"
    "a=sendrecv\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=rtcp-fb:111 transport-cc\r\n"
    "a=candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host "
    "generation 0 ufrag abcd\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:abcd\r\n"
    "a=ice-pwd:abcdefghijklmnopqrstuvwx\r\n"
    "a=fingerprint:sha-256 "
    "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:"
    "10:20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:00\r\n"
    "a=setup:actpass\r\n"
    "a=mid:1\r\n"
    "a=sendrecv\r\n"
    "a=rtcp-mux\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
    "a=candidate:2 1 UDP 1686052607 192.0.2.2 5000 typ srflx "
    "raddr 192.0.2.1 rport 5000 generation 0\r\n";

static void test_parse_fields(void)
{
    wr_arena *a = wr_arena_create(64 * 1024);
    wr_sdp_session s;
    wr_status st = wr_sdp_parse(a, wr_span_c_from_str(kOffer),
                                WR_SDP_STRICT, &s);
    WR_TEST_EQ_U64(st, WR_OK);
    if (st != WR_OK) {
        return;
    }
    WR_TEST_EQ_U64(s.media.len, 2);
    WR_TEST_EQ_U64(s.attr.len, 2);
    WR_TEST_EQ_U64(s.media.data[0].port, 9);
    WR_TEST_EQ_U64(s.media.data[0].fmt.len, 2);
    WR_TEST_EQ_U64(s.media.data[0].fmt.data[0].len, 3);
    WR_TEST_EQ_U64(s.media.data[0].fmt.data[0].ptr[0], '1');
    WR_TEST_EQ_U64(s.media.data[1].fmt.len, 1);
    WR_TEST_EQ_U64(s.media.data[1].fmt.data[0].ptr[0], '9');

    wr_sdp_ice ice;
    WR_TEST_EQ_U64(wr_sdp_ice_parse(&s, &s.media.data[0], &ice), WR_OK);
    WR_TEST_CHECK(ice.present);
    WR_TEST_CHECK(ice.ufrag.len == 4);
    WR_TEST_CHECK(ice.pwd.len == 24);
    WR_TEST_CHECK(ice.ice_lite == false);
    WR_TEST_CHECK(ice.end_of_candidates == false);

    const wr_sdp_attr *fp = wr_sdp_attr_find(&s.media.data[0].attr,
                                             wr_span_c_from_str("fingerprint"));
    WR_TEST_CHECK(fp != NULL);
    if (!fp) {
        wr_arena_destroy(a);
        return;
    }
    wr_sdp_fingerprint f;
    WR_TEST_CHECK(wr_sdp_fingerprint_parse(fp->value, &f));
    WR_TEST_EQ_U64(f.len, 32);
    WR_TEST_EQ_U64(f.value[0], 0x00);
    WR_TEST_EQ_U64(f.value[1], 0x11);
    WR_TEST_EQ_U64(f.value[31], 0x00);

    const wr_sdp_attr *setup = wr_sdp_attr_find(&s.media.data[0].attr,
                                                wr_span_c_from_str("setup"));
    WR_TEST_EQ_U64(wr_sdp_setup_parse(setup->value), WR_SDP_SETUP_ACTPASS);
    WR_TEST_EQ_STR(wr_sdp_setup_str(WR_SDP_SETUP_ACTPASS), "actpass");

    const wr_sdp_attr *cand = wr_sdp_attr_find(&s.media.data[0].attr,
                                               wr_span_c_from_str("candidate"));
    WR_TEST_CHECK(cand != NULL);
    if (!cand) {
        wr_arena_destroy(a);
        return;
    }
    wr_sdp_candidate c;
    WR_TEST_CHECK(wr_sdp_candidate_parse(cand->value, &c));
    WR_TEST_EQ_U64(c.component, 1);
    WR_TEST_EQ_U64(c.priority, 2122260223u);
    WR_TEST_EQ_U64(c.addr.port, 5000);
    WR_TEST_EQ_U64(c.type, WR_SDP_CAND_HOST);
    WR_TEST_EQ_U64(c.has_raddr, false);

    const wr_sdp_attr *cand2 = wr_sdp_attr_find(&s.media.data[1].attr,
                                                wr_span_c_from_str("candidate"));
    WR_TEST_CHECK(cand2 != NULL);
    if (cand2) {
        WR_TEST_CHECK(wr_sdp_candidate_parse(cand2->value, &c));
    }
    WR_TEST_EQ_U64(c.type, WR_SDP_CAND_SRFLX);
    WR_TEST_EQ_U64(c.has_raddr, true);
    WR_TEST_EQ_U64(c.raddr.port, 5000);

    wr_arena_destroy(a);
}

static void test_roundtrip(void)
{
    wr_arena *a = wr_arena_create(64 * 1024);
    wr_sdp_session s1, s2;
    WR_TEST_EQ_U64(wr_sdp_parse(a, wr_span_c_from_str(kOffer),
                                WR_SDP_STRICT, &s1), WR_OK);

    char buf[8192];
    size_t n = 0;
    WR_TEST_EQ_U64(wr_sdp_serialize(&s1, buf, sizeof(buf), &n), WR_OK);
    WR_TEST_CHECK(n < sizeof(buf));

    wr_arena_mark m = wr_arena_mark_save(a);
    WR_TEST_EQ_U64(wr_sdp_parse(a, wr_span_c_make(buf, n),
                                WR_SDP_STRICT, &s2), WR_OK);

    char buf2[8192];
    size_t n2 = 0;
    WR_TEST_EQ_U64(wr_sdp_serialize(&s2, buf2, sizeof(buf2), &n2), WR_OK);
    WR_TEST_EQ_U64(n, n2);
    WR_TEST_EQ_U64(memcmp(buf, buf2, n), 0);
    wr_arena_mark_release(a, m);
    wr_arena_destroy(a);
}

static void test_errors(void)
{
    wr_arena *a = wr_arena_create(64 * 1024);
    wr_sdp_session s;
    WR_TEST_CHECK(wr_sdp_parse(a, wr_span_c_from_str("v=0\r\n"), WR_SDP_STRICT,
                               &s) == WR_ERR_INVAL);
    WR_TEST_CHECK(wr_sdp_parse(a, wr_span_c_from_str("v=1\r\n"), WR_SDP_STRICT,
                               &s) == WR_ERR_INVAL);
    WR_TEST_CHECK(wr_sdp_parse(a, wr_span_c_from_str("garbage"),
                               WR_SDP_STRICT, &s) == WR_ERR_INVAL);
    WR_TEST_CHECK(wr_sdp_parse(a, wr_span_c_from_str("v=0\n"),
                               WR_SDP_LIBERAL, &s) == WR_ERR_INVAL);

    const char *bad_media =
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
        "m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n";
    WR_TEST_EQ_U64(wr_sdp_parse(a, wr_span_c_from_str(bad_media),
                                WR_SDP_STRICT, &s), WR_OK);
    WR_TEST_EQ_U64(s.media.data[0].port, 0);
    WR_TEST_EQ_U64(s.media.data[0].port_count, 1);

    const char *bad_port =
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
        "m=audio x UDP/TLS/RTP/SAVPF 111\r\n";
    WR_TEST_CHECK(wr_sdp_parse(a, wr_span_c_from_str(bad_port),
                               WR_SDP_STRICT, &s) == WR_ERR_INVAL);
    wr_arena_destroy(a);
}

void test_sdp(void)
{
    test_parse_fields();
    test_roundtrip();
    test_errors();
}