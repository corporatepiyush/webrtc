#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/sdp.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void exercise_helpers(const wr_sdp_session *s)
{
    if (!s) {
        return;
    }
    wr_sdp_ice ice;
    (void)wr_sdp_ice_parse(s, NULL, &ice);
    (void)wr_sdp_find_media(s, wr_span_c_from_str("0"));
    (void)wr_sdp_find_media_by_type(s, wr_span_c_from_str("audio"));
    (void)wr_sdp_find_media_by_type(s, wr_span_c_from_str("video"));
    (void)wr_sdp_find_media_by_type(s, wr_span_c_from_str("application"));

    static const char *setups[] = { "active", "passive", "actpass",
                                    "holdconn", "garbage" };
    for (size_t i = 0; i < WR_ARRAY_LEN(setups); ++i) {
        wr_sdp_setup st = wr_sdp_setup_parse(
            wr_span_c_from_str(setups[i]));
        (void)wr_sdp_setup_str(st);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(192u * 1024u);
    if (!a) {
        return 0;
    }
    wr_sdp_session s;
    if (wr_sdp_parse(a, wr_span_c_make(data, size), WR_SDP_LIBERAL, &s) ==
        WR_OK) {
        size_t n = 0;
        (void)wr_sdp_serialize(&s, NULL, 0, &n);
        if (n > 0u && n < 512u * 1024u) {
            char *buf = (char *)malloc(n + 1u);
            if (buf) {
                if (wr_sdp_serialize(&s, buf, n + 1u, &n) == WR_OK) {
                    wr_sdp_session s2;
                    wr_arena *a2 = wr_arena_create(192u * 1024u);
                    if (a2 &&
                        wr_sdp_parse(a2, wr_span_c_make(buf, n),
                                     WR_SDP_LIBERAL, &s2) != WR_OK) {
                        __builtin_trap();
                    }
                    wr_arena_destroy(a2);
                }
                free(buf);
            }
        }

        exercise_helpers(&s);

        /* Attribute mutation must preserve find semantics and keep the
         * serializer/parser round trip stable. */
        static const wr_span_c names[] = {
            { (const uint8_t *)"mid", 3 },
            { (const uint8_t *)"ice-ufrag", 9 },
            { (const uint8_t *)"ice-pwd", 7 },
            { (const uint8_t *)"fingerprint", 11 },
            { (const uint8_t *)"setup", 5 },
            { (const uint8_t *)"candidate", 9 },
            { (const uint8_t *)"extmap", 6 },
            { (const uint8_t *)"rtcp-fb", 7 },
        };
        size_t pos = 0u;
        for (size_t i = 0; i < 8u && pos < size; ++i) {
            const wr_span_c name = names[i % WR_ARRAY_LEN(names)];
            wr_span_c value = wr_fuzz_slice(data, size, &pos, 32u);
            if (wr_sdp_attr_set(&s.attr, name, value)) {
                const wr_sdp_attr *got = wr_sdp_attr_find(&s.attr, name);
                if (!got || !wr_span_c_eq(got->value, value)) {
                    __builtin_trap();
                }
            }
            (void)wr_sdp_attr_add(&s.attr, name, value);
        }

        wr_sdp_ice ice;
        for (size_t m = 0; m < s.media.len; ++m) {
            wr_sdp_media *md = &s.media.data[m];
            (void)wr_sdp_ice_parse(&s, md, &ice);
            (void)wr_sdp_media_has_attr(md, wr_span_c_from_str("mid"));
            wr_sdp_candidate cand;
            (void)wr_sdp_candidate_parse(
                wr_span_c_from_str(
                    "1 1 udp 2122260223 192.0.2.1 3478 typ host"),
                &cand);
            wr_sdp_fingerprint fp;
            (void)wr_sdp_fingerprint_parse(
                wr_span_c_from_str(
                    "sha-256 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:"
                    "ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:"
                    "ee:ff"),
                &fp);
            wr_sdp_extmap em;
            (void)wr_sdp_extmap_parse(
                wr_span_c_from_str("3 http://example.com/ext"), &em);
            wr_sdp_rtcp_fb fb;
            (void)wr_sdp_rtcp_fb_parse(
                wr_span_c_from_str("96 nack pli"), &fb);
        }
    }
    wr_sdp_session strict;
    (void)wr_sdp_parse(a, wr_span_c_make(data, size), WR_SDP_STRICT, &strict);
    wr_arena_destroy(a);
    return 0;
}