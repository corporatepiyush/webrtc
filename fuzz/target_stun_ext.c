#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/net.h"
#include "wr/stun.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    if (!a) {
        return 0;
    }

    /* Strict mode must be safe on the same arbitrary bytes. */
    wr_stun_msg strict;
    (void)wr_stun_parse(a, wr_span_c_make(data, size), WR_STUN_STRICT, &strict);

    /* 1. Parser / verifier / serializer round trip on arbitrary input. */
    wr_stun_msg m;
    if (wr_stun_parse(a, wr_span_c_make(data, size), WR_STUN_LIBERAL, &m) ==
        WR_OK) {
        static const uint8_t key[16] = { 0 };
        (void)wr_stun_verify_fingerprint(&m);
        (void)wr_stun_verify_integrity(&m, key, sizeof(key));
        (void)wr_stun_attr_find(&m, WR_STUN_ATTR_USERNAME);
        (void)wr_stun_attr_find(&m, WR_STUN_ATTR_XOR_MAPPED_ADDRESS);

        char buf[4096];
        size_t n = 0;
        if (wr_stun_serialize(&m, buf, sizeof(buf), &n) == WR_OK) {
            wr_stun_msg m2;
            if (wr_stun_parse(a, wr_span_c_make(buf, n), WR_STUN_LIBERAL,
                              &m2) == WR_OK) {
                if (m2.type != m.type ||
                    memcmp(m2.txid, m.txid, sizeof(m2.txid)) != 0 ||
                    m2.attr.len != m.attr.len) {
                    __builtin_trap();
                }
            }
        }
        wr_stun_method method = WR_STUN_METHOD_BINDING;
        wr_stun_class cls = WR_STUN_CLASS_REQUEST;
        wr_stun_type_decode(m.type, &method, &cls);
        (void)method;
        (void)cls;
        (void)wr_stun_is_response(m.type);
    }

    /* 2. Structured build with a fuzz-chosen attribute mix. */
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    wr_stun_msg b;
    uint8_t txid[12];
    for (size_t i = 0; i < sizeof(txid); ++i) {
        txid[i] = wr_fuzz_stream_u8(&fs);
    }
    wr_stun_msg_init(&b, a, wr_stun_type(WR_STUN_METHOD_BINDING,
                                         WR_STUN_CLASS_REQUEST),
                     txid);
    uint8_t vbuf[64];
    for (int i = 0; i < 8; ++i) {
        uint16_t type = (uint16_t)(wr_fuzz_stream_next(&fs) | 1u);
        size_t vlen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(vbuf));
        for (size_t k = 0; k < vlen; ++k) {
            vbuf[k] = wr_fuzz_stream_u8(&fs);
        }
        (void)wr_stun_attr_add(&b, type, wr_span_c_make(vbuf, vlen));
    }

    static const uint8_t key[16] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
                                     1, 2, 3, 4, 5, 6 };
    char out[4096];
    size_t out_n = 0;
    if (wr_stun_append_integrity(&b, key, sizeof(key), out, sizeof(out),
                                 &out_n) == WR_OK) {
        wr_stun_msg parsed;
        if (wr_stun_parse(a, wr_span_c_make(out, out_n), WR_STUN_LIBERAL,
                          &parsed) == WR_OK) {
            (void)wr_stun_verify_integrity(&parsed, key, sizeof(key));
        }
    }
    if (wr_stun_append_fingerprint(&b, out, sizeof(out), &out_n) == WR_OK) {
        wr_stun_msg parsed;
        if (wr_stun_parse(a, wr_span_c_make(out, out_n), WR_STUN_LIBERAL,
                          &parsed) == WR_OK) {
            (void)wr_stun_verify_fingerprint(&parsed);
        }
    }

    /* 3. Address codec round trip for fuzzed endpoints. */
    wr_endpoint ep;
    wr_endpoint_loopback(&ep, (uint16_t)wr_fuzz_stream_next(&fs));
    if (wr_fuzz_stream_bool(&fs)) {
        uint8_t v6[16];
        for (size_t i = 0; i < sizeof(v6); ++i) {
            v6[i] = wr_fuzz_stream_u8(&fs);
        }
        wr_endpoint_v6(&ep, v6, 0u, ep.port);
    }
    uint8_t abuf[20];
    size_t alen = 0;
    for (int x = 0; x < 2; ++x) {
        if (!wr_stun_addr_encode(abuf, sizeof(abuf), &ep, x != 0, txid,
                                 &alen)) {
            continue;
        }
        wr_endpoint back;
        if (wr_stun_addr_decode(wr_span_c_make(abuf, alen), x != 0, txid,
                                &back)) {
            if (!wr_endpoint_eq(&ep, &back)) {
                __builtin_trap();
            }
        }
        /* Truncated decodes must not read out of bounds. */
        for (size_t cut = 0; cut < alen; ++cut) {
            (void)wr_stun_addr_decode(wr_span_c_make(abuf, cut), x != 0,
                                      txid, &back);
        }
    }

    /* 4. ChannelData framing round trip. */
    uint16_t num = 0;
    wr_span_c cdata;
    if (wr_turn_channel_parse(wr_span_c_make(data, size), &num, &cdata) ==
        WR_OK) {
        char cbuf[2048];
        size_t cn = 0;
        if (wr_turn_channel_serialize(cbuf, sizeof(cbuf), num, cdata, &cn) ==
            WR_OK) {
            uint16_t n2 = 0;
            wr_span_c d2;
            if (wr_turn_channel_parse(wr_span_c_make(cbuf, cn), &n2, &d2) ==
                    WR_OK &&
                (n2 != num || !wr_span_c_eq(d2, cdata))) {
                __builtin_trap();
            }
        }
    }

    /* 5. Binding request construction with fuzzed fields. */
    wr_stun_msg req;
    wr_stun_msg_init(&req, a, wr_stun_type(WR_STUN_METHOD_BINDING,
                                           WR_STUN_CLASS_REQUEST),
                     txid);
    (void)wr_stun_build_binding_request(
        &req, a, wr_fuzz_stream_next(&fs), wr_fuzz_stream_next(&fs),
        wr_span_c_make(data, size < 32u ? size : 32u),
        wr_fuzz_stream_next(&fs), wr_fuzz_stream_bool(&fs),
        wr_fuzz_stream_bool(&fs));
    /* Serialize after the builder returned: attribute values must not point
     * into the builder's dead stack frame. */
    char reqbuf[1024];
    size_t reqn = 0;
    if (wr_stun_serialize(&req, reqbuf, sizeof(reqbuf), &reqn) == WR_OK) {
        wr_stun_msg parsed_req;
        if (wr_stun_parse(a, wr_span_c_make(reqbuf, reqn), WR_STUN_LIBERAL,
                          &parsed_req) == WR_OK) {
            const wr_stun_attr *pri =
                wr_stun_attr_find(&parsed_req, WR_STUN_ATTR_PRIORITY);
            if (pri && pri->value.len != 4u) {
                __builtin_trap();
            }
            const wr_stun_attr *tie = wr_stun_attr_find(
                &parsed_req, WR_STUN_ATTR_ICE_CONTROLLING);
            if (!tie) {
                tie = wr_stun_attr_find(&parsed_req,
                                        WR_STUN_ATTR_ICE_CONTROLLED);
            }
            if (tie && tie->value.len != 8u) {
                __builtin_trap();
            }
        }
    }

    wr_arena_destroy(a);
    return 0;
}