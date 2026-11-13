#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/sctp.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    if (!a) {
        return 0;
    }
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);

    /* 1. Chunk body builders + chunk serialization + packet round trip. */
    uint8_t body[256];
    size_t blen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(body));
    for (size_t i = 0; i < blen; ++i) {
        body[i] = wr_fuzz_stream_u8(&fs);
    }

    char cbuf[512];
    size_t cn = 0;
    uint8_t ctype = (uint8_t)(WR_SCTP_DATA + wr_fuzz_stream_below(&fs, 12u));
    if (ctype == WR_SCTP_FORWARD_TSN) {
        ctype = WR_SCTP_DATA;
    }
    uint8_t cflags = wr_fuzz_stream_u8(&fs);
    if (wr_sctp_chunk_serialize(ctype, cflags, wr_span_c_make(body, blen),
                                cbuf, sizeof(cbuf), &cn) == WR_OK) {
        wr_sctp_packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.src_port = 1000u;
        pkt.dst_port = 2000u;
        pkt.vtag = 0x1000u;
        char raw[1024];
        size_t raw_n = 0;
        if (wr_sctp_serialize(&pkt, wr_span_c_make(cbuf, cn), raw,
                              sizeof(raw), &raw_n) == WR_OK) {
            wr_sctp_msg m;
            if (wr_sctp_parse(a, wr_span_c_make(raw, raw_n), &m) != WR_OK) {
                __builtin_trap();
            }
            if (m.chunks.len != 1u || m.chunks.data[0].type != ctype ||
                m.chunks.data[0].flags != cflags ||
                m.chunks.data[0].len != 4u + blen ||
                !wr_span_c_eq(m.chunks.data[0].body,
                              wr_span_c_make(body, blen))) {
                __builtin_trap();
            }
        }
    }

    /* 2. DATA body round trip. */
    {
        uint32_t tsn = (uint32_t)wr_fuzz_stream_next(&fs);
        uint16_t stream = (uint16_t)wr_fuzz_stream_next(&fs);
        uint16_t seq = (uint16_t)wr_fuzz_stream_next(&fs);
        uint32_t ppid = (uint32_t)wr_fuzz_stream_next(&fs);
        char dbody[512];
        size_t dn = 0;
        if (wr_sctp_data_body(tsn, stream, seq, ppid,
                              wr_span_c_make(body, blen), dbody,
                              sizeof(dbody), &dn) == WR_OK) {
            char dchunk[576];
            size_t dcn = 0;
            if (wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                        wr_span_c_make(dbody, dn), dchunk,
                                        sizeof(dchunk), &dcn) == WR_OK) {
                wr_sctp_packet pkt = { 1000u, 2000u, 0x1000u, 0u, 12u, 0u };
                char raw[640];
                size_t raw_n = 0;
                if (wr_sctp_serialize(&pkt, wr_span_c_make(dchunk, dcn),
                                      raw, sizeof(raw), &raw_n) == WR_OK) {
                    wr_sctp_msg m;
                    if (wr_sctp_parse(a, wr_span_c_make(raw, raw_n), &m) !=
                            WR_OK ||
                        m.chunks.len != 1u) {
                        __builtin_trap();
                    }
                }
            }
        }
    }

    /* 3. SACK body with random gap/dup arrays. */
    {
        uint32_t gaps[16];
        uint32_t dups[8];
        size_t ngaps = wr_fuzz_stream_below(&fs, 9u);
        size_t ndups = wr_fuzz_stream_below(&fs, 9u);
        for (size_t i = 0; i < ngaps; ++i) {
            gaps[2u * i] = 1u + (uint32_t)wr_fuzz_stream_below(&fs, 16u);
            gaps[2u * i + 1u] = gaps[2u * i] +
                                (uint32_t)wr_fuzz_stream_below(&fs, 4u);
        }
        for (size_t i = 0; i < ndups; ++i) {
            dups[i] = (uint32_t)wr_fuzz_stream_next(&fs);
        }
        char sbuf[256];
        size_t sn = 0;
        if (wr_sctp_sack_body((uint32_t)wr_fuzz_stream_next(&fs),
                              (uint32_t)wr_fuzz_stream_next(&fs), gaps, ngaps,
                              dups, ndups, sbuf, sizeof(sbuf), &sn) == WR_OK) {
            char schunk[320];
            size_t scn = 0;
            if (wr_sctp_chunk_serialize(WR_SCTP_SACK, 0u,
                                        wr_span_c_make(sbuf, sn), schunk,
                                        sizeof(schunk), &scn) == WR_OK) {
                wr_sctp_packet pkt = { 1000u, 2000u, 0x1000u, 0u, 12u, 0u };
                char raw[384];
                size_t raw_n = 0;
                (void)wr_sctp_serialize(&pkt, wr_span_c_make(schunk, scn),
                                        raw, sizeof(raw), &raw_n);
            }
        }
    }

    /* 4. INIT body + DCEP round trip. */
    {
        char ibuf[128];
        size_t in = 0;
        (void)wr_sctp_init_body((uint32_t)wr_fuzz_stream_next(&fs),
                                (uint32_t)wr_fuzz_stream_next(&fs),
                                (uint16_t)wr_fuzz_stream_below(&fs, 128u),
                                (uint16_t)wr_fuzz_stream_below(&fs, 128u),
                                (uint32_t)wr_fuzz_stream_next(&fs), ibuf,
                                sizeof(ibuf), &in);

        char dcep[256];
        size_t dcn = 0;
        uint8_t label[32];
        size_t llen = wr_fuzz_stream_below(&fs, (uint32_t)sizeof(label));
        for (size_t i = 0; i < llen; ++i) {
            label[i] = wr_fuzz_stream_u8(&fs);
        }
        if (wr_dcep_open_serialize(wr_span_c_make(label, llen),
                                   wr_span_c_from_str("proto"),
                                   0u, 0u, 0u, dcep,
                                   sizeof(dcep), &dcn) == WR_OK) {
            wr_dcep_msg dm;
            if (wr_dcep_parse(wr_span_c_make(dcep, dcn), &dm) == WR_OK) {
                if (!wr_span_c_eq(dm.label, wr_span_c_make(label, llen))) {
                    __builtin_trap();
                }
            }
        }
        char ack[8];
        size_t an = 0;
        if (wr_dcep_ack_serialize(ack, sizeof(ack), &an) == WR_OK) {
            wr_dcep_msg dm;
            (void)wr_dcep_parse(wr_span_c_make(ack, an), &dm);
        }
    }

    /* 5. TSN set invariants over a random add/has/advance stream. */
    {
        wr_tsn_set s;
        uint32_t cum = (uint32_t)wr_fuzz_stream_below(&fs, 100u);
        wr_tsn_set_init(&s, cum);
        for (int i = 0; i < 64; ++i) {
            uint32_t tsn = cum + (uint32_t)wr_fuzz_stream_below(&fs, 96u);
            bool added = wr_tsn_set_add(&s, tsn);
            if (added) {
                if (!wr_tsn_set_has(&s, tsn) ||
                    wr_tsn_set_add(&s, tsn)) {
                    __builtin_trap();
                }
            }
            (void)wr_tsn_set_advance(&s);
            uint32_t out = 0;
            (void)wr_tsn_set_pop_next(&s, &out);
            wr_tsn_gap tgaps[4];
            (void)wr_tsn_set_gaps(&s, tgaps, WR_ARRAY_LEN(tgaps));
        }
    }

    wr_arena_destroy(a);
    return 0;
}