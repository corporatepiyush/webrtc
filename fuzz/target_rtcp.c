#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/rtp.h"

#include <string.h>

static void exercise_hdr(const wr_rtcp_hdr *h)
{
    switch (h->pt) {
    case 200: {
        wr_rtcp_sr_info info;
        wr_rtcp_rr_block blocks[8];
        size_t n = 0;
        (void)wr_rtcp_sr_parse(h, &info, blocks, WR_ARRAY_LEN(blocks), &n);
        break;
    }
    case 201: {
        wr_rtcp_rr_block blocks[8];
        size_t n = 0;
        (void)wr_rtcp_rr_parse(h, blocks, WR_ARRAY_LEN(blocks), &n);
        break;
    }
    case 202: {
        wr_span_c cname;
        (void)wr_rtcp_sdes_cname(h, &cname);
        break;
    }
    case 203: {
        uint32_t ssrcs[8];
        size_t n = 0;
        wr_span_c reason;
        (void)wr_rtcp_bye_parse(h, ssrcs, WR_ARRAY_LEN(ssrcs), &n, &reason);
        break;
    }
    case 205: {
        uint32_t pid = 0;
        uint16_t blp = 0;
        size_t n = 0;
        (void)wr_rtcp_nack_parse(h, &pid, &blp, 1u, &n);
        break;
    }
    case 206: {
        uint32_t ssrc = 0;
        (void)wr_rtcp_pli_parse(h, &ssrc);
        break;
    }
    case 207: {
        uint32_t ssrc = 0;
        uint8_t seq[8];
        size_t n = 0;
        (void)wr_rtcp_fir_parse(h, &ssrc, seq, WR_ARRAY_LEN(seq), &n);
        break;
    }
    default:
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Walk every packet in a compound packet, not just offset zero. */
    size_t off = 0;
    while (off + 4u <= size) {
        wr_rtcp_hdr h;
        size_t consumed = 0;
        if (wr_rtcp_parse_one(wr_span_c_sub(wr_span_c_make(data, size), off,
                                            size - off),
                              &consumed, &h) != WR_OK) {
            /* Try resynchronizing at the next 4-byte boundary. */
            off += 4u;
            continue;
        }
        exercise_hdr(&h);
        if (consumed < 4u) {
            break;
        }
        off += consumed;
    }

    /* Serialize each feedback type from fuzz-derived values, then reparse. */
    wr_fuzz_rng rng = { UINT64_C(0x1234567890abcdef) ^ size };
    char buf[512];
    size_t n = 0;
    uint32_t ssrc = (uint32_t)wr_fuzz_next(&rng);
    wr_rtcp_rr_block rb;
    memset(&rb, 0, sizeof(rb));
    rb.ssrc = (uint32_t)wr_fuzz_next(&rng);
    rb.fraction = (uint8_t)wr_fuzz_next(&rng);
    rb.lost = (int32_t)wr_fuzz_next(&rng);
    rb.seq = (uint16_t)wr_fuzz_next(&rng);
    rb.jitter = (uint32_t)wr_fuzz_next(&rng);
    rb.lsr = (uint32_t)wr_fuzz_next(&rng);
    rb.dlsr = (uint32_t)wr_fuzz_next(&rng);

    if (wr_rtcp_sr_serialize(ssrc, wr_fuzz_next(&rng),
                             (uint32_t)wr_fuzz_next(&rng),
                             (uint32_t)wr_fuzz_next(&rng),
                             (uint32_t)wr_fuzz_next(&rng), &rb, 1u, buf,
                             sizeof(buf), &n) == WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            wr_rtcp_sr_info info;
            wr_rtcp_rr_block blocks[4];
            size_t bn = 0;
            (void)wr_rtcp_sr_parse(&h, &info, blocks, 4u, &bn);
        }
    }
    if (wr_rtcp_rr_serialize(ssrc, &rb, 1u, buf, sizeof(buf), &n) == WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            wr_rtcp_rr_block blocks[4];
            size_t bn = 0;
            (void)wr_rtcp_rr_parse(&h, blocks, 4u, &bn);
        }
    }
    if (wr_rtcp_bye_serialize(&ssrc, 1u, wr_span_c_from_str("bye"), buf,
                              sizeof(buf), &n) == WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            uint32_t ssrcs[4];
            size_t sn = 0;
            wr_span_c reason;
            (void)wr_rtcp_bye_parse(&h, ssrcs, 4u, &sn, &reason);
        }
    }
    uint32_t pids[2] = { 1u, 2u };
    uint16_t blps[2] = { 3u, 4u };
    if (wr_rtcp_nack_serialize(ssrc, pids, blps, 2u, buf, sizeof(buf), &n) ==
        WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            uint32_t pid = 0;
            uint16_t blp = 0;
            size_t cn = 0;
            (void)wr_rtcp_nack_parse(&h, &pid, &blp, 1u, &cn);
        }
    }
    if (wr_rtcp_pli_serialize(ssrc, buf, sizeof(buf), &n) == WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            uint32_t got = 0;
            (void)wr_rtcp_pli_parse(&h, &got);
        }
    }
    uint32_t targets[2] = { 1u, 2u };
    uint8_t seqs[2] = { 5u, 6u };
    if (wr_rtcp_fir_serialize(ssrc, targets, seqs, 2u, buf, sizeof(buf), &n) ==
        WR_OK) {
        wr_rtcp_hdr h;
        size_t used = 0;
        if (wr_rtcp_parse_one(wr_span_c_make(buf, n), &used, &h) == WR_OK) {
            uint32_t got[4];
            uint8_t seq[4];
            size_t sn = 0;
            (void)wr_rtcp_fir_parse(&h, got, seq, 4u, &sn);
        }
    }
    return 0;
}