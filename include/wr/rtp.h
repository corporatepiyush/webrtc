#ifndef WR_RTP_H
#define WR_RTP_H

#include "wr/base.h"

/* ------------------------------------------------------------------------- */
/* RTP                                                                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t version;
    uint8_t padding;
    uint8_t ext;
    uint8_t cc;
    uint8_t marker;
    uint8_t pt;
    uint16_t seq;
    uint32_t timestamp;
    uint32_t ssrc;
    size_t header_len;
    size_t payload_off;
    size_t payload_len;
    wr_span_c ext_raw;
} wr_rtp_hdr;

bool wr_rtp_parse(wr_span_c pkt, wr_rtp_hdr *out);
size_t wr_rtp_header_len(uint8_t cc, bool ext, uint16_t ext_words);
wr_status wr_rtp_serialize(const wr_rtp_hdr *h, wr_span_c payload, char *buf,
                           size_t cap, size_t *out_len);
size_t wr_rtp_ext_parse(wr_span_c ext, uint16_t *id, wr_span_c *data,
                        size_t max, size_t *count);

/* ------------------------------------------------------------------------- */
/* RTCP                                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t version;
    uint8_t padding;
    uint8_t count;
    uint8_t pt;
    uint16_t length; /* 32-bit words minus one */
    wr_span_c body;
} wr_rtcp_hdr;

wr_status wr_rtcp_parse_one(wr_span_c pkt, size_t *consumed, wr_rtcp_hdr *out);
wr_status wr_rtcp_compound_parse(wr_span_c pkt, size_t max_pkts,
                                 wr_rtcp_hdr *out, size_t *count);

typedef struct {
    uint32_t ssrc;
    uint64_t ntp;
    uint32_t rtp_ts;
    uint32_t pkt_count;
    uint32_t octet_count;
} wr_rtcp_sr_info;

typedef struct {
    uint32_t ssrc;
    uint8_t fraction;
    int32_t lost;
    uint16_t seq;
    uint32_t jitter;
    uint32_t lsr;
    uint32_t dlsr;
} wr_rtcp_rr_block;

wr_status wr_rtcp_sr_parse(const wr_rtcp_hdr *pkt, wr_rtcp_sr_info *info,
                           wr_rtcp_rr_block *blocks, size_t max,
                           size_t *count);
wr_status wr_rtcp_rr_parse(const wr_rtcp_hdr *pkt, wr_rtcp_rr_block *blocks,
                           size_t max, size_t *count);
wr_status wr_rtcp_sdes_cname(const wr_rtcp_hdr *pkt, wr_span_c *cname);
wr_status wr_rtcp_bye_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrcs,
                            size_t max, size_t *count, wr_span_c *reason);
wr_status wr_rtcp_nack_parse(const wr_rtcp_hdr *pkt, uint32_t *pid,
                             uint16_t *blp, size_t max, size_t *count);
wr_status wr_rtcp_pli_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrc);
wr_status wr_rtcp_fir_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrc,
                            uint8_t *seq, size_t max, size_t *count);

wr_status wr_rtcp_sr_serialize(uint32_t ssrc, uint64_t ntp, uint32_t rtp_ts,
                               uint32_t pkt_count, uint32_t octet_count,
                               const wr_rtcp_rr_block *blocks, size_t nblocks,
                               char *buf, size_t cap, size_t *out_len);
wr_status wr_rtcp_rr_serialize(uint32_t ssrc,
                               const wr_rtcp_rr_block *blocks, size_t nblocks,
                               char *buf, size_t cap, size_t *out_len);
wr_status wr_rtcp_bye_serialize(const uint32_t *ssrcs, size_t count,
                                wr_span_c reason, char *buf, size_t cap,
                                size_t *out_len);
wr_status wr_rtcp_nack_serialize(uint32_t ssrc, const uint32_t *pids,
                                 const uint16_t *blps, size_t count, char *buf,
                                 size_t cap, size_t *out_len);
wr_status wr_rtcp_pli_serialize(uint32_t ssrc, char *buf, size_t cap,
                                size_t *out_len);
wr_status wr_rtcp_fir_serialize(uint32_t ssrc, const uint32_t *targets,
                                const uint8_t *seqs, size_t count, char *buf,
                                size_t cap, size_t *out_len);

#endif /* WR_RTP_H */