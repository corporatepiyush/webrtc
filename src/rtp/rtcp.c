#include "wr/rtp.h"
#include "wr/sb.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* RTCP                                                                      */
/* ------------------------------------------------------------------------- */

wr_status wr_rtcp_parse_one(wr_span_c pkt, size_t *consumed, wr_rtcp_hdr *out)
{
    if (WR_UNLIKELY(!pkt.ptr || pkt.len < 4u || !consumed || !out)) {
        return WR_ERR_TRUNCATED;
    }
    if (WR_UNLIKELY((pkt.ptr[0] >> 6) != 2u)) {
        return WR_ERR_INVAL;
    }
    memset(out, 0, sizeof(*out));
    out->version = (uint8_t)(pkt.ptr[0] >> 6);
    out->padding = (uint8_t)((pkt.ptr[0] >> 5) & 1u);
    out->count = (uint8_t)(pkt.ptr[0] & 0x1fu);
    out->pt = pkt.ptr[1];
    out->length = wr_load_be16(pkt.ptr + 2u);
    size_t total = 4u + 4u * (size_t)out->length;
    if (total > pkt.len) {
        return WR_ERR_TRUNCATED;
    }
    size_t blen = 4u * (size_t)out->length;
    if (out->padding) {
        if (blen == 0u) {
            return WR_ERR_INVAL;
        }
        size_t pad = pkt.ptr[total - 1u];
        if (pad == 0u || pad > blen) {
            return WR_ERR_INVAL;
        }
        blen -= pad;
    }
    out->body = wr_span_c_sub(pkt, 4u, blen);
    *consumed = total;
    return WR_OK;
}

wr_status wr_rtcp_compound_parse(wr_span_c pkt, size_t max_pkts,
                                 wr_rtcp_hdr *out, size_t *count)
{
    if (!pkt.ptr || !out || !count) {
        return WR_ERR_INVAL;
    }
    size_t n = 0u;
    size_t off = 0u;
    while (off < pkt.len) {
        if (n >= max_pkts) {
            return WR_ERR_LIMIT;
        }
        size_t used = 0u;
        wr_status st = wr_rtcp_parse_one(wr_span_c_sub(pkt, off, pkt.len - off),
                                         &used, &out[n]);
        if (st != WR_OK) {
            return st;
        }
        if (used == 0u) {
            return WR_ERR_INVAL;
        }
        off += used;
        n++;
    }
    if (n == 0u) {
        return WR_ERR_INVAL;
    }
    *count = n;
    return WR_OK;
}

static int32_t read_lost(const uint8_t *p)
{
    int32_t v = ((int32_t)p[0] << 16) | ((int32_t)p[1] << 8) | (int32_t)p[2];
    if (v & 0x800000) {
        v |= (int32_t)0xff000000u;
    }
    return v;
}

static void write_lost(uint8_t *p, int32_t lost)
{
    uint32_t v = (uint32_t)lost & 0x00ffffffu;
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

static wr_status parse_blocks_only(const wr_rtcp_hdr *pkt,
                                   wr_rtcp_rr_block *blocks, size_t max,
                                   size_t *count)
{
    if (!pkt || pkt->body.len < 24u * (size_t)pkt->count) {
        return WR_ERR_TRUNCATED;
    }
    size_t n = pkt->count;
    if (n > max) {
        return WR_ERR_LIMIT;
    }
    const uint8_t *p = pkt->body.ptr;
    for (size_t i = 0; i < n; ++i) {
        blocks[i].ssrc = wr_load_be32(p);
        blocks[i].fraction = p[4];
        blocks[i].lost = read_lost(p + 5u);
        blocks[i].seq = wr_load_be16(p + 8u);
        blocks[i].jitter = wr_load_be32(p + 12u);
        blocks[i].lsr = wr_load_be32(p + 16u);
        blocks[i].dlsr = wr_load_be32(p + 20u);
        p += 24u;
    }
    if (count) {
        *count = n;
    }
    return WR_OK;
}

static wr_status parse_rr_blocks(const wr_rtcp_hdr *pkt, uint32_t *sender,
                                 wr_rtcp_rr_block *blocks, size_t max,
                                 size_t *count)
{
    if (!pkt || pkt->body.len < 4u) {
        return WR_ERR_TRUNCATED;
    }
    if (sender) {
        *sender = wr_load_be32(pkt->body.ptr);
    }
    wr_rtcp_hdr tmp = *pkt;
    tmp.body = wr_span_c_sub(pkt->body, 4u, pkt->body.len - 4u);
    return parse_blocks_only(&tmp, blocks, max, count);
}

wr_status wr_rtcp_sr_parse(const wr_rtcp_hdr *pkt, wr_rtcp_sr_info *info,
                           wr_rtcp_rr_block *blocks, size_t max,
                           size_t *count)
{
    if (!pkt || !info || pkt->body.len < 28u) {
        return WR_ERR_TRUNCATED;
    }
    info->ssrc = wr_load_be32(pkt->body.ptr);
    info->ntp = wr_load_be64(pkt->body.ptr + 4u);
    info->rtp_ts = wr_load_be32(pkt->body.ptr + 12u);
    info->pkt_count = wr_load_be32(pkt->body.ptr + 16u);
    info->octet_count = wr_load_be32(pkt->body.ptr + 20u);
    wr_rtcp_hdr tmp = *pkt;
    tmp.body = wr_span_c_sub(pkt->body, 24u, pkt->body.len - 24u);
    return parse_blocks_only(&tmp, blocks, max, count);
}

wr_status wr_rtcp_rr_parse(const wr_rtcp_hdr *pkt, wr_rtcp_rr_block *blocks,
                           size_t max, size_t *count)
{
    if (!pkt) {
        return WR_ERR_INVAL;
    }
    return parse_rr_blocks(pkt, NULL, blocks, max, count);
}

wr_status wr_rtcp_sdes_cname(const wr_rtcp_hdr *pkt, wr_span_c *cname)
{
    if (!pkt || !cname || pkt->body.len < 4u) {
        return WR_ERR_TRUNCATED;
    }
    const uint8_t *p = pkt->body.ptr;
    size_t len = pkt->body.len;
    while (len >= 4u) {
        p += 4u;
        len -= 4u;
        while (len > 0u) {
            uint8_t t = *p++;
            len--;
            if (t == 0u) {
                break;
            }
            if (len == 0u) {
                return WR_ERR_TRUNCATED;
            }
            uint8_t l = *p++;
            len--;
            if ((size_t)l > len) {
                return WR_ERR_TRUNCATED;
            }
            if (t == 1u) {
                *cname = wr_span_c_make(p, l);
                return WR_OK;
            }
            p += l;
            len -= l;
        }
    }
    return WR_ERR_NOT_FOUND;
}

wr_status wr_rtcp_bye_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrcs,
                            size_t max, size_t *count, wr_span_c *reason)
{
    if (!pkt || !count) {
        return WR_ERR_INVAL;
    }
    size_t n = pkt->count;
    if (n > max || pkt->body.len < 4u * n) {
        return WR_ERR_TRUNCATED;
    }
    for (size_t i = 0; i < n; ++i) {
        if (ssrcs) {
            ssrcs[i] = wr_load_be32(pkt->body.ptr + 4u * i);
        }
    }
    *count = n;
    if (reason) {
        if (pkt->body.len > 4u * n) {
            size_t off = 4u * n;
            uint8_t rl = pkt->body.ptr[off++];
            if (off + rl > pkt->body.len) {
                return WR_ERR_TRUNCATED;
            }
            *reason = wr_span_c_sub(pkt->body, off, rl);
        } else {
            *reason = wr_span_c_make(NULL, 0);
        }
    }
    return WR_OK;
}

wr_status wr_rtcp_nack_parse(const wr_rtcp_hdr *pkt, uint32_t *pid,
                             uint16_t *blp, size_t max, size_t *count)
{
    if (!pkt || !count) {
        return WR_ERR_INVAL;
    }
    if (pkt->pt != 205u || (pkt->count & 0x0fu) != 1u) {
        return WR_ERR_INVAL;
    }
    if (pkt->body.len < 4u) {
        return WR_ERR_TRUNCATED;
    }
    size_t n = (pkt->body.len - 4u) / 4u;
    if ((pkt->body.len - 4u) % 4u != 0u || n > max) {
        return WR_ERR_TRUNCATED;
    }
    const uint8_t *p = pkt->body.ptr + 4u;
    for (size_t i = 0; i < n; ++i) {
        if (pid) {
            pid[i] = wr_load_be16(p + 4u * i) & 0x7fffu;
        }
        if (blp) {
            blp[i] = wr_load_be16(p + 4u * i + 2u);
        }
    }
    *count = n;
    return WR_OK;
}

wr_status wr_rtcp_pli_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrc)
{
    if (!pkt || pkt->pt != 206u || (pkt->count & 0x0fu) != 1u ||
        pkt->body.len < 4u) {
        return WR_ERR_INVAL;
    }
    if (ssrc) {
        *ssrc = wr_load_be32(pkt->body.ptr);
    }
    return WR_OK;
}

wr_status wr_rtcp_fir_parse(const wr_rtcp_hdr *pkt, uint32_t *ssrc,
                            uint8_t *seq, size_t max, size_t *count)
{
    if (!pkt || !count) {
        return WR_ERR_INVAL;
    }
    if (pkt->pt != 206u || (pkt->count & 0x0fu) != 4u ||
        pkt->body.len < 4u || (pkt->body.len - 4u) % 8u != 0u) {
        return WR_ERR_INVAL;
    }
    size_t n = (pkt->body.len - 4u) / 8u;
    if (n > max) {
        return WR_ERR_LIMIT;
    }
    const uint8_t *p = pkt->body.ptr + 4u;
    for (size_t i = 0; i < n; ++i) {
        if (ssrc) {
            ssrc[i] = wr_load_be32(p + 8u * i);
        }
        if (seq) {
            seq[i] = p[8u * i + 4u];
        }
    }
    *count = n;
    return WR_OK;
}

static wr_status finish(wr_sb *s, uint8_t pt, uint8_t count, char *buf,
                        size_t cap, size_t *out_len)
{
    if (s->len > cap) {
        return WR_ERR_OVERFLOW;
    }
    size_t words = s->len / 4u;
    if (s->len % 4u != 0u) {
        return WR_ERR_INVAL;
    }
    /* The RTCP length field is 16-bit words minus one. Reject packets whose
     * encoded length would wrap instead of emitting a malformed compound
     * packet that the parser would mis-split. */
    if (WR_UNLIKELY(words == 0u || words - 1u > UINT16_MAX)) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    p[0] = (uint8_t)(0x80u | (count & 0x1fu));
    p[1] = pt;
    wr_store_be16(p + 2u, (uint16_t)(words - 1u));
    *out_len = s->len;
    return WR_OK;
}

wr_status wr_rtcp_sr_serialize(uint32_t ssrc, uint64_t ntp, uint32_t rtp_ts,
                               uint32_t pkt_count, uint32_t octet_count,
                               const wr_rtcp_rr_block *blocks, size_t nblocks,
                               char *buf, size_t cap, size_t *out_len)
{
    if (!buf || !out_len || nblocks > 31u) {
        return WR_ERR_INVAL;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    wr_sb_put_be32(&s, ssrc);
    wr_sb_put_be64(&s, ntp);
    wr_sb_put_be32(&s, rtp_ts);
    wr_sb_put_be32(&s, pkt_count);
    wr_sb_put_be32(&s, octet_count);
    for (size_t i = 0; i < nblocks; ++i) {
        wr_sb_put_be32(&s, blocks[i].ssrc);
        wr_sb_put_u8(&s, blocks[i].fraction);
        uint8_t lost[3];
        write_lost(lost, blocks[i].lost);
        wr_sb_put_u8(&s, lost[0]);
        wr_sb_put_u8(&s, lost[1]);
        wr_sb_put_u8(&s, lost[2]);
        wr_sb_put_be16(&s, blocks[i].seq);
        wr_sb_put_be16(&s, 0u);
        wr_sb_put_be32(&s, blocks[i].jitter);
        wr_sb_put_be32(&s, blocks[i].lsr);
        wr_sb_put_be32(&s, blocks[i].dlsr);
    }
    return finish(&s, 200u, (uint8_t)nblocks, buf, cap, out_len);
}

wr_status wr_rtcp_rr_serialize(uint32_t ssrc,
                               const wr_rtcp_rr_block *blocks, size_t nblocks,
                               char *buf, size_t cap, size_t *out_len)
{
    if (!buf || !out_len || nblocks > 31u) {
        return WR_ERR_INVAL;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    wr_sb_put_be32(&s, ssrc);
    for (size_t i = 0; i < nblocks; ++i) {
        wr_sb_put_be32(&s, blocks[i].ssrc);
        wr_sb_put_u8(&s, blocks[i].fraction);
        uint8_t lost[3];
        write_lost(lost, blocks[i].lost);
        wr_sb_put_u8(&s, lost[0]);
        wr_sb_put_u8(&s, lost[1]);
        wr_sb_put_u8(&s, lost[2]);
        wr_sb_put_be16(&s, blocks[i].seq);
        wr_sb_put_be16(&s, 0u);
        wr_sb_put_be32(&s, blocks[i].jitter);
        wr_sb_put_be32(&s, blocks[i].lsr);
        wr_sb_put_be32(&s, blocks[i].dlsr);
    }
    return finish(&s, 201u, (uint8_t)nblocks, buf, cap, out_len);
}

wr_status wr_rtcp_bye_serialize(const uint32_t *ssrcs, size_t count,
                                wr_span_c reason, char *buf, size_t cap,
                                size_t *out_len)
{
    if (!buf || !out_len || count > 31u || reason.len > 255u) {
        return WR_ERR_INVAL;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    for (size_t i = 0; i < count; ++i) {
        wr_sb_put_be32(&s, ssrcs[i]);
    }
    if (reason.ptr && reason.len) {
        wr_sb_put_u8(&s, (uint8_t)reason.len);
        wr_sb_put_span(&s, reason);
        while (s.len % 4u != 0u) {
            wr_sb_put_u8(&s, 0u);
        }
    }
    return finish(&s, 203u, (uint8_t)count, buf, cap, out_len);
}

wr_status wr_rtcp_nack_serialize(uint32_t ssrc, const uint32_t *pids,
                                 const uint16_t *blps, size_t count, char *buf,
                                 size_t cap, size_t *out_len)
{
    if (!buf || !out_len || !pids || !blps || count == 0u) {
        return WR_ERR_INVAL;
    }
    /* 8 bytes of header + 4-byte FCI entries; the length field is
     * 16-bit words minus one, so at most 65534 entries fit. */
    if (count > 65534u) {
        return WR_ERR_OVERFLOW;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    wr_sb_put_be32(&s, ssrc);
    for (size_t i = 0; i < count; ++i) {
        wr_sb_put_be16(&s, (uint16_t)(pids[i] & 0x7fffu));
        wr_sb_put_be16(&s, blps[i]);
    }
    return finish(&s, 205u, 1u, buf, cap, out_len);
}

wr_status wr_rtcp_pli_serialize(uint32_t ssrc, char *buf, size_t cap,
                                size_t *out_len)
{
    if (!buf || !out_len) {
        return WR_ERR_INVAL;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    wr_sb_put_be32(&s, ssrc);
    return finish(&s, 206u, 1u, buf, cap, out_len);
}

wr_status wr_rtcp_fir_serialize(uint32_t ssrc, const uint32_t *targets,
                                const uint8_t *seqs, size_t count, char *buf,
                                size_t cap, size_t *out_len)
{
    if (!buf || !out_len || !targets || !seqs || count == 0u) {
        return WR_ERR_INVAL;
    }
    /* 8 bytes of header + 8-byte FCI entries; at most 32767 fit in the
     * 16-bit word count. */
    if (count > 32767u) {
        return WR_ERR_OVERFLOW;
    }
    wr_sb s;
    wr_sb_init(&s, buf, cap);
    s.len = 4u;
    wr_sb_put_be32(&s, ssrc);
    for (size_t i = 0; i < count; ++i) {
        wr_sb_put_be32(&s, targets[i]);
        wr_sb_put_u8(&s, seqs[i]);
        wr_sb_put_u8(&s, 0u);
        wr_sb_put_u8(&s, 0u);
        wr_sb_put_u8(&s, 0u);
    }
    return finish(&s, 206u, 4u, buf, cap, out_len);
}