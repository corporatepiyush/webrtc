#include "wr/rtp.h"

#include <string.h>

bool wr_rtp_parse(wr_span_c pkt, wr_rtp_hdr *out)
{
    if (WR_UNLIKELY(!out || !pkt.ptr || pkt.len < 12u)) {
        return false;
    }
    if (WR_UNLIKELY((pkt.ptr[0] >> 6) != 2u)) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->version = (uint8_t)(pkt.ptr[0] >> 6);
    out->padding = (uint8_t)((pkt.ptr[0] >> 5) & 1u);
    out->ext = (uint8_t)((pkt.ptr[0] >> 4) & 1u);
    out->cc = (uint8_t)(pkt.ptr[0] & 0x0fu);
    out->marker = (uint8_t)((pkt.ptr[1] >> 7) & 1u);
    out->pt = (uint8_t)(pkt.ptr[1] & 0x7fu);
    out->seq = wr_load_be16(pkt.ptr + 2u);
    out->timestamp = wr_load_be32(pkt.ptr + 4u);
    out->ssrc = wr_load_be32(pkt.ptr + 8u);
    size_t hl = 12u + 4u * (size_t)out->cc;
    if (hl > pkt.len) {
        return false;
    }
    if (out->ext) {
        if (hl + 4u > pkt.len) {
            return false;
        }
        uint16_t words = wr_load_be16(pkt.ptr + hl + 2u);
        size_t elen = 4u + 4u * (size_t)words;
        if (hl + elen > pkt.len) {
            return false;
        }
        out->ext_raw = wr_span_c_sub(pkt, hl + 4u, 4u * (size_t)words);
        hl += elen;
    }
    size_t pad = 0u;
    if (out->padding) {
        if (hl >= pkt.len) {
            return false;
        }
        pad = pkt.ptr[pkt.len - 1u];
        if (pad == 0u || pad > pkt.len - hl) {
            return false;
        }
    }
    out->header_len = hl;
    out->payload_off = hl;
    out->payload_len = pkt.len - hl - pad;
    return true;
}

size_t wr_rtp_header_len(uint8_t cc, bool ext, uint16_t ext_words)
{
    size_t hl = 12u + 4u * (size_t)(cc & 0x0fu);
    if (ext) {
        hl += 4u + 4u * (size_t)ext_words;
    }
    return hl;
}

wr_status wr_rtp_serialize(const wr_rtp_hdr *h, wr_span_c payload, char *buf,
                           size_t cap, size_t *out_len)
{
    if (!h || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (h->cc != 0u || h->ext || h->padding) {
        /* CSRC lists, header extensions, and padding are not modelled. */
        return WR_ERR_UNSUPPORTED;
    }
    size_t hl = wr_rtp_header_len(h->cc, h->ext, 0u);
    if (payload.len > SIZE_MAX - hl) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = hl + payload.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    p[0] = (uint8_t)(0x80u | ((h->padding ? 1u : 0u) << 5) |
                     ((h->ext ? 1u : 0u) << 4) | (h->cc & 0x0fu));
    p[1] = (uint8_t)((h->marker ? 0x80u : 0u) | (h->pt & 0x7fu));
    wr_store_be16(p + 2u, h->seq);
    wr_store_be32(p + 4u, h->timestamp);
    wr_store_be32(p + 8u, h->ssrc);
    if (payload.len) {
        memcpy(p + hl, payload.ptr, payload.len);
    }
    *out_len = total;
    return WR_OK;
}

size_t wr_rtp_ext_parse(wr_span_c ext, uint16_t *id, wr_span_c *data,
                        size_t max, size_t *count)
{
    size_t n = 0u;
    size_t off = 0u;
    while (off < ext.len && n < max) {
        uint8_t b = ext.ptr[off++];
        uint16_t eid = (uint16_t)(b >> 4);
        size_t len = (size_t)(b & 0x0fu) + 1u;
        if (eid == 0u || eid == 15u) {
            break;
        }
        if (off + len > ext.len) {
            break;
        }
        id[n] = eid;
        data[n] = wr_span_c_sub(ext, off, len);
        n++;
        off += len;
    }
    if (count) {
        *count = n;
    }
    return off;
}
