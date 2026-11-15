#include "wr/media.h"

#include "wr/rtp.h"

#include <string.h>

static wr_status emit(const wr_rtp_pay_cfg *cfg, uint16_t seq, bool marker,
                      wr_span_c payload, wr_rtp_out *out)
{
    wr_rtp_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = 2u;
    h.pt = cfg->pt;
    h.seq = seq;
    h.timestamp = cfg->ts;
    h.ssrc = cfg->ssrc;
    h.marker = marker ? 1u : 0u;
    return wr_rtp_serialize(&h, payload, (char *)out->ptr, out->cap, &out->len);
}

/* ------------------------------------------------------------------------- */
/* H.264                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    const uint8_t *ptr;
    size_t len;
} nal_span;

static bool next_nal(wr_span_c in, size_t *off, nal_span *nal)
{
    size_t i = *off;
    for (;;) {
        /* Find the next Annex B start code. */
        while (i + 3u <= in.len) {
            if (in.ptr[i] == 0u && in.ptr[i + 1u] == 0u &&
                (in.ptr[i + 2u] == 1u ||
                 (i + 3u < in.len && in.ptr[i + 2u] == 0u &&
                  in.ptr[i + 3u] == 1u))) {
                break;
            }
            i++;
        }
        if (i + 3u > in.len) {
            return false;
        }
        size_t sc = (in.ptr[i + 2u] == 1u) ? 3u : 4u;
        if (i + sc > in.len) {
            return false;
        }
        size_t start = i + sc;

        size_t end = in.len;
        size_t j = start;
        while (j + 2u < in.len) {
            if (in.ptr[j] == 0u && in.ptr[j + 1u] == 0u &&
                (in.ptr[j + 2u] == 1u ||
                 (j + 3u < in.len && in.ptr[j + 2u] == 0u &&
                  in.ptr[j + 3u] == 1u))) {
                end = j;
                break;
            }
            j++;
        }

        if (start < end) {
            nal->ptr = in.ptr + start;
            nal->len = end - start;
            *off = end; /* next call starts at this start code */
            return true;
        }

        /* Empty NAL: skip it and look for the next one. */
        i = end;
    }
}

wr_status wr_h264_packetize(wr_span_c annex_b, const wr_rtp_pay_cfg *cfg,
                            wr_rtp_out *out, uint32_t max, uint32_t *count)
{
    if (!cfg || !out || !count || !annex_b.ptr || cfg->mtu < 4u) {
        return WR_ERR_INVAL;
    }
    uint32_t n = 0u;
    uint16_t seq = cfg->seq;
    size_t off = 0u;
    nal_span nal;
    while (next_nal(annex_b, &off, &nal)) {
        if (n >= max) {
            return WR_ERR_LIMIT;
        }
        bool last_nal = false;
        /* Peek whether another NAL follows; the marker goes on the final
         * packet of the access unit. */
        size_t probe = off;
        nal_span dummy;
        last_nal = !next_nal(annex_b, &probe, &dummy);

        if (nal.len <= cfg->mtu) {
            if (emit(cfg, seq, last_nal && cfg->marker,
                     wr_span_c_make(nal.ptr, nal.len), &out[n]) != WR_OK) {
                return WR_ERR_OVERFLOW;
            }
            n++;
            seq++;
            continue;
        }

        uint8_t fu_ind = (uint8_t)((nal.ptr[0] & 0x60u) | 28u);
        uint8_t fu_hdr = (uint8_t)(nal.ptr[0] & 0x1fu);
        size_t frag = cfg->mtu - 2u;
        size_t src = 1u;
        bool first = true;
        while (src < nal.len) {
            if (n >= max) {
                return WR_ERR_LIMIT;
            }
            size_t take = nal.len - src;
            if (take > frag) {
                take = frag;
            }
            bool last = (src + take >= nal.len);
            bool end = last; /* FU-A end bit ends the fragmented NAL */
            uint8_t hdr = (uint8_t)((first ? 0x80u : 0u) |
                                    (end ? 0x40u : 0u) | fu_hdr);
            /* FU header is two bytes: indicator + header, then fragment. */
            uint8_t tmp[2048];
            if (2u + take > sizeof(tmp)) {
                return WR_ERR_OVERFLOW;
            }
            tmp[0] = fu_ind;
            tmp[1] = hdr;
            memcpy(tmp + 2u, nal.ptr + src, take);
            wr_rtp_hdr h;
            memset(&h, 0, sizeof(h));
            h.version = 2u;
            h.pt = cfg->pt;
            h.seq = seq;
            h.timestamp = cfg->ts;
            h.ssrc = cfg->ssrc;
            h.marker = (end && last_nal && cfg->marker) ? 1u : 0u;
            if (wr_rtp_serialize(&h, wr_span_c_make(tmp, 2u + take),
                                 (char *)out[n].ptr, out[n].cap,
                                 &out[n].len) != WR_OK) {
                return WR_ERR_OVERFLOW;
            }
            n++;
            seq++;
            first = false;
            src += take;
        }
    }
    *count = n;
    return n ? WR_OK : WR_ERR_INVAL;
}

void wr_h264_depay_init(wr_h264_depay *d, uint8_t *buf, size_t cap)
{
    if (!d) {
        return;
    }
    memset(d, 0, sizeof(*d));
    d->buf = buf;
    d->cap = cap;
}

wr_status wr_h264_depay_input(wr_h264_depay *d, wr_span_c payload,
                              wr_span_c *out)
{
    if (!d || !payload.ptr || payload.len < 1u || !out) {
        return WR_ERR_INVAL;
    }
    uint8_t nal_type = (uint8_t)(payload.ptr[0] & 0x1fu);
    if (nal_type == 28u) { /* FU-A */
        if (payload.len < 2u) {
            return WR_ERR_TRUNCATED;
        }
        uint8_t fu = payload.ptr[1];
        bool start = (fu & 0x80u) != 0u;
        bool end = (fu & 0x40u) != 0u;
        uint8_t type = (uint8_t)(fu & 0x1fu);
        /* RFC 6184 5.8: NAL types 1-23 may be fragmented with FU-A; type 0 and
         * the aggregation/fragmentation types 24-31 may not. */
        if (type == 0u || type >= 24u) {
            return WR_ERR_INVAL;
        }
        if (start) {
            d->active = true;
            d->ref_idc = (uint8_t)(payload.ptr[0] >> 5);
            d->type = type;
            d->len = 0u;
            if (d->cap < 1u) {
                return WR_ERR_OVERFLOW;
            }
            d->buf[d->len++] = (uint8_t)((d->ref_idc << 5) | type);
        }
        if (!d->active) {
            return WR_ERR_STATE;
        }
        /* A middle fragment that is also marked "end" is legal (single-fragment
         * NAL), but a fragment whose type disagrees with the one announced by
         * the start fragment is not: reject it instead of emitting a NAL whose
         * header lies about its contents. */
        if (type != d->type) {
            return WR_ERR_INVAL;
        }
        wr_span_c frag = wr_span_c_sub(payload, 2u, payload.len - 2u);
        if (d->len + frag.len > d->cap) {
            return WR_ERR_OVERFLOW;
        }
        memcpy(d->buf + d->len, frag.ptr, frag.len);
        d->len += frag.len;
        if (!end) {
            return WR_ERR_AGAIN;
        }
        d->active = false;
        out->ptr = d->buf;
        out->len = d->len;
        return WR_OK;
    }
    if (nal_type >= 24u && nal_type <= 27u) {
        /* STAP/MTAP aggregation is not produced by this encoder. */
        return WR_ERR_UNSUPPORTED;
    }
    out->ptr = payload.ptr;
    out->len = payload.len;
    return WR_OK;
}

/* ------------------------------------------------------------------------- */
/* VP8                                                                       */
/* ------------------------------------------------------------------------- */

wr_status wr_vp8_packetize(wr_span_c frame, const wr_rtp_pay_cfg *cfg,
                           wr_rtp_out *out, uint32_t max, uint32_t *count)
{
    if (!cfg || !out || !count || !frame.ptr || cfg->mtu < 2u) {
        return WR_ERR_INVAL;
    }
    size_t frag = cfg->mtu - 1u;
    uint32_t n = 0u;
    uint16_t seq = cfg->seq;
    size_t off = 0u;
    do {
        if (n >= max) {
            return WR_ERR_LIMIT;
        }
        size_t take = frame.len - off;
        if (take > frag) {
            take = frag;
        }
        bool last = (off + take >= frame.len);
        uint8_t desc = (uint8_t)(off == 0u ? 0x10u : 0u);
        if (out[n].cap < 1u + take) {
            return WR_ERR_OVERFLOW;
        }
        uint8_t tmp[2048];
        if (1u + take > sizeof(tmp)) {
            return WR_ERR_OVERFLOW;
        }
        tmp[0] = desc;
        memcpy(tmp + 1u, frame.ptr + off, take);
        if (emit(cfg, seq, last && cfg->marker,
                 wr_span_c_make(tmp, 1u + take), &out[n]) != WR_OK) {
            return WR_ERR_OVERFLOW;
        }
        n++;
        seq++;
        off += take;
    } while (off < frame.len);
    *count = n;
    return WR_OK;
}

void wr_vp8_depay_init(wr_vp8_depay *d, uint8_t *buf, size_t cap)
{
    if (!d) {
        return;
    }
    memset(d, 0, sizeof(*d));
    d->buf = buf;
    d->cap = cap;
}

wr_status wr_vp8_depay_input(wr_vp8_depay *d, wr_span_c payload, bool marker,
                             wr_span_c *out)
{
    if (!d || !payload.ptr || payload.len < 1u || !out) {
        return WR_ERR_INVAL;
    }
    uint8_t desc = payload.ptr[0];
    size_t off = 1u;
    if (desc & 0x80u) { /* X bit: the extension header follows */
        if (off >= payload.len) {
            return WR_ERR_TRUNCATED;
        }
        uint8_t ext = payload.ptr[off++];
        /* RFC 7741 4.2: the X bit is followed by an extension header whose
         * presence bits are I (0x80), L (0x40), T (0x20) and K (0x10). Each
         * present field occupies one octet, in that order. Skipping only
         * L/T (as this parser once did) desynchronises the payload whenever I
         * or K is set, so every later packet of the frame is misparsed. */
        if (ext & 0x80u) { /* I: PictureID, 1 or 2 octets */
            if (off >= payload.len) {
                return WR_ERR_TRUNCATED;
            }
            bool wide = (payload.ptr[off] & 0x80u) != 0u;
            off++;
            if (wide) {
                /* A 16-bit PictureID occupies a second octet. */
                if (off >= payload.len) {
                    return WR_ERR_TRUNCATED;
                }
                off++;
            }
        }
        if (ext & 0x40u) { /* L: TL0PICIDX */
            if (off >= payload.len) {
                return WR_ERR_TRUNCATED;
            }
            off++;
        }
        if (ext & 0x20u || ext & 0x10u) { /* T: TID/KEYIDX */
            if (off >= payload.len) {
                return WR_ERR_TRUNCATED;
            }
            off++;
        }
    }
    if (off > payload.len) {
        return WR_ERR_TRUNCATED;
    }
    if (desc & 0x10u) { /* Start of partition */
        d->len = 0u;
    }
    wr_span_c data = wr_span_c_sub(payload, off, payload.len - off);
    if (d->len + data.len > d->cap) {
        return WR_ERR_OVERFLOW;
    }
    memcpy(d->buf + d->len, data.ptr, data.len);
    d->len += data.len;
    if (!marker) {
        return WR_ERR_AGAIN;
    }
    out->ptr = d->buf;
    out->len = d->len;
    d->len = 0u;
    return WR_OK;
}

/* ------------------------------------------------------------------------- */
/* Opus                                                                      */
/* ------------------------------------------------------------------------- */

wr_status wr_opus_packetize(wr_span_c frame, const wr_rtp_pay_cfg *cfg,
                            wr_rtp_out *out, uint32_t max, uint32_t *count)
{
    if (!cfg || !out || !count || !frame.ptr || max == 0u) {
        return WR_ERR_INVAL;
    }
    if (emit(cfg, cfg->seq, cfg->marker, frame, out) != WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    *count = 1u;
    return WR_OK;
}