#include "wr/sctp.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* DCEP                                                                      */
/* ------------------------------------------------------------------------- */

wr_status wr_dcep_open_serialize(wr_span_c label, wr_span_c protocol,
                                 uint8_t channel_type, uint16_t priority,
                                 uint32_t reliability, char *buf, size_t cap,
                                 size_t *out_len)
{
    if (!buf || !out_len || label.len > UINT16_MAX ||
        protocol.len > UINT16_MAX) {
        return WR_ERR_INVAL;
    }
    size_t total = 1u + 1u + 2u + 4u + 2u + label.len + 2u + protocol.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0u;
    p[off++] = WR_DCEP_OPEN;
    p[off++] = channel_type;
    wr_store_be16(p + off, priority);
    off += 2u;
    wr_store_be32(p + off, reliability);
    off += 4u;
    wr_store_be16(p + off, (uint16_t)label.len);
    off += 2u;
    if (label.len) {
        memcpy(p + off, label.ptr, label.len);
        off += label.len;
    }
    wr_store_be16(p + off, (uint16_t)protocol.len);
    off += 2u;
    if (protocol.len) {
        memcpy(p + off, protocol.ptr, protocol.len);
        off += protocol.len;
    }
    *out_len = off;
    return WR_OK;
}

wr_status wr_dcep_ack_serialize(char *buf, size_t cap, size_t *out_len)
{
    if (!buf || cap < 1u || !out_len) {
        return WR_ERR_INVAL;
    }
    buf[0] = (char)WR_DCEP_ACK;
    *out_len = 1u;
    return WR_OK;
}

wr_status wr_dcep_parse(wr_span_c body, wr_dcep_msg *out)
{
    if (!body.ptr || body.len < 1u || !out) {
        return WR_ERR_TRUNCATED;
    }
    memset(out, 0, sizeof(*out));
    out->type = (wr_dcep_type)body.ptr[0];
    if (out->type == WR_DCEP_ACK) {
        return WR_OK;
    }
    if (out->type != WR_DCEP_OPEN || body.len < 10u) {
        return WR_ERR_INVAL;
    }
    size_t off = 1u;
    out->channel_type = body.ptr[off++];
    out->priority = wr_load_be16(body.ptr + off);
    off += 2u;
    out->reliability = wr_load_be32(body.ptr + off);
    off += 4u;
    uint16_t llen = wr_load_be16(body.ptr + off);
    off += 2u;
    if (off + llen > body.len) {
        return WR_ERR_TRUNCATED;
    }
    out->label = wr_span_c_sub(body, off, llen);
    off += llen;
    if (off + 2u > body.len) {
        return WR_ERR_TRUNCATED;
    }
    uint16_t plen = wr_load_be16(body.ptr + off);
    off += 2u;
    if (off + plen > body.len) {
        return WR_ERR_TRUNCATED;
    }
    out->protocol = wr_span_c_sub(body, off, plen);
    return WR_OK;
}