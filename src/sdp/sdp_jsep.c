#include "wr/sdp.h"
#include "sdp_internal.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* JSEP helpers                                                              */
/* ------------------------------------------------------------------------- */

static const wr_sdp_attr *attr_on(const wr_sdp_session *s, const wr_sdp_media *m,
                                  wr_span_c name)
{
    const wr_sdp_attr *a = m ? wr_sdp_attr_find(&m->attr, name) : NULL;
    if (!a && s) {
        a = wr_sdp_attr_find(&s->attr, name);
    }
    return a;
}

wr_status wr_sdp_ice_parse(const wr_sdp_session *s, const wr_sdp_media *m,
                           wr_sdp_ice *out)
{
    if (!s || !out) {
        return WR_ERR_INVAL;
    }
    memset(out, 0, sizeof(*out));
    const wr_sdp_attr *a = attr_on(s, m, wr_span_c_from_str("ice-ufrag"));
    if (a && a->value.len > 0u) {
        out->ufrag = a->value;
        out->has_ufrag = true;
    }
    a = attr_on(s, m, wr_span_c_from_str("ice-pwd"));
    if (a && a->value.len > 0u) {
        out->pwd = a->value;
        out->has_pwd = true;
    }
    /* `present` means "usable ICE parameters were supplied": a half-specified
     * ufrag/pwd pair must not look like a complete one, or the caller will
     * install a truncated credential and every check will fail to verify. */
    out->present = out->has_ufrag && out->has_pwd;
    a = attr_on(s, m, wr_span_c_from_str("ice-options"));
    if (a) {
        out->options = a->value;
    }
    a = attr_on(s, m, wr_span_c_from_str("ice-lite"));
    if (a) {
        out->ice_lite = true;
    }
    a = attr_on(s, m, wr_span_c_from_str("end-of-candidates"));
    if (a) {
        out->end_of_candidates = true;
    }
    return WR_OK;
}

bool wr_sdp_candidate_parse(wr_span_c value, wr_sdp_candidate *out)
{
    if (!out || value.len == 0u) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wr_span_c rest = value;
    wr_span_c t[8];
    for (size_t i = 0; i < 8; ++i) {
        if (!sdp_tok_next(&rest, &t[i])) {
            return false;
        }
    }
    out->foundation = t[0];
    if (!wr_parse_u32(t[1], &out->component) || out->component == 0u) {
        return false;
    }
    out->transport = t[2];
    if (!wr_parse_u64(t[3], &out->priority)) {
        return false;
    }
    if (!sdp_parse_addr(t[4], &out->addr)) {
        return false;
    }
    uint32_t port;
    if (!wr_parse_u32(t[5], &port) || port > UINT16_MAX) {
        return false;
    }
    out->addr.port = (uint16_t)port;
    if (!wr_span_c_case_eq(t[6], wr_span_c_from_str("typ"))) {
        return false;
    }
    if (wr_span_c_case_eq(t[7], wr_span_c_from_str("host"))) {
        out->type = WR_SDP_CAND_HOST;
    } else if (wr_span_c_case_eq(t[7], wr_span_c_from_str("srflx"))) {
        out->type = WR_SDP_CAND_SRFLX;
    } else if (wr_span_c_case_eq(t[7], wr_span_c_from_str("prflx"))) {
        out->type = WR_SDP_CAND_PRFLX;
    } else if (wr_span_c_case_eq(t[7], wr_span_c_from_str("relay"))) {
        out->type = WR_SDP_CAND_RELAY;
    } else {
        return false;
    }

    wr_span_c opt;
    while (sdp_tok_next(&rest, &opt)) {
        if (wr_span_c_case_eq(opt, wr_span_c_from_str("raddr"))) {
            wr_span_c addr;
            if (!sdp_tok_next(&rest, &addr) || !sdp_parse_addr(addr, &out->raddr)) {
                return false;
            }
            out->has_raddr = true;
        } else if (wr_span_c_case_eq(opt, wr_span_c_from_str("rport"))) {
            wr_span_c p;
            uint32_t pv;
            if (!sdp_tok_next(&rest, &p) || !wr_parse_u32(p, &pv) ||
                pv > UINT16_MAX) {
                return false;
            }
            out->raddr.port = (uint16_t)pv;
            out->has_raddr = true;
        } else if (wr_span_c_case_eq(opt, wr_span_c_from_str("generation"))) {
            wr_span_c g;
            if (!sdp_tok_next(&rest, &g)) {
                return false;
            }
        } else if (wr_span_c_case_eq(opt, wr_span_c_from_str("ufrag"))) {
            if (!sdp_tok_next(&rest, &out->ufrag)) {
                return false;
            }
            out->has_ufrag = true;
        }
    }
    return true;
}

bool wr_sdp_fingerprint_parse(wr_span_c value, wr_sdp_fingerprint *out)
{
    if (!out || value.len == 0u) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wr_span_c rest = value;
    wr_span_c hash, fp;
    if (!sdp_tok_next(&rest, &hash) || !sdp_tok_next(&rest, &fp)) {
        return false;
    }
    out->present = true;
    out->hash = hash;
    if (!wr_span_c_case_eq(hash, wr_span_c_from_str("sha-256"))) {
        return false;
    }
    size_t nibbles = 0;
    for (size_t i = 0; i < fp.len; ++i) {
        if (fp.ptr[i] == ':') {
            continue;
        }
        uint8_t v;
        if (!sdp_parse_hex(fp.ptr[i], &v) || out->len >= sizeof(out->value)) {
            return false;
        }
        if ((nibbles & 1u) == 0u) {
            out->value[out->len] = (uint8_t)(v << 4);
        } else {
            out->value[out->len] |= v;
            out->len++;
        }
        nibbles++;
    }
    return nibbles == sizeof(out->value) * 2u;
}

wr_sdp_setup wr_sdp_setup_parse(wr_span_c value)
{
    if (wr_span_c_case_eq(value, wr_span_c_from_str("active"))) {
        return WR_SDP_SETUP_ACTIVE;
    }
    if (wr_span_c_case_eq(value, wr_span_c_from_str("passive"))) {
        return WR_SDP_SETUP_PASSIVE;
    }
    if (wr_span_c_case_eq(value, wr_span_c_from_str("actpass"))) {
        return WR_SDP_SETUP_ACTPASS;
    }
    if (wr_span_c_case_eq(value, wr_span_c_from_str("holdconn"))) {
        return WR_SDP_SETUP_HOLDCON;
    }
    return WR_SDP_SETUP_UNSET;
}

const char *wr_sdp_setup_str(wr_sdp_setup setup)
{
    switch (setup) {
    case WR_SDP_SETUP_ACTIVE:  return "active";
    case WR_SDP_SETUP_PASSIVE: return "passive";
    case WR_SDP_SETUP_ACTPASS: return "actpass";
    case WR_SDP_SETUP_HOLDCON: return "holdconn";
    case WR_SDP_SETUP_UNSET:   return "unset";
    default:                   return "unset";
    }
}

bool wr_sdp_extmap_parse(wr_span_c value, wr_sdp_extmap *out)
{
    if (!out || value.len == 0u) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wr_span_c rest = value;
    wr_span_c id;
    if (!sdp_tok_next(&rest, &id)) {
        return false;
    }
    const uint8_t *slash = memchr(id.ptr, '/', id.len);
    wr_span_c idpart = id;
    if (slash) {
        idpart = wr_span_c_sub(id, 0, (size_t)(slash - id.ptr));
    }
    if (!wr_parse_u32(idpart, &out->id)) {
        return false;
    }
    if (!sdp_tok_next(&rest, &out->uri)) {
        return false;
    }
    return out->uri.len > 0u;
}

bool wr_sdp_rtcp_fb_parse(wr_span_c value, wr_sdp_rtcp_fb *out)
{
    if (!out || value.len == 0u) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wr_span_c rest = value;
    wr_span_c fmt, type;
    if (!sdp_tok_next(&rest, &fmt)) {
        return false;
    }
    if (wr_span_c_case_eq(fmt, wr_span_c_from_str("*"))) {
        out->fmt = UINT32_MAX;
    } else if (!wr_parse_u32(fmt, &out->fmt)) {
        return false;
    }
    if (!sdp_tok_next(&rest, &type)) {
        return false;
    }
    out->type = type;
    (void)sdp_tok_next(&rest, &out->param);
    return true;
}

const wr_sdp_media *wr_sdp_find_media(const wr_sdp_session *s, wr_span_c mid)
{
    if (!s) {
        return NULL;
    }
    for (size_t i = 0; i < s->media.len; ++i) {
        const wr_sdp_attr *a = wr_sdp_attr_find(&s->media.data[i].attr,
                                                wr_span_c_from_str("mid"));
        if (a && wr_span_c_case_eq(a->value, mid)) {
            return &s->media.data[i];
        }
    }
    return NULL;
}

const wr_sdp_media *wr_sdp_find_media_by_type(const wr_sdp_session *s,
                                              wr_span_c type)
{
    if (!s) {
        return NULL;
    }
    for (size_t i = 0; i < s->media.len; ++i) {
        if (wr_span_c_case_eq(s->media.data[i].type, type)) {
            return &s->media.data[i];
        }
    }
    return NULL;
}
