#include "wr/pc.h"
#include "pc_internal.h"

#include "wr/sdp.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* Minimal JSEP                                                              */
/* ------------------------------------------------------------------------- */

static void random_token(wr_rng *rng, char *out, size_t n)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (rng) {
        for (size_t i = 0; i < n; ++i) {
            out[i] = alpha[wr_rng_u64(rng) % (uint64_t)(sizeof(alpha) - 1u)];
        }
    } else {
        for (size_t i = 0; i < n; ++i) {
            out[i] = alpha[(i * 7u + 3u) % (sizeof(alpha) - 1u)];
        }
    }
    out[n] = '\0';
}

static void ensure_local_creds(wr_pc *pc)
{
    if (pc->has_local_creds) {
        return;
    }
    random_token(pc->rng, pc->local_ufrag, 4);
    random_token(pc->rng, pc->local_pwd, 24);
    wr_ice_set_local_credentials(pc->ice,
                                 wr_span_c_from_str(pc->local_ufrag),
                                 wr_span_c_from_str(pc->local_pwd));
    pc->has_local_creds = true;
}

static bool add_attr(wr_sdp_attr_vec *v, const char *name, const char *value)
{
    return wr_sdp_attr_add(v, wr_span_c_from_str(name),
                           wr_span_c_from_str(value));
}

static wr_status build_sdp(wr_pc *pc, const char *setup, char *buf,
                           size_t cap, size_t *out_len)
{
    if (!pc || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    ensure_local_creds(pc);
    const uint8_t *fp = NULL;
    size_t fp_len = 0u;
    if (!wr_pc_local_fingerprint(pc, &fp, &fp_len)) {
        return WR_ERR_STATE;
    }
    char fp_hex[128];
    size_t off = 0u;
    memcpy(fp_hex + off, "sha-256 ", 8u);
    off += 8u;
    for (size_t i = 0; i < fp_len && off + 3u < sizeof(fp_hex); ++i) {
        static const char hex[] = "0123456789abcdef";
        fp_hex[off++] = hex[fp[i] >> 4];
        fp_hex[off++] = hex[fp[i] & 0x0fu];
        if (i + 1u < fp_len) {
            fp_hex[off++] = ':';
        }
    }
    fp_hex[off] = '\0';

    wr_sdp_session s;
    memset(&s, 0, sizeof(s));
    wr_sdp_attr_vec_init(&s.attr, pc->a);
    wr_sdp_media_vec_init(&s.media, pc->a);
    s.version = wr_span_c_from_str("0");
    s.origin = wr_span_c_from_str("- 1 1 IN IP4 127.0.0.1");
    s.name = wr_span_c_from_str("-");
    s.timing = wr_span_c_from_str("0 0");

    wr_sdp_media m;
    memset(&m, 0, sizeof(m));
    wr_span_c_vec_init(&m.fmt, pc->a);
    wr_sdp_attr_vec_init(&m.attr, pc->a);
    m.type = wr_span_c_from_str("application");
    m.port = 9u;
    m.port_count = 1u;
    m.proto = wr_span_c_from_str("UDP/DTLS/SCTP");
    (void)wr_span_c_vec_push(&m.fmt,
                             wr_span_c_from_str("webrtc-datachannel"));
    (void)add_attr(&m.attr, "mid", "0");
    (void)add_attr(&m.attr, "ice-ufrag", pc->local_ufrag);
    (void)add_attr(&m.attr, "ice-pwd", pc->local_pwd);
    (void)add_attr(&m.attr, "fingerprint", fp_hex);
    (void)add_attr(&m.attr, "setup", setup);
    (void)add_attr(&m.attr, "sctp-port", "5000");
    (void)add_attr(&m.attr, "max-message-size", "262144");
    (void)wr_sdp_media_vec_push(&s.media, m);

    return wr_sdp_serialize(&s, buf, cap, out_len);
}

wr_status wr_pc_create_offer(wr_pc *pc, char *buf, size_t cap, size_t *out_len)
{
    if (!pc) {
        return WR_ERR_INVAL;
    }
    wr_pc_enable_dtls(pc);
    return build_sdp(pc, "actpass", buf, cap, out_len);
}

wr_status wr_pc_create_answer(wr_pc *pc, wr_span_c offer, char *buf,
                              size_t cap, size_t *out_len)
{
    if (!pc) {
        return WR_ERR_INVAL;
    }
    if (offer.ptr && offer.len) {
        wr_status st = wr_pc_set_remote_description(pc, offer);
        if (st != WR_OK) {
            return st;
        }
    }
    return build_sdp(pc, "active", buf, cap, out_len);
}

wr_status wr_pc_set_remote_description(wr_pc *pc, wr_span_c sdp)
{
    if (!pc || !sdp.ptr) {
        return WR_ERR_INVAL;
    }
    wr_sdp_session s;
    wr_status st = wr_sdp_parse(pc->a, sdp, WR_SDP_LIBERAL, &s);
    if (st != WR_OK) {
        return st;
    }
    const wr_sdp_media *m = wr_sdp_find_media_by_type(&s,
                                                      wr_span_c_from_str(
                                                          "application"));
    if (!m && s.media.len) {
        m = &s.media.data[0];
    }
    if (!m) {
        return WR_ERR_NOT_FOUND;
    }

    wr_sdp_ice ice;
    (void)wr_sdp_ice_parse(&s, m, &ice);
    if (ice.present) {
        wr_ice_set_remote_credentials(pc->ice, ice.ufrag, ice.pwd);
    }
    const wr_sdp_attr *fp = wr_sdp_attr_find(&m->attr,
                                             wr_span_c_from_str("fingerprint"));
    if (fp) {
        wr_sdp_fingerprint f;
        if (wr_sdp_fingerprint_parse(fp->value, &f)) {
            memcpy(pc->peer_fp, f.value, WR_MIN(f.len, sizeof(pc->peer_fp)));
            pc->have_peer_fp = f.len == 32u;
            if (pc->dtls && pc->have_peer_fp) {
                (void)wr_dtls_set_peer_fingerprint(pc->dtls, pc->peer_fp,
                                                   32u);
            }
        }
    }

    bool added = false;
    for (size_t i = 0; i < m->attr.len; ++i) {
        const wr_sdp_attr *a = &m->attr.data[i];
        if (!wr_span_c_case_eq(a->name, wr_span_c_from_str("candidate"))) {
            continue;
        }
        wr_sdp_candidate c;
        if (wr_sdp_candidate_parse(a->value, &c)) {
            (void)wr_ice_add_remote_candidate(pc->ice, c.addr,
                                              WR_ICE_CAND_HOST, 1u);
            added = true;
        }
    }
    if (!added && m->has_conn) {
        wr_endpoint e = m->conn;
        e.port = m->port;
        (void)wr_ice_add_remote_candidate(pc->ice, e, WR_ICE_CAND_HOST, 1u);
    }
    return WR_OK;
}
