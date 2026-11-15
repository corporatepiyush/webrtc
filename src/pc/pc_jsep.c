#include "wr/pc.h"
#include "pc_internal.h"

#include "wr/sdp.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Minimal JSEP                                                              */
/* ------------------------------------------------------------------------- */

static void random_token(wr_rng *rng, char *out, size_t n)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (size_t i = 0; i < n; ++i) {
        out[i] = alpha[wr_rng_u64(rng) % (uint64_t)(sizeof(alpha) - 1u)];
    }
    out[n] = '\0';
}

static bool ensure_local_creds(wr_pc *pc)
{
    if (pc->has_local_creds) {
        return true;
    }
    if (!pc->rng) {
        /* Without an RNG the credentials would be a fixed, guessable
         * sequence. Refuse rather than mint deterministic ones. */
        return false;
    }
    random_token(pc->rng, pc->local_ufrag, 4);
    random_token(pc->rng, pc->local_pwd, 24);
    wr_ice_set_local_credentials(pc->ice,
                                 wr_span_c_from_str(pc->local_ufrag),
                                 wr_span_c_from_str(pc->local_pwd));
    pc->has_local_creds = true;
    return true;
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
    if (!ensure_local_creds(pc)) {
        return WR_ERR_STATE;
    }
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

    /* Remember which setup role we are advertising: it determines the DTLS
     * role (RFC 8842 5.1), which must not be inferred from the ICE role. */
    if (wr_span_c_case_eq(wr_span_c_from_str(setup),
                          wr_span_c_from_str("active"))) {
        pc->local_setup = WR_SDP_SETUP_ACTIVE;
        pc->have_local_setup = true;
    } else if (wr_span_c_case_eq(wr_span_c_from_str(setup),
                                 wr_span_c_from_str("passive"))) {
        pc->local_setup = WR_SDP_SETUP_PASSIVE;
        pc->have_local_setup = true;
    } else {
        pc->local_setup = WR_SDP_SETUP_ACTPASS;
        pc->have_local_setup = false;
    }
    wr_pc_update_dtls_role(pc);

    char port_str[8];
    (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)pc->sctp_port);
    char msize_str[16];
    (void)snprintf(msize_str, sizeof(msize_str), "%u",
                   (unsigned)WR_PC_MAX_MESSAGE_SIZE);

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
    (void)add_attr(&m.attr, "sctp-port", port_str);
    (void)add_attr(&m.attr, "max-message-size", msize_str);
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
    /* The answerer picks the setup role, but it must be the opposite of the
     * offer's (RFC 3264 6.1 / RFC 8842 5.1). Answering "active" to an offer
     * of "active" makes both sides the DTLS client and the handshake can never
     * complete. */
    const char *setup = pc->remote_setup == WR_SDP_SETUP_ACTIVE ? "passive"
                                                               : "active";
    return build_sdp(pc, setup, buf, cap, out_len);
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
    /* RFC 8841: the peer's SCTP port is signalled in the SDP. */
    const wr_sdp_attr *sctp_port = wr_sdp_attr_find(&m->attr,
                                                   wr_span_c_from_str("sctp-port"));
    if (sctp_port) {
        uint32_t v = 0u;
        if (wr_parse_u32(sctp_port->value, &v) && v != 0u && v <= UINT16_MAX) {
            pc->remote_sctp_port = (uint16_t)v;
        }
    }
    /* The setup attribute decides the DTLS role (RFC 8842 5.1). */
    const wr_sdp_attr *setup = wr_sdp_attr_find(&m->attr,
                                               wr_span_c_from_str("setup"));
    if (setup) {
        if (wr_span_c_case_eq(setup->value, wr_span_c_from_str("active"))) {
            pc->remote_setup = WR_SDP_SETUP_ACTIVE;
        } else if (wr_span_c_case_eq(setup->value,
                                     wr_span_c_from_str("passive"))) {
            pc->remote_setup = WR_SDP_SETUP_PASSIVE;
        } else if (wr_span_c_case_eq(setup->value,
                                     wr_span_c_from_str("actpass"))) {
            pc->remote_setup = WR_SDP_SETUP_ACTPASS;
        } else {
            return WR_ERR_UNSUPPORTED;
        }
        pc->have_remote_setup = true;
        wr_pc_update_dtls_role(pc);
    }

    /* Fail closed: an unrecognised fingerprint hash (sha-1, sha-384, ...) must
     * abort the session. Silently continuing without a peer fingerprint would
     * disable DTLS authentication entirely. */
    const wr_sdp_attr *fp = wr_sdp_attr_find(&m->attr,
                                             wr_span_c_from_str("fingerprint"));
    if (fp) {
        wr_sdp_fingerprint f;
        if (!wr_sdp_fingerprint_parse(fp->value, &f) || f.len != 32u) {
            return WR_ERR_UNSUPPORTED;
        }
        memcpy(pc->peer_fp, f.value, sizeof(pc->peer_fp));
        pc->have_peer_fp = true;
        if (pc->dtls) {
            (void)wr_dtls_set_peer_fingerprint(pc->dtls, pc->peer_fp, 32u);
        }
    } else if (pc->dtls_enabled) {
        /* No fingerprint means the peer's certificate cannot be verified.
         * Refuse here so the failure lands on the description that caused it,
         * not later when the handshake is already running. */
        return WR_ERR_UNSUPPORTED;
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
