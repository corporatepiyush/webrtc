#include "wr/ice.h"
#include "ice_internal.h"

#include <string.h>

/* Drop finished entries in place so the check vector stays bounded; used when
 * the cap is reached (long-lived sessions run consent checks forever). */
static void compact_checks(wr_ice_agent *ag)
{
    size_t w = 0u;
    for (size_t i = 0; i < ag->checks.len; ++i) {
        if (ag->checks.data[i].done) {
            continue;
        }
        if (w != i) {
            ag->checks.data[w] = ag->checks.data[i];
        }
        w++;
    }
    ag->checks.len = w;
}

wr_status wr_ice_send_check(wr_ice_agent *ag, size_t pair_idx, uint64_t now_ms,
                            bool use_candidate, const uint8_t *txid_in,
                            bool record)
{
    if (!ag || pair_idx >= ag->pairs.len || !ag->io) {
        return WR_ERR_STATE;
    }
    if (!ag->local_ufrag.ptr || !ag->remote_ufrag.ptr || !ag->remote_pwd.ptr) {
        return WR_ERR_STATE;
    }
    uint8_t txid[12];
    if (txid_in) {
        memcpy(txid, txid_in, 12);
    } else {
        /* The RNG is required at create time, so a check without an explicit
         * transaction id always gets a random one. */
        if (wr_rng_fill(ag->rng, txid, sizeof(txid)) != WR_OK) {
            return WR_ERR_CRYPTO;
        }
    }

    wr_ice_pair *p = &ag->pairs.data[pair_idx];
    const wr_ice_cand *lc = &ag->local.data[p->local];
    const wr_ice_cand *rc = &ag->remote.data[p->remote];

    char *user = (char *)wr_arena_alloc(ag->a, ag->remote_ufrag.len +
                                                       1u +
                                                       ag->local_ufrag.len);
    if (!user) {
        return WR_ERR_NOMEM;
    }
    memcpy(user, ag->remote_ufrag.ptr, ag->remote_ufrag.len);
    user[ag->remote_ufrag.len] = ':';
    memcpy(user + ag->remote_ufrag.len + 1u, ag->local_ufrag.ptr,
           ag->local_ufrag.len);

    wr_stun_msg m;
    wr_stun_msg_init(&m, ag->a, wr_stun_type(WR_STUN_METHOD_BINDING,
                                             WR_STUN_CLASS_REQUEST),
                     txid);
    if (!wr_stun_attr_add(&m, WR_STUN_ATTR_USERNAME,
                          wr_span_c_make(user,
                                         ag->remote_ufrag.len + 1u +
                                             ag->local_ufrag.len))) {
        return WR_ERR_NOMEM;
    }
    uint8_t pri[4];
    wr_store_be32(pri, (uint32_t)lc->priority);
    if (!wr_stun_attr_add(&m, WR_STUN_ATTR_PRIORITY, wr_span_c_make(pri, 4))) {
        return WR_ERR_NOMEM;
    }
    uint8_t tie[8];
    wr_store_be64(tie, ag->tie_breaker);
    uint16_t tie_type = ag->cfg.role == WR_ICE_ROLE_CONTROLLING
                            ? WR_STUN_ATTR_ICE_CONTROLLING
                            : WR_STUN_ATTR_ICE_CONTROLLED;
    if (!wr_stun_attr_add(&m, tie_type, wr_span_c_make(tie, 8))) {
        return WR_ERR_NOMEM;
    }
    if (use_candidate) {
        (void)wr_stun_attr_add(&m, WR_STUN_ATTR_USE_CANDIDATE,
                               wr_span_c_make(NULL, 0));
    }

    uint8_t buf[1024];
    size_t n = 0;
    /* RFC 8445 7.2.4: a Binding request is integrity-protected with the
     * *peer's* password (the remote credentials), not our own. */
    wr_status st = wr_stun_append_integrity(&m, ag->remote_pwd.ptr,
                                            ag->remote_pwd.len, (char *)buf,
                                            sizeof(buf), &n);
    if (st != WR_OK) {
        return st;
    }
    size_t sent = 0;
    st = wr_io_send(ag->io, &rc->addr, wr_span_c_make(buf, n), &sent);
    if (st != WR_OK) {
        return st;
    }

    p->last_check_ms = now_ms;
    p->checks_sent++;
    ag->checks_sent++;
    if (p->state != WR_ICE_PAIR_SUCCEEDED) {
        p->state = WR_ICE_PAIR_IN_PROGRESS;
    }

    if (record) {
        wr_ice_check ck;
        memcpy(ck.txid, txid, 12);
        ck.pair = (uint32_t)pair_idx;
        ck.sent_ms = now_ms;
        ck.retransmits = 0u;
        ck.use_candidate = use_candidate;
        ck.done = false;
        if (ag->checks.len >= WR_ICE_MAX_CHECKS) {
            compact_checks(ag);
        }
        if (ag->checks.len >= WR_ICE_MAX_CHECKS) {
            /* Still full: drop the oldest recorded check so the vector cannot
             * grow without bound across a long-lived session (consent checks
             * fire every interval forever). */
            memmove(&ag->checks.data[0], &ag->checks.data[1],
                    (ag->checks.len - 1u) * sizeof(ag->checks.data[0]));
            ag->checks.len--;
        }
        if (!wr_ice_check_vec_push(&ag->checks, ck)) {
            return WR_ERR_NOMEM;
        }
    }
    return WR_OK;
}

bool wr_ice_all_pairs_done(const wr_ice_agent *ag, bool *any_success)
{
    bool success = false;
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        uint8_t s = ag->pairs.data[i].state;
        if (s != WR_ICE_PAIR_SUCCEEDED && s != WR_ICE_PAIR_FAILED) {
            return false;
        }
        if (s == WR_ICE_PAIR_SUCCEEDED) {
            success = true;
        }
    }
    if (any_success) {
        *any_success = success;
    }
    return true;
}

void wr_ice_mark_pair_success(wr_ice_agent *ag, size_t idx, uint64_t now_ms)
{
    wr_ice_pair *p = &ag->pairs.data[idx];
    p->state = WR_ICE_PAIR_SUCCEEDED;
    p->last_response_ms = now_ms;
    ag->last_response_ms = now_ms;
    ag->responses++;
    if (ag->selected == UINT32_MAX ||
        p->priority > ag->pairs.data[ag->selected].priority) {
        ag->selected = (uint32_t)idx;
    }
    if (ag->state == WR_ICE_NOT_STARTED || ag->state == WR_ICE_CHECKING) {
        ag->state = WR_ICE_CONNECTED;
    }
    if (ag->cfg.role == WR_ICE_ROLE_CONTROLLING && !p->nominated &&
        ag->selected == (uint32_t)idx) {
        p->nominated = true;
        (void)wr_ice_send_check(ag, idx, now_ms, true, NULL, true);
    }
    bool any = false;
    if (wr_ice_all_pairs_done(ag, &any)) {
        if (!any) {
            ag->state = WR_ICE_FAILED;
        } else if (ag->cfg.role == WR_ICE_ROLE_CONTROLLED ||
                   ag->nomination_ack) {
            ag->state = WR_ICE_COMPLETED;
        } else {
            ag->state = WR_ICE_CONNECTED;
        }
    }
}

static size_t find_local_for_addr(const wr_ice_agent *ag,
                                  const wr_endpoint *addr)
{
    for (size_t i = 0; i < ag->local.len; ++i) {
        if (wr_endpoint_eq(&ag->local.data[i].addr, addr)) {
            return i;
        }
    }
    /* No local candidate matches the address we would answer on. Returning 0
     * would silently attribute the check to the wrong pair; signal "none"
     * instead so the caller can reject it. */
    return (size_t)-1;
}

static size_t find_remote_for_addr(const wr_ice_agent *ag,
                                   const wr_endpoint *addr,
                                   uint16_t component)
{
    for (size_t i = 0; i < ag->remote.len; ++i) {
        if (ag->remote.data[i].component == component &&
            wr_endpoint_eq(&ag->remote.data[i].addr, addr)) {
            return i;
        }
    }
    return (size_t)-1;
}

static bool is_valid_username(const wr_ice_agent *ag, wr_span_c u)
{
    if (!ag->remote_ufrag.ptr || !ag->local_ufrag.ptr) {
        return false;
    }
    size_t n = ag->remote_ufrag.len + 1u + ag->local_ufrag.len;
    if (u.len != n) {
        return false;
    }
    if (u.ptr[ag->local_ufrag.len] != ':') {
        return false;
    }
    return memcmp(u.ptr, ag->local_ufrag.ptr, ag->local_ufrag.len) == 0 &&
           memcmp(u.ptr + ag->local_ufrag.len + 1u, ag->remote_ufrag.ptr,
                  ag->remote_ufrag.len) == 0;
}

/* RFC 8445 7.3.1.1 role-conflict detection and repair. Returns true when the
 * request must not be processed further (a 487 error response was sent). On a
 * role switch the request is still processed, using the new role. */
static bool handle_role_conflict(wr_ice_agent *ag, const wr_stun_msg *m,
                                 const wr_endpoint *from)
{
    const wr_stun_attr *ctrl = wr_stun_attr_find(m, WR_STUN_ATTR_ICE_CONTROLLING);
    const wr_stun_attr *ctl = wr_stun_attr_find(m, WR_STUN_ATTR_ICE_CONTROLLED);
    const wr_stun_attr *peer_tie_attr = NULL;
    bool we_are_controlling = ag->cfg.role == WR_ICE_ROLE_CONTROLLING;

    if (we_are_controlling && ctrl) {
        peer_tie_attr = ctrl;
    } else if (!we_are_controlling && ctl) {
        peer_tie_attr = ctl;
    } else {
        return false; /* no conflict (or the peer's role matches ours) */
    }
    if (!peer_tie_attr || peer_tie_attr->value.len != 8u) {
        return false;
    }
    uint64_t peer_tie = wr_load_be64(peer_tie_attr->value.ptr);
    bool peer_wins = we_are_controlling ? (ag->tie_breaker < peer_tie)
                                        : (ag->tie_breaker >= peer_tie);
    if (!peer_wins) {
        /* Retain our role and answer 487 Role Conflict. */
        wr_stun_msg r;
        wr_stun_msg_init(&r, ag->a,
                         wr_stun_type(WR_STUN_METHOD_BINDING,
                                      WR_STUN_CLASS_ERROR),
                         m->txid);
        uint8_t ec[4] = { 0x00u, 0x00u, 0x01u, 0xe7u }; /* 487 = class 4, 87 */
        if (!wr_stun_attr_add(&r, WR_STUN_ATTR_ERROR_CODE,
                              wr_span_c_make(ec, sizeof(ec)))) {
            return true;
        }
        uint8_t buf[512];
        size_t n = 0u;
        /* A response is signed with the same key the request was verified
         * with: our local password. */
        if (wr_stun_append_integrity(&r, ag->local_pwd.ptr, ag->local_pwd.len,
                                     (char *)buf, sizeof(buf), &n) != WR_OK) {
            return true;
        }
        size_t sent = 0u;
        (void)wr_io_send(ag->io, from, wr_span_c_make(buf, n), &sent);
        return true;
    }

    /* Switch roles and recompute pair priorities (RFC 8445 7.3.1.1). */
    ag->cfg.role = we_are_controlling ? WR_ICE_ROLE_CONTROLLED
                                      : WR_ICE_ROLE_CONTROLLING;
    wr_ice_recompute_pair_priorities(ag);
    return false;
}

wr_status wr_ice_handle_request(wr_ice_agent *ag, uint64_t now_ms,
                                const wr_endpoint *from, wr_stun_msg *m)
{
    /* RFC 8445 7.2.2 / 7.3.1: an incoming Binding request is integrity-
     * protected with *our* (local) password, not the peer's. */
    if (!ag->local_pwd.ptr || !wr_stun_verify_fingerprint(m) ||
        !wr_stun_verify_integrity(m, ag->local_pwd.ptr, ag->local_pwd.len)) {
        return WR_ERR_AUTH;
    }
    const wr_stun_attr *user = wr_stun_attr_find(m, WR_STUN_ATTR_USERNAME);
    if (!user || !is_valid_username(ag, user->value)) {
        return WR_ERR_AUTH;
    }
    if (handle_role_conflict(ag, m, from)) {
        /* 487 sent: the request is not processed further. */
        return WR_OK;
    }
    bool use_candidate =
        wr_stun_attr_find(m, WR_STUN_ATTR_USE_CANDIDATE) != NULL;

    size_t ri = find_remote_for_addr(ag, from, ag->cfg.component);
    if (ri == (size_t)-1) {
        ri = wr_ice_add_remote_candidate(ag, *from, WR_ICE_CAND_PRFLX,
                                         ag->cfg.component);
        if (ri == UINT32_MAX || ri >= ag->remote.len) {
            return WR_ERR_LIMIT;
        }
    }
    size_t li = find_local_for_addr(ag, &ag->local_addr);
    if (li >= ag->local.len) {
        return WR_ERR_STATE;
    }
    if (wr_ice_pair_find(ag, (uint32_t)li, (uint32_t)ri) < 0) {
        if (!wr_ice_add_pair(ag, (uint32_t)li, (uint32_t)ri)) {
            return WR_ERR_LIMIT;
        }
    }
    int pi = wr_ice_pair_find(ag, (uint32_t)li, (uint32_t)ri);
    if (pi < 0) {
        return WR_ERR_STATE;
    }
    wr_ice_mark_pair_success(ag, (size_t)pi, now_ms);
    if (use_candidate && ag->cfg.role == WR_ICE_ROLE_CONTROLLED) {
        ag->pairs.data[pi].nominated = true;
        ag->state = WR_ICE_COMPLETED;
    }

    wr_stun_msg r;
    wr_stun_msg_init(&r, ag->a,
                     wr_stun_type(WR_STUN_METHOD_BINDING,
                                  WR_STUN_CLASS_SUCCESS),
                     m->txid);
    uint8_t addrbuf[20];
    size_t alen = 0u;
    if (!wr_stun_addr_encode(addrbuf, sizeof(addrbuf), from, true, m->txid,
                             &alen)) {
        return WR_ERR_INVAL;
    }
    if (!wr_stun_attr_add(&r, WR_STUN_ATTR_XOR_MAPPED_ADDRESS,
                          wr_span_c_make(addrbuf, alen))) {
        return WR_ERR_NOMEM;
    }
    uint8_t buf[1024];
    size_t n = 0;
    wr_status st = wr_stun_append_integrity(&r, ag->local_pwd.ptr,
                                            ag->local_pwd.len, (char *)buf,
                                            sizeof(buf), &n);
    if (st != WR_OK) {
        return st;
    }
    size_t sent = 0;
    wr_status sst = wr_io_send(ag->io, from, wr_span_c_make(buf, n), &sent);
    return sst;
}

wr_status wr_ice_handle_response(wr_ice_agent *ag, uint64_t now_ms,
                                 const wr_endpoint *from, wr_stun_msg *m)
{
    if (!ag->remote_pwd.ptr || !wr_stun_verify_fingerprint(m) ||
        !wr_stun_verify_integrity(m, ag->remote_pwd.ptr, ag->remote_pwd.len)) {
        return WR_ERR_AUTH;
    }
    for (size_t i = 0; i < ag->checks.len; ++i) {
        if (ag->checks.data[i].done) {
            continue;
        }
        if (memcmp(ag->checks.data[i].txid, m->txid, 12) != 0) {
            continue;
        }
        ag->checks.data[i].done = true;
        uint32_t pi = ag->checks.data[i].pair;
        if (pi >= ag->pairs.len) {
            return WR_ERR_STATE;
        }
        const wr_ice_cand *rc = &ag->remote.data[ag->pairs.data[pi].remote];
        if (!wr_endpoint_eq(&rc->addr, from)) {
            return WR_ERR_AUTH;
        }
        wr_ice_mark_pair_success(ag, pi, now_ms);
        if (ag->cfg.role == WR_ICE_ROLE_CONTROLLING &&
            ag->checks.data[i].use_candidate) {
            ag->nomination_ack = true;
            bool any = false;
            if (wr_ice_all_pairs_done(ag, &any) && any) {
                ag->state = WR_ICE_COMPLETED;
            }
        }
        return WR_OK;
    }
    return WR_ERR_NOT_FOUND;
}

