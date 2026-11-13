#include "wr/ice.h"
#include "ice_internal.h"

#include <string.h>

wr_status wr_ice_send_check(wr_ice_agent *ag, size_t pair_idx, uint64_t now_ms,
                            bool use_candidate, const uint8_t *txid_in,
                            bool record)
{
    if (!ag || pair_idx >= ag->pairs.len || !ag->io) {
        return WR_ERR_STATE;
    }
    if (!ag->local_ufrag.ptr || !ag->remote_ufrag.ptr || !ag->local_pwd.ptr) {
        return WR_ERR_STATE;
    }
    uint8_t txid[12];
    if (txid_in) {
        memcpy(txid, txid_in, 12);
    } else {
        if (ag->rng) {
            if (wr_rng_fill(ag->rng, txid, sizeof(txid)) != WR_OK) {
                return WR_ERR_CRYPTO;
            }
        } else {
            memset(txid, 0, sizeof(txid));
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
    wr_status st = wr_stun_append_integrity(&m, ag->local_pwd.ptr,
                                            ag->local_pwd.len, (char *)buf,
                                            sizeof(buf), &n);
    if (st != WR_OK) {
        return st;
    }
    size_t sent = 0;
    st = wr_io_send(ag->io, &rc->addr, wr_span_c_make(buf, n), &sent);
    if (st != WR_OK) {
        return st;
    }

    p->state = WR_ICE_PAIR_IN_PROGRESS;
    p->last_check_ms = now_ms;
    p->checks_sent++;
    ag->checks_sent++;

    if (record) {
        wr_ice_check ck;
        memcpy(ck.txid, txid, 12);
        ck.pair = (uint32_t)pair_idx;
        ck.sent_ms = now_ms;
        ck.retransmits = 0u;
        ck.use_candidate = use_candidate;
        ck.done = false;
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
    return 0u;
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

wr_status wr_ice_handle_request(wr_ice_agent *ag, uint64_t now_ms,
                                const wr_endpoint *from, wr_stun_msg *m)
{
    if (!ag->remote_pwd.ptr || !wr_stun_verify_fingerprint(m) ||
        !wr_stun_verify_integrity(m, ag->remote_pwd.ptr, ag->remote_pwd.len)) {
        return WR_ERR_AUTH;
    }
    const wr_stun_attr *user = wr_stun_attr_find(m, WR_STUN_ATTR_USERNAME);
    if (!user || !is_valid_username(ag, user->value)) {
        return WR_ERR_AUTH;
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

