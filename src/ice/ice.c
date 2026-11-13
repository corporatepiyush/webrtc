#include "wr/ice.h"
#include "ice_internal.h"

#include <string.h>

void wr_ice_config_defaults(wr_ice_config *cfg)
{
    if (!cfg) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->role = WR_ICE_ROLE_CONTROLLED;
    cfg->component = 1u;
    cfg->max_pairs = 64u;
    cfg->check_rto_ms = 500u;
    cfg->max_retransmits = 7u;
    cfg->consent_freshness = true;
    cfg->consent_interval_ms = 5000u;
    cfg->consent_timeout_ms = 15000u;
}

wr_ice_agent *wr_ice_create(wr_arena *a, const wr_ice_config *cfg,
                            wr_rng *rng)
{
    if (!a) {
        return NULL;
    }
    wr_ice_agent *ag = (wr_ice_agent *)wr_arena_calloc(a, 1, sizeof(*ag));
    if (!ag) {
        return NULL;
    }
    ag->a = a;
    ag->rng = rng;
    if (cfg) {
        ag->cfg = *cfg;
    } else {
        wr_ice_config_defaults(&ag->cfg);
    }
    if (ag->cfg.check_rto_ms == 0u) {
        ag->cfg.check_rto_ms = 500u;
    }
    if (ag->cfg.max_pairs == 0u) {
        ag->cfg.max_pairs = 64u;
    }
    if (ag->cfg.consent_interval_ms == 0u) {
        ag->cfg.consent_interval_ms = 5000u;
    }
    if (ag->cfg.consent_timeout_ms == 0u) {
        ag->cfg.consent_timeout_ms = 15000u;
    }
    wr_ice_cand_vec_init(&ag->local, a);
    wr_ice_cand_vec_init(&ag->remote, a);
    wr_ice_pair_vec_init(&ag->pairs, a);
    wr_ice_check_vec_init(&ag->checks, a);
    if (!ag->local.a || !ag->remote.a || !ag->pairs.a || !ag->checks.a) {
        return NULL;
    }
    ag->selected = UINT32_MAX;
    ag->tie_breaker = rng ? wr_rng_u64(rng) : 0x1234567890abcdefULL;
    if (ag->tie_breaker == 0u) {
        ag->tie_breaker = 1u;
    }
    return ag;
}

void wr_ice_destroy(wr_ice_agent *ag)
{
    WR_UNUSED(ag);
}

static char *dup_span(wr_ice_agent *ag, wr_span_c s, wr_span_c *out)
{
    if (!s.ptr || s.len == 0u || s.len > 512u) {
        out->ptr = NULL;
        out->len = 0u;
        return NULL;
    }
    char *p = (char *)wr_arena_alloc(ag->a, s.len);
    if (!p) {
        return NULL;
    }
    memcpy(p, s.ptr, s.len);
    out->ptr = (const uint8_t *)p;
    out->len = s.len;
    return p;
}

void wr_ice_set_local_credentials(wr_ice_agent *ag, wr_span_c ufrag,
                                  wr_span_c pwd)
{
    if (!ag) {
        return;
    }
    if (ufrag.len <= 256u && pwd.len <= 256u) {
        (void)dup_span(ag, ufrag, &ag->local_ufrag);
        (void)dup_span(ag, pwd, &ag->local_pwd);
    }
}

void wr_ice_set_remote_credentials(wr_ice_agent *ag, wr_span_c ufrag,
                                   wr_span_c pwd)
{
    if (!ag) {
        return;
    }
    if (ufrag.len <= 256u && pwd.len <= 256u) {
        (void)dup_span(ag, ufrag, &ag->remote_ufrag);
        (void)dup_span(ag, pwd, &ag->remote_pwd);
    }
}

void wr_ice_attach_io(wr_ice_agent *ag, wr_io *io,
                      const wr_endpoint *local_addr)
{
    if (!ag) {
        return;
    }
    ag->io = io;
    if (local_addr) {
        ag->local_addr = *local_addr;
    }
}

wr_status wr_ice_start(wr_ice_agent *ag, uint64_t now_ms)
{
    if (!ag) {
        return WR_ERR_INVAL;
    }
    if (!ag->local.len || !ag->remote.len || !ag->local_ufrag.ptr ||
        !ag->local_pwd.ptr || !ag->remote_ufrag.ptr) {
        return WR_ERR_STATE;
    }
    wr_ice_form_pairs(ag);
    if (ag->pairs.len == 0u) {
        ag->state = WR_ICE_FAILED;
        return WR_ERR_STATE;
    }
    ag->state = WR_ICE_CHECKING;
    ag->started = true;
    ag->nomination_ack = false;
    ag->last_response_ms = now_ms;
    ag->last_consent_ms = now_ms;
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        if (ag->pairs.data[i].state == WR_ICE_PAIR_FROZEN) {
            ag->pairs.data[i].state = WR_ICE_PAIR_WAITING;
        }
    }
    /* Kick the highest-priority pair. */
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        if (ag->pairs.data[i].state == WR_ICE_PAIR_WAITING) {
            return wr_ice_send_check(ag, i, now_ms,
                              ag->cfg.role == WR_ICE_ROLE_CONTROLLING &&
                                  ag->pairs.data[i].nominated,
                              NULL, true);
        }
    }
    return WR_OK;
}

wr_status wr_ice_step(wr_ice_agent *ag, uint64_t now_ms)
{
    if (!ag || !ag->started) {
        return WR_ERR_STATE;
    }
    if (ag->state == WR_ICE_CLOSED || ag->state == WR_ICE_FAILED ||
        ag->state == WR_ICE_COMPLETED) {
        return WR_OK;
    }

    /* Retransmit due checks. */
    for (size_t i = 0; i < ag->checks.len; ++i) {
        wr_ice_check *c = &ag->checks.data[i];
        if (c->done || c->pair >= ag->pairs.len) {
            continue;
        }
        uint64_t rto = (uint64_t)ag->cfg.check_rto_ms << c->retransmits;
        if (now_ms - c->sent_ms < rto) {
            continue;
        }
        if (c->retransmits >= ag->cfg.max_retransmits) {
            c->done = true;
            ag->pairs.data[c->pair].state = WR_ICE_PAIR_FAILED;
            ag->failures++;
            bool any = false;
            if (wr_ice_all_pairs_done(ag, &any)) {
                ag->state = any ? WR_ICE_COMPLETED : WR_ICE_FAILED;
            }
            continue;
        }
        c->retransmits++;
        c->sent_ms = now_ms;
        (void)wr_ice_send_check(ag, c->pair, now_ms, c->use_candidate, c->txid,
                         false);
    }

    if (ag->state == WR_ICE_CHECKING) {
        if (ag->pairs.len == 0u) {
            ag->state = WR_ICE_FAILED;
            return WR_OK;
        }
        bool any_inflight = false;
        for (size_t i = 0; i < ag->checks.len; ++i) {
            if (!ag->checks.data[i].done) {
                any_inflight = true;
                break;
            }
        }
        if (!any_inflight) {
            for (size_t i = 0; i < ag->pairs.len; ++i) {
                if (ag->pairs.data[i].state == WR_ICE_PAIR_WAITING) {
                    (void)wr_ice_send_check(ag, i, now_ms, false, NULL, true);
                    break;
                }
            }
        }
    }

    if (ag->cfg.consent_freshness && ag->state == WR_ICE_CONNECTED &&
        ag->selected != UINT32_MAX) {
        if (now_ms - ag->last_response_ms >= ag->cfg.consent_timeout_ms) {
            ag->state = WR_ICE_FAILED;
            return WR_OK;
        }
        if (now_ms - ag->last_consent_ms >= ag->cfg.consent_interval_ms) {
            ag->last_consent_ms = now_ms;
            (void)wr_ice_send_check(ag, ag->selected, now_ms, false, NULL, true);
        }
    }
    return WR_OK;
}

wr_status wr_ice_input(wr_ice_agent *ag, uint64_t now_ms,
                       const wr_endpoint *from, wr_span_c data)
{
    if (!ag || !from || !ag->started || !ag->remote_pwd.ptr) {
        return WR_ERR_STATE;
    }
    if (ag->state == WR_ICE_CLOSED) {
        return WR_ERR_CLOSED;
    }
    wr_stun_msg m;
    wr_status st = wr_stun_parse(ag->a, data, WR_STUN_LIBERAL, &m);
    if (st != WR_OK) {
        return st;
    }
    if (wr_stun_is_response(m.type)) {
        if (m.type == wr_stun_type(WR_STUN_METHOD_BINDING,
                                   WR_STUN_CLASS_SUCCESS)) {
            return wr_ice_handle_response(ag, now_ms, from, &m);
        }
        return WR_OK;
    }
    if (m.type == wr_stun_type(WR_STUN_METHOD_BINDING,
                               WR_STUN_CLASS_REQUEST)) {
        return wr_ice_handle_request(ag, now_ms, from, &m);
    }
    return WR_OK;
}

void wr_ice_close(wr_ice_agent *ag)
{
    if (ag) {
        ag->state = WR_ICE_CLOSED;
    }
}

wr_ice_state wr_ice_get_state(const wr_ice_agent *ag)
{
    return ag ? ag->state : WR_ICE_CLOSED;
}

bool wr_ice_is_complete(const wr_ice_agent *ag)
{
    return ag && (ag->state == WR_ICE_CONNECTED ||
                  ag->state == WR_ICE_COMPLETED);
}

bool wr_ice_selected(const wr_ice_agent *ag, wr_endpoint *local,
                     wr_endpoint *remote)
{
    if (!ag || ag->selected == UINT32_MAX) {
        return false;
    }
    const wr_ice_pair *p = &ag->pairs.data[ag->selected];
    if (local) {
        *local = ag->local.data[p->local].addr;
    }
    if (remote) {
        *remote = ag->remote.data[p->remote].addr;
    }
    return true;
}

const wr_ice_cand *wr_ice_local_candidates(const wr_ice_agent *ag,
                                           size_t *count)
{
    if (count) {
        *count = ag ? ag->local.len : 0u;
    }
    return ag ? ag->local.data : NULL;
}

const wr_ice_cand *wr_ice_remote_candidates(const wr_ice_agent *ag,
                                            size_t *count)
{
    if (count) {
        *count = ag ? ag->remote.len : 0u;
    }
    return ag ? ag->remote.data : NULL;
}

size_t wr_ice_pair_count(const wr_ice_agent *ag)
{
    return ag ? ag->pairs.len : 0u;
}