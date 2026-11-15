#include "wr/ice.h"
#include "ice_internal.h"

#include "wr/crc32c.h"

#include <string.h>

static uint32_t type_pref(wr_ice_cand_type t)
{
    switch (t) {
    case WR_ICE_CAND_HOST: return 126u;
    case WR_ICE_CAND_PRFLX: return 110u;
    case WR_ICE_CAND_SRFLX: return 100u;
    case WR_ICE_CAND_RELAY: return 0u;
    default: return 0u;
    }
}

/* RFC 8445 4.1.2.1: priority = 2^24 * type_pref + 2^8 * local_pref +
 * (256 - component). local_pref is an agent-chosen value that ranks local
 * interfaces; without interface information it defaults to the maximum so it
 * never skews the type/component ordering. */
static uint64_t candidate_priority(wr_ice_cand_type t, uint16_t component,
                                   uint16_t local_pref)
{
    uint32_t p = ((uint32_t)type_pref(t) << 24) |
                 ((uint32_t)local_pref << 8) |
                 (256u - (uint32_t)(component & 0xffu));
    return (uint64_t)p;
}

/* RFC 8445 6.1.2.3: G is the controlling agent's candidate, D the controlled
 * one. The controlling agent is the one whose role decides the ordering, so
 * the caller must pass (controlling, controlled) accordingly. */
static uint64_t pair_priority(uint64_t g, uint64_t d)
{
    uint64_t mn = g < d ? g : d;
    uint64_t mx = g < d ? d : g;
    return (mn << 32) | (mx << 1) | (g > d ? 1u : 0u);
}

static uint64_t pair_priority_for(const wr_ice_agent *ag, size_t local,
                                  size_t remote)
{
    uint64_t lp = ag->local.data[local].priority;
    uint64_t rp = ag->remote.data[remote].priority;
    return ag->cfg.role == WR_ICE_ROLE_CONTROLLING ? pair_priority(lp, rp)
                                                   : pair_priority(rp, lp);
}

/* Insertion sort, descending pair priority. */
static void sort_pairs(wr_ice_agent *ag)
{
    for (size_t i = ag->pairs.len; i > 1u; --i) {
        if (ag->pairs.data[i - 1u].priority > ag->pairs.data[i - 2u].priority) {
            wr_ice_pair t = ag->pairs.data[i - 1u];
            ag->pairs.data[i - 1u] = ag->pairs.data[i - 2u];
            ag->pairs.data[i - 2u] = t;
        } else {
            break;
        }
    }
}

void wr_ice_recompute_pair_priorities(wr_ice_agent *ag)
{
    if (!ag || ag->pairs.len == 0u) {
        return;
    }
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        wr_ice_pair *p = &ag->pairs.data[i];
        if (p->local < ag->local.len && p->remote < ag->remote.len) {
            p->priority = pair_priority_for(ag, p->local, p->remote);
        }
    }
    /* Sort pairs and remember the permutation: in-flight checks refer to pairs
     * by index, so reordering without remapping them would match responses to
     * the wrong pair. */
    uint32_t *order = (uint32_t *)wr_arena_alloc_array(
        ag->a, ag->pairs.len, sizeof(uint32_t));
    uint32_t *new_pos = (uint32_t *)wr_arena_alloc_array(
        ag->a, ag->pairs.len, sizeof(uint32_t));
    if (!order || !new_pos) {
        return; /* cannot reorder safely: leave the order as it is */
    }
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        order[i] = (uint32_t)i;
    }
    /* Insertion sort, descending priority, carrying the original indices. */
    for (size_t i = 1u; i < ag->pairs.len; ++i) {
        wr_ice_pair key = ag->pairs.data[i];
        uint32_t key_order = order[i];
        size_t j = i;
        while (j > 0u && ag->pairs.data[j - 1u].priority < key.priority) {
            ag->pairs.data[j] = ag->pairs.data[j - 1u];
            order[j] = order[j - 1u];
            j--;
        }
        ag->pairs.data[j] = key;
        order[j] = key_order;
    }
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        new_pos[order[i]] = (uint32_t)i;
    }
    for (size_t i = 0; i < ag->checks.len; ++i) {
        uint32_t old = ag->checks.data[i].pair;
        if (old < ag->pairs.len) {
            ag->checks.data[i].pair = new_pos[old];
        }
    }
}

static uint32_t foundation_for(const wr_ice_cand *c)
{
    uint32_t h = 2166136261u;
    uint8_t fam = c->addr.af == WR_AF_INET ? 4u : 6u;
    h = wr_crc32c_span(h, wr_span_c_make(&fam, 1));
    h = wr_crc32c_span(h, wr_span_c_make(c->addr.ip.b.v6, 16));
    h = wr_crc32c_span(h, wr_span_c_make(&c->type, sizeof(c->type)));
    return h;
}

uint32_t wr_ice_add_local_candidate(wr_ice_agent *ag, wr_endpoint addr,
                                    wr_ice_cand_type type, uint16_t component)
{
    if (!ag || ag->local.len >= UINT16_MAX) {
        return UINT32_MAX;
    }
    wr_ice_cand c;
    memset(&c, 0, sizeof(c));
    c.addr = addr;
    c.component = component ? component : ag->cfg.component;
    c.type = type;
    c.priority = candidate_priority(type, (uint16_t)c.component, ag->cfg.local_pref);
    c.local = true;
    c.id = (uint32_t)ag->local.len;
    c.foundation = foundation_for(&c);
    if (!wr_ice_cand_vec_push(&ag->local, c)) {
        return UINT32_MAX;
    }
    wr_ice_form_pairs(ag);
    return c.id;
}

uint32_t wr_ice_add_remote_candidate(wr_ice_agent *ag, wr_endpoint addr,
                                     wr_ice_cand_type type, uint16_t component)
{
    if (!ag || ag->remote.len >= UINT16_MAX) {
        return UINT32_MAX;
    }
    for (size_t i = 0; i < ag->remote.len; ++i) {
        if (wr_endpoint_eq(&ag->remote.data[i].addr, &addr) &&
            ag->remote.data[i].type == type) {
            return (uint32_t)i;
        }
    }
    wr_ice_cand c;
    memset(&c, 0, sizeof(c));
    c.addr = addr;
    c.component = component ? component : ag->cfg.component;
    c.type = type;
    c.priority = candidate_priority(type, (uint16_t)c.component, ag->cfg.local_pref);
    c.local = false;
    c.id = (uint32_t)ag->remote.len;
    c.foundation = foundation_for(&c);
    if (!wr_ice_cand_vec_push(&ag->remote, c)) {
        return UINT32_MAX;
    }
    wr_ice_form_pairs(ag);
    return c.id;
}

int wr_ice_pair_find(const wr_ice_agent *ag, uint32_t local, uint32_t remote)
{
    for (size_t i = 0; i < ag->pairs.len; ++i) {
        if (ag->pairs.data[i].local == (uint16_t)local &&
            ag->pairs.data[i].remote == (uint16_t)remote) {
            return (int)i;
        }
    }
    return -1;
}

bool wr_ice_add_pair(wr_ice_agent *ag, uint32_t local, uint32_t remote)
{
    if (local >= ag->local.len || remote >= ag->remote.len ||
        local > UINT16_MAX || remote > UINT16_MAX) {
        return false;
    }
    if (ag->pairs.len >= ag->cfg.max_pairs) {
        return false;
    }
    if (wr_ice_pair_find(ag, local, remote) >= 0) {
        return true;
    }
    wr_ice_pair p;
    memset(&p, 0, sizeof(p));
    p.local = (uint16_t)local;
    p.remote = (uint16_t)remote;
    p.state = WR_ICE_PAIR_WAITING;
    p.priority = pair_priority_for(ag, local, remote);
    if (!wr_ice_pair_vec_push(&ag->pairs, p)) {
        return false;
    }
    /* Insertion sort by descending priority. */
    sort_pairs(ag);
    return true;
}

void wr_ice_form_pairs(wr_ice_agent *ag)
{
    for (size_t l = 0; l < ag->local.len; ++l) {
        for (size_t r = 0; r < ag->remote.len; ++r) {
            if (ag->local.data[l].component != ag->remote.data[r].component) {
                continue;
            }
            (void)wr_ice_add_pair(ag, (uint32_t)l, (uint32_t)r);
        }
    }
}

void wr_ice_end_of_remote_candidates(wr_ice_agent *ag)
{
    if (ag) {
        ag->remote_end = true;
    }
}

void wr_ice_restart(wr_ice_agent *ag, wr_span_c ufrag, wr_span_c pwd)
{
    if (!ag) {
        return;
    }
    ag->state = WR_ICE_NOT_STARTED;
    ag->started = false;
    ag->nomination_ack = false;
    ag->remote_end = false;
    ag->selected = UINT32_MAX;
    ag->last_response_ms = 0u;
    ag->last_consent_ms = 0u;
    ag->pairs.len = 0u;
    ag->checks.len = 0u;
    /* The peer's candidate list belongs to the previous ICE generation: a
     * restart is signalled with new credentials, and stale remote candidates
     * would otherwise be paired and checked against the new ufrag. */
    ag->remote.len = 0u;
    ag->checks_sent = 0u;
    ag->responses = 0u;
    ag->failures = 0u;
    wr_ice_set_local_credentials(ag, ufrag, pwd);
}
