#include "wr/map.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* String map                                                                */
/* ------------------------------------------------------------------------- */

static bool str_slots(wr_str_map *m, uint32_t cap)
{
    uint64_t *h = (uint64_t *)wr_arena_calloc(m->a, cap, sizeof(uint64_t));
    uint32_t *id = (uint32_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint32_t));
    if (!h || !id) {
        return false;
    }
    m->slot_hash = h;
    m->slot_id = id;
    m->slot_cap = cap;
    m->slot_mask = cap - 1u;
    return true;
}

static bool str_grow_slots(wr_str_map *m)
{
    uint64_t *oh = m->slot_hash;
    uint32_t *oid = m->slot_id;
    uint32_t ocap = m->slot_cap;
    if (!str_slots(m, ocap * 2u)) {
        return false;
    }
    for (uint32_t i = 0; i < ocap; ++i) {
        if (oh[i] == 0u) {
            continue;
        }
        uint32_t id = oid[i];
        uint32_t j = (uint32_t)oh[i] & m->slot_mask;
        while (m->slot_hash[j] != 0u) {
            j = (j + 1u) & m->slot_mask;
        }
        m->slot_hash[j] = oh[i];
        m->slot_id[j] = id;
    }
    return true;
}

static uint32_t str_find_slot(const wr_str_map *m, uint64_t h, wr_span_c key)
{
    if (m->slot_cap == 0u) {
        return m->slot_cap;
    }
    uint32_t i = (uint32_t)h & m->slot_mask;
    while (m->slot_hash[i] != 0u) {
        uint32_t id = m->slot_id[i];
        if (m->slot_hash[i] == h && m->len[id] == key.len &&
            memcmp(m->buf + m->off[id], key.ptr, key.len) == 0) {
            return i;
        }
        i = (i + 1u) & m->slot_mask;
    }
    return m->slot_cap;
}

static bool buf_reserve(wr_str_map *m, size_t extra)
{
    if (m->used + extra <= m->buf_cap) {
        return true;
    }
    size_t cap = m->buf_cap ? m->buf_cap : 256u;
    while (cap < m->used + extra) {
        if (cap > SIZE_MAX / 2u) {
            return false;
        }
        cap *= 2u;
    }
    char *nb = (char *)wr_arena_alloc_array(m->a, cap, sizeof(char));
    if (!nb) {
        return false;
    }
    if (m->used) {
        memcpy(nb, m->buf, m->used);
    }
    m->buf = nb;
    m->buf_cap = cap;
    return true;
}

static bool id_reserve(wr_str_map *m)
{
    if (m->count < m->cap) {
        return true;
    }
    uint32_t cap = m->cap ? m->cap * 2u : 16u;
    uint32_t *off = (uint32_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint32_t));
    uint32_t *len = (uint32_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint32_t));
    uint32_t *val = (uint32_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint32_t));
    if (!off || !len || !val) {
        return false;
    }
    if (m->count) {
        memcpy(off, m->off, (size_t)m->count * sizeof(uint32_t));
        memcpy(len, m->len, (size_t)m->count * sizeof(uint32_t));
        memcpy(val, m->val, (size_t)m->count * sizeof(uint32_t));
    }
    m->off = off;
    m->len = len;
    m->val = val;
    m->cap = cap;
    return true;
}

bool wr_str_map_init(wr_str_map *m, wr_arena *a, uint32_t hint)
{
    if (!m || !a) {
        return false;
    }
    memset(m, 0, sizeof(*m));
    m->a = a;
    if (hint > (UINT32_MAX / 4u)) {
        return false;
    }
    uint32_t cap = 16u;
    while (cap < hint * 2u) {
        if (cap > (UINT32_MAX / 2u)) {
            return false;
        }
        cap *= 2u;
    }
    if (!str_slots(m, cap)) {
        return false;
    }
    if (!id_reserve(m)) {
        return false;
    }
    return true;
}

void wr_str_map_destroy(wr_str_map *m)
{
    if (m) {
        memset(m, 0, sizeof(*m));
    }
}

uint32_t *wr_str_map_find(wr_str_map *m, wr_span_c key)
{
    if (!m || !key.ptr) {
        return NULL;
    }
    uint64_t h = wr_hash64(key.ptr, key.len, 0u);
    uint32_t slot = str_find_slot(m, h, key);
    if (slot == m->slot_cap) {
        return NULL;
    }
    return &m->val[m->slot_id[slot]];
}

const char *wr_str_map_key(const wr_str_map *m, uint32_t id)
{
    if (!m || id >= m->count || m->off[id] >= m->used) {
        return NULL;
    }
    return m->buf + m->off[id];
}

uint32_t wr_str_map_len(const wr_str_map *m)
{
    return m ? m->count : 0u;
}

bool wr_str_map_put(wr_str_map *m, wr_span_c key, uint32_t val)
{
    if (!m || !key.ptr) {
        return false;
    }
    uint64_t h = wr_hash64(key.ptr, key.len, 0u);
    uint32_t slot = str_find_slot(m, h, key);
    if (slot != m->slot_cap) {
        m->val[m->slot_id[slot]] = val;
        return true;
    }

    if ((m->count + 1u) * 10u >= m->slot_cap * 7u) {
        if (!str_grow_slots(m)) {
            return false;
        }
        slot = str_find_slot(m, h, key);
        if (slot != m->slot_cap) {
            m->val[m->slot_id[slot]] = val;
            return true;
        }
    }
    if (!id_reserve(m) || !buf_reserve(m, key.len + 1u)) {
        return false;
    }
    uint32_t id = m->count++;
    memcpy(m->buf + m->used, key.ptr, key.len);
    m->buf[m->used + key.len] = '\0';
    m->off[id] = (uint32_t)m->used;
    m->len[id] = (uint32_t)key.len;
    m->val[id] = val;
    m->used += key.len + 1u;

    uint32_t i = (uint32_t)h & m->slot_mask;
    while (m->slot_hash[i] != 0u) {
        i = (i + 1u) & m->slot_mask;
    }
    m->slot_hash[i] = h;
    m->slot_id[i] = id;
    return true;
}
