#include "wr/map.h"

#include <string.h>

static inline uint64_t key_hash(uint64_t key)
{
    return wr_mix64(key) | 1u;
}

/* ------------------------------------------------------------------------- */
/* u64 map                                                                   */
/* ------------------------------------------------------------------------- */

static bool map_alloc(wr_u64_map *m, uint32_t cap)
{
    uint64_t *h = (uint64_t *)wr_arena_calloc(m->a, cap, sizeof(uint64_t));
    uint64_t *k = (uint64_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint64_t));
    uint32_t *v = (uint32_t *)wr_arena_alloc_array(m->a, cap, sizeof(uint32_t));
    if (!h || !k || !v) {
        return false;
    }
    m->hash = h;
    m->key = k;
    m->val = v;
    m->cap = cap;
    m->mask = cap - 1u;
    m->len = 0u;
    return true;
}

bool wr_u64_map_init(wr_u64_map *m, wr_arena *a, uint32_t hint)
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
    return map_alloc(m, cap);
}

void wr_u64_map_destroy(wr_u64_map *m)
{
    if (m) {
        memset(m, 0, sizeof(*m));
    }
}

uint32_t *wr_u64_map_find_hash(const wr_u64_map *m, uint64_t h, uint64_t key)
{
    if (!m || m->cap == 0u) {
        return NULL;
    }
    uint32_t i = (uint32_t)h & m->mask;
    while (m->hash[i] != 0u) {
        if (m->hash[i] == h && m->key[i] == key) {
            return &m->val[i];
        }
        i = (i + 1u) & m->mask;
    }
    return NULL;
}

uint32_t *wr_u64_map_find(const wr_u64_map *m, uint64_t key)
{
    if (!m || m->cap == 0u) {
        return NULL;
    }
    return wr_u64_map_find_hash(m, key_hash(key), key);
}

static bool map_grow(wr_u64_map *m)
{
    wr_u64_map n;
    if (!wr_u64_map_init(&n, m->a, m->cap * 2u + 1u)) {
        return false;
    }
    for (uint32_t i = 0; i < m->cap; ++i) {
        if (m->hash[i] == 0u) {
            continue;
        }
        if (!wr_u64_map_put_hash(&n, m->hash[i], m->key[i], m->val[i])) {
            return false;
        }
    }
    *m = n;
    return true;
}

bool wr_u64_map_put_hash(wr_u64_map *m, uint64_t h, uint64_t key, uint32_t val)
{
    if (!m || m->cap == 0u) {
        return false;
    }
    if ((m->len + 1u) * 10u >= m->cap * 7u) {
        if (!map_grow(m)) {
            return false;
        }
    }
    uint32_t i = (uint32_t)h & m->mask;
    while (m->hash[i] != 0u) {
        if (m->hash[i] == h && m->key[i] == key) {
            m->val[i] = val;
            return true;
        }
        i = (i + 1u) & m->mask;
    }
    m->hash[i] = h;
    m->key[i] = key;
    m->val[i] = val;
    m->len++;
    return true;
}

bool wr_u64_map_put(wr_u64_map *m, uint64_t key, uint32_t val)
{
    return wr_u64_map_put_hash(m, key_hash(key), key, val);
}

bool wr_u64_map_erase(wr_u64_map *m, uint64_t key)
{
    if (!m || m->cap == 0u) {
        return false;
    }
    uint64_t h = key_hash(key);
    uint32_t i = (uint32_t)h & m->mask;
    while (m->hash[i] != 0u && !(m->hash[i] == h && m->key[i] == key)) {
        i = (i + 1u) & m->mask;
    }
    if (m->hash[i] == 0u) {
        return false;
    }

    /* Backward-shift deletion (no tombstones). The hole stays at i until a
     * later entry can legally move into it. */
    uint32_t mask = m->mask;
    uint32_t hole = i;
    uint32_t j = i;
    for (;;) {
        j = (j + 1u) & mask;
        if (m->hash[j] == 0u) {
            break;
        }
        uint32_t home = (uint32_t)m->hash[j] & mask;
        /* Move j into the hole if its home is not cyclically inside
         * (hole, j]. */
        bool must_move;
        if (hole <= j) {
            must_move = home <= hole || home > j;
        } else {
            must_move = home <= hole && home > j;
        }
        if (must_move) {
            m->hash[hole] = m->hash[j];
            m->key[hole] = m->key[j];
            m->val[hole] = m->val[j];
            hole = j;
        }
    }
    m->hash[hole] = 0u;
    m->len--;
    return true;
}

uint32_t wr_u64_map_len(const wr_u64_map *m)
{
    return m ? m->len : 0u;
}
