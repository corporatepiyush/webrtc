#include "wr/pool.h"

#include <string.h>

bool wr_pool_init(wr_pool *p, wr_arena *a, uint32_t cap, size_t elem,
                  size_t align)
{
    if (!p || !a || cap == 0u || elem == 0u) {
        return false;
    }
    if (align == 0u || (align & (align - 1u)) != 0u) {
        return false;
    }
    if (elem > UINT32_MAX || align > 4096u ||
        cap > SIZE_MAX / elem) {
        return false;
    }
    memset(p, 0, sizeof(*p));
    p->a = a;
    p->cap = cap;
    p->elem = (uint32_t)elem;
    p->objects = (uint8_t *)wr_arena_alloc_aligned(a, cap * elem, align);
    p->free_stack = (uint32_t *)wr_arena_alloc_array(a, cap, sizeof(uint32_t));
    size_t bits_bytes = ((size_t)cap + 7u) / 8u;
    p->used_bits = (uint8_t *)wr_arena_calloc(a, bits_bytes, 1u);
    if (!p->objects || !p->free_stack || !p->used_bits) {
        return false;
    }
    for (uint32_t i = 0; i < cap; ++i) {
        p->free_stack[i] = cap - 1u - i;
    }
    p->free_count = cap;
    return true;
}

static bool pool_bit_get(const uint8_t *bits, uint32_t idx)
{
    return (bits[idx >> 3u] & (uint8_t)(1u << (idx & 7u))) != 0u;
}

static void pool_bit_set(uint8_t *bits, uint32_t idx)
{
    bits[idx >> 3u] |= (uint8_t)(1u << (idx & 7u));
}

static void pool_bit_clear(uint8_t *bits, uint32_t idx)
{
    bits[idx >> 3u] &= (uint8_t)~(uint8_t)(1u << (idx & 7u));
}

void wr_pool_destroy(wr_pool *p)
{
    if (p) {
        memset(p, 0, sizeof(*p));
    }
}

void *wr_pool_alloc(wr_pool *p)
{
    if (!p || p->free_count == 0u) {
        return NULL;
    }
    uint32_t idx = p->free_stack[--p->free_count];
    if (pool_bit_get(p->used_bits, idx)) {
        /* Corrupt free stack: the slot is already live. Refuse rather than
         * hand the same object to two owners. */
        p->free_count++;
        return NULL;
    }
    pool_bit_set(p->used_bits, idx);
    p->in_use++;
    return p->objects + (size_t)idx * p->elem;
}

void wr_pool_free(wr_pool *p, void *obj)
{
    if (!p || !obj) {
        return;
    }
    uint8_t *base = p->objects;
    uint8_t *ptr = (uint8_t *)obj;
    if (ptr < base || (size_t)(ptr - base) % p->elem != 0u) {
        return;
    }
    size_t idx = (size_t)(ptr - base) / p->elem;
    if (idx >= p->cap) {
        return;
    }
    /* Without allocation bookkeeping a second free of the same object pushes
     * its index past free_stack[cap], which writes out of bounds through the
     * arena. Track residency so double frees and foreign pointers are no-ops. */
    if (!pool_bit_get(p->used_bits, (uint32_t)idx)) {
        return;
    }
    if (p->free_count >= p->cap) {
        return;
    }
    pool_bit_clear(p->used_bits, (uint32_t)idx);
    p->free_stack[p->free_count++] = (uint32_t)idx;
    if (p->in_use) {
        p->in_use--;
    }
}

uint32_t wr_pool_in_use(const wr_pool *p)
{
    return p ? p->in_use : 0u;
}

uint32_t wr_pool_index(const wr_pool *p, const void *obj)
{
    if (!p || !obj) {
        return UINT32_MAX;
    }
    const uint8_t *base = p->objects;
    const uint8_t *ptr = (const uint8_t *)obj;
    if (ptr < base) {
        return UINT32_MAX;
    }
    size_t off = (size_t)(ptr - base);
    if (off % p->elem != 0u) {
        return UINT32_MAX;
    }
    uint32_t idx = (uint32_t)(off / p->elem);
    return idx < p->cap ? idx : UINT32_MAX;
}

void *wr_pool_at(const wr_pool *p, uint32_t idx)
{
    if (!p || idx >= p->cap) {
        return NULL;
    }
    return p->objects + (size_t)idx * p->elem;
}

uint32_t wr_pool_capacity(const wr_pool *p)
{
    return p ? p->cap : 0u;
}