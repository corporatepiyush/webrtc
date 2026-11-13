#include "wr/arena.h"

#include <stdlib.h>

#define WR_CHUNK_BYTES ((size_t)64u * 1024u)
#define WR_MAX_ALIGN   ((size_t)64u)

typedef struct wr_chunk {
    struct wr_chunk *next;
    uint8_t *data;
    size_t cap;
    size_t used;
} wr_chunk;

struct wr_arena {
    wr_chunk *head;
    size_t budget;
    size_t used;
    size_t high;
    size_t default_chunk;
    uint64_t alloc_count;
    uint64_t alloc_bytes;
};

static bool is_pow2(size_t x)
{
    return x != 0u && (x & (x - 1u)) == 0u;
}

static wr_chunk *chunk_alloc(size_t cap)
{
    size_t header = (sizeof(wr_chunk) + WR_MAX_ALIGN - 1u) &
                    ~(WR_MAX_ALIGN - 1u);
    /* Over-allocate so the data region is cache-line aligned even when
     * malloc returns a 16-byte-aligned block. */
    uint8_t *raw = (uint8_t *)malloc(header + WR_MAX_ALIGN + cap);
    if (!raw) {
        return NULL;
    }
    wr_chunk *c = (wr_chunk *)(void *)raw;
    c->next = NULL;
    c->data = (uint8_t *)(((uintptr_t)(raw + header) + (WR_MAX_ALIGN - 1u)) &
                          ~(uintptr_t)(WR_MAX_ALIGN - 1u));
    c->cap = cap;
    c->used = 0;
    return c;
}

wr_arena *wr_arena_create(size_t budget_bytes)
{
    wr_arena *a = (wr_arena *)calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    a->budget = budget_bytes ? budget_bytes : ((size_t)1024u * 1024u);
    a->default_chunk = WR_CHUNK_BYTES;
    if (a->default_chunk > a->budget) {
        a->default_chunk = a->budget;
    }
    if (!is_pow2(WR_MAX_ALIGN)) {
        free(a);
        return NULL;
    }
    return a;
}

void wr_arena_destroy(wr_arena *a)
{
    if (!a) {
        return;
    }
    wr_chunk *c = a->head;
    while (c) {
        wr_chunk *next = c->next;
        free(c);
        c = next;
    }
    free(a);
}

static void *chunk_bump(wr_chunk *c, size_t size, size_t align)
{
    size_t start = (c->used + align - 1u) & ~(align - 1u);
    if (start > c->cap || size > c->cap - start) {
        return NULL;
    }
    void *p = c->data + start;
    c->used = start + size;
    return p;
}

void *wr_arena_alloc_aligned(wr_arena *a, size_t size, size_t align)
{
    if (WR_UNLIKELY(!a || size == 0u || align == 0u || !is_pow2(align) ||
                    align > WR_MAX_ALIGN)) {
        return NULL;
    }
    if (WR_UNLIKELY(size > a->budget - a->used)) {
        return NULL;
    }
    if (a->head) {
        void *p = chunk_bump(a->head, size, align);
        if (WR_LIKELY(p)) {
            a->used += size;
            if (a->used > a->high) a->high = a->used;
            a->alloc_count++;
            a->alloc_bytes += size;
            return p;
        }
    }
    size_t cap = a->default_chunk;
    if (size > cap) {
        cap = size;
    }
    wr_chunk *c = chunk_alloc(cap);
    if (!c) {
        return NULL;
    }
    c->next = a->head;
    a->head = c;
    void *p = chunk_bump(c, size, align);
    if (!p) {
        /* Cannot happen: cap >= size and align <= 64. */
        return NULL;
    }
    a->used += size;
    if (a->used > a->high) a->high = a->used;
    a->alloc_count++;
    a->alloc_bytes += size;
    return p;
}

void *wr_arena_alloc(wr_arena *a, size_t size)
{
    return wr_arena_alloc_aligned(a, size, _Alignof(max_align_t));
}

void *wr_arena_alloc_array(wr_arena *a, size_t count, size_t elem)
{
    if (elem != 0u && count > SIZE_MAX / elem) {
        return NULL;
    }
    return wr_arena_alloc(a, count * elem);
}

void *wr_arena_calloc(wr_arena *a, size_t count, size_t elem)
{
    void *p = wr_arena_alloc_array(a, count, elem);
    if (p) {
        memset(p, 0, count * elem);
    }
    return p;
}

wr_arena_mark wr_arena_mark_save(const wr_arena *a)
{
    wr_arena_mark m;
    m.ptr = a->head ? a->head->data : NULL;
    m.used = a->head ? a->head->used : 0u;
    m.total_used = a->used;
    return m;
}

void wr_arena_mark_release(wr_arena *a, wr_arena_mark m)
{
    if (!a || !a->head) {
        return;
    }
    wr_chunk *c = a->head;
    while (c && c->data > m.ptr) {
        wr_chunk *next = c->next;
        free(c);
        c = next;
    }
    a->head = c;
    if (a->head) {
        a->head->used = m.used;
    }
    a->used = m.total_used;
}

void wr_arena_reset(wr_arena *a)
{
    if (!a) {
        return;
    }
    wr_chunk *c = a->head;
    while (c) {
        wr_chunk *next = c->next;
        free(c);
        c = next;
    }
    a->head = NULL;
    a->used = 0u;
}

size_t wr_arena_used(const wr_arena *a)
{
    return a ? a->used : 0u;
}

size_t wr_arena_budget(const wr_arena *a)
{
    return a ? a->budget : 0u;
}

size_t wr_arena_high_water(const wr_arena *a)
{
    return a ? a->high : 0u;
}

uint64_t wr_arena_alloc_count(const wr_arena *a)
{
    return a ? a->alloc_count : 0u;
}

uint64_t wr_arena_alloc_bytes(const wr_arena *a)
{
    return a ? a->alloc_bytes : 0u;
}