#ifndef WR_POOL_H
#define WR_POOL_H

#include "wr/arena.h"

/*
 * Fixed-capacity object pool with an intrusive free stack. Allocation is a
 * single stack pop and returns cache-line-aligned storage; free is a push.
 * The pool never moves objects, so pointers handed out stay valid until the
 * object is freed. Useful for packet-sized objects on the RTP/SCTP path.
 */
typedef struct {
    uint8_t *objects;
    uint32_t *free_stack;
    uint8_t *used_bits; /* one bit per slot: set while allocated */
    uint32_t cap;
    uint32_t elem;
    uint32_t in_use;
    uint32_t free_count;
    wr_arena *a;
} wr_pool;

bool wr_pool_init(wr_pool *p, wr_arena *a, uint32_t cap, size_t elem,
                  size_t align);
void wr_pool_destroy(wr_pool *p);
void *wr_pool_alloc(wr_pool *p);
void wr_pool_free(wr_pool *p, void *obj);
uint32_t wr_pool_index(const wr_pool *p, const void *obj);
void *wr_pool_at(const wr_pool *p, uint32_t idx);
uint32_t wr_pool_in_use(const wr_pool *p);
uint32_t wr_pool_capacity(const wr_pool *p);

#endif /* WR_POOL_H */