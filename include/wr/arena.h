#ifndef WR_ARENA_H
#define WR_ARENA_H

#include "wr/base.h"

typedef struct wr_arena wr_arena;

wr_arena *wr_arena_create(size_t budget_bytes);
void wr_arena_destroy(wr_arena *a);

/* Aligned to max_align_t. */
void *wr_arena_alloc(wr_arena *a, size_t size);
/* Aligned to `align` (power of two). */
void *wr_arena_alloc_aligned(wr_arena *a, size_t size, size_t align);
void *wr_arena_alloc_array(wr_arena *a, size_t count, size_t elem);
void *wr_arena_calloc(wr_arena *a, size_t count, size_t elem);

typedef struct { uint8_t *ptr; size_t used; size_t total_used; } wr_arena_mark;

wr_arena_mark wr_arena_mark_save(const wr_arena *a);
void wr_arena_mark_release(wr_arena *a, wr_arena_mark m);
void wr_arena_reset(wr_arena *a);

size_t wr_arena_used(const wr_arena *a);
size_t wr_arena_budget(const wr_arena *a);
size_t wr_arena_high_water(const wr_arena *a);
uint64_t wr_arena_alloc_count(const wr_arena *a);
uint64_t wr_arena_alloc_bytes(const wr_arena *a);

#endif /* WR_ARENA_H */