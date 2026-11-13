#ifndef WR_VEC_H
#define WR_VEC_H

#include "wr/arena.h"

#if defined(__GNUC__) || defined(__clang__)
#define WR_VEC_INLINE static inline __attribute__((unused))
#else
#define WR_VEC_INLINE static inline
#endif

/*
 * Arena-backed growable vector. `init` captures the arena; `destroy` releases
 * the arena (it does not free individual elements). Growth doubles capacity,
 * bounded by the arena budget.
 */
#define WR_VEC_DEF(NAME, T)                                                   \
    typedef struct { T *data; size_t len; size_t cap; wr_arena *a; } NAME;    \
                                                                              \
    WR_VEC_INLINE void NAME##_init(NAME *v, wr_arena *a)                      \
    {                                                                         \
        v->data = NULL;                                                       \
        v->len = 0;                                                           \
        v->cap = 0;                                                           \
        v->a = a;                                                             \
    }                                                                         \
                                                                              \
    WR_VEC_INLINE void NAME##_destroy(NAME *v)                                \
    {                                                                         \
        v->data = NULL;                                                       \
        v->len = 0;                                                           \
        v->cap = 0;                                                           \
        v->a = NULL;                                                          \
    }                                                                         \
                                                                              \
    WR_VEC_INLINE bool NAME##_reserve(NAME *v, size_t n)                      \
    {                                                                         \
        if (n <= v->cap) return true;                                         \
        size_t nc = v->cap ? v->cap : 8u;                                     \
        while (nc < n) {                                                      \
            if (nc > (SIZE_MAX / 2u)) return false;                           \
            nc *= 2u;                                                         \
        }                                                                     \
        T *nd = (T *)wr_arena_alloc_array(v->a, nc, sizeof(T));               \
        if (!nd) return false;                                                \
        if (v->len) memcpy(nd, v->data, v->len * sizeof(T));                  \
        v->data = nd;                                                         \
        v->cap = nc;                                                          \
        return true;                                                          \
    }                                                                         \
                                                                              \
    WR_VEC_INLINE bool NAME##_push(NAME *v, T value)                          \
    {                                                                         \
        if (!NAME##_reserve(v, v->len + 1u)) return false;                    \
        v->data[v->len++] = value;                                            \
        return true;                                                          \
    }                                                                         \
                                                                              \
    WR_VEC_INLINE void NAME##_pop(NAME *v)                                    \
    {                                                                         \
        if (v->len) v->len--;                                                 \
    }                                                                         \
                                                                              \
    WR_VEC_INLINE void NAME##_clear(NAME *v) { v->len = 0; }                  \
                                                                              \
    WR_VEC_INLINE T *NAME##_at(NAME *v, size_t i)                             \
    {                                                                         \
        return (i < v->len) ? &v->data[i] : NULL;                             \
    }

#endif /* WR_VEC_H */