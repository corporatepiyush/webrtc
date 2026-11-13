#include "wr/net.h"

#include <stdlib.h>

typedef struct {
    bool used;
    uint64_t id;
    uint64_t at_ms;
    wr_timer_fn fn;
    void *ctx;
} wr_timer_ent;

struct wr_timer {
    wr_timer_ent *ents;
    size_t cap;
    size_t n;
    uint64_t next_id;
};

wr_timer *wr_timer_create(size_t capacity)
{
    if (capacity == 0u) {
        capacity = 16u;
    }
    wr_timer *t = (wr_timer *)calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    t->ents = (wr_timer_ent *)calloc(capacity, sizeof(wr_timer_ent));
    if (!t->ents) {
        free(t);
        return NULL;
    }
    t->cap = capacity;
    t->next_id = 1u;
    return t;
}

void wr_timer_destroy(wr_timer *t)
{
    if (!t) {
        return;
    }
    free(t->ents);
    free(t);
}

wr_status wr_timer_schedule(wr_timer *t, uint64_t at_ms, wr_timer_fn fn,
                            void *ctx, uint64_t *id)
{
    if (!t || !fn || t->n >= t->cap) {
        return WR_ERR_LIMIT;
    }
    for (size_t i = 0; i < t->cap; ++i) {
        if (!t->ents[i].used) {
            t->ents[i].used = true;
            t->ents[i].id = t->next_id++;
            t->ents[i].at_ms = at_ms;
            t->ents[i].fn = fn;
            t->ents[i].ctx = ctx;
            t->n++;
            if (id) {
                *id = t->ents[i].id;
            }
            return WR_OK;
        }
    }
    return WR_ERR_LIMIT;
}

bool wr_timer_cancel(wr_timer *t, uint64_t id)
{
    if (!t || id == 0u) {
        return false;
    }
    for (size_t i = 0; i < t->cap; ++i) {
        if (t->ents[i].used && t->ents[i].id == id) {
            t->ents[i].used = false;
            t->n--;
            return true;
        }
    }
    return false;
}

uint64_t wr_timer_next_deadline(const wr_timer *t, uint64_t now_ms)
{
    if (!t) {
        return 0u;
    }
    uint64_t best = 0u;
    bool found = false;
    for (size_t i = 0; i < t->cap; ++i) {
        if (!t->ents[i].used) {
            continue;
        }
        if (t->ents[i].at_ms <= now_ms) {
            return now_ms;
        }
        if (!found || t->ents[i].at_ms < best) {
            best = t->ents[i].at_ms;
            found = true;
        }
    }
    return found ? best : 0u;
}

uint32_t wr_timer_fire(wr_timer *t, uint64_t now_ms)
{
    if (!t) {
        return 0u;
    }
    uint32_t fired = 0u;
    for (size_t i = 0; i < t->cap; ++i) {
        if (!t->ents[i].used || t->ents[i].at_ms > now_ms) {
            continue;
        }
        wr_timer_ent e = t->ents[i];
        t->ents[i].used = false;
        t->n--;
        e.fn(e.ctx, now_ms);
        fired++;
    }
    return fired;
}