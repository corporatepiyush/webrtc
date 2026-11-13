#include "wr/rtp_stream.h"

#include <stdlib.h>
#include <string.h>

struct wr_rtp_stream_table {
    wr_pool pool;
    wr_u64_map by_ssrc;
    uint32_t count;
    wr_arena *a;
};

wr_rtp_stream_table *wr_rtp_stream_table_create(wr_arena *a,
                                                uint32_t max_streams)
{
    if (!a || max_streams == 0u) {
        return NULL;
    }
    wr_rtp_stream_table *t =
        (wr_rtp_stream_table *)wr_arena_calloc(a, 1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    t->a = a;
    if (!wr_pool_init(&t->pool, a, max_streams, sizeof(wr_rtp_stream), 64u) ||
        !wr_u64_map_init(&t->by_ssrc, a, max_streams)) {
        return NULL;
    }
    return t;
}

void wr_rtp_stream_table_destroy(wr_rtp_stream_table *t)
{
    if (t) {
        wr_pool_destroy(&t->pool);
        wr_u64_map_destroy(&t->by_ssrc);
        memset(t, 0, sizeof(*t));
    }
}

wr_rtp_stream *wr_rtp_stream_find(const wr_rtp_stream_table *t, uint32_t ssrc)
{
    if (!t) {
        return NULL;
    }
    uint32_t *idx = wr_u64_map_find(&t->by_ssrc, ssrc);
    if (!idx) {
        return NULL;
    }
    return (wr_rtp_stream *)wr_pool_at(&t->pool, *idx);
}

wr_rtp_stream *wr_rtp_stream_get_or_create(wr_rtp_stream_table *t,
                                           uint32_t ssrc)
{
    wr_rtp_stream *s = wr_rtp_stream_find(t, ssrc);
    if (s) {
        return s;
    }
    if (!t) {
        return NULL;
    }
    void *obj = wr_pool_alloc(&t->pool);
    if (!obj) {
        return NULL;
    }
    uint32_t idx = wr_pool_index(&t->pool, obj);
    if (idx == UINT32_MAX || !wr_u64_map_put(&t->by_ssrc, ssrc, idx)) {
        wr_pool_free(&t->pool, obj);
        return NULL;
    }
    s = (wr_rtp_stream *)obj;
    memset(s, 0, sizeof(*s));
    s->ssrc = ssrc;
    t->count++;
    return s;
}

bool wr_rtp_stream_remove(wr_rtp_stream_table *t, uint32_t ssrc)
{
    if (!t) {
        return false;
    }
    uint32_t *idx = wr_u64_map_find(&t->by_ssrc, ssrc);
    if (!idx) {
        return false;
    }
    wr_pool_free(&t->pool, wr_pool_at(&t->pool, *idx));
    (void)wr_u64_map_erase(&t->by_ssrc, ssrc);
    if (t->count) {
        t->count--;
    }
    return true;
}

void wr_rtp_stream_update(wr_rtp_stream *s, const wr_rtp_hdr *h, size_t bytes,
                          uint64_t now_ms)
{
    if (!s || !h) {
        return;
    }
    if (s->packets != 0u) {
        int16_t d = (int16_t)(h->seq - s->seq);
        if (d > 0) {
            if (s->seq > h->seq) {
                s->cycles++;
            }
        } else if (d < 0) {
            if (s->seq < h->seq) {
                s->cycles--;
            }
        }
    }
    s->seq = h->seq;
    s->timestamp = h->timestamp;
    s->packets++;
    s->bytes += bytes;
    s->last_ms = now_ms;
}

uint32_t wr_rtp_stream_count(const wr_rtp_stream_table *t)
{
    return t ? t->count : 0u;
}

uint32_t wr_rtp_stream_capacity(const wr_rtp_stream_table *t)
{
    return t ? wr_pool_capacity(&t->pool) : 0u;
}