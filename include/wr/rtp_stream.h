#ifndef WR_RTP_STREAM_H
#define WR_RTP_STREAM_H

#include "wr/arena.h"
#include "wr/map.h"
#include "wr/pool.h"
#include "wr/rtp.h"

/*
 * SSRC-indexed per-stream state. Objects are pooled and stored contiguously;
 * the hash map maps SSRC to a pool slot index, so a packet lookup is one
 * hash probe plus one array index, not a linked-list walk.
 */
typedef struct {
    uint32_t ssrc;
    uint16_t seq;
    uint16_t cycles;
    uint32_t timestamp;
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_ms;
} wr_rtp_stream;

typedef struct wr_rtp_stream_table wr_rtp_stream_table;

wr_rtp_stream_table *wr_rtp_stream_table_create(wr_arena *a,
                                                uint32_t max_streams);
void wr_rtp_stream_table_destroy(wr_rtp_stream_table *t);

wr_rtp_stream *wr_rtp_stream_find(const wr_rtp_stream_table *t, uint32_t ssrc);
wr_rtp_stream *wr_rtp_stream_get_or_create(wr_rtp_stream_table *t,
                                           uint32_t ssrc);
bool wr_rtp_stream_remove(wr_rtp_stream_table *t, uint32_t ssrc);

/* Update sequence/timestamp/counters, tracking the 16-bit rollover. */
void wr_rtp_stream_update(wr_rtp_stream *s, const wr_rtp_hdr *h, size_t bytes,
                          uint64_t now_ms);

uint32_t wr_rtp_stream_count(const wr_rtp_stream_table *t);
uint32_t wr_rtp_stream_capacity(const wr_rtp_stream_table *t);

#endif /* WR_RTP_STREAM_H */