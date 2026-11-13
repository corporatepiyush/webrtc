#ifndef WR_TURN_H
#define WR_TURN_H

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/net.h"
#include "wr/rng.h"

typedef enum {
    WR_TURN_NEW = 0,
    WR_TURN_ALLOCATING,
    WR_TURN_AUTHENTICATING,
    WR_TURN_ALLOCATED,
    WR_TURN_FAILED,
    WR_TURN_CLOSED,
} wr_turn_status;

typedef struct wr_turn wr_turn;

wr_turn *wr_turn_create(wr_arena *a, wr_rng *rng, wr_io *io,
                        const wr_endpoint *server, wr_span_c username,
                        wr_span_c password);
void wr_turn_destroy(wr_turn *t);

wr_status wr_turn_start(wr_turn *t, uint64_t now_ms);
wr_status wr_turn_step(wr_turn *t, uint64_t now_ms);
wr_status wr_turn_input(wr_turn *t, uint64_t now_ms, wr_span_c pkt);
wr_status wr_turn_send(wr_turn *t, wr_span_c data);
bool wr_turn_recv(wr_turn *t, wr_span_c *out);

wr_turn_status wr_turn_get_status(const wr_turn *t);
const wr_endpoint *wr_turn_relayed(const wr_turn *t);

/* Allocate a permission/channel for `peer`; returns after the requests are
 * queued on the wire. */
wr_status wr_turn_connect(wr_turn *t, const wr_endpoint *peer,
                          uint16_t channel);

#endif /* WR_TURN_H */