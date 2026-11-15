#ifndef WR_SCTP_H
#define WR_SCTP_H

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/vec.h"

typedef enum {
    WR_SCTP_DATA = 0,
    WR_SCTP_INIT = 1,
    WR_SCTP_INIT_ACK = 2,
    WR_SCTP_SACK = 3,
    WR_SCTP_HEARTBEAT = 4,
    WR_SCTP_HEARTBEAT_ACK = 5,
    WR_SCTP_ABORT = 6,
    WR_SCTP_SHUTDOWN = 7,
    WR_SCTP_SHUTDOWN_ACK = 8,
    WR_SCTP_ERROR = 9,
    WR_SCTP_COOKIE_ECHO = 10,
    WR_SCTP_COOKIE_ACK = 11,
    WR_SCTP_FORWARD_TSN = 192,
} wr_sctp_chunk_type;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t vtag;
    uint32_t checksum;
    size_t body_off;
    size_t body_len;
} wr_sctp_packet;

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t len;
    size_t offset;
    wr_span_c body;
} wr_sctp_chunk;
WR_VEC_DEF(wr_sctp_chunk_vec, wr_sctp_chunk)

typedef struct {
    wr_sctp_packet hdr;
    wr_sctp_chunk_vec chunks;
    wr_span_c raw;
} wr_sctp_msg;

wr_status wr_sctp_parse(wr_arena *a, wr_span_c raw, wr_sctp_msg *out);
wr_status wr_sctp_serialize(const wr_sctp_packet *pkt, wr_span_c chunks,
                            char *buf, size_t cap, size_t *out_len);
wr_status wr_sctp_chunk_serialize(uint8_t type, uint8_t flags, wr_span_c body,
                                  char *buf, size_t cap, size_t *out_len);

/* Chunk body helpers. */
wr_status wr_sctp_data_body(uint32_t tsn, uint16_t stream, uint16_t seq,
                            uint32_t ppid, wr_span_c data, char *buf,
                            size_t cap, size_t *out_len);
wr_status wr_sctp_sack_body(uint32_t cum_tsn, uint32_t a_rwnd,
                            const uint32_t *gaps, size_t gap_count,
                            const uint32_t *dups, size_t dup_count, char *buf,
                            size_t cap, size_t *out_len);
wr_status wr_sctp_init_body(uint32_t tag, uint32_t a_rwnd, uint16_t out_streams,
                            uint16_t in_streams, uint32_t initial_tsn,
                            char *buf, size_t cap, size_t *out_len);

/* ------------------------------------------------------------------------- */
/* Association                                                               */
/* ------------------------------------------------------------------------- */

typedef enum {
    WR_SCTP_ST_CLOSED = 0,
    WR_SCTP_ST_INIT_SENT,
    WR_SCTP_ST_COOKIE_ECHOED,
    WR_SCTP_ST_COOKIE_SENT,
    WR_SCTP_ST_ESTABLISHED,
    WR_SCTP_ST_CLOSING,
    WR_SCTP_ST_FAILED, /* appended: the association was aborted locally */
} wr_sctp_state;

typedef struct wr_sctp_assoc wr_sctp_assoc;

typedef struct {
    uint16_t stream;
    uint32_t ppid;
    wr_span_c data;
} wr_sctp_delivery;

#define WR_SCTP_RX_WINDOW 8192u

typedef struct {
    uint32_t start;
    uint32_t end;
} wr_tsn_gap;

typedef struct {
    uint64_t w[WR_SCTP_RX_WINDOW / 64u];
    uint32_t cum;
    uint32_t off;   /* physical bit offset of logical window bit 0 */
    uint32_t count; /* set bits above cum (received, not yet delivered) */
} wr_tsn_set;

void wr_tsn_set_init(wr_tsn_set *s, uint32_t cum);
bool wr_tsn_set_add(wr_tsn_set *s, uint32_t tsn);
bool wr_tsn_set_has(const wr_tsn_set *s, uint32_t tsn);
uint32_t wr_tsn_set_advance(wr_tsn_set *s);
bool wr_tsn_set_pop_next(wr_tsn_set *s, uint32_t *tsn);
/* Fills gap ack blocks: ascending, non-overlapping runs of received TSNs
 * above the cumulative TSN (RFC 4960 section 3.3.4). Returns the number of
 * blocks written, capped at max. */
uint32_t wr_tsn_set_gaps(const wr_tsn_set *s, wr_tsn_gap *gaps, size_t max);

wr_sctp_assoc *wr_sctp_create(wr_arena *a, uint16_t local_port,
                              uint16_t remote_port, wr_rng *rng);
void wr_sctp_attach_io(wr_sctp_assoc *as, wr_io *io,
                       const wr_endpoint *remote);
wr_status wr_sctp_start(wr_sctp_assoc *as, uint64_t now_ms);
wr_sctp_state wr_sctp_get_state(const wr_sctp_assoc *as);
void wr_sctp_start_established(wr_sctp_assoc *as, uint32_t my_vtag,
                               uint32_t peer_vtag, uint32_t peer_initial_tsn);
wr_status wr_sctp_send_data(wr_sctp_assoc *as, uint16_t stream, uint32_t ppid,
                            wr_span_c data, uint64_t now_ms);
/* `from` is the source address of the datagram as reported by the transport.
 * It must match the association's peer: SCTP cannot tell an injected packet
 * from a legitimate one, so an off-path attacker could otherwise drive the
 * state machine with DATA/INIT/SHUTDOWN chunks. Pass NULL only when the
 * transport is already point-to-point and has validated the source. */
wr_status wr_sctp_input(wr_sctp_assoc *as, uint64_t now_ms,
                        const wr_endpoint *from, wr_span_c packet);
wr_status wr_sctp_step(wr_sctp_assoc *as, uint64_t now_ms);
bool wr_sctp_recv(wr_sctp_assoc *as, wr_sctp_delivery *out);
uint32_t wr_sctp_last_ack(const wr_sctp_assoc *as);
void wr_sctp_close(wr_sctp_assoc *as);

/* ------------------------------------------------------------------------- */
/* DCEP                                                                      */
/* ------------------------------------------------------------------------- */

typedef enum {
    WR_DCEP_OPEN = 0x03,
    WR_DCEP_ACK = 0x02,
} wr_dcep_type;

typedef struct {
    wr_dcep_type type;
    uint8_t channel_type;
    uint16_t priority;
    uint32_t reliability;
    wr_span_c label;
    wr_span_c protocol;
} wr_dcep_msg;

wr_status wr_dcep_open_serialize(wr_span_c label, wr_span_c protocol,
                                 uint8_t channel_type, uint16_t priority,
                                 uint32_t reliability, char *buf, size_t cap,
                                 size_t *out_len);
wr_status wr_dcep_ack_serialize(char *buf, size_t cap, size_t *out_len);
wr_status wr_dcep_parse(wr_span_c body, wr_dcep_msg *out);

#endif /* WR_SCTP_H */