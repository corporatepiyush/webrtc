#ifndef WR_PC_H
#define WR_PC_H

#include "wr/arena.h"
#include "wr/ice.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/sctp.h"

typedef struct wr_pc wr_pc;

typedef struct {
    uint16_t stream;
    uint32_t ppid;
} wr_dc;

wr_pc *wr_pc_create(wr_arena *a, wr_rng *rng, wr_io *io,
                    const wr_endpoint *local, const wr_endpoint *remote,
                    wr_ice_role role);
void wr_pc_destroy(wr_pc *pc);

void wr_pc_set_credentials(wr_pc *pc, wr_span_c local_ufrag,
                           wr_span_c local_pwd, wr_span_c remote_ufrag,
                           wr_span_c remote_pwd);
void wr_pc_enable_dtls(wr_pc *pc);
bool wr_pc_local_fingerprint(wr_pc *pc, const uint8_t **fp, size_t *len);
bool wr_pc_set_peer_fingerprint(wr_pc *pc, const uint8_t *fp, size_t len);
bool wr_pc_dtls_ready(const wr_pc *pc);

/* Minimal JSEP offer/answer over the SDP subset used by this core. */
wr_status wr_pc_create_offer(wr_pc *pc, char *buf, size_t cap,
                             size_t *out_len);
wr_status wr_pc_create_answer(wr_pc *pc, wr_span_c offer, char *buf,
                              size_t cap, size_t *out_len);
wr_status wr_pc_set_remote_description(wr_pc *pc, wr_span_c sdp);

wr_status wr_pc_start(wr_pc *pc, uint64_t now_ms);
wr_status wr_pc_step(wr_pc *pc, uint64_t now_ms);
bool wr_pc_ready(wr_pc *pc);
wr_ice_state wr_pc_ice_state(const wr_pc *pc);
wr_ice_agent *wr_pc_ice(wr_pc *pc);
wr_sctp_assoc *wr_pc_sctp(wr_pc *pc);

wr_status wr_pc_send(wr_pc *pc, wr_span_c data);
bool wr_pc_recv(wr_pc *pc, wr_sctp_delivery *out);
void wr_pc_close(wr_pc *pc);

#endif /* WR_PC_H */