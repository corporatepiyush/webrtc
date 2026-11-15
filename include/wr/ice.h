#ifndef WR_ICE_H
#define WR_ICE_H

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/rng.h"
#include "wr/stun.h"

typedef enum {
    WR_ICE_ROLE_CONTROLLED = 0,
    WR_ICE_ROLE_CONTROLLING = 1,
} wr_ice_role;

typedef enum {
    WR_ICE_CAND_HOST = 0,
    WR_ICE_CAND_SRFLX,
    WR_ICE_CAND_PRFLX,
    WR_ICE_CAND_RELAY,
} wr_ice_cand_type;

typedef enum {
    WR_ICE_NOT_STARTED = 0,
    WR_ICE_CHECKING,
    WR_ICE_CONNECTED,
    WR_ICE_COMPLETED,
    WR_ICE_FAILED,
    WR_ICE_CLOSED,
} wr_ice_state;

typedef enum {
    WR_ICE_PAIR_WAITING = 0,
    WR_ICE_PAIR_IN_PROGRESS,
    WR_ICE_PAIR_SUCCEEDED,
    WR_ICE_PAIR_FAILED,
    WR_ICE_PAIR_FROZEN,
} wr_ice_pair_state;

typedef struct {
    wr_endpoint addr;
    uint32_t component;
    wr_ice_cand_type type;
    uint64_t priority;
    uint32_t foundation;
    uint32_t id;
    bool local;
} wr_ice_cand;

typedef struct {
    wr_ice_role role;
    uint16_t component;
    uint32_t max_pairs;
    uint32_t check_rto_ms;
    uint32_t max_retransmits;
    bool consent_freshness;
    uint32_t consent_interval_ms;
    uint32_t consent_timeout_ms;
    /* Local preference term of the RFC 8445 candidate-priority formula. */
    uint16_t local_pref;
} wr_ice_config;

typedef struct wr_ice_agent wr_ice_agent;

void wr_ice_config_defaults(wr_ice_config *cfg);

wr_ice_agent *wr_ice_create(wr_arena *a, const wr_ice_config *cfg,
                            wr_rng *rng);
void wr_ice_destroy(wr_ice_agent *ag);

void wr_ice_set_local_credentials(wr_ice_agent *ag, wr_span_c ufrag,
                                  wr_span_c pwd);
void wr_ice_set_remote_credentials(wr_ice_agent *ag, wr_span_c ufrag,
                                   wr_span_c pwd);
void wr_ice_attach_io(wr_ice_agent *ag, wr_io *io,
                      const wr_endpoint *local_addr);

uint32_t wr_ice_add_local_candidate(wr_ice_agent *ag, wr_endpoint addr,
                                    wr_ice_cand_type type, uint16_t component);
uint32_t wr_ice_add_remote_candidate(wr_ice_agent *ag, wr_endpoint addr,
                                     wr_ice_cand_type type, uint16_t component);
void wr_ice_end_of_remote_candidates(wr_ice_agent *ag);
void wr_ice_restart(wr_ice_agent *ag, wr_span_c ufrag, wr_span_c pwd);

wr_status wr_ice_start(wr_ice_agent *ag, uint64_t now_ms);
wr_status wr_ice_step(wr_ice_agent *ag, uint64_t now_ms);
wr_status wr_ice_input(wr_ice_agent *ag, uint64_t now_ms,
                       const wr_endpoint *from, wr_span_c data);
void wr_ice_close(wr_ice_agent *ag);

wr_ice_state wr_ice_get_state(const wr_ice_agent *ag);
/* Current role. An agent that detects a role conflict may have switched from
 * the role it was configured with (RFC 8445 7.3.1.1). */
wr_ice_role wr_ice_get_role(const wr_ice_agent *ag);
bool wr_ice_is_complete(const wr_ice_agent *ag);
bool wr_ice_selected(const wr_ice_agent *ag, wr_endpoint *local,
                     wr_endpoint *remote);
const wr_ice_cand *wr_ice_local_candidates(const wr_ice_agent *ag,
                                           size_t *count);
const wr_ice_cand *wr_ice_remote_candidates(const wr_ice_agent *ag,
                                            size_t *count);
size_t wr_ice_pair_count(const wr_ice_agent *ag);

#endif /* WR_ICE_H */