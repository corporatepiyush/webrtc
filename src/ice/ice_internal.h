#ifndef WR_ICE_INTERNAL_H
#define WR_ICE_INTERNAL_H

#include "wr/ice.h"

typedef struct {
    uint16_t local;
    uint16_t remote;
    uint64_t priority;
    uint8_t state;
    bool nominated;
    uint32_t checks_sent;
    uint64_t last_check_ms;
    uint64_t last_response_ms;
    uint8_t retransmits;
} wr_ice_pair;

typedef struct {
    uint8_t txid[12];
    uint32_t pair;
    uint64_t sent_ms;
    uint8_t retransmits;
    bool use_candidate;
    bool done;
} wr_ice_check;

WR_VEC_DEF(wr_ice_cand_vec, wr_ice_cand)
WR_VEC_DEF(wr_ice_pair_vec, wr_ice_pair)
WR_VEC_DEF(wr_ice_check_vec, wr_ice_check)

struct wr_ice_agent {
    wr_arena *a;
    wr_ice_config cfg;
    wr_rng *rng;
    wr_io *io;
    wr_endpoint local_addr;

    wr_span_c local_ufrag;
    wr_span_c local_pwd;
    wr_span_c remote_ufrag;
    wr_span_c remote_pwd;

    wr_ice_cand_vec local;
    wr_ice_cand_vec remote;
    wr_ice_pair_vec pairs;
    wr_ice_check_vec checks;

    wr_ice_state state;
    uint64_t tie_breaker;
    bool started;
    bool remote_end;
    uint32_t selected;
    bool nomination_ack;
    uint64_t last_response_ms;
    uint64_t last_consent_ms;

    uint64_t checks_sent;
    uint64_t responses;
    uint64_t failures;
};

int wr_ice_pair_find(const wr_ice_agent *ag, uint32_t local, uint32_t remote);
bool wr_ice_add_pair(wr_ice_agent *ag, uint32_t local, uint32_t remote);
void wr_ice_form_pairs(wr_ice_agent *ag);

wr_status wr_ice_send_check(wr_ice_agent *ag, size_t pair_idx, uint64_t now_ms,
                            bool use_candidate, const uint8_t *txid_in,
                            bool record);
bool wr_ice_all_pairs_done(const wr_ice_agent *ag, bool *any_success);
void wr_ice_mark_pair_success(wr_ice_agent *ag, size_t idx, uint64_t now_ms);
wr_status wr_ice_handle_request(wr_ice_agent *ag, uint64_t now_ms,
                                const wr_endpoint *from, wr_stun_msg *m);
wr_status wr_ice_handle_response(wr_ice_agent *ag, uint64_t now_ms,
                                 const wr_endpoint *from, wr_stun_msg *m);

#endif /* WR_ICE_INTERNAL_H */
