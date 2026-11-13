#ifndef WR_STATS_H
#define WR_STATS_H

#include "wr/base.h"

typedef struct {
    uint64_t allocs;
    uint64_t bytes_peak;
    uint64_t stun_tx;
    uint64_t stun_rx;
    uint64_t stun_fail;
    uint64_t ice_checks;
    uint64_t dtls_records;
    uint64_t dtls_retransmits;
    uint64_t srtp_protect;
    uint64_t srtp_unprotect;
    uint64_t srtp_auth_fail;
    uint64_t rtp_tx;
    uint64_t rtp_rx;
    uint64_t rtcp_tx;
    uint64_t rtcp_rx;
    uint64_t sctp_chunks;
    uint64_t sctp_retransmits;
    uint64_t parse_failures;
    uint64_t bytes_in;
    uint64_t bytes_out;
} wr_stats;

void wr_stats_reset(wr_stats *s);

#endif /* WR_STATS_H */