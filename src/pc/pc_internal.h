#ifndef WR_PC_INTERNAL_H
#define WR_PC_INTERNAL_H

#include "wr/pc.h"
#include "wr/dtls.h"

struct wr_pc {
    wr_arena *a;
    wr_rng *rng;
    wr_io *io;
    wr_endpoint local;
    wr_endpoint remote;
    wr_ice_agent *ice;
    wr_ice_role role;
    wr_sctp_assoc *sctp;
    wr_dtls *dtls;
    wr_io *dtls_io;
    bool dtls_enabled;
    char local_ufrag[8];
    char local_pwd[32];
    bool has_local_creds;
    uint8_t peer_fp[32];
    bool have_peer_fp;
    bool started;
    bool closed;
    uint64_t now_ms;
};

#endif /* WR_PC_INTERNAL_H */
