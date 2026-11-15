#ifndef WR_PC_INTERNAL_H
#define WR_PC_INTERNAL_H

#include "wr/pc.h"
#include "wr/dtls.h"

/* RFC 8841 5: the SCTP port is signalled in the SDP and is independent of the
 * UDP port that carries ICE. Both sides default to 5000. */
#define WR_PC_SCTP_PORT 5000u

/* Advertised maximum message size (RFC 8841). The receive path reassembles a
 * message from DATA chunks, each bounded by one DTLS record (2048 bytes) held
 * in arena storage, so the practical bound is the association's TSN receive
 * window (WR_SCTP_RX_WINDOW) times the record size. Callers must size the
 * arena to hold a message this large. */
#define WR_PC_MAX_MESSAGE_SIZE 262144u

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
    /* DTLS role follows the SDP `setup` attribute, not the ICE role
     * (RFC 8842 5.1): "active" means DTLS client. */
    bool dtls_client;
    int local_setup;
    bool have_local_setup;
    int remote_setup;
    bool have_remote_setup;
    uint16_t sctp_port;
    uint16_t remote_sctp_port;
    char local_ufrag[8];
    char local_pwd[32];
    bool has_local_creds;
    uint8_t peer_fp[32];
    bool have_peer_fp;
    bool started;
    bool closed;
    uint64_t now_ms;
};

/* Defined in pc.c: recomputes the DTLS role from the negotiated setup. */
void wr_pc_update_dtls_role(wr_pc *pc);

#endif /* WR_PC_INTERNAL_H */
