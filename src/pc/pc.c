#include "wr/pc.h"
#include "pc_internal.h"

#include "wr/dtls.h"
#include "wr/sdp.h"

#include <stdlib.h>
#include <string.h>

wr_pc *wr_pc_create(wr_arena *a, wr_rng *rng, wr_io *io,
                    const wr_endpoint *local, const wr_endpoint *remote,
                    wr_ice_role role)
{
    /* The RNG is mandatory: without it the ICE credentials, the tie-breaker
     * and every transaction id become predictable (or constant), which makes
     * the whole session forgeable. */
    if (!a || !rng || !io || !local || !remote) {
        return NULL;
    }
    wr_pc *pc = (wr_pc *)wr_arena_calloc(a, 1, sizeof(*pc));
    if (!pc) {
        return NULL;
    }
    pc->a = a;
    pc->rng = rng;
    pc->io = io;
    pc->local = *local;
    pc->remote = *remote;
    pc->role = role;
    pc->sctp_port = WR_PC_SCTP_PORT;
    pc->remote_sctp_port = WR_PC_SCTP_PORT;
    pc->local_setup = WR_SDP_SETUP_ACTPASS;
    /* Provisional until the SDP is available; corrected by
     * wr_pc_update_dtls_role() once a description is set. */
    pc->dtls_client = role == WR_ICE_ROLE_CONTROLLING;

    wr_ice_config ic;
    wr_ice_config_defaults(&ic);
    ic.role = role;
    pc->ice = wr_ice_create(a, &ic, rng);
    if (!pc->ice) {
        return NULL;
    }
    wr_ice_attach_io(pc->ice, io, local);
    /* DTLS is the normal path: without it the SCTP association runs in the
     * clear over the UDP socket with predictable verification tags. Enable it
     * here so a caller that does nothing gets an authenticated session. */
    wr_pc_enable_dtls(pc);
    return pc;
}

void wr_pc_destroy(wr_pc *pc)
{
    if (!pc) {
        return;
    }
    if (pc->ice) {
        wr_ice_close(pc->ice);
    }
    if (pc->sctp) {
        wr_sctp_close(pc->sctp);
    }
    if (pc->dtls) {
        wr_dtls_destroy(pc->dtls);
        pc->dtls = NULL;
    }
    if (pc->dtls_io) {
        wr_io_destroy(pc->dtls_io);
        pc->dtls_io = NULL;
    }
    pc->closed = true;
}

void wr_pc_set_credentials(wr_pc *pc, wr_span_c local_ufrag,
                           wr_span_c local_pwd, wr_span_c remote_ufrag,
                           wr_span_c remote_pwd)
{
    if (!pc || !pc->ice) {
        return;
    }
    wr_ice_set_local_credentials(pc->ice, local_ufrag, local_pwd);
    wr_ice_set_remote_credentials(pc->ice, remote_ufrag, remote_pwd);
}

/* The DTLS role is a function of the negotiated SDP `setup` attribute
 * (RFC 8842 5.1): the agent that says "active" is the DTLS client. */
void wr_pc_update_dtls_role(wr_pc *pc)
{
    /* The DTLS role is a function of the negotiated SDP `setup` attribute
     * (RFC 8842 5.1): the agent that says "active" is the DTLS client. Until
     * the setup is known (no local/remote description yet) fall back to the
     * ICE role, which is the conventional pairing; the role is corrected as
     * soon as the SDP is available, and wr_dtls_set_role refuses to change it
     * once the handshake has begun. */
    bool client;
    if (pc->have_local_setup) {
        client = pc->local_setup == WR_SDP_SETUP_ACTIVE;
    } else if (pc->have_remote_setup) {
        client = pc->remote_setup == WR_SDP_SETUP_PASSIVE;
    } else {
        client = pc->role == WR_ICE_ROLE_CONTROLLING;
    }
    pc->dtls_client = client;
    if (pc->dtls) {
        (void)wr_dtls_set_role(pc->dtls, client ? WR_DTLS_ROLE_CLIENT
                                                : WR_DTLS_ROLE_SERVER);
    }
}

void wr_pc_enable_dtls(wr_pc *pc)
{
    if (!pc || pc->dtls) {
        if (pc) {
            pc->dtls_enabled = true;
        }
        return;
    }
    pc->dtls_enabled = true;
    wr_dtls_role role = pc->dtls_client ? WR_DTLS_ROLE_CLIENT
                                        : WR_DTLS_ROLE_SERVER;
    pc->dtls = wr_dtls_create(pc->a, pc->rng, role, pc->io, &pc->remote);
    if (pc->dtls && pc->have_peer_fp) {
        (void)wr_dtls_set_peer_fingerprint(pc->dtls, pc->peer_fp, 32u);
    }
}

void wr_pc_disable_dtls(wr_pc *pc)
{
    if (!pc) {
        return;
    }
    /* Opting out is a deliberate act. The plaintext path carries SCTP over
     * the UDP socket with no cryptographic protection and with verification
     * tags derived from the port numbers, so both peers must already agree on
     * them: it exists for loopback tests and benchmarks only. */
    pc->dtls_enabled = false;
    if (pc->dtls) {
        wr_dtls_destroy(pc->dtls);
        pc->dtls = NULL;
    }
    if (pc->dtls_io) {
        wr_io_destroy(pc->dtls_io);
        pc->dtls_io = NULL;
    }
    if (pc->sctp) {
        wr_sctp_close(pc->sctp);
        pc->sctp = NULL;
    }
}

bool wr_pc_local_fingerprint(wr_pc *pc, const uint8_t **fp, size_t *len)
{
    if (!pc || !fp || !len) {
        return false;
    }
    if (!pc->dtls) {
        wr_pc_enable_dtls(pc);
    }
    if (!pc->dtls) {
        return false;
    }
    *fp = wr_dtls_fingerprint(pc->dtls, len);
    return *fp != NULL;
}

bool wr_pc_set_peer_fingerprint(wr_pc *pc, const uint8_t *fp, size_t len)
{
    if (!pc || !fp || len != 32u) {
        return false;
    }
    memcpy(pc->peer_fp, fp, 32);
    pc->have_peer_fp = true;
    if (pc->dtls) {
        (void)wr_dtls_set_peer_fingerprint(pc->dtls, pc->peer_fp, 32u);
    }
    return true;
}

bool wr_pc_dtls_ready(const wr_pc *pc)
{
    return pc && pc->dtls && wr_dtls_ready(pc->dtls);
}

wr_status wr_pc_start(wr_pc *pc, uint64_t now_ms)
{
    if (!pc || !pc->ice) {
        return WR_ERR_INVAL;
    }
    /* Fail closed: a DTLS session whose peer certificate cannot be matched
     * against a fingerprint is unauthenticated, and DTLS verification is the
     * only thing standing between this association and a machine-in-the-
     * middle. Refuse to start rather than negotiate a session nobody vouches
     * for. (The plaintext path is unaffected; it is an explicit opt-out.) */
    if (pc->dtls_enabled && !pc->have_peer_fp) {
        return WR_ERR_STATE;
    }
    if (wr_ice_add_local_candidate(pc->ice, pc->local, WR_ICE_CAND_HOST, 1) ==
        UINT32_MAX) {
        return WR_ERR_LIMIT;
    }
    if (wr_ice_add_remote_candidate(pc->ice, pc->remote, WR_ICE_CAND_HOST, 1) ==
        UINT32_MAX) {
        return WR_ERR_LIMIT;
    }
    wr_status st = wr_ice_start(pc->ice, now_ms);
    if (st != WR_OK) {
        return st;
    }
    pc->started = true;
    pc->now_ms = now_ms;
    return WR_OK;
}

/* RFC 5764 / RFC 7983 first-byte demultiplexing of a shared UDP socket. */
typedef enum {
    WR_DEMUX_STUN = 0,
    WR_DEMUX_ZRTP,
    WR_DEMUX_DTLS,
    WR_DEMUX_TURN_CHANNEL,
    WR_DEMUX_RTP,
    WR_DEMUX_UNKNOWN,
} wr_demux_kind;

static wr_demux_kind demux(wr_span_c data)
{
    if (data.len == 0u) {
        return WR_DEMUX_UNKNOWN;
    }
    uint8_t b = data.ptr[0];
    if (b <= 3u) {
        return WR_DEMUX_STUN;
    }
    if (b >= 16u && b <= 19u) {
        return WR_DEMUX_ZRTP;
    }
    if (b >= 20u && b <= 63u) {
        return WR_DEMUX_DTLS;
    }
    if (b >= 64u && b <= 79u) {
        return WR_DEMUX_TURN_CHANNEL;
    }
    if (b >= 128u && b <= 191u) {
        return WR_DEMUX_RTP;
    }
    return WR_DEMUX_UNKNOWN;
}

static void pump(wr_pc *pc, uint64_t now_ms)
{
    uint8_t buf[2048];
    for (int i = 0; i < 20; ++i) {
        bool ready = false;
        /* wr_pc_step is a non-blocking step: the caller drives the clock, so
         * waiting here (even briefly) would stall it. */
        (void)wr_io_wait(pc->io, 0u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(pc->io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            break;
        }
        /* Route by content, not by "has ICE finished": an off-path host can
         * otherwise reach DTLS (and through it SCTP) with a single datagram,
         * and STUN consent traffic is fed to the DTLS parser after ICE
         * completes. */
        if (!pc->dtls_enabled && pc->sctp) {
            /* Explicit plaintext test transport (see wr_pc_disable_dtls): no
             * multiplexing is defined for it, so every non-STUN datagram is
             * offered to the association. */
            if (demux(wr_span_upcast(data)) == WR_DEMUX_STUN) {
                (void)wr_ice_input(pc->ice, now_ms, &from,
                                   wr_span_upcast(data));
            } else {
                (void)wr_sctp_input(pc->sctp, now_ms, &from,
                                    wr_span_upcast(data));
            }
            continue;
        }
        switch (demux(wr_span_upcast(data))) {
        case WR_DEMUX_STUN:
            /* ICE authenticates every request itself, so a spoofed source is
             * rejected by the integrity check. */
            (void)wr_ice_input(pc->ice, now_ms, &from, wr_span_upcast(data));
            break;
        case WR_DEMUX_DTLS:
            if (pc->dtls && wr_ice_is_complete(pc->ice)) {
                (void)wr_dtls_input(pc->dtls, &from, wr_span_upcast(data));
            }
            break;
        case WR_DEMUX_TURN_CHANNEL:
        case WR_DEMUX_ZRTP:
        case WR_DEMUX_RTP:
        case WR_DEMUX_UNKNOWN:
        default:
            /* No TURN relay, ZRTP or media plane is negotiated by this core;
             * drop rather than guess. */
            break;
        }
    }
}

static void pump_sctp(wr_pc *pc, uint64_t now_ms)
{
    if (!pc->dtls || !pc->sctp) {
        return;
    }
    wr_span_c app;
    while (wr_dtls_recv(pc->dtls, &app)) {
        /* DTLS is point-to-point: the record was decrypted under the session
         * keys established with the authenticated peer, so there is no source
         * to re-check here. */
        (void)wr_sctp_input(pc->sctp, now_ms, NULL, app);
        if (app.len == 0u) {
            break;
        }
    }
}

static void start_sctp(wr_pc *pc, uint64_t now_ms)
{
    if (pc->sctp || !pc->started) {
        return;
    }
    if (pc->dtls_enabled) {
        if (!pc->dtls || !wr_dtls_ready(pc->dtls)) {
            return;
        }
        pc->dtls_io = wr_io_dtls_create(pc->io, pc->dtls);
        if (!pc->dtls_io) {
            return;
        }
        pc->sctp = wr_sctp_create(pc->a, pc->sctp_port, pc->remote_sctp_port,
                                  pc->rng);
        if (!pc->sctp) {
            return;
        }
        wr_sctp_attach_io(pc->sctp, pc->dtls_io, &pc->remote);
        if (pc->role == WR_ICE_ROLE_CONTROLLING) {
            (void)wr_sctp_start(pc->sctp, now_ms);
        }
        return;
    }
    uint32_t my_vtag = UINT32_C(0x10000000) | pc->sctp_port;
    uint32_t peer_vtag = UINT32_C(0x10000000) | pc->remote_sctp_port;
    pc->sctp = wr_sctp_create(pc->a, pc->sctp_port, pc->remote_sctp_port,
                              pc->rng);
    if (!pc->sctp) {
        return;
    }
    wr_sctp_attach_io(pc->sctp, pc->io, &pc->remote);
    wr_sctp_start_established(pc->sctp, my_vtag, peer_vtag,
                              UINT32_C(0x10000000) | pc->remote_sctp_port);
    (void)now_ms;
}

wr_status wr_pc_step(wr_pc *pc, uint64_t now_ms)
{
    if (!pc || pc->closed) {
        return WR_ERR_CLOSED;
    }
    pc->now_ms = now_ms;
    pump(pc, now_ms);
    (void)wr_ice_step(pc->ice, now_ms);
    if (wr_ice_is_complete(pc->ice)) {
        if (pc->dtls_enabled && !pc->dtls) {
            wr_pc_enable_dtls(pc);
        }
        if (pc->dtls && wr_dtls_state(pc->dtls) == WR_DTLS_NEW) {
            (void)wr_dtls_start(pc->dtls, now_ms);
        }
        if (pc->dtls && !wr_dtls_ready(pc->dtls)) {
            (void)wr_dtls_step(pc->dtls, now_ms);
        }
        start_sctp(pc, now_ms);
    }
    if (pc->sctp) {
        pump_sctp(pc, now_ms);
        (void)wr_sctp_step(pc->sctp, now_ms);
    }
    return WR_OK;
}

bool wr_pc_ready(wr_pc *pc)
{
    return pc && pc->sctp && wr_ice_is_complete(pc->ice) &&
           wr_sctp_get_state(pc->sctp) == WR_SCTP_ST_ESTABLISHED;
}

wr_ice_state wr_pc_ice_state(const wr_pc *pc)
{
    return pc && pc->ice ? wr_ice_get_state(pc->ice) : WR_ICE_CLOSED;
}

wr_ice_agent *wr_pc_ice(wr_pc *pc)
{
    return pc ? pc->ice : NULL;
}

wr_sctp_assoc *wr_pc_sctp(wr_pc *pc)
{
    return pc ? pc->sctp : NULL;
}

wr_status wr_pc_send(wr_pc *pc, wr_span_c data)
{
    if (!pc || !pc->sctp) {
        return WR_ERR_STATE;
    }
    return wr_sctp_send_data(pc->sctp, 0u, 54u, data, pc->now_ms);
}

bool wr_pc_recv(wr_pc *pc, wr_sctp_delivery *out)
{
    if (!pc || !pc->sctp || !out) {
        return false;
    }
    return wr_sctp_recv(pc->sctp, out);
}

void wr_pc_close(wr_pc *pc)
{
    if (!pc) {
        return;
    }
    if (pc->sctp) {
        wr_sctp_close(pc->sctp);
    }
    if (pc->ice) {
        wr_ice_close(pc->ice);
    }
    pc->closed = true;
}
