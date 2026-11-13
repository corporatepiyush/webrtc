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
    if (!a || !io || !local || !remote) {
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

    wr_ice_config ic;
    wr_ice_config_defaults(&ic);
    ic.role = role;
    pc->ice = wr_ice_create(a, &ic, rng);
    if (!pc->ice) {
        return NULL;
    }
    wr_ice_attach_io(pc->ice, io, local);
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

void wr_pc_enable_dtls(wr_pc *pc)
{
    if (!pc || pc->dtls) {
        if (pc) {
            pc->dtls_enabled = true;
        }
        return;
    }
    pc->dtls_enabled = true;
    wr_dtls_role role = pc->role == WR_ICE_ROLE_CONTROLLING
                            ? WR_DTLS_ROLE_CLIENT
                            : WR_DTLS_ROLE_SERVER;
    pc->dtls = wr_dtls_create(pc->a, pc->rng, role, pc->io, &pc->remote);
    if (pc->dtls && pc->have_peer_fp) {
        (void)wr_dtls_set_peer_fingerprint(pc->dtls, pc->peer_fp, 32u);
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

static void pump(wr_pc *pc, uint64_t now_ms)
{
    uint8_t buf[2048];
    for (int i = 0; i < 20; ++i) {
        bool ready = false;
        (void)wr_io_wait(pc->io, 10u, &ready);
        if (!ready) {
            break;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(pc->io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            break;
        }
        if (pc->dtls && wr_ice_is_complete(pc->ice)) {
            (void)wr_dtls_input(pc->dtls, wr_span_upcast(data));
        } else if (pc->sctp && !pc->dtls) {
            (void)wr_sctp_input(pc->sctp, now_ms, wr_span_upcast(data));
        } else {
            (void)wr_ice_input(pc->ice, now_ms, &from, wr_span_upcast(data));
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
        (void)wr_sctp_input(pc->sctp, now_ms, app);
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
        pc->sctp = wr_sctp_create(pc->a, pc->local.port, pc->remote.port,
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
    uint32_t my_vtag = UINT32_C(0x10000000) | pc->local.port;
    uint32_t peer_vtag = UINT32_C(0x10000000) | pc->remote.port;
    pc->sctp = wr_sctp_create(pc->a, pc->local.port, pc->remote.port, pc->rng);
    if (!pc->sctp) {
        return;
    }
    wr_sctp_attach_io(pc->sctp, pc->io, &pc->remote);
    wr_sctp_start_established(pc->sctp, my_vtag, peer_vtag,
                              UINT32_C(0x10000000) | pc->remote.port);
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
