#include "wr/sctp.h"

#include "wr/crc32c.h"
#include "wr/map.h"

#include <stdlib.h>
#include <string.h>


#define WR_SCTP_INLINE_CHUNKS 16u

static wr_status sctp_walk(wr_span_c raw, wr_sctp_packet *hdr,
                           wr_sctp_chunk *chunks, size_t max_chunks,
                           size_t *count)
{
    if (WR_UNLIKELY(!hdr || !chunks || !count || !raw.ptr ||
                    raw.len < 12u)) {
        return WR_ERR_TRUNCATED;
    }
    memset(hdr, 0, sizeof(*hdr));
    hdr->src_port = wr_load_be16(raw.ptr);
    hdr->dst_port = wr_load_be16(raw.ptr + 2u);
    hdr->vtag = wr_load_be32(raw.ptr + 4u);
    hdr->checksum = wr_load_be32(raw.ptr + 8u);
    hdr->body_off = 12u;
    hdr->body_len = raw.len - 12u;

    uint8_t hdrbuf[12];
    memcpy(hdrbuf, raw.ptr, 12u);
    wr_store_be32(hdrbuf + 8u, 0u);
    uint32_t crc = wr_crc32c(0u, hdrbuf, 12u);
    crc = wr_crc32c(crc, raw.ptr + 12u, raw.len - 12u);
    if (WR_UNLIKELY(crc != hdr->checksum)) {
        return WR_ERR_AUTH;
    }

    size_t off = 12u;
    size_t n = 0u;
    while (off < raw.len) {
        if (raw.len - off < 4u) {
            return WR_ERR_TRUNCATED;
        }
        if (n >= max_chunks) {
            return WR_ERR_LIMIT;
        }
        wr_sctp_chunk *c = &chunks[n];
        c->type = raw.ptr[off];
        c->flags = raw.ptr[off + 1u];
        c->len = wr_load_be16(raw.ptr + off + 2u);
        if (c->len < 4u || c->len > raw.len - off) {
            return WR_ERR_TRUNCATED;
        }
        c->offset = off;
        c->body = wr_span_c_sub(raw, off + 4u, c->len - 4u);
        n++;
        off += c->len;
        off = (off + 3u) & ~(size_t)3u;
    }
    *count = n;
    return WR_OK;
}

wr_status wr_sctp_parse(wr_arena *a, wr_span_c raw, wr_sctp_msg *out)
{
    if (WR_UNLIKELY(!a || !out || !raw.ptr || raw.len < 12u)) {
        return WR_ERR_TRUNCATED;
    }
    memset(out, 0, sizeof(*out));
    out->raw = raw;
    out->hdr.src_port = wr_load_be16(raw.ptr);
    out->hdr.dst_port = wr_load_be16(raw.ptr + 2u);
    out->hdr.vtag = wr_load_be32(raw.ptr + 4u);
    out->hdr.checksum = wr_load_be32(raw.ptr + 8u);
    out->hdr.body_off = 12u;
    out->hdr.body_len = raw.len - 12u;

    uint8_t hdr[12];
    memcpy(hdr, raw.ptr, 12);
    wr_store_be32(hdr + 8u, 0u);
    uint32_t crc = wr_crc32c(0u, hdr, 12u);
    crc = wr_crc32c(crc, raw.ptr + 12u, raw.len - 12u);
    if (crc != out->hdr.checksum) {
        return WR_ERR_AUTH;
    }

    wr_sctp_chunk_vec_init(&out->chunks, a);
    if (!out->chunks.a) {
        return WR_ERR_NOMEM;
    }
    size_t off = 12u;
    while (off < raw.len) {
        if (raw.len - off < 4u) {
            return WR_ERR_TRUNCATED;
        }
        wr_sctp_chunk c;
        c.type = raw.ptr[off];
        c.flags = raw.ptr[off + 1u];
        c.len = wr_load_be16(raw.ptr + off + 2u);
        if (c.len < 4u || c.len > raw.len - off) {
            return WR_ERR_TRUNCATED;
        }
        c.offset = off;
        c.body = wr_span_c_sub(raw, off + 4u, c.len - 4u);
        if (!wr_sctp_chunk_vec_push(&out->chunks, c)) {
            return WR_ERR_NOMEM;
        }
        off += c.len;
        off = (off + 3u) & ~(size_t)3u;
    }
    return WR_OK;
}

wr_status wr_sctp_serialize(const wr_sctp_packet *pkt, wr_span_c chunks,
                            char *buf, size_t cap, size_t *out_len)
{
    if (!pkt || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (chunks.len > SIZE_MAX - 12u) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = 12u + chunks.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    wr_store_be16(p, pkt->src_port);
    wr_store_be16(p + 2u, pkt->dst_port);
    wr_store_be32(p + 4u, pkt->vtag);
    wr_store_be32(p + 8u, 0u);
    if (chunks.len) {
        memcpy(p + 12u, chunks.ptr, chunks.len);
    }
    uint32_t crc = wr_crc32c(0u, p, total);
    wr_store_be32(p + 8u, crc);
    *out_len = total;
    return WR_OK;
}

wr_status wr_sctp_chunk_serialize(uint8_t type, uint8_t flags, wr_span_c body,
                                  char *buf, size_t cap, size_t *out_len)
{
    if (!buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (body.len > UINT16_MAX - 4u) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = 4u + body.len;
    total = (total + 3u) & ~(size_t)3u;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    buf[0] = (char)type;
    buf[1] = (char)flags;
    wr_store_be16((uint8_t *)buf + 2u, (uint16_t)(4u + body.len));
    if (body.len) {
        memcpy(buf + 4u, body.ptr, body.len);
    }
    memset(buf + 4u + body.len, 0, total - 4u - body.len);
    *out_len = total;
    return WR_OK;
}

wr_status wr_sctp_data_body(uint32_t tsn, uint16_t stream, uint16_t seq,
                            uint32_t ppid, wr_span_c data, char *buf,
                            size_t cap, size_t *out_len)
{
    if (!buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (data.len > SIZE_MAX - 12u) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = 12u + data.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    wr_store_be32(p, tsn);
    wr_store_be16(p + 4u, stream);
    wr_store_be16(p + 6u, seq);
    wr_store_be32(p + 8u, ppid);
    if (data.len) {
        memcpy(p + 12u, data.ptr, data.len);
    }
    *out_len = total;
    return WR_OK;
}

wr_status wr_sctp_sack_body(uint32_t cum_tsn, uint32_t a_rwnd,
                            const uint32_t *gaps, size_t gap_count,
                            const uint32_t *dups, size_t dup_count, char *buf,
                            size_t cap, size_t *out_len)
{
    if (!buf || !out_len || gap_count > UINT16_MAX || dup_count > UINT16_MAX) {
        return WR_ERR_INVAL;
    }
    if (gap_count > (SIZE_MAX - 12u) / 4u ||
        dup_count > (SIZE_MAX - 12u) / 4u) {
        return WR_ERR_OVERFLOW;
    }
    /* gaps is a flat array of (start, end) pairs; gap_count is the number
     * of gap ack blocks. */
    size_t total = 12u + 8u * gap_count + 4u * dup_count;
    if (total > UINT16_MAX - 4u || total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    wr_store_be32(p, cum_tsn);
    wr_store_be32(p + 4u, a_rwnd);
    wr_store_be16(p + 8u, (uint16_t)gap_count);
    wr_store_be16(p + 10u, (uint16_t)dup_count);
    size_t off = 12u;
    for (size_t i = 0; i < gap_count; ++i) {
        wr_store_be32(p + off, gaps[2u * i]);
        wr_store_be32(p + off + 4u, gaps[2u * i + 1u]);
        off += 8u;
    }
    for (size_t i = 0; i < dup_count; ++i) {
        wr_store_be32(p + off, dups[i]);
        off += 4u;
    }
    *out_len = total;
    return WR_OK;
}

wr_status wr_sctp_init_body(uint32_t tag, uint32_t a_rwnd, uint16_t out_streams,
                            uint16_t in_streams, uint32_t initial_tsn,
                            char *buf, size_t cap, size_t *out_len)
{
    if (!buf || !out_len || cap < 16u) {
        return WR_ERR_INVAL;
    }
    uint8_t *p = (uint8_t *)buf;
    wr_store_be32(p, tag);
    wr_store_be32(p + 4u, a_rwnd);
    wr_store_be16(p + 8u, out_streams);
    wr_store_be16(p + 10u, in_streams);
    wr_store_be32(p + 12u, initial_tsn);
    *out_len = 16u;
    return WR_OK;
}


/* ------------------------------------------------------------------------- */
/* Association                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t tsn;
    uint16_t stream;
    uint16_t seq;
    uint32_t ppid;
    wr_span_c data;
    uint64_t sent_ms;
    uint8_t xmit;
    bool acked;
} wr_sctp_tx;

typedef struct {
    uint32_t tsn;
    uint16_t stream;
    uint32_t ppid;
    wr_span_c data;
} wr_sctp_rx;

WR_VEC_DEF(wr_sctp_tx_vec, wr_sctp_tx)
WR_VEC_DEF(wr_sctp_rx_vec, wr_sctp_rx)
WR_VEC_DEF(wr_sctp_u32_vec, uint32_t)

/* RFC 4960 3.3.1: the stream sequence number is maintained independently for
 * each stream, so the transmit side must not share one counter across all of
 * them. */
#define WR_SCTP_MAX_STREAMS 64u

struct wr_sctp_assoc {
    wr_arena *a;
    wr_io *io;
    wr_rng *rng;
    wr_endpoint remote;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t my_vtag;
    uint32_t peer_vtag;
    uint32_t peer_initial_tsn;
    uint32_t peer_cum_tsn; /* peer's DATA cumulative ack */
    uint32_t ack_tsn;      /* our send TSNs acked by peer */
    uint32_t next_tsn;
    uint16_t next_ssn[WR_SCTP_MAX_STREAMS];
    uint16_t peer_last_ssn[WR_SCTP_MAX_STREAMS];
    uint32_t my_initial_tsn;
    wr_sctp_state state;
    uint8_t cookie[256];
    uint8_t cookie_len;
    uint8_t handshake[256];
    size_t handshake_len;
    uint64_t last_handshake_ms;
    uint32_t cwnd;
    uint32_t ssthresh;
    bool slow_start;
    uint32_t rwnd;
    bool established;
    bool closed;
    wr_tsn_set rx_tsn;
    wr_u64_map rx_map;
    wr_sctp_tx_vec tx;
    wr_sctp_rx_vec rx;
    wr_sctp_rx_vec ready;
    wr_sctp_u32_vec rx_free;
    size_t tx_off;    /* consumed, SACK-acked prefix of tx */
    size_t ready_off; /* consumed prefix of ready */
    uint64_t last_rto_ms;
    uint64_t retransmits;
    uint64_t received;
};

wr_sctp_assoc *wr_sctp_create(wr_arena *a, uint16_t local_port,
                              uint16_t remote_port, wr_rng *rng)
{
    if (!a) {
        return NULL;
    }
    wr_sctp_assoc *as = (wr_sctp_assoc *)wr_arena_calloc(a, 1, sizeof(*as));
    if (!as) {
        return NULL;
    }
    as->a = a;
    as->rng = rng;
    as->local_port = local_port;
    as->remote_port = remote_port;
    wr_sctp_tx_vec_init(&as->tx, a);
    wr_sctp_rx_vec_init(&as->rx, a);
    wr_sctp_rx_vec_init(&as->ready, a);
    wr_sctp_u32_vec_init(&as->rx_free, a);
    (void)wr_sctp_tx_vec_reserve(&as->tx, 32u);
    (void)wr_sctp_rx_vec_reserve(&as->rx, 64u);
    (void)wr_sctp_rx_vec_reserve(&as->ready, 64u);
    (void)wr_sctp_u32_vec_reserve(&as->rx_free, 64u);
    if (!as->tx.a || !as->rx.a || !as->ready.a || !as->rx_free.a ||
        !wr_u64_map_init(&as->rx_map, a, 64u)) {
        return NULL;
    }
    wr_tsn_set_init(&as->rx_tsn, 0u);
    if (rng) {
        as->my_vtag = wr_rng_u64(rng);
    }
    if (as->my_vtag == 0u) {
        as->my_vtag = 0x40000000u;
    }
    as->my_initial_tsn = as->my_vtag ^ UINT32_C(0x9e3779b9);
    as->state = WR_SCTP_ST_CLOSED;
    as->cwnd = 4u * 1200u;
    as->ssthresh = 65535u;
    as->slow_start = true;
    as->rwnd = 65535u;
    return as;
}

void wr_sctp_attach_io(wr_sctp_assoc *as, wr_io *io, const wr_endpoint *remote)
{
    if (!as) {
        return;
    }
    as->io = io;
    if (remote) {
        as->remote = *remote;
    }
}

void wr_sctp_start_established(wr_sctp_assoc *as, uint32_t my_vtag,
                               uint32_t peer_vtag, uint32_t peer_initial_tsn)
{
    if (!as) {
        return;
    }
    as->my_vtag = my_vtag;
    as->peer_vtag = peer_vtag;
    as->peer_initial_tsn = peer_initial_tsn;
    as->peer_cum_tsn = peer_initial_tsn - 1u;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
    as->next_tsn = my_vtag;
    memset(as->next_ssn, 0, sizeof(as->next_ssn));
    as->established = true;
    as->closed = false;
    as->state = WR_SCTP_ST_ESTABLISHED;
    as->my_initial_tsn = my_vtag;
    as->peer_cum_tsn = peer_initial_tsn - 1u;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
}

static wr_status send_packet(wr_sctp_assoc *as, wr_span_c chunks)
{
    if (!as || !as->io) {
        return WR_ERR_STATE;
    }
    wr_sctp_packet p;
    memset(&p, 0, sizeof(p));
    p.src_port = as->local_port;
    p.dst_port = as->remote_port;
    p.vtag = as->peer_vtag;
    uint8_t buf[2048];
    size_t n = 0;
    wr_status st = wr_sctp_serialize(&p, chunks, (char *)buf, sizeof(buf), &n);
    if (st != WR_OK) {
        return st;
    }
    size_t sent = 0;
    return wr_io_send(as->io, &as->remote, wr_span_c_make(buf, n), &sent);
}

/* Advertised receive window: the negotiated TSN window minus the chunks that
 * are stored but not yet delivered. Advertising a constant 65535 (as this
 * layer once did) lets a peer overrun the association regardless of state. */
static uint32_t available_rwnd(const wr_sctp_assoc *as)
{
    size_t live = as->rx.len - as->rx_free.len;
    if (live >= WR_SCTP_RX_WINDOW) {
        return 0u;
    }
    return (uint32_t)(WR_SCTP_RX_WINDOW - live);
}

static wr_status send_sack(wr_sctp_assoc *as, uint32_t cum_tsn)
{
    wr_tsn_gap gaps[8];
    uint32_t ngaps = wr_tsn_set_gaps(&as->rx_tsn, gaps, WR_ARRAY_LEN(gaps));
    uint32_t flat[16];
    for (uint32_t i = 0; i < ngaps; ++i) {
        flat[2u * i] = gaps[i].start;
        flat[2u * i + 1u] = gaps[i].end;
    }
    char body[128];
    size_t blen = 0;
    wr_status st = wr_sctp_sack_body(cum_tsn, available_rwnd(as), flat, ngaps,
                                     NULL, 0u, body, sizeof(body), &blen);
    if (st != WR_OK) {
        return st;
    }
    char chunk[160];
    size_t clen = 0;
    st = wr_sctp_chunk_serialize(WR_SCTP_SACK, 0u,
                                 wr_span_c_make(body, blen), chunk,
                                 sizeof(chunk), &clen);
    if (st != WR_OK) {
        return st;
    }
    return send_packet(as, wr_span_c_make(chunk, clen));
}


static wr_status send_handshake(wr_sctp_assoc *as, uint8_t type, uint8_t flags,
                                wr_span_c body, uint64_t now_ms)
{
    char chunk[512];
    size_t clen = 0u;
    if (wr_sctp_chunk_serialize(type, flags, body, chunk, sizeof(chunk),
                                &clen) != WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    wr_sctp_packet p;
    memset(&p, 0, sizeof(p));
    p.src_port = as->local_port;
    p.dst_port = as->remote_port;
    p.vtag = as->peer_vtag;
    char raw[600];
    size_t raw_len = 0u;
    if (wr_sctp_serialize(&p, wr_span_c_make(chunk, clen), raw, sizeof(raw),
                          &raw_len) != WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    if (raw_len > sizeof(as->handshake)) {
        return WR_ERR_OVERFLOW;
    }
    memcpy(as->handshake, raw, raw_len);
    as->handshake_len = raw_len;
    as->last_handshake_ms = now_ms;
    size_t sent = 0u;
    return wr_io_send(as->io, &as->remote, wr_span_c_make(raw, raw_len), &sent);
}

static wr_status send_init(wr_sctp_assoc *as, uint64_t now_ms)
{
    uint8_t body[16];
    wr_store_be32(body, as->my_vtag);
    wr_store_be32(body + 4u, 65535u);
    wr_store_be16(body + 8u, 64u);
    wr_store_be16(body + 10u, 64u);
    wr_store_be32(body + 12u, as->my_initial_tsn);
    return send_handshake(as, WR_SCTP_INIT, 0u,
                          wr_span_c_make(body, sizeof(body)), now_ms);
}

static void handle_init(wr_sctp_assoc *as, const wr_sctp_chunk *c)
{
    if (c->body.len < 16u) {
        return;
    }
    uint32_t peer_vtag = wr_load_be32(c->body.ptr);
    if (as->state == WR_SCTP_ST_COOKIE_ECHOED) {
        /* A retransmitted INIT from the client we already answered: replay the
         * stored INIT_ACK instead of ignoring it. Dropping it wedges the peer
         * in COOKIE_ECHOED until it gives up. */
        if (peer_vtag == as->peer_vtag && as->io && as->handshake_len != 0u) {
            size_t sent = 0u;
            (void)wr_io_send(as->io, &as->remote,
                             wr_span_c_make(as->handshake, as->handshake_len),
                             &sent);
        }
        return;
    }
    if (as->state != WR_SCTP_ST_CLOSED) {
        return;
    }
    as->peer_vtag = peer_vtag;
    as->peer_initial_tsn = wr_load_be32(c->body.ptr + 12u);
    as->peer_cum_tsn = as->peer_initial_tsn - 1u;
    if (as->rng) {
        (void)wr_rng_fill(as->rng, as->cookie, sizeof(as->cookie));
    }
    /* This stack issues a 16-byte cookie; the buffer is larger only so a peer's
     * longer cookie can be stored. */
    as->cookie_len = 16u;
    uint8_t body[16 + 2 + 16];
    wr_store_be32(body, as->my_vtag);
    wr_store_be32(body + 4u, 65535u);
    wr_store_be16(body + 8u, 64u);
    wr_store_be16(body + 10u, 64u);
    wr_store_be32(body + 12u, as->my_initial_tsn);
    wr_store_be16(body + 16u, (uint16_t)as->cookie_len);
    memcpy(body + 18u, as->cookie, as->cookie_len);
    (void)send_handshake(as, WR_SCTP_INIT_ACK, 0u,
                         wr_span_c_make(body, sizeof(body)), 0u);
    as->state = WR_SCTP_ST_COOKIE_ECHOED;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
}

static void handle_init_ack(wr_sctp_assoc *as, const wr_sctp_chunk *c)
{
    if (as->state != WR_SCTP_ST_INIT_SENT || c->body.len < 18u) {
        return;
    }
    as->peer_vtag = wr_load_be32(c->body.ptr);
    as->peer_initial_tsn = wr_load_be32(c->body.ptr + 12u);
    as->peer_cum_tsn = as->peer_initial_tsn - 1u;
    uint16_t ck_len = wr_load_be16(c->body.ptr + 16u);
    /* RFC 4960 3.3.10: the cookie is an opaque, variable-length blob chosen by
     * the peer (up to 32768 bytes). This stack issues 16-byte cookies, but a
     * peer may echo anything it was sent, so accept the full 1-octet length
     * range rather than requiring exactly 16. */
    if (18u + ck_len > c->body.len || ck_len == 0u ||
        ck_len > sizeof(as->cookie)) {
        return;
    }
    as->cookie_len = (uint8_t)ck_len;
    memcpy(as->cookie, c->body.ptr + 18u, ck_len);
    (void)send_handshake(as, WR_SCTP_COOKIE_ECHO, 0u,
                         wr_span_c_make(as->cookie, as->cookie_len), 0u);
    as->state = WR_SCTP_ST_COOKIE_SENT;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
}

static void handle_cookie_echo(wr_sctp_assoc *as, const wr_sctp_chunk *c)
{
    if (as->state != WR_SCTP_ST_COOKIE_ECHOED || as->cookie_len == 0u ||
        c->body.len != as->cookie_len ||
        memcmp(c->body.ptr, as->cookie, as->cookie_len) != 0) {
        return;
    }
    (void)send_handshake(as, WR_SCTP_COOKIE_ACK, 0u,
                         wr_span_c_make(NULL, 0u), 0u);
    as->established = true;
    as->state = WR_SCTP_ST_ESTABLISHED;
    as->next_tsn = as->my_initial_tsn;
    as->ack_tsn = as->my_initial_tsn - 1u;
    as->peer_cum_tsn = as->peer_initial_tsn - 1u;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
}

static void handle_cookie_ack(wr_sctp_assoc *as, const wr_sctp_chunk *c)
{
    (void)c;
    if (as->state != WR_SCTP_ST_COOKIE_SENT) {
        return;
    }
    as->established = true;
    as->state = WR_SCTP_ST_ESTABLISHED;
    as->next_tsn = as->my_initial_tsn;
    as->ack_tsn = as->my_initial_tsn - 1u;
    as->peer_cum_tsn = as->peer_initial_tsn - 1u;
    wr_tsn_set_init(&as->rx_tsn, as->peer_cum_tsn);
}

wr_status wr_sctp_send_data(wr_sctp_assoc *as, uint16_t stream, uint32_t ppid,
                            wr_span_c data, uint64_t now_ms)
{
    if (!as || !as->established || !data.ptr) {
        return WR_ERR_STATE;
    }
    /* 12 (DATA body) + 4 (chunk) + 12 (SCTP header), padded to 4 bytes,
     * must fit send_packet's 2048-byte buffer. */
    if (data.len > 2020u) {
        return WR_ERR_OVERFLOW;
    }
    wr_sctp_tx tx;
    memset(&tx, 0, sizeof(tx));
    tx.tsn = as->next_tsn++;
    tx.stream = stream;
    if (stream < WR_SCTP_MAX_STREAMS) {
        tx.seq = as->next_ssn[stream]++;
    } else {
        /* Stream ids outside the negotiated range are refused rather than
         * silently aliasing another stream's sequence space. */
        return WR_ERR_INVAL;
    }
    tx.ppid = ppid;
    uint8_t *copy = (uint8_t *)wr_arena_alloc(as->a, data.len + 1u);
    if (!copy) {
        return WR_ERR_NOMEM;
    }
    if (data.len) {
        memcpy(copy, data.ptr, data.len);
    }
    tx.data.ptr = copy;
    tx.data.len = data.len;
    tx.sent_ms = now_ms;
    tx.xmit = 1u;
    if (as->tx_off == as->tx.len) {
        as->tx.len = 0u;
        as->tx_off = 0u;
    }
    if (!wr_sctp_tx_vec_push(&as->tx, tx)) {
        return WR_ERR_NOMEM;
    }

    char body[2048];
    size_t blen = 0;
    if (wr_sctp_data_body(tx.tsn, stream, tx.seq, ppid, data, body,
                          sizeof(body), &blen) != WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    char chunk[2100];
    size_t clen = 0;
    if (wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                wr_span_c_make(body, blen), chunk,
                                sizeof(chunk), &clen) != WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    return send_packet(as, wr_span_c_make(chunk, clen));
}

static void deliver_ready(wr_sctp_assoc *as)
{
    for (;;) {
        uint32_t tsn = 0u;
        if (!wr_tsn_set_pop_next(&as->rx_tsn, &tsn)) {
            break;
        }
        uint32_t *idx = wr_u64_map_find(&as->rx_map, tsn);
        if (idx) {
            wr_sctp_rx out = as->rx.data[*idx];
            (void)wr_sctp_rx_vec_push(&as->ready, out);
            (void)wr_u64_map_erase(&as->rx_map, tsn);
            as->rx.data[*idx].data = wr_span_c_make(NULL, 0u);
            (void)wr_sctp_u32_vec_push(&as->rx_free, *idx);
        }
        as->peer_cum_tsn = tsn;
    }
}

static void handle_data(wr_sctp_assoc *as, wr_sctp_chunk *c, uint64_t now_ms)
{
    if (c->body.len < 12u) {
        return;
    }
    /* DATA is only meaningful inside an established association. Without this
     * check an off-path host could inject TSNs and desynchronise the receive
     * window before (or after) the handshake, which is exactly the state
     * confusion an attacker wants. */
    if (as->state != WR_SCTP_ST_ESTABLISHED) {
        return;
    }
    uint32_t tsn = wr_load_be32(c->body.ptr);
    uint16_t stream = wr_load_be16(c->body.ptr + 4u);
    uint16_t seq = wr_load_be16(c->body.ptr + 6u);
    uint32_t ppid = wr_load_be32(c->body.ptr + 8u);
    if (stream >= WR_SCTP_MAX_STREAMS) {
        /* The association was negotiated for at most this many streams. */
        return;
    }
    wr_span_c payload = wr_span_c_sub(c->body, 12u, c->body.len - 12u);

    if (tsn <= as->peer_cum_tsn || wr_tsn_set_has(&as->rx_tsn, tsn)) {
        (void)send_sack(as, as->peer_cum_tsn);
        return;
    }
    if (!wr_tsn_set_add(&as->rx_tsn, tsn)) {
        (void)send_sack(as, as->peer_cum_tsn);
        return;
    }
    /* Track the per-stream sequence so a gap or a replay is visible. Delivery
     * is TSN-ordered, so this is advisory, but it keeps the association honest
     * about stream-level loss. */
    as->peer_last_ssn[stream] = seq;

    uint8_t *copy = (uint8_t *)wr_arena_alloc(as->a, payload.len + 1u);
    if (!copy) {
        (void)send_sack(as, as->peer_cum_tsn);
        return;
    }
    if (payload.len) {
        memcpy(copy, payload.ptr, payload.len);
    }
    wr_sctp_rx rx;
    memset(&rx, 0, sizeof(rx));
    rx.tsn = tsn;
    rx.stream = stream;
    rx.ppid = ppid;
    rx.data.ptr = copy;
    rx.data.len = payload.len;
    uint32_t idx;
    if (as->rx_free.len) {
        idx = as->rx_free.data[--as->rx_free.len];
        as->rx.data[idx] = rx;
    } else {
        if (!wr_sctp_rx_vec_push(&as->rx, rx)) {
            (void)send_sack(as, as->peer_cum_tsn);
            return;
        }
        idx = (uint32_t)(as->rx.len - 1u);
    }
    (void)wr_u64_map_put(&as->rx_map, tsn, idx);
    as->received++;

    deliver_ready(as);
    (void)now_ms;
    (void)send_sack(as, as->peer_cum_tsn);
}

static void handle_sack(wr_sctp_assoc *as, wr_sctp_chunk *c)
{
    if (c->body.len < 12u) {
        return;
    }
    uint32_t cum = wr_load_be32(c->body.ptr);
    uint32_t a_rwnd = wr_load_be32(c->body.ptr + 4u);
    uint16_t ngaps = wr_load_be16(c->body.ptr + 8u);
    uint16_t ndups = wr_load_be16(c->body.ptr + 10u);
    /* Gap-ack blocks: [start, end] inclusive, relative to the cumulative TSN
     * (RFC 4960 3.3.4). Ignoring them (as this layer once did) makes every
     * out-of-order delivery look lost, so a reordered stream retransmits
     * forever and never advances. */
    size_t off = 12u;
    uint32_t gap_start[16];
    uint32_t gap_end[16];
    uint32_t nblocks = 0u;
    if ((size_t)ngaps > (c->body.len - off) / 8u) {
        ngaps = (uint16_t)((c->body.len - off) / 8u);
    }
    for (uint32_t i = 0; i < ngaps && nblocks < WR_ARRAY_LEN(gap_start); ++i) {
        gap_start[nblocks] = wr_load_be32(c->body.ptr + off);
        gap_end[nblocks] = wr_load_be32(c->body.ptr + off + 4u);
        off += 8u;
        nblocks++;
    }
    (void)ndups; /* duplicate TSN reports carry no action for the sender */

    uint32_t newly = 0u;
    for (size_t i = as->tx_off; i < as->tx.len; ++i) {
        wr_sctp_tx *tx = &as->tx.data[i];
        if (tx->acked) {
            continue;
        }
        bool acked = tx->tsn <= cum;
        if (!acked) {
            for (uint32_t g = 0; g < nblocks; ++g) {
                if (tx->tsn >= cum + gap_start[g] &&
                    tx->tsn <= cum + gap_end[g]) {
                    acked = true;
                    break;
                }
            }
        }
        if (acked) {
            tx->acked = true;
            newly++;
        }
    }
    /* Drop the SACK-acked prefix. The vector is TSN-ordered, so this is a
     * contiguous run; advancing a head index keeps handle_sack and step from
     * rescanning history. Compact when the dead prefix dominates. */
    while (as->tx_off < as->tx.len && as->tx.data[as->tx_off].acked) {
        as->tx_off++;
    }
    if (as->tx_off == as->tx.len) {
        as->tx.len = 0u;
        as->tx_off = 0u;
    } else if (as->tx_off >= 64u && as->tx_off * 2u >= as->tx.len) {
        size_t live = as->tx.len - as->tx_off;
        memmove(as->tx.data, as->tx.data + as->tx_off,
                live * sizeof(as->tx.data[0]));
        as->tx.len = live;
        as->tx_off = 0u;
    }
    if (cum > as->ack_tsn) {
        for (uint32_t i = 0; i < newly; ++i) {
            if (as->slow_start) {
                as->cwnd += 1200u;
            } else {
                as->cwnd += (1200u * 1200u) / (as->cwnd ? as->cwnd : 1u);
            }
            if (as->cwnd >= as->ssthresh) {
                as->slow_start = false;
            }
        }
        as->ack_tsn = cum;
    }
    /* The peer's receive window bounds how much may be in flight. */
    as->rwnd = a_rwnd;
}

static bool vtag_ok(const wr_sctp_assoc *as, const wr_sctp_packet *hdr,
                    const wr_sctp_chunk *chunks, size_t n)
{
    /* An INIT is the only chunk that carries the *sender's* tag: a packet made
     * up exclusively of INIT chunks is acceptable only before any state
     * exists. Everything else must echo the tag we chose (RFC 4960 3.3.1 /
     * 8.4.1), which is what makes off-path injection detectable. */
    bool only_init = n > 0u;
    for (size_t i = 0; i < n; ++i) {
        if (chunks[i].type != WR_SCTP_INIT) {
            only_init = false;
            break;
        }
    }
    if (only_init) {
        return as->state == WR_SCTP_ST_CLOSED;
    }
    if (hdr->vtag == as->my_vtag) {
        return true;
    }
    /* An ABORT may be sent with a zero verification tag (RFC 4960 3.3.7). */
    if (hdr->vtag == 0u) {
        for (size_t i = 0; i < n; ++i) {
            if (chunks[i].type == WR_SCTP_ABORT) {
                return true;
            }
        }
    }
    return false;
}

/* RFC 6525 3.3.2: a STREAM_RESET chunk carries a list of parameter types.
 * Type 3 means "all streams". */
#define WR_SCTP_STREAM_RESET 130u
#define WR_SCTP_RESET_ALL_STREAMS 3u

static void send_stream_reset_all(wr_sctp_assoc *as)
{
    uint8_t param[4];
    wr_store_be16(param, WR_SCTP_RESET_ALL_STREAMS);
    wr_store_be16(param + 2u, 4u);
    char chunk[16];
    size_t clen = 0u;
    /* Flags bit 0 = "last chunk in the packet" (RFC 6525 3.3.2). */
    if (wr_sctp_chunk_serialize(WR_SCTP_STREAM_RESET, 0x01u,
                                wr_span_c_make(param, sizeof(param)), chunk,
                                sizeof(chunk), &clen) != WR_OK) {
        return;
    }
    (void)send_packet(as, wr_span_c_make(chunk, clen));
}

static void handle_stream_reset(wr_sctp_assoc *as, const wr_sctp_chunk *c)
{
    if (as->state != WR_SCTP_ST_ESTABLISHED) {
        return;
    }
    /* Find the parameter list and look for the "all streams" marker. A peer
     * that resets individual streams is not distinguished here: the local
     * stream table is a single set of sequence counters, so dropping
     * undelivered data is the conservative action either way. */
    size_t off = 0u;
    bool all = false;
    while (off + 4u <= c->body.len) {
        uint16_t ptype = wr_load_be16(c->body.ptr + off);
        uint16_t plen = wr_load_be16(c->body.ptr + off + 2u);
        if (plen < 4u || off + plen > c->body.len) {
            break;
        }
        if (ptype == WR_SCTP_RESET_ALL_STREAMS) {
            all = true;
        }
        off += plen;
    }
    if (!all) {
        return;
    }
    /* Discard chunks that were received but never delivered. Already-ready
     * entries are left alone: they were accepted before the reset. */
    for (size_t i = 0; i < as->rx.len; ++i) {
        if (as->rx.data[i].data.ptr != NULL) {
            (void)wr_u64_map_erase(&as->rx_map, as->rx.data[i].tsn);
            as->rx.data[i].data = wr_span_c_make(NULL, 0u);
            if (as->rx_free.len < as->rx_free.cap) {
                (void)wr_sctp_u32_vec_push(&as->rx_free, (uint32_t)i);
            }
        }
    }
    as->peer_cum_tsn = as->rx_tsn.cum;
    memset(as->next_ssn, 0, sizeof(as->next_ssn));
    memset(as->peer_last_ssn, 0, sizeof(as->peer_last_ssn));
    (void)send_stream_reset_all(as);
}

wr_status wr_sctp_input(wr_sctp_assoc *as, uint64_t now_ms,
                        const wr_endpoint *from, wr_span_c packet)
{
    if (!as) {
        return WR_ERR_INVAL;
    }
    /* Source filtering: the association is bound to one peer. Without it any
     * host that can reach the socket can inject chunks, and SCTP has no
     * cryptographic protection of its own. */
    if (from && as->remote.port != 0u && !wr_endpoint_eq(&as->remote, from)) {
        return WR_ERR_AUTH;
    }
    wr_sctp_packet hdr;
    wr_sctp_chunk stack_chunks[WR_SCTP_INLINE_CHUNKS];
    size_t stack_count = 0u;
    wr_status st = sctp_walk(packet, &hdr, stack_chunks,
                             WR_SCTP_INLINE_CHUNKS, &stack_count);
    wr_sctp_msg msg;
    wr_sctp_chunk *chunks = stack_chunks;
    size_t chunk_count = stack_count;
    if (st == WR_ERR_LIMIT) {
        st = wr_sctp_parse(as->a, packet, &msg);
        if (st != WR_OK) {
            return st;
        }
        chunks = msg.chunks.data;
        chunk_count = msg.chunks.len;
    } else if (st != WR_OK) {
        return st;
    }
    if (chunk_count == 0u) {
        return WR_ERR_TRUNCATED;
    }
    if (!vtag_ok(as, &hdr, chunks, chunk_count)) {
        return WR_ERR_AUTH;
    }
    for (size_t i = 0; i < chunk_count; ++i) {
        wr_sctp_chunk *c = &chunks[i];
        switch (c->type) {
        case WR_SCTP_DATA:
            handle_data(as, c, now_ms);
            break;
        case WR_SCTP_SACK:
            handle_sack(as, c);
            break;
        case WR_SCTP_HEARTBEAT: {
            /* Only an established association has a peer to answer. */
            if (as->state != WR_SCTP_ST_ESTABLISHED) {
                break;
            }
            char chunk[64];
            size_t clen = 0;
            (void)wr_sctp_chunk_serialize(WR_SCTP_HEARTBEAT_ACK, 0u,
                                          wr_span_c_make(NULL, 0), chunk,
                                          sizeof(chunk), &clen);
            (void)send_packet(as, wr_span_c_make(chunk, clen));
            break;
        }
        case WR_SCTP_INIT:
            handle_init(as, c);
            break;
        case WR_SCTP_INIT_ACK:
            handle_init_ack(as, c);
            break;
        case WR_SCTP_COOKIE_ECHO:
            handle_cookie_echo(as, c);
            break;
        case WR_SCTP_COOKIE_ACK:
            handle_cookie_ack(as, c);
            break;
        case WR_SCTP_STREAM_RESET:
            handle_stream_reset(as, c);
            break;
        case WR_SCTP_SHUTDOWN: {
            if (as->state != WR_SCTP_ST_ESTABLISHED) {
                break;
            }
            char chunk[8];
            size_t clen = 0;
            (void)wr_sctp_chunk_serialize(WR_SCTP_SHUTDOWN_ACK, 0u,
                                          wr_span_c_make(NULL, 0), chunk,
                                          sizeof(chunk), &clen);
            (void)send_packet(as, wr_span_c_make(chunk, clen));
            break;
        }
        default:
            break;
        }
    }
    return WR_OK;
}

wr_status wr_sctp_step(wr_sctp_assoc *as, uint64_t now_ms)
{
    if (!as) {
        return WR_ERR_INVAL;
    }
    if (!as->established) {
        if (as->state != WR_SCTP_ST_CLOSED && as->handshake_len != 0u &&
            now_ms - as->last_handshake_ms >= 1000u) {
            size_t sent = 0u;
            (void)wr_io_send(as->io, &as->remote,
                             wr_span_c_make(as->handshake, as->handshake_len),
                             &sent);
            as->last_handshake_ms = now_ms;
        }
        return WR_OK;
    }
    for (size_t i = as->tx_off; i < as->tx.len; ++i) {
        wr_sctp_tx *tx = &as->tx.data[i];
        if (tx->acked || tx->xmit >= 6u) {
            continue;
        }
        if (now_ms - tx->sent_ms < 1000u) {
            continue;
        }
        char body[2048];
        size_t blen = 0;
        if (wr_sctp_data_body(tx->tsn, tx->stream, tx->seq, tx->ppid,
                              tx->data, body, sizeof(body), &blen) != WR_OK) {
            continue;
        }
        char chunk[2100];
        size_t clen = 0;
        if (wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                    wr_span_c_make(body, blen), chunk,
                                    sizeof(chunk), &clen) != WR_OK) {
            continue;
        }
        if (send_packet(as, wr_span_c_make(chunk, clen)) == WR_OK) {
            tx->sent_ms = now_ms;
            tx->xmit++;
            as->retransmits++;
            as->ssthresh = as->cwnd / 2u;
            as->cwnd = 1200u;
            as->slow_start = true;
        }
    }
    /* If every outstanding chunk has exhausted its retransmit budget the peer
     * is gone. Signal failure instead of looping silently forever. */
    bool any_live = false;
    for (size_t i = as->tx_off; i < as->tx.len; ++i) {
        if (!as->tx.data[i].acked && as->tx.data[i].xmit < 6u) {
            any_live = true;
            break;
        }
    }
    if (!any_live && as->tx_off < as->tx.len) {
        as->state = WR_SCTP_ST_FAILED;
        as->established = false;
    }
    return WR_OK;
}

uint32_t wr_sctp_last_ack(const wr_sctp_assoc *as)
{
    return as ? as->peer_cum_tsn : 0u;
}

bool wr_sctp_recv(wr_sctp_assoc *as, wr_sctp_delivery *out)
{
    if (!as || !out || as->ready_off >= as->ready.len) {
        return false;
    }
    const wr_sctp_rx *rx = &as->ready.data[as->ready_off];
    out->stream = rx->stream;
    out->ppid = rx->ppid;
    out->data = rx->data;
    as->ready_off++;
    if (as->ready_off == as->ready.len) {
        as->ready.len = 0u;
        as->ready_off = 0u;
    }
    return true;
}

void wr_sctp_close(wr_sctp_assoc *as)
{
    if (!as) {
        return;
    }
    if (as->state == WR_SCTP_ST_ESTABLISHED) {
        /* Tell the peer the streams are gone instead of just dropping them:
         * without this its delivery queue fills with data that will never be
         * read. */
        send_stream_reset_all(as);
        as->state = WR_SCTP_ST_CLOSING;
    }
    as->closed = true;
    as->established = false;
}

wr_status wr_sctp_start(wr_sctp_assoc *as, uint64_t now_ms)
{
    if (!as || as->state != WR_SCTP_ST_CLOSED) {
        return WR_ERR_STATE;
    }
    wr_status st = send_init(as, now_ms);
    if (st == WR_OK) {
        as->state = WR_SCTP_ST_INIT_SENT;
    }
    return st;
}

wr_sctp_state wr_sctp_get_state(const wr_sctp_assoc *as)
{
    return as ? as->state : WR_SCTP_ST_CLOSED;
}
