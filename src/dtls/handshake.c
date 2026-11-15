#include "wr/dtls.h"
#include "dtls_internal.h"

#include "wr/crypto.h"
#include "wr/net.h"
#include "wr/rng.h"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static bool append_transcript(wr_dtls *d, const void *p, size_t n)
{
    if (!d || !p || n == 0u) {
        return d != NULL;
    }
    if (d->tr_len + n > sizeof(d->transcript)) {
        /* A silent truncation desynchronises the handshake hash and fails
         * Finished with no diagnostic. Refuse instead: the caller fails the
         * association and the peer sees a clean alert. */
        return false;
    }
    memcpy(d->transcript + d->tr_len, p, n);
    d->tr_len += n;
    return true;
}

static void hs_message(uint8_t type, wr_span_c body, uint16_t seq,
                       uint8_t *out, size_t cap, size_t *out_len)
{
    if (cap < 12u + body.len) {
        *out_len = 0u;
        return;
    }
    out[0] = type;
    store_be24(out + 1u, (uint32_t)body.len);
    wr_store_be16(out + 4u, seq);
    store_be24(out + 6u, 0u);
    store_be24(out + 9u, (uint32_t)body.len);
    if (body.len) {
        memcpy(out + 12u, body.ptr, body.len);
    }
    *out_len = 12u + body.len;
}

static void next_seq(uint8_t seq[6])
{
    for (int i = 5; i >= 0; --i) {
        if (++seq[i] != 0u) {
            break;
        }
    }
}

static bool flight_add(wr_dtls *d, wr_span_c rec)
{
    if (d->flight_len + rec.len > sizeof(d->flight)) {
        return false;
    }
    memcpy(d->flight + d->flight_len, rec.ptr, rec.len);
    d->flight_len += rec.len;
    return true;
}

/* Starting a new flight invalidates the retransmission timer for the previous
 * one: the next wr_dtls_step() must wait a full interval before resending, and
 * the retry budget resets. */
static void flight_reset(wr_dtls *d)
{
    d->flight_len = 0u;
    d->flight_gen++;
}

static bool send_flight(wr_dtls *d)
{
    if (!d->io || d->flight_len == 0u) {
        return false;
    }
    size_t sent = 0u;
    return wr_io_send(d->io, &d->peer, wr_span_c_make(d->flight, d->flight_len),
                       &sent) == WR_OK;
}


static bool verify_finished(wr_dtls *d, wr_span_c body, bool client_finished)
{
    if (!d->keys_ready || body.len != 12u) {
        return false;
    }
    uint8_t hash[32];
    wr_crypto_sha256(wr_span_c_make(d->transcript, d->tr_len), hash);
    uint8_t expect[12];
    wr_dtls_prf(d->master, sizeof(d->master),
                wr_span_c_from_str(client_finished ? "client finished"
                                                   : "server finished"),
                wr_span_c_make(hash, 32), expect, sizeof(expect));
    uint8_t diff = 0u;
    for (size_t i = 0; i < 12u; ++i) {
        diff |= (uint8_t)(expect[i] ^ body.ptr[i]);
    }
    return diff == 0u;
}

/* ------------------------------------------------------------------------- */
/* Handshake construction                                                      */
/* ------------------------------------------------------------------------- */

/* TLS transcript form: a handshake message is hashed with the TLS 4-byte
 * header (type + 24-bit length), never the DTLS 12-byte header with its
 * message_seq and fragment fields (RFC 6347 4.2.1 / RFC 7627). */
static void tls_message(uint8_t type, wr_span_c body, uint8_t *out,
                        size_t cap, size_t *out_len)
{
    if (cap < 4u + body.len) {
        *out_len = 0u;
        return;
    }
    out[0] = type;
    store_be24(out + 1u, (uint32_t)body.len);
    if (body.len) {
        memcpy(out + 4u, body.ptr, body.len);
    }
    *out_len = 4u + body.len;
}

/* Transcript-mode switch removed: the hash construction is fixed to RFC 6347
 * (the pre-cookie ClientHello and the HelloVerifyRequest are not hashed), so
 * behaviour can no longer be changed through the environment. */

static bool queue_hs(wr_dtls *d, uint8_t type, wr_span_c body, bool encrypt,
                     bool transcript)
{
    uint8_t msg[2048];
    size_t msg_len = 0u;
    hs_message(type, body, d->hs_send_seq, msg, sizeof(msg), &msg_len);
    if (msg_len == 0u) {
        return false;
    }
    if (transcript) {
        uint8_t tmsg[2048];
        size_t tmsg_len = 0u;
        tls_message(type, body, tmsg, sizeof(tmsg), &tmsg_len);
        if (tmsg_len == 0u || !append_transcript(d, tmsg, tmsg_len)) {
            return false;
        }
    }
    d->hs_send_seq++;

    if (!encrypt) {
        wr_dtls_hs h;
        memset(&h, 0, sizeof(h));
        h.type = type;
        h.length = (uint32_t)body.len;
        h.msg_seq = (uint16_t)(d->hs_send_seq - 1u);
        h.frag_len = (uint32_t)body.len;
        h.body = body;
        uint8_t hs[2048];
        size_t hs_len = 0u;
        if (wr_dtls_hs_serialize(&h, (char *)hs, sizeof(hs), &hs_len) != WR_OK) {
            return false;
        }
        wr_dtls_record r;
        memset(&r, 0, sizeof(r));
        r.type = WR_DTLS_HANDSHAKE;
        r.version = UINT16_C(0xfefd);
        r.epoch = 0u;
        memcpy(r.seq, d->write_seq[0], 6u);
        r.body = wr_span_c_make(hs, hs_len);
        uint8_t rec[2048];
        size_t rec_len = 0u;
        if (wr_dtls_record_serialize(&r, (char *)rec, sizeof(rec),
                                     &rec_len) != WR_OK) {
            return false;
        }
        next_seq(d->write_seq[0]);
        return flight_add(d, wr_span_c_make(rec, rec_len));
    }

    uint8_t rec[2048];
    size_t rec_len = 0u;
    if (wr_dtls_encrypt(&d->cwrite, WR_DTLS_HANDSHAKE, 1u, d->write_seq[1],
                        wr_span_c_make(msg, msg_len), (char *)rec, sizeof(rec),
                        &rec_len) != WR_OK) {
        return false;
    }
    next_seq(d->write_seq[1]);
    return flight_add(d, wr_span_c_make(rec, rec_len));
}

static bool queue_ccs(wr_dtls *d)
{
    /* ChangeCipherSpec is a plaintext record in the current epoch carrying a
     * single 0x01 byte (RFC 5246 7.1). The peer switches its read cipher on
     * receipt; the following Finished is the first record of epoch 1. */
    wr_dtls_record r;
    memset(&r, 0, sizeof(r));
    r.type = WR_DTLS_CCS;
    r.version = UINT16_C(0xfefd);
    r.epoch = 0u;
    memcpy(r.seq, d->write_seq[0], 6u);
    r.body = wr_span_c_from_str("\x01");
    uint8_t rec[32];
    size_t rec_len = 0u;
    if (wr_dtls_record_serialize(&r, (char *)rec, sizeof(rec), &rec_len) !=
        WR_OK) {
        return false;
    }
    next_seq(d->write_seq[0]);
    return flight_add(d, wr_span_c_make(rec, rec_len));
}

static bool build_client_hello(wr_dtls *d)
{
    /* RFC 6347 4.2.1: the cookie is a variable-length opaque blob (up to 255
     * bytes) chosen by the server, so the body must accommodate the largest
     * legal one plus the fixed fields and the extension block. */
    uint8_t body[384];
    size_t off = 0u;
    if (WR_UNLIKELY(2u + 32u + 1u + 1u + (size_t)d->cookie_len + 80u >
                    sizeof(body))) {
        return false;
    }
    body[off++] = 0xfe;
    body[off++] = 0xfd;
    /* The ClientHello carries no key material; the ECDH key is sent later in
     * the ClientKeyExchange, so it is generated once and kept across the
     * HelloVerifyRequest round trip. */
    if (!d->have_ecdh &&
        (wr_rng_fill(d->rng, d->client_random, 32) != WR_OK ||
         wr_crypto_ecdh_keygen(wr_crypto_openssl(), d->ecdh_priv,
                               d->ecdh_pub) != WR_OK)) {
        return false;
    }
    d->have_ecdh = true;
    memcpy(body + off, d->client_random, 32);
    off += 32u;
    body[off++] = 0u; /* session id */
    body[off++] = (uint8_t)d->cookie_len;
    if (d->cookie_len != 0u) {
        memcpy(body + off, d->cookie, d->cookie_len);
        off += d->cookie_len;
    }
    wr_store_be16(body + off, 2u);
    off += 2u;
    wr_store_be16(body + off, UINT16_C(0xc02b)); /* ECDHE_ECDSA_AES_128_GCM */
    off += 2u;
    body[off++] = 1u; /* null compression */
    body[off++] = 0u;

    /* Extensions block. */
    size_t ext_len_off = off;
    off += 2u;
    /* use_srtp (0x000e): SRTP_AES128_CM_HMAC_SHA1_80, empty MKI. */
    wr_store_be16(body + off, UINT16_C(0x000e));
    off += 2u;
    wr_store_be16(body + off, 5u);
    off += 2u;
    wr_store_be16(body + off, 2u);
    off += 2u;
    wr_store_be16(body + off, UINT16_C(0x0001));
    off += 2u;
    body[off++] = 0u; /* mki_len */
    /* supported_groups (0x000a): secp256r1, the only curve implemented. */
    wr_store_be16(body + off, UINT16_C(0x000a));
    off += 2u;
    wr_store_be16(body + off, 4u);
    off += 2u;
    wr_store_be16(body + off, 2u);
    off += 2u;
    wr_store_be16(body + off, 23u);
    off += 2u;
    /* signature_algorithms (0x000d): ecdsa_secp256r1_sha256. */
    wr_store_be16(body + off, UINT16_C(0x000d));
    off += 2u;
    wr_store_be16(body + off, 4u);
    off += 2u;
    wr_store_be16(body + off, 2u);
    off += 2u;
    wr_store_be16(body + off, UINT16_C(0x0403));
    off += 2u;
    /* extended_master_secret (0x0017). */
    wr_store_be16(body + off, UINT16_C(0x0017));
    off += 2u;
    wr_store_be16(body + off, 0u);
    off += 2u;
    /* supported_point_formats (0x000b): uncompressed. */
    wr_store_be16(body + off, UINT16_C(0x000b));
    off += 2u;
    wr_store_be16(body + off, 2u);
    off += 2u;
    body[off++] = 1u;
    body[off++] = 0u;
    wr_store_be16(body + ext_len_off, (uint16_t)(off - ext_len_off - 2u));

    flight_reset(d);
    return queue_hs(d, WR_DTLS_HIERARCHY_CLIENT_HELLO,
                    wr_span_c_make(body, off), false, true);
}

static bool build_server_hello(wr_dtls *d)
{
    uint8_t body[64];
    size_t off = 0u;
    body[off++] = 0xfe;
    body[off++] = 0xfd;
    if (wr_rng_fill(d->rng, d->server_random, 32) != WR_OK) {
        return false;
    }
    memcpy(body + off, d->server_random, 32);
    off += 32u;
    body[off++] = 0u;
    wr_store_be16(body + off, UINT16_C(0xc02b));
    off += 2u;
    body[off++] = 0u;
    if (d->use_ems) {
        /* Echo the extended_master_secret extension the client offered. */
        wr_store_be16(body + off, 4u);
        off += 2u;
        wr_store_be16(body + off, UINT16_C(0x0017));
        off += 2u;
        wr_store_be16(body + off, 0u);
        off += 2u;
    }
    return queue_hs(d, WR_DTLS_HIERARCHY_SERVER_HELLO,
                    wr_span_c_make(body, off), false, true);
}

static bool build_certificate(wr_dtls *d)
{
    uint8_t body[WR_DTLS_CERT_MAX + 8u];
    if (d->cert_der_len + 6u > sizeof(body)) {
        return false;
    }
    store_be24(body, (uint32_t)(d->cert_der_len + 3u));
    store_be24(body + 3u, (uint32_t)d->cert_der_len);
    memcpy(body + 6u, d->cert_der, d->cert_der_len);
    return queue_hs(d, WR_DTLS_HIERARCHY_CERTIFICATE,
                    wr_span_c_make(body, d->cert_der_len + 6u), false, true);
}

static bool build_ske(wr_dtls *d)
{
    if (wr_crypto_ecdh_keygen(wr_crypto_openssl(), d->ecdh_priv,
                              d->ecdh_pub) != WR_OK) {
        return false;
    }
    d->have_ecdh = true;
    uint8_t params[69];
    size_t off = 0u;
    params[off++] = 3u; /* named_curve */
    wr_store_be16(params + off, 23u); /* secp256r1 */
    off += 2u;
    params[off++] = 65u;
    memcpy(params + off, d->ecdh_pub, 65u);

    uint8_t signed_data[32 + 32 + 69];
    memcpy(signed_data, d->client_random, 32);
    memcpy(signed_data + 32, d->server_random, 32);
    memcpy(signed_data + 64, params, 69);

    uint8_t sig[160];
    size_t sig_len = 0u;
    if (!wr_dtls_sign_ske(d, wr_span_c_make(signed_data, sizeof(signed_data)), sig,
                  sizeof(sig), &sig_len)) {
        return false;
    }
    uint8_t body[69 + 4 + 160];
    memcpy(body, params, 69);
    off = 69u;
    wr_store_be16(body + off, UINT16_C(0x0403)); /* ecdsa_secp256r1_sha256 */
    off += 2u;
    wr_store_be16(body + off, (uint16_t)sig_len);
    off += 2u;
    memcpy(body + off, sig, sig_len);
    off += sig_len;
    return queue_hs(d, WR_DTLS_HIERARCHY_SERVER_KEY_EXCHANGE,
                    wr_span_c_make(body, off), false, true);
}

static bool build_server_hello_done(wr_dtls *d)
{
    return queue_hs(d, WR_DTLS_HIERARCHY_SERVER_HELLO_DONE,
                    wr_span_c_make(NULL, 0u), false, true);
}

static bool build_client_key_exchange(wr_dtls *d)
{
    uint8_t body[66];
    body[0] = 65u;
    memcpy(body + 1u, d->ecdh_pub, 65u);
    return queue_hs(d, WR_DTLS_HIERARCHY_CLIENT_KEY_EXCHANGE,
                    wr_span_c_make(body, 66u), false, true);
}

static bool build_finished(wr_dtls *d, bool client)
{
    uint8_t hash[32];
    wr_crypto_sha256(wr_span_c_make(d->transcript, d->tr_len), hash);
    uint8_t verify[12];
    wr_dtls_prf(d->master, sizeof(d->master),
                wr_span_c_from_str(client ? "client finished"
                                          : "server finished"),
                wr_span_c_make(hash, 32), verify, sizeof(verify));
    if (!queue_hs(d, WR_DTLS_HIERARCHY_FINISHED,
                  wr_span_c_make(verify, 12u), true, false)) {
        return false;
    }
    if (client) {
        /* The client Finished is part of the server's transcript. */
        uint8_t msg[4 + 12];
        size_t msg_len = 0u;
        tls_message(WR_DTLS_HIERARCHY_FINISHED,
                    wr_span_c_make(verify, 12u), msg, sizeof(msg), &msg_len);
        if (msg_len == 0u || !append_transcript(d, msg, msg_len)) {
            return false;
        }
    }
    return true;
}

static bool build_client_flight(wr_dtls *d)
{
    flight_reset(d);
    /* The RFC 7627 session hash covers handshake messages up to and including
     * the ClientKeyExchange, so the keys are derived only after it is queued
     * and appended to the transcript. */
    if (!build_client_key_exchange(d)) {
        return false;
    }
    wr_dtls_derive_keys(d, wr_span_c_make(d->shared_secret, 32u));
    if (!d->keys_ready) {
        return false;
    }
    if (!queue_ccs(d)) {
        return false;
    }
    return build_finished(d, true);
}

static bool build_server_flight(wr_dtls *d)
{
    flight_reset(d);
    if (!build_server_hello(d) || !build_certificate(d) || !build_ske(d) ||
        !build_server_hello_done(d)) {
        return false;
    }
    return true;
}

static bool build_server_final(wr_dtls *d)
{
    flight_reset(d);
    return queue_ccs(d) && build_finished(d, false);
}

/* ------------------------------------------------------------------------- */
/* Handshake input                                                           */
/* ------------------------------------------------------------------------- */

static void fail(wr_dtls *d)
{
    d->state = WR_DTLS_FAILED;
    d->wait = WAIT_NONE;
    d->flight_len = 0u;
}

/* ------------------------------------------------------------------------- */
/* HelloVerifyRequest cookie (RFC 6347 4.2.1)                                */
/* ------------------------------------------------------------------------- */

/* The cookie binds the per-association secret, the peer endpoint, and the
 * ClientHello random: the server allocates handshake state only after the
 * client proves it can receive at the claimed address, which removes the
 * amplification attack surface. */
static void cookie_compute(wr_dtls *d, wr_span_c client_random,
                           uint8_t out[WR_DTLS_COOKIE_LEN])
{
    uint8_t buf[16u + 1u + 16u + 2u + 32u];
    size_t off = 0u;
    memcpy(buf, d->cookie_secret, sizeof(d->cookie_secret));
    off += sizeof(d->cookie_secret);
    buf[off++] = (uint8_t)d->peer.af;
    memcpy(buf + off, d->peer.ip.b.v6, 16u);
    off += 16u;
    wr_store_be16(buf + off, d->peer.port);
    off += 2u;
    if (client_random.len == 32u) {
        memcpy(buf + off, client_random.ptr, 32u);
        off += 32u;
    }
    uint8_t hash[32];
    wr_crypto_sha256(wr_span_c_make(buf, off), hash);
    memcpy(out, hash, WR_DTLS_COOKIE_LEN);
    wr_secure_zero(buf, sizeof(buf));
    wr_secure_zero(hash, sizeof(hash));
}

static bool send_hvr(wr_dtls *d)
{
    uint8_t body[3u + WR_DTLS_COOKIE_LEN];
    size_t off = 0u;
    body[off++] = 0xfe;
    body[off++] = 0xfd;
    body[off++] = WR_DTLS_COOKIE_LEN;
    cookie_compute(d, wr_span_c_make(d->client_random, 32u), body + off);
    off += WR_DTLS_COOKIE_LEN;
    uint8_t msg[12u + sizeof(body)];
    size_t msg_len = 0u;
    hs_message(WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST,
               wr_span_c_make(body, off), 0u, msg, sizeof(msg), &msg_len);
    if (msg_len == 0u) {
        return false;
    }
    wr_dtls_record r;
    memset(&r, 0, sizeof(r));
    r.type = WR_DTLS_HANDSHAKE;
    r.version = UINT16_C(0xfefd);
    r.epoch = 0u;
    memcpy(r.seq, d->write_seq[0], 6u);
    r.body = wr_span_c_make(msg, msg_len);
    uint8_t rec[64u + sizeof(msg)];
    size_t rec_len = 0u;
    if (wr_dtls_record_serialize(&r, (char *)rec, sizeof(rec), &rec_len) !=
        WR_OK) {
        return false;
    }
    next_seq(d->write_seq[0]);
    flight_reset(d);
    if (!flight_add(d, wr_span_c_make(rec, rec_len))) {
        return false;
    }
    /* The HelloVerifyRequest occupies server message sequence 0, so the
     * ServerHello that follows is sequence 1. */
    d->hs_send_seq = 1u;
    return send_flight(d);
}

/* Parses the ClientHello the server receives: version, random, session id,
 * cookie, cipher suites, compression, and the extensions block. Returns the
 * cookie span and whether extended_master_secret was offered. */
static bool parse_client_hello(wr_dtls *d, wr_span_c body, wr_span_c *cookie,
                               bool *ems)
{
    (void)d;
    if (body.len < 34u) {
        return false;
    }
    size_t off = 34u; /* version(2) + random(32) */
    uint8_t sid_len = body.ptr[off++];
    if (off + sid_len > body.len) {
        return false;
    }
    off += sid_len;
    if (off >= body.len) {
        return false;
    }
    uint8_t ck_len = body.ptr[off++];
    if (off + ck_len > body.len) {
        return false;
    }
    *cookie = wr_span_c_make(body.ptr + off, ck_len);
    off += ck_len;
    if (off + 2u > body.len) {
        return false;
    }
    uint16_t cs_len = wr_load_be16(body.ptr + off);
    off += 2u;
    if (off + cs_len > body.len || (cs_len & 1u) != 0u) {
        return false;
    }
    off += cs_len;
    if (off >= body.len) {
        return false;
    }
    uint8_t comp_len = body.ptr[off++];
    if (off + comp_len > body.len) {
        return false;
    }
    off += comp_len;
    *ems = false;
    if (off == body.len) {
        return true;
    }
    if (off + 2u > body.len) {
        return false;
    }
    uint16_t ext_len = wr_load_be16(body.ptr + off);
    off += 2u;
    if (ext_len != body.len - off) {
        return false;
    }
    size_t end = body.len;
    while (off + 4u <= end) {
        uint16_t type = wr_load_be16(body.ptr + off);
        uint16_t len = wr_load_be16(body.ptr + off + 2u);
        off += 4u;
        if (off + len > end) {
            return false;
        }
        if (type == UINT16_C(0x0017) && len == 0u) {
            *ems = true;
        }
        off += len;
    }
    return off == end;
}

static bool handle_handshake(wr_dtls *d, const wr_dtls_hs *h);

/* Returns false when a completed fragment failed handling; the caller must
 * fail the association, otherwise a broken handshake would stall silently in
 * the retransmit wait state. */
static bool handle_fragment(wr_dtls *d, wr_span_c body, uint8_t type,
                            uint16_t seq, uint32_t off, uint32_t total_len)
{
    if (d->have_recv_hs && seq <= d->last_recv_hs && !d->hs_frag_active) {
        return true;
    }
    if (off == 0u) {
        d->hs_frag_len = 0u;
        d->hs_frag_need = total_len;
        d->hs_frag_seq = seq;
        d->hs_frag_active = true;
    }
    if (!d->hs_frag_active || seq != d->hs_frag_seq) {
        return true;
    }
    if (off != d->hs_frag_len || d->hs_frag_len + body.len > sizeof(d->hs_frag)) {
        return true;
    }
    memcpy(d->hs_frag + d->hs_frag_len, body.ptr, body.len);
    d->hs_frag_len += body.len;
    if (d->hs_frag_len < d->hs_frag_need) {
        return true;
    }
    d->hs_frag_active = false;
    wr_dtls_hs full;
    memset(&full, 0, sizeof(full));
    full.type = type;
    full.length = d->hs_frag_need;
    full.msg_seq = seq;
    full.body = wr_span_c_make(d->hs_frag, d->hs_frag_len);
    if (!d->have_recv_hs || seq > d->last_recv_hs) {
        uint8_t msg[4 + WR_DTLS_HI_MAX];
        size_t msg_len = 0u;
        tls_message(type, full.body, msg, sizeof(msg), &msg_len);
        /* Same transcript rule as the unfragmented path: Finished carries the
         * verify data over the transcript, and the HelloVerifyRequest round is
         * not part of it (RFC 6347 4.2.1). */
        if (type != WR_DTLS_HIERARCHY_FINISHED &&
            type != WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST) {
            if (msg_len == 0u || !append_transcript(d, msg, msg_len)) {
                return false;
            }
        }
        d->last_recv_hs = seq;
        d->have_recv_hs = true;
    }
    return handle_handshake(d, &full);
}

static bool cookie_valid(wr_dtls *d, wr_span_c cookie,
                         wr_span_c client_random)
{
    uint8_t expect[WR_DTLS_COOKIE_LEN];
    cookie_compute(d, client_random, expect);
    uint8_t diff = 0u;
    /* Strict length check plus a constant-time compare: the server only
     * accepts an echo of the exact cookie it issued. (The client side is the
     * one that must tolerate other lengths; WR_DTLS_COOKIE_MAX bounds that.) */
    if (cookie.len != sizeof(expect)) {
        wr_secure_zero(expect, sizeof(expect));
        return false;
    }
    for (size_t i = 0; i < sizeof(expect); ++i) {
        diff |= (uint8_t)(expect[i] ^ cookie.ptr[i]);
    }
    wr_secure_zero(expect, sizeof(expect));
    return diff == 0u;
}

static bool handle_handshake(wr_dtls *d, const wr_dtls_hs *h)
{
    switch (h->type) {
    case WR_DTLS_HIERARCHY_CLIENT_HELLO: {
        if (d->role != WR_DTLS_ROLE_SERVER || h->body.len < 34u) {
            return false;
        }
        /* Retransmissions are deduplicated by message_seq before this point;
         * a new ClientHello is only expected before the first flight. The
         * server may be in NEW (not yet started) or WAIT. */
        if ((d->state != WR_DTLS_NEW && d->state != WR_DTLS_WAIT) ||
            d->wait != WAIT_NONE) {
            return true;
        }
        memcpy(d->client_random, h->body.ptr + 2u, 32u);
        wr_span_c cookie;
        bool ems = false;
        if (!parse_client_hello(d, h->body, &cookie, &ems)) {
            return false;
        }
        if (!cookie_valid(d, cookie,
                          wr_span_c_make(d->client_random, 32u))) {
            return send_hvr(d);
        }
        d->use_ems = ems;
        /* RFC 6347 4.2.1: the HelloVerifyRequest round is not part of the
         * transcript; the hash starts at the cookie-bearing ClientHello.
         * handle_record already appended it, so restart from here. The
         * re-append must use the TLS 4-byte header form, matching every
         * other transcript site. */
        d->tr_len = 0u;
        {
            uint8_t msg[4u + 4096u];
            size_t msg_len = 0u;
            tls_message(h->type, h->body, msg, sizeof(msg), &msg_len);
            if (msg_len == 0u || !append_transcript(d, msg, msg_len)) {
                return false;
            }
        }
        if (!build_server_flight(d)) {
            return false;
        }
        d->wait = WAIT_CLIENT_KEY_EXCHANGE;
        d->state = WR_DTLS_WAIT;
        return send_flight(d);
    }

    case WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST: {
        if (d->role != WR_DTLS_ROLE_CLIENT || h->body.len < 3u) {
            return false;
        }
        uint8_t clen = h->body.ptr[2];
        if ((size_t)clen + 3u != h->body.len || clen > sizeof(d->cookie)) {
            return false;
        }
        if (d->wait != WAIT_SERVER_HELLO) {
            return true;
        }
        if (d->have_cookie && d->cookie_len == clen &&
            memcmp(d->cookie, h->body.ptr + 3u, clen) == 0) {
            /* Same cookie: retransmit the pending ClientHello. */
            return send_flight(d);
        }
        memcpy(d->cookie, h->body.ptr + 3u, clen);
        d->cookie_len = clen;
        d->have_cookie = true;
        /* Re-emit the ClientHello with the cookie. The transcript restarts
         * here (the HelloVerifyRequest round is not hashed), and the
         * ClientHello is re-emitted with its pending message sequence. */
        if (d->hs_send_seq > 1u) {
            d->hs_send_seq--;
        }
        d->tr_len = 0u;
        if (!build_client_hello(d) || !send_flight(d)) {
            return false;
        }
        return true;
    }

    case WR_DTLS_HIERARCHY_SERVER_HELLO: {
        if (d->role != WR_DTLS_ROLE_CLIENT || h->body.len < 38u) {
            return false;
        }
        if (d->wait != WAIT_SERVER_HELLO) {
            return true;
        }
        memcpy(d->server_random, h->body.ptr + 2u, 32u);
        size_t off = 34u;
        uint8_t sid_len = h->body.ptr[off++];
        if (off + sid_len > h->body.len) {
            return false;
        }
        off += sid_len;
        if (off + 3u > h->body.len) {
            return false;
        }
        if (wr_load_be16(h->body.ptr + off) != UINT16_C(0xc02b)) {
            return false; /* the only suite offered */
        }
        off += 3u; /* cipher(2) + compression(1) */
        d->use_ems = false;
        if (off < h->body.len) {
            if (off + 2u > h->body.len) {
                return false;
            }
            uint16_t ext_len = wr_load_be16(h->body.ptr + off);
            off += 2u;
            if (ext_len != h->body.len - off) {
                return false;
            }
            while (off + 4u <= h->body.len) {
                uint16_t type = wr_load_be16(h->body.ptr + off);
                uint16_t len = wr_load_be16(h->body.ptr + off + 2u);
                off += 4u;
                if (off + len > h->body.len) {
                    return false;
                }
                if (type == UINT16_C(0x0017) && len == 0u) {
                    d->use_ems = true;
                }
                off += len;
            }
            if (off != h->body.len) {
                return false;
            }
        }
        d->wait = WAIT_CERTIFICATE;
        return true;
    }

    case WR_DTLS_HIERARCHY_CERTIFICATE:
        if (d->role != WR_DTLS_ROLE_CLIENT || d->wait != WAIT_CERTIFICATE) {
            return false;
        }
        if (!wr_dtls_parse_certificate(d, h->body)) {
            return false;
        }
        d->wait = WAIT_SERVER_KEY_EXCHANGE;
        return true;

    case WR_DTLS_HIERARCHY_SERVER_KEY_EXCHANGE: {
        if (d->role != WR_DTLS_ROLE_CLIENT ||
            d->wait != WAIT_SERVER_KEY_EXCHANGE) {
            return false;
        }
        if (h->body.len < 69u + 4u) {
            return false;
        }
        if (h->body.ptr[0] != 3u || h->body.ptr[3] != 65u) {
            return false; /* named_curve secp256r1, uncompressed point */
        }
        memcpy(d->peer_ecdh_pub, h->body.ptr + 4u, 65u);
        {
            uint8_t sdbuf[32 + 32 + 69];
            memcpy(sdbuf, d->client_random, 32);
            memcpy(sdbuf + 32, d->server_random, 32);
            memcpy(sdbuf + 64, h->body.ptr, 69);
            wr_span_c sd = wr_span_c_make(sdbuf, sizeof(sdbuf));
            size_t sig_off = 69u;
            uint16_t sig_alg = wr_load_be16(h->body.ptr + sig_off);
            uint16_t sig_len = wr_load_be16(h->body.ptr + sig_off + 2u);
            sig_off += 4u;
            if (sig_alg != UINT16_C(0x0403) ||
                sig_off + sig_len > h->body.len) {
                return false;
            }
            if (!wr_dtls_verify_ske(d, sd,
                            wr_span_c_make(h->body.ptr + sig_off, sig_len))) {
                return false;
            }
        }
        if (wr_crypto_ecdh_derive(wr_crypto_openssl(), d->ecdh_priv,
                                  d->peer_ecdh_pub,
                                  d->shared_secret) != WR_OK) {
            return false;
        }
        d->wait = WAIT_SERVER_HELLO_DONE;
        return true;
    }

    case WR_DTLS_HIERARCHY_SERVER_HELLO_DONE:
        if (d->role != WR_DTLS_ROLE_CLIENT ||
            d->wait != WAIT_SERVER_HELLO_DONE) {
            return false;
        }
        if (!build_client_flight(d)) {
            return false;
        }
        d->wait = WAIT_SERVER_FINISHED;
        d->state = WR_DTLS_WAIT;
        return send_flight(d);

    case WR_DTLS_HIERARCHY_CLIENT_KEY_EXCHANGE:
        if (d->role != WR_DTLS_ROLE_SERVER ||
            d->wait != WAIT_CLIENT_KEY_EXCHANGE || h->body.len < 66u) {
            return false;
        }
        memcpy(d->peer_ecdh_pub, h->body.ptr + 1u, 65u);
        {
            uint8_t shared[32];
            if (wr_crypto_ecdh_derive(wr_crypto_openssl(), d->ecdh_priv,
                                      d->peer_ecdh_pub, shared) != WR_OK) {
                return false;
            }
            /* The transcript already contains the ClientKeyExchange, so the
             * RFC 7627 session hash (if in use) is complete. */
            wr_dtls_derive_keys(d, wr_span_c_make(shared, 32));
            wr_secure_zero(shared, sizeof(shared));
        }
        d->wait = WAIT_CLIENT_FINISHED;
        return true;

    case WR_DTLS_HIERARCHY_FINISHED:
        if (d->role == WR_DTLS_ROLE_SERVER) {
            if (d->wait != WAIT_CLIENT_FINISHED) {
                return false;
            }
            if (!verify_finished(d, h->body, true)) {
                return false;
            }
            uint8_t msg[4 + 12];
            size_t msg_len = 0u;
            tls_message(WR_DTLS_HIERARCHY_FINISHED, h->body, msg, sizeof(msg),
                        &msg_len);
            append_transcript(d, msg, msg_len);
            if (!build_server_final(d)) {
                return false;
            }
            d->state = WR_DTLS_DONE;
            d->wait = WAIT_NONE;
            bool sent = send_flight(d);
            return sent;
        }
        if (d->wait != WAIT_SERVER_FINISHED) {
            return false;
        }
        if (!verify_finished(d, h->body, false)) {
            return false;
        }
        d->state = WR_DTLS_DONE;
        d->wait = WAIT_NONE;
        d->flight_len = 0u;
        return true;

    default:
        return true;
    }
}

/* ------------------------------------------------------------------------- */
/* Records                                                                   */
/* ------------------------------------------------------------------------- */

static uint64_t record_seq48(const uint8_t seq[6])
{
    return ((uint64_t)seq[0] << 40) | ((uint64_t)seq[1] << 32) |
           ((uint64_t)seq[2] << 24) | ((uint64_t)seq[3] << 16) |
           ((uint64_t)seq[4] << 8) | (uint64_t)seq[5];
}

/* RFC 6347 Section 4.1.2.6: a sliding replay window per epoch. Epoch 0
 * handshake messages are deduplicated by message_seq below. */
static bool replay_ok(wr_dtls *d, const wr_dtls_record *r)
{
    if (r->epoch == 0u) {
        return true;
    }
    uint64_t s = record_seq48(r->seq);
    if (!d->rx_seq_valid) {
        d->rx_seq_valid = true;
        d->rx_last_seq = s;
        d->rx_window = 1u;
        return true;
    }
    if (s > d->rx_last_seq) {
        uint64_t diff = s - d->rx_last_seq;
        d->rx_window = diff >= 64u ? 1u : (d->rx_window << diff) | 1u;
        d->rx_last_seq = s;
        return true;
    }
    if (s == d->rx_last_seq) {
        return false;
    }
    uint64_t diff = d->rx_last_seq - s;
    if (diff >= 64u || (d->rx_window & (UINT64_C(1) << diff)) != 0u) {
        return false;
    }
    d->rx_window |= UINT64_C(1) << diff;
    return true;
}

static wr_status handle_record(wr_dtls *d, wr_span_c pkt)
{
    wr_dtls_record r;
    wr_status st = wr_dtls_record_parse(pkt, &r);
    if (st != WR_OK) {
        return st;
    }
    /* Once the handshake is done every record must be authenticated. An
     * unprotected epoch-0 record (alert, handshake, CCS) is trivially
     * forgeable by anyone who can send a datagram to the socket, and would
     * otherwise be able to fail or perturb an established session. */
    if (d->state == WR_DTLS_DONE && r.epoch == 0u) {
        return WR_OK;
    }
    if (r.type == WR_DTLS_ALERT) {
        fail(d);
        return WR_ERR_CLOSED;
    }
    if (r.epoch != 0u) {
        uint8_t plain[2048];
        wr_span out = wr_span_make(plain, sizeof(plain));
        if (wr_dtls_decrypt(&d->cread, pkt, &out, &r) != WR_OK) {
            return WR_ERR_AUTH;
        }
        /* Only authenticated records may advance the replay window. Checking
         * first would let an attacker suppress later valid records with a
         * forged high sequence number. */
        if (!replay_ok(d, &r)) {
            return WR_OK;
        }
        if (r.type == WR_DTLS_APPDATA) {
            if (out.len > WR_DTLS_RECV_MAX) {
                return WR_ERR_OVERFLOW;
            }
            if (d->recvq_count >= WR_DTLS_RECVQ_MAX) {
                /* Bounded queue: drop rather than corrupt framing. SCTP
                 * recovers via retransmission; the drop is observable. */
                d->recvq_drops++;
                return WR_OK;
            }
            uint8_t tail =
                (uint8_t)((d->recvq_head + d->recvq_count) % WR_DTLS_RECVQ_MAX);
            if (out.len != 0u) {
                memcpy(d->recvq[tail], out.ptr, out.len);
            }
            d->recvq_len[tail] = (uint16_t)out.len;
            d->recvq_count++;
            return WR_OK;
        }
        if (r.type != WR_DTLS_HANDSHAKE) {
            return WR_OK;
        }
        wr_dtls_hs h;
        if (wr_dtls_hs_parse(out.ptr ? wr_span_c_make(out.ptr, out.len)
                                      : wr_span_c_make(NULL, 0u),
                           &h) != WR_OK) {
            return WR_ERR_TRUNCATED;
        }
        if (h.frag_off == 0u && h.frag_len == h.length) {
            if (d->have_recv_hs && h.msg_seq <= d->last_recv_hs) {
                return WR_OK;
            }
            uint8_t msg[4 + 4096];
            size_t msg_len = 0u;
            tls_message(h.type, h.body, msg, sizeof(msg), &msg_len);
            /* The HelloVerifyRequest round is not part of the transcript
             * (RFC 6347 4.2.1); retransmitted HVRs must never re-enter it. */
            if (h.type != WR_DTLS_HIERARCHY_FINISHED &&
                h.type != WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST) {
                if (msg_len == 0u || !append_transcript(d, msg, msg_len)) {
                    return WR_ERR_STATE;
                }
            }
            d->last_recv_hs = h.msg_seq;
            d->have_recv_hs = true;
            if (!handle_handshake(d, &h)) {
                fail(d);
                return WR_ERR_STATE;
            }
        } else if (!handle_fragment(d, h.body, h.type, h.msg_seq, h.frag_off,
                                    h.length)) {
            fail(d);
            return WR_ERR_STATE;
        }
        return WR_OK;
    }

    if (r.type == WR_DTLS_CCS) {
        /* A plaintext ChangeCipherSpec carries no state this layer needs; the
         * peer switches read keys when the first epoch-1 record arrives. */
        return WR_OK;
    }
    if (r.type != WR_DTLS_HANDSHAKE) {
        return WR_OK;
    }
    wr_dtls_hs h;
    if (wr_dtls_hs_parse(r.body, &h) != WR_OK) {
        return WR_ERR_TRUNCATED;
    }
    if (h.frag_off == 0u && h.frag_len == h.length) {
        /* A HelloVerifyRequest may arrive repeatedly (retransmission, or a
         * new cookie after a server restart) while the client is still
         * waiting for the ServerHello. */
        bool is_hvr = h.type == WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST &&
                      d->role == WR_DTLS_ROLE_CLIENT &&
                      d->wait == WAIT_SERVER_HELLO;
        if (!is_hvr && d->have_recv_hs && h.msg_seq <= d->last_recv_hs) {
            return WR_OK;
        }
        uint8_t msg[4 + 4096];
        size_t msg_len = 0u;
        tls_message(h.type, h.body, msg, sizeof(msg), &msg_len);
        /* The HelloVerifyRequest round is not part of the transcript
         * (RFC 6347 4.2.1); retransmitted HVRs must never re-enter it. */
        if (h.type != WR_DTLS_HIERARCHY_FINISHED &&
            h.type != WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST) {
            if (msg_len == 0u || !append_transcript(d, msg, msg_len)) {
                return WR_ERR_STATE;
            }
        }
        d->last_recv_hs = h.msg_seq;
        d->have_recv_hs = true;
        if (!handle_handshake(d, &h)) {
            fail(d);
            return WR_ERR_STATE;
        }
    } else if (!handle_fragment(d, h.body, h.type, h.msg_seq, h.frag_off,
                                h.length)) {
        fail(d);
        return WR_ERR_STATE;
    }
    return WR_OK;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

wr_dtls *wr_dtls_create(wr_arena *a, wr_rng *rng, wr_dtls_role role,
                        wr_io *io, const wr_endpoint *peer)
{
    if (!a || !rng || !io || !peer) {
        return NULL;
    }
    wr_dtls *d = (wr_dtls *)wr_arena_calloc(a, 1, sizeof(*d));
    if (!d) {
        return NULL;
    }
    d->a = a;
    d->rng = rng;
    d->io = io;
    d->peer = *peer;
    d->role = role;
    d->state = WR_DTLS_NEW;
    if (wr_rng_fill(d->rng, d->cookie_secret, sizeof(d->cookie_secret)) !=
        WR_OK) {
        return NULL;
    }
    if (!wr_dtls_make_cert(d)) {
        return NULL;
    }
    return d;
}

void wr_dtls_destroy(wr_dtls *d)
{
    if (!d) {
        return;
    }
    wr_dtls_cert_free(d);
    wr_dtls_cipher_free(&d->cwrite);
    wr_dtls_cipher_free(&d->cread);
    wr_secure_zero(d->master, sizeof(d->master));
    wr_secure_zero(d->ecdh_priv, sizeof(d->ecdh_priv));
    memset(d, 0, sizeof(*d));
}

wr_status wr_dtls_start(wr_dtls *d, uint64_t now_ms)
{
    if (!d || d->state != WR_DTLS_NEW) {
        return WR_ERR_STATE;
    }
    d->state = WR_DTLS_WAIT;
    if (d->role == WR_DTLS_ROLE_CLIENT) {
        if (!build_client_hello(d) || !send_flight(d)) {
            fail(d);
            return WR_ERR_IO;
        }
        d->wait = WAIT_SERVER_HELLO;
        d->last_sent_ms = now_ms;
    } else {
        d->wait = WAIT_NONE;
        d->state = WR_DTLS_WAIT;
    }
    return WR_OK;
}

wr_status wr_dtls_step(wr_dtls *d, uint64_t now_ms)
{
    if (!d || d->state != WR_DTLS_WAIT) {
        return WR_OK;
    }
    if (d->flight_len == 0u) {
        return WR_OK;
    }
    if (d->last_gen != d->flight_gen) {
        /* A new flight was queued since the last step: start its timer. */
        d->last_gen = d->flight_gen;
        d->last_sent_ms = now_ms;
        d->flight_retx = 0u;
        return WR_OK;
    }
    uint64_t shift = d->flight_retx < 6u ? d->flight_retx : 6u;
    uint64_t interval = WR_DTLS_RETX_BASE_MS << shift;
    if (interval > WR_DTLS_RETX_MAX_MS) {
        interval = WR_DTLS_RETX_MAX_MS;
    }
    if (now_ms - d->last_sent_ms < interval) {
        return WR_OK;
    }
    if (d->flight_retx >= WR_DTLS_MAX_RETX) {
        fail(d);
        return WR_ERR_TIMEOUT;
    }
    d->flight_retx++;
    if (!send_flight(d)) {
        return WR_ERR_IO;
    }
    d->last_sent_ms = now_ms;
    return WR_OK;
}

wr_status wr_dtls_input(wr_dtls *d, const wr_endpoint *from,
                        wr_span_c pkt)
{
    if (!d || !pkt.ptr) {
        return WR_ERR_INVAL;
    }
    /* Source filtering. The socket is shared with ICE/STUN, so anything that
     * reaches this layer can otherwise be injected by an off-path host; the
     * handshake itself only authenticates the peer once it completes, and
     * epoch-0 records are unauthenticated by construction. */
    if (from && d->peer.port != 0u && !wr_endpoint_eq(&d->peer, from)) {
        return WR_ERR_AUTH;
    }
    size_t off = 0u;
    while (off < pkt.len) {
        wr_dtls_record r;
        if (wr_dtls_record_parse(wr_span_c_sub(pkt, off, pkt.len - off),
                                 &r) != WR_OK) {
            return WR_ERR_TRUNCATED;
        }
        wr_status st = handle_record(d, wr_span_c_sub(pkt, off, pkt.len - off));
        if (st != WR_OK && st != WR_ERR_AUTH) {
            return st;
        }
        size_t total = 13u + (size_t)r.length;
        if (total > pkt.len - off) {
            return WR_ERR_TRUNCATED;
        }
        off += total;
    }
    return WR_OK;
}

wr_status wr_dtls_send(wr_dtls *d, wr_span_c app)
{
    if (!d || !d->keys_ready || d->state != WR_DTLS_DONE) {
        return WR_ERR_STATE;
    }
    if (app.len > WR_DTLS_RECV_MAX - 64u) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t rec[2048];
    size_t n = 0u;
    wr_status st = wr_dtls_encrypt(&d->cwrite, WR_DTLS_APPDATA, 1u,
                                   d->write_seq[1], app, (char *)rec,
                                   sizeof(rec), &n);
    if (st != WR_OK) {
        return st;
    }
    next_seq(d->write_seq[1]);
    size_t sent = 0u;
    return wr_io_send(d->io, &d->peer, wr_span_c_make(rec, n), &sent);
}

bool wr_dtls_recv(wr_dtls *d, wr_span_c *out)
{
    if (!d || !out || d->recvq_count == 0u) {
        return false;
    }
    /* One record per call: DTLS application data is a stream of records, not
     * a byte stream. The returned span is valid until the next call. */
    out->ptr = d->recvq[d->recvq_head];
    out->len = d->recvq_len[d->recvq_head];
    d->recvq_head =
        (uint8_t)((d->recvq_head + 1u) % WR_DTLS_RECVQ_MAX);
    d->recvq_count--;
    return true;
}

uint32_t wr_dtls_recv_drops(const wr_dtls *d)
{
    return d ? d->recvq_drops : 0u;
}

bool wr_dtls_ready(const wr_dtls *d)
{
    return d && d->state == WR_DTLS_DONE;
}

wr_dtls_status wr_dtls_state(const wr_dtls *d)
{
    return d ? d->state : WR_DTLS_FAILED;
}

bool wr_dtls_set_role(wr_dtls *d, wr_dtls_role role)
{
    if (!d || d->state != WR_DTLS_NEW) {
        return false;
    }
    d->role = role;
    return true;
}

const uint8_t *wr_dtls_fingerprint(const wr_dtls *d, size_t *len)
{
    if (!d || !len) {
        return NULL;
    }
    *len = 32u;
    return d->fp;
}

bool wr_dtls_set_peer_fingerprint(wr_dtls *d, const uint8_t *fp, size_t len)
{
    if (!d || !fp || len != 32u) {
        return false;
    }
    memcpy(d->peer_fp, fp, 32);
    d->have_peer_fp = true;
    return true;
}