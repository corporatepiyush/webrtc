#ifndef WR_DTLS_H
#define WR_DTLS_H

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/net.h"
#include "wr/rng.h"

typedef enum {
    WR_DTLS_CCS = 20,
    WR_DTLS_ALERT = 21,
    WR_DTLS_HANDSHAKE = 22,
    WR_DTLS_APPDATA = 23,
} wr_dtls_content;

typedef enum {
    WR_DTLS_HIERARCHY_CLIENT_HELLO = 1,
    WR_DTLS_HIERARCHY_SERVER_HELLO = 2,
    WR_DTLS_HIERARCHY_HELLO_VERIFY_REQUEST = 3,
    WR_DTLS_HIERARCHY_CERTIFICATE = 11,
    WR_DTLS_HIERARCHY_SERVER_KEY_EXCHANGE = 12,
    WR_DTLS_HIERARCHY_CERTIFICATE_REQUEST = 13,
    WR_DTLS_HIERARCHY_SERVER_HELLO_DONE = 14,
    WR_DTLS_HIERARCHY_CERTIFICATE_VERIFY = 15,
    WR_DTLS_HIERARCHY_CLIENT_KEY_EXCHANGE = 16,
    WR_DTLS_HIERARCHY_FINISHED = 20,
} wr_dtls_hs_type;

typedef struct {
    uint8_t type;
    uint16_t version;
    uint16_t epoch;
    uint8_t seq[6];
    uint16_t length;
    size_t header_len;
    wr_span_c body;
} wr_dtls_record;

wr_status wr_dtls_record_parse(wr_span_c pkt, wr_dtls_record *out);
wr_status wr_dtls_record_serialize(const wr_dtls_record *r, char *buf,
                                   size_t cap, size_t *out_len);

typedef struct {
    uint8_t type;
    uint32_t length;
    uint16_t msg_seq;
    uint32_t frag_off;
    uint32_t frag_len;
    size_t header_len;
    wr_span_c body;
} wr_dtls_hs;

wr_status wr_dtls_hs_parse(wr_span_c pkt, wr_dtls_hs *out);
wr_status wr_dtls_hs_serialize(const wr_dtls_hs *h, char *buf, size_t cap,
                               size_t *out_len);

typedef struct {
    uint8_t key[16];
    uint8_t iv[4];
    uint8_t salt[4];
    void *enc; /* cached EVP_CIPHER_CTX, or NULL */
    void *dec;
} wr_dtls_cipher;

bool wr_dtls_cipher_init(wr_dtls_cipher *c);
void wr_dtls_cipher_free(wr_dtls_cipher *c);

wr_status wr_dtls_encrypt(const wr_dtls_cipher *c, uint8_t type,
                          uint16_t epoch, const uint8_t seq[6], wr_span_c plain,
                          char *buf, size_t cap, size_t *out_len);
wr_status wr_dtls_decrypt(const wr_dtls_cipher *c, wr_span_c pkt,
                          wr_span *out, wr_dtls_record *meta);
void wr_dtls_prf(const uint8_t *secret, size_t secret_len, wr_span_c label,
                 wr_span_c seed, uint8_t *out, size_t out_len);

/* ------------------------------------------------------------------------- */
/* DTLS 1.2 handshake                                                        */
/* ------------------------------------------------------------------------- */

typedef enum {
    WR_DTLS_ROLE_CLIENT = 0,
    WR_DTLS_ROLE_SERVER = 1,
} wr_dtls_role;

typedef enum {
    WR_DTLS_NEW = 0,
    WR_DTLS_WAIT,
    WR_DTLS_DONE,
    WR_DTLS_FAILED,
} wr_dtls_status;

typedef struct wr_dtls wr_dtls;

wr_dtls *wr_dtls_create(wr_arena *a, wr_rng *rng, wr_dtls_role role,
                        wr_io *io, const wr_endpoint *peer);
void wr_dtls_destroy(wr_dtls *d);

wr_status wr_dtls_start(wr_dtls *d, uint64_t now_ms);
wr_status wr_dtls_step(wr_dtls *d, uint64_t now_ms);
/* `from` is the source address of the datagram. When the socket is shared
 * with other protocols the caller must pass it: DTLS is point-to-point, so
 * a record from any other address is dropped before parsing. Pass NULL only
 * when the transport is already a dedicated, validated path. */
wr_status wr_dtls_input(wr_dtls *d, const wr_endpoint *from,
                        wr_span_c pkt);
wr_status wr_dtls_send(wr_dtls *d, wr_span_c app);
bool wr_dtls_recv(wr_dtls *d, wr_span_c *out);
uint32_t wr_dtls_recv_drops(const wr_dtls *d);
bool wr_dtls_ready(const wr_dtls *d);
wr_dtls_status wr_dtls_state(const wr_dtls *d);
/* Set the handshake role before the handshake starts. The DTLS role is
 * negotiated by the SDP `setup` attribute, not by the ICE role, so the peer
 * connection may need to correct the role chosen when the certificate was
 * minted. Returns false once the handshake has begun. */
bool wr_dtls_set_role(wr_dtls *d, wr_dtls_role role);

const uint8_t *wr_dtls_fingerprint(const wr_dtls *d, size_t *len);
bool wr_dtls_set_peer_fingerprint(wr_dtls *d, const uint8_t *fp, size_t len);

#endif /* WR_DTLS_H */