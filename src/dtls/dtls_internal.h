#ifndef WR_DTLS_INTERNAL_H
#define WR_DTLS_INTERNAL_H

#include "wr/dtls.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#define WR_DTLS_FLIGHT_MAX 4096u
#define WR_DTLS_HI_MAX     4096u
#define WR_DTLS_CERT_MAX   1536u
/* Application-data queue: DTLS records are datagrams. Each decrypted record is
 * queued separately and returned by one wr_dtls_recv call; records are never
 * concatenated, because the upper layer (SCTP) parses each record as one
 * self-delimiting packet. */
#define WR_DTLS_RECV_MAX   2048u
#define WR_DTLS_RECVQ_MAX  16u
/* Retransmit schedule: exponential backoff from 1 s, capped at 60 s, giving up
 * after WR_DTLS_MAX_RETX tries so a dead peer fails the session instead of
 * retransmitting forever (RFC 6347 4.2.4). */
#define WR_DTLS_RETX_BASE_MS 1000u
#define WR_DTLS_RETX_MAX_MS  60000u
#define WR_DTLS_MAX_RETX     8u

/* HelloVerifyRequest cookie (RFC 6347 4.2.1). The value this stack generates is
 * WR_DTLS_COOKIE_LEN bytes; WR_DTLS_COOKIE_MAX is the largest cookie a peer
 * server may hand back (the length is a single octet on the wire). */
#define WR_DTLS_COOKIE_LEN 16u
#define WR_DTLS_COOKIE_MAX 255u

typedef enum {
    WAIT_NONE = 0,
    WAIT_SERVER_HELLO,
    WAIT_CERTIFICATE,
    WAIT_SERVER_KEY_EXCHANGE,
    WAIT_SERVER_HELLO_DONE,
    WAIT_CLIENT_KEY_EXCHANGE,
    WAIT_CLIENT_FINISHED,
    WAIT_SERVER_FINISHED,
} wait_for;

struct wr_dtls {
    wr_arena *a;
    wr_rng *rng;
    wr_io *io;
    wr_endpoint peer;
    wr_dtls_role role;
    wr_dtls_status state;
    wait_for wait;

    EVP_PKEY *cert_key;
    X509 *cert;
    uint8_t cert_der[WR_DTLS_CERT_MAX];
    size_t cert_der_len;
    uint8_t fp[32];

    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t ecdh_priv[32];
    uint8_t ecdh_pub[65];
    uint8_t peer_ecdh_pub[65];
    uint8_t shared_secret[32];
    bool have_ecdh;

    uint8_t master[48];
    wr_dtls_cipher cwrite;
    wr_dtls_cipher cread;
    bool keys_ready;
    uint8_t write_seq[2][6];
    bool rx_seq_valid;
    uint64_t rx_last_seq;
    uint64_t rx_window;

    uint8_t transcript[8192];
    size_t tr_len;

    uint8_t flight[WR_DTLS_FLIGHT_MAX];
    size_t flight_len;
    uint64_t last_sent_ms;
    /* Bumped whenever a new flight is queued, so the retransmit timer restarts
     * instead of firing immediately for a flight that has not been sent yet. */
    uint64_t flight_gen;
    uint64_t last_gen;
    uint8_t flight_retx;

    uint16_t hs_send_seq;
    bool have_recv_hs;
    uint16_t last_recv_hs;

    uint8_t hs_frag[WR_DTLS_HI_MAX];
    size_t hs_frag_len;
    uint32_t hs_frag_need;
    uint16_t hs_frag_seq;
    bool hs_frag_active;

    EVP_PKEY *peer_pub;
    uint8_t peer_fp[32];
    bool have_peer_fp;

    uint8_t recvq[WR_DTLS_RECVQ_MAX][WR_DTLS_RECV_MAX];
    uint16_t recvq_len[WR_DTLS_RECVQ_MAX];
    uint8_t recvq_head;
    uint8_t recvq_count;
    uint32_t recvq_drops;

    /* HelloVerifyRequest cookie exchange (RFC 6347 4.2.1). The client stores
     * the cookie from the server's request and re-sends the ClientHello with
     * it; the server validates a cookie bound to the endpoint and the
     * ClientHello random before it allocates handshake state. */
    uint8_t cookie[WR_DTLS_COOKIE_MAX];
    uint8_t cookie_len;
    bool have_cookie;
    uint8_t cookie_secret[16];

    /* TLS extensions. use_ems selects RFC 7627 (extended master secret);
     * both peers must agree, which the offer/echo pair guarantees. */
    bool use_ems;
};

static inline uint32_t load_be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static inline void store_be24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

void wr_dtls_cert_free(wr_dtls *d);
bool wr_dtls_make_cert(wr_dtls *d);
bool wr_dtls_parse_certificate(wr_dtls *d, wr_span_c body);
bool wr_dtls_sign_ske(wr_dtls *d, wr_span_c signed_data, uint8_t *sig,
                      size_t cap, size_t *sig_len);
bool wr_dtls_verify_ske(wr_dtls *d, wr_span_c signed_data, wr_span_c sig);
void wr_dtls_derive_keys(wr_dtls *d, wr_span_c shared);

#endif /* WR_DTLS_INTERNAL_H */
