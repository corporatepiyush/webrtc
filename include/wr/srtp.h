#ifndef WR_SRTP_H
#define WR_SRTP_H

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/bitmap.h"

typedef enum {
    WR_SRTP_AES_CM_128_HMAC_SHA1_80 = 0,
    WR_SRTP_AES_GCM_128 = 1,
    /* Appended: adding these does not renumber the existing profiles. */
    WR_SRTP_AES_CM_256_HMAC_SHA1_80 = 2,
    WR_SRTP_AES_GCM_256 = 3,
} wr_srtp_profile;

typedef struct {
    wr_srtp_profile profile;
    uint8_t key[32]; /* 16 for AES-128, 32 for AES-256 */
    uint8_t salt[14];
    uint8_t auth[20];
    uint8_t tag_len;
    uint32_t ssrc;
    uint32_t roc;
    uint16_t last_seq;
    uint64_t replay;
    bool replay_valid;
    bool seq_valid;
    uint64_t last_index;
    bool initialized;
    bool srtcp; /* keys derived with the SRTCP labels (3/4/5) */
    uint32_t srtcp_index; /* last 32-bit ESRTCP word seen (replay bookkeeping) */
    void *impl; /* cached cipher/HMAC contexts, or NULL */
} wr_srtp_ctx;

wr_status wr_srtp_init(wr_srtp_ctx *ctx, wr_srtp_profile profile,
                       const uint8_t master_key[16],
                       const uint8_t master_salt[14], uint32_t ssrc);
void wr_srtp_fini(wr_srtp_ctx *ctx);
wr_status wr_srtp_protect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out);
wr_status wr_srtp_unprotect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out);
void wr_srtp_set_roc(wr_srtp_ctx *ctx, uint32_t roc);
uint32_t wr_srtp_get_roc(const wr_srtp_ctx *ctx);

/* ------------------------------------------------------------------------- */
/* SRTCP (RFC 3711 3.4)                                                      */
/* ------------------------------------------------------------------------- */

/* Same master key/salt as the SRTP context, but the session keys come from
 * labels 3 (encryption), 4 (authentication) and 5 (salt). The context is
 * separate from the SRTP one because the key material differs. */
wr_status wr_srtcp_init(wr_srtp_ctx *ctx, wr_srtp_profile profile,
                        const uint8_t master_key[16],
                        const uint8_t master_salt[14], uint32_t ssrc);

/* Protect an RTCP packet. `index` is the 31-bit SRTCP index of this packet;
 * the E bit is set because the payload is encrypted. `out` receives the
 * 8-octet RTCP header in the clear, the encrypted remainder, the 4-octet
 * E-flag||index word and the authentication tag. */
wr_status wr_srtcp_protect(wr_srtp_ctx *ctx, wr_span_c rtcp, wr_span out,
                           uint32_t index);

/* Verify and decrypt. On success *index receives the 31-bit SRTCP index. */
wr_status wr_srtcp_unprotect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out,
                             uint32_t *index);

#endif /* WR_SRTP_H */