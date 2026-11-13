#ifndef WR_SRTP_H
#define WR_SRTP_H

#include "wr/arena.h"
#include "wr/base.h"
#include "wr/bitmap.h"

typedef enum {
    WR_SRTP_AES_CM_128_HMAC_SHA1_80 = 0,
    WR_SRTP_AES_GCM_128 = 1,
} wr_srtp_profile;

typedef struct {
    wr_srtp_profile profile;
    uint8_t key[16];
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

#endif /* WR_SRTP_H */