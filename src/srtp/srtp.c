#include "wr/srtp.h"

#include "wr/crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

typedef struct {
    EVP_CIPHER_CTX *ctr;
    uint8_t ipad[64];
    uint8_t opad[64];
    SHA_CTX ipad_ctx;
    SHA_CTX opad_ctx;
    EVP_CIPHER_CTX *gcm_enc;
    EVP_CIPHER_CTX *gcm_dec;
} wr_srtp_impl;

static void hmac_sha1(const wr_srtp_impl *im, const uint8_t *data, size_t len,
                      uint8_t out[20])
{
    SHA_CTX c;
    uint8_t inner[20];
    c = im->ipad_ctx;
    SHA1_Update(&c, data, len);
    SHA1_Final(inner, &c);
    c = im->opad_ctx;
    SHA1_Update(&c, inner, sizeof(inner));
    SHA1_Final(out, &c);
    wr_secure_zero(inner, sizeof(inner));
}

static void kdf_n(const uint8_t master_key[16], const uint8_t master_salt[14],
                  uint8_t label, uint8_t *out, size_t out_len)
{
    uint8_t iv[16];
    uint8_t zero[32] = { 0 };
    uint8_t ks[32];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, master_salt, 14);
    /* Initial KDF (kdr = 0): key_id = label || 0^48, right-aligned in
     * the 112-bit salt, so the label lands in octet 7. */
    iv[7] ^= label;
    wr_crypto_aes_ctr(master_key, 16, iv, wr_span_c_make(zero, 32), ks);
    memcpy(out, ks, out_len);
}

static void kdf(const uint8_t master_key[16], const uint8_t master_salt[14],
                uint8_t label, uint8_t *out, size_t out_len)
{
    kdf_n(master_key, master_salt, label, out, out_len);
}

static bool profile_gcm(wr_srtp_profile p)
{
    return p == WR_SRTP_AES_GCM_128 || p == WR_SRTP_AES_GCM_256;
}

/* AES-256 profiles take a 32-octet key; the KDF output is that wide too. */
static size_t profile_key_len(wr_srtp_profile p)
{
    return (p == WR_SRTP_AES_CM_256_HMAC_SHA1_80 || p == WR_SRTP_AES_GCM_256)
               ? 32u
               : 16u;
}

/* The master key is 16 octets in this API; the AES-256 profiles derive a
 * 32-octet session key from it. */
static void kdf_key(const uint8_t master_key[16],
                    const uint8_t master_salt[14], uint8_t label,
                    uint8_t *out, size_t out_len)
{
    uint8_t wide[32];
    size_t n = out_len > 32u ? 32u : out_len;
    kdf_n(master_key, master_salt, label, wide, n);
    memcpy(out, wide, n);
    wr_secure_zero(wide, sizeof(wide));
}

static wr_status srtp_init(wr_srtp_ctx *ctx, wr_srtp_profile profile,
                           const uint8_t master_key[16],
                           const uint8_t master_salt[14], uint32_t ssrc,
                           bool srtcp)
{
    if (!ctx || !master_key || !master_salt) {
        return WR_ERR_INVAL;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->profile = profile;
    ctx->ssrc = ssrc;
    ctx->srtcp = srtcp;
    /* The master salt is 14 octets for the AES-CM profiles and 12 for GCM
     * (RFC 7714). Read only what the profile defines: reading 14 from a
     * 12-octet caller buffer is an out-of-bounds read. */
    memcpy(ctx->salt, master_salt, profile_gcm(profile) ? 12u : 14u);
    /* RFC 3711 4.3.1: labels 0/1/2 are the SRTP encryption, authentication
     * and salt keys; 3/4/5 are the SRTCP equivalents. */
    const uint8_t label_key = srtcp ? 3u : 0u;
    const uint8_t label_auth = (uint8_t)(label_key + 1u);
    const uint8_t label_salt = (uint8_t)(label_key + 2u);
    size_t key_len = profile_key_len(profile);
    if (profile_gcm(profile)) {
        uint8_t k[32];
        uint8_t s[14];
        /* GCM uses a 96-bit master salt, zero-extended to the 112-bit
         * salt expected by the legacy AES-CM KDF. */
        uint8_t ms[14] = { 0 };
        memcpy(ms, master_salt, 12);
        kdf_key(master_key, ms, label_key, k, key_len);
        kdf_key(master_key, ms, label_salt, s, sizeof(s));
        memcpy(ctx->key, k, key_len);
        memcpy(ctx->salt, s, 14);
        ctx->tag_len = 16u;
        wr_secure_zero(k, sizeof(k));
        wr_secure_zero(s, sizeof(s));
        wr_secure_zero(ms, sizeof(ms));
    } else {
        uint8_t k[32];
        uint8_t a[20];
        uint8_t s[14];
        kdf_key(master_key, master_salt, label_key, k, key_len);
        kdf(master_key, master_salt, label_auth, a, sizeof(a));
        kdf(master_key, master_salt, label_salt, s, sizeof(s));
        memcpy(ctx->key, k, key_len);
        memcpy(ctx->auth, a, 20);
        memcpy(ctx->salt, s, 14);
        ctx->tag_len = 10u;
        wr_secure_zero(k, sizeof(k));
        wr_secure_zero(a, sizeof(a));
        wr_secure_zero(s, sizeof(s));
    }
    ctx->initialized = true;
    ctx->impl = NULL;

    /* Cache the reusable cipher/HMAC contexts so the per-packet path does
     * not allocate. Contexts are single-threaded per SRTP stream. */
    wr_srtp_impl *im = (wr_srtp_impl *)calloc(1, sizeof(*im));
    if (!im) {
        return WR_ERR_NOMEM;
    }
    bool ok = true;
    const EVP_CIPHER *gcm =
        key_len == 32u ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    const EVP_CIPHER *ctr =
        key_len == 32u ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
    if (profile_gcm(profile)) {
        im->gcm_enc = EVP_CIPHER_CTX_new();
        im->gcm_dec = EVP_CIPHER_CTX_new();
        ok = im->gcm_enc && im->gcm_dec &&
             EVP_EncryptInit_ex(im->gcm_enc, gcm, NULL, ctx->key,
                                NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(im->gcm_enc, EVP_CTRL_GCM_SET_IVLEN, 12,
                                 NULL) == 1 &&
             EVP_DecryptInit_ex(im->gcm_dec, gcm, NULL, ctx->key,
                                NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(im->gcm_dec, EVP_CTRL_GCM_SET_IVLEN, 12,
                                 NULL) == 1;
    } else {
        im->ctr = EVP_CIPHER_CTX_new();
        ok = im->ctr &&
             EVP_EncryptInit_ex(im->ctr, ctr, NULL, ctx->key,
                                NULL) == 1;
        if (ok) {
            uint8_t k0[64];
            memset(k0, 0, sizeof(k0));
            memcpy(k0, ctx->auth, 20);
            for (size_t i = 0; i < 64u; ++i) {
                im->ipad[i] = (uint8_t)(k0[i] ^ 0x36u);
                im->opad[i] = (uint8_t)(k0[i] ^ 0x5cu);
            }
            wr_secure_zero(k0, sizeof(k0));
            SHA1_Init(&im->ipad_ctx);
            SHA1_Update(&im->ipad_ctx, im->ipad, sizeof(im->ipad));
            SHA1_Init(&im->opad_ctx);
            SHA1_Update(&im->opad_ctx, im->opad, sizeof(im->opad));
        }
    }
    ctx->impl = im;
    if (!ok) {
        wr_srtp_fini(ctx);
        return WR_ERR_NOMEM;
    }
    return WR_OK;
}

wr_status wr_srtp_init(wr_srtp_ctx *ctx, wr_srtp_profile profile,
                       const uint8_t master_key[16],
                       const uint8_t master_salt[14], uint32_t ssrc)
{
    return srtp_init(ctx, profile, master_key, master_salt, ssrc, false);
}

wr_status wr_srtcp_init(wr_srtp_ctx *ctx, wr_srtp_profile profile,
                        const uint8_t master_key[16],
                        const uint8_t master_salt[14], uint32_t ssrc)
{
    return srtp_init(ctx, profile, master_key, master_salt, ssrc, true);
}

void wr_srtp_fini(wr_srtp_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
    if (im) {
        if (im->ctr) EVP_CIPHER_CTX_free(im->ctr);
        if (im->gcm_enc) EVP_CIPHER_CTX_free(im->gcm_enc);
        if (im->gcm_dec) EVP_CIPHER_CTX_free(im->gcm_dec);
        wr_secure_zero(im, sizeof(*im));
        free(im);
    }
    wr_secure_zero(ctx->key, sizeof(ctx->key));
    wr_secure_zero(ctx->auth, sizeof(ctx->auth));
    wr_secure_zero(ctx->salt, sizeof(ctx->salt));
    ctx->impl = NULL;
    ctx->initialized = false;
}

void wr_srtp_set_roc(wr_srtp_ctx *ctx, uint32_t roc)
{
    if (ctx) {
        ctx->roc = roc;
        ctx->last_index = ((uint64_t)roc << 16);
        ctx->replay = 1ull;
        ctx->replay_valid = false;
        ctx->seq_valid = false;
    }
}

uint32_t wr_srtp_get_roc(const wr_srtp_ctx *ctx)
{
    return ctx ? ctx->roc : 0u;
}

static bool parse_rtp(wr_span_c in, size_t *hdr_len, uint16_t *seq,
                      uint32_t *ssrc)
{
    if (in.len < 12u || (in.ptr[0] >> 6) != 2u) {
        return false;
    }
    size_t hl = 12u + 4u * (size_t)(in.ptr[0] & 0x0fu);
    if (hl > in.len) {
        return false;
    }
    if (in.ptr[0] & 0x10u) {
        if (hl + 4u > in.len) {
            return false;
        }
        uint16_t el = wr_load_be16(in.ptr + hl + 2u);
        hl += 4u + 4u * (size_t)el;
        if (hl > in.len) {
            return false;
        }
    }
    *hdr_len = hl;
    *seq = wr_load_be16(in.ptr + 2u);
    *ssrc = wr_load_be32(in.ptr + 8u);
    return true;
}

static void aes_iv(wr_srtp_ctx *ctx, uint64_t index, uint8_t iv[16])
{
    memset(iv, 0, 16);
    memcpy(iv, ctx->salt, 14);
    uint32_t s = wr_load_be32(iv + 4u) ^ ctx->ssrc;
    wr_store_be32(iv + 4u, s);
    iv[8] ^= (uint8_t)(index >> 40);
    iv[9] ^= (uint8_t)(index >> 32);
    iv[10] ^= (uint8_t)(index >> 24);
    iv[11] ^= (uint8_t)(index >> 16);
    iv[12] ^= (uint8_t)(index >> 8);
    iv[13] ^= (uint8_t)index;
}

static void gcm_nonce(wr_srtp_ctx *ctx, uint64_t index, uint8_t nonce[12])
{
    /* RFC 7714 Section 8.1:
     * IV = (00 00 || SSRC || ROC || SEQ) XOR salt. */
    uint8_t base[12] = { 0 };
    wr_store_be32(base + 2u, ctx->ssrc);
    wr_store_be32(base + 6u, (uint32_t)(index >> 16));
    wr_store_be16(base + 10u, (uint16_t)(index & 0xffffu));
    for (size_t i = 0; i < 12u; ++i) {
        nonce[i] = (uint8_t)(base[i] ^ ctx->salt[i]);
    }
}

static bool replay_update(wr_srtp_ctx *ctx, uint64_t idx)
{
    if (!ctx->replay_valid) {
        ctx->replay_valid = true;
        ctx->replay = 1ull;
        ctx->last_index = idx;
        return true;
    }
    if (idx == ctx->last_index) {
        return false;
    }
    if (idx > ctx->last_index) {
        uint64_t diff = idx - ctx->last_index;
        if (diff >= 64u) {
            ctx->replay = 1ull;
        } else {
            ctx->replay = (ctx->replay << diff) | 1ull;
        }
        ctx->last_index = idx;
        return true;
    }
    uint64_t diff = ctx->last_index - idx;
    if (diff >= 64u) {
        return false;
    }
    if (ctx->replay & (UINT64_C(1) << diff)) {
        return false;
    }
    ctx->replay |= UINT64_C(1) << diff;
    return true;
}

wr_status wr_srtp_protect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out)
{
    if (WR_UNLIKELY(!ctx || !ctx->initialized || !in.ptr)) {
        return WR_ERR_INVAL;
    }
    size_t hl = 0u;
    uint16_t seq = 0u;
    uint32_t ssrc = 0u;
    if (WR_UNLIKELY(!parse_rtp(in, &hl, &seq, &ssrc) ||
                    ssrc != ctx->ssrc)) {
        return WR_ERR_INVAL;
    }
    if (ctx->seq_valid && seq < ctx->last_seq &&
        (uint16_t)(ctx->last_seq - seq) > 0x8000u) {
        ctx->roc++;
    }
    uint64_t index = ((uint64_t)ctx->roc << 16) | seq;
    ctx->last_seq = seq;
    ctx->seq_valid = true;

    size_t ct_len = in.len - hl;
    if (out.len < in.len + ctx->tag_len) {
        return WR_ERR_OVERFLOW;
    }
    memcpy(out.ptr, in.ptr, hl);

    if (profile_gcm(ctx->profile)) {
        uint8_t nonce[12];
        uint8_t tag[16];
        gcm_nonce(ctx, index, nonce);
        wr_status st;
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->gcm_enc) {
            int len = 0;
            int total = 0;
            if (EVP_EncryptInit_ex(im->gcm_enc, NULL, NULL, NULL, nonce) != 1 ||
                (hl != 0u && EVP_EncryptUpdate(im->gcm_enc, NULL, &len, in.ptr,
                                               (int)hl) != 1) ||
                EVP_EncryptUpdate(im->gcm_enc, out.ptr + hl, &len,
                                  in.ptr + hl, (int)ct_len) != 1) {
                return WR_ERR_CRYPTO;
            }
            total = len;
            if (EVP_EncryptFinal_ex(im->gcm_enc, out.ptr + hl + total,
                                    &len) != 1 ||
                EVP_CIPHER_CTX_ctrl(im->gcm_enc, EVP_CTRL_GCM_GET_TAG, 16,
                                    tag) != 1) {
                return WR_ERR_CRYPTO;
            }
            st = WR_OK;
        } else {
            st = wr_crypto_aead_encrypt(
                wr_crypto_openssl(), ctx->key, profile_key_len(ctx->profile), nonce,
                wr_span_c_make(in.ptr, hl),
                wr_span_c_make(in.ptr + hl, ct_len), out.ptr + hl, tag,
                sizeof(tag));
        }
        if (st != WR_OK) {
            return st;
        }
        memcpy(out.ptr + hl + ct_len, tag, 16);
    } else {
        uint8_t iv[16];
        uint8_t mac[20];
        aes_iv(ctx, index, iv);
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->ctr) {
            int len = 0;
            if (EVP_EncryptInit_ex(im->ctr, NULL, NULL, NULL, iv) != 1 ||
                EVP_EncryptUpdate(im->ctr, out.ptr + hl, &len,
                                  in.ptr + hl, (int)ct_len) != 1) {
                return WR_ERR_CRYPTO;
            }
            hmac_sha1(im, out.ptr, hl + ct_len, mac);
        } else {
            wr_crypto_aes_ctr(ctx->key, profile_key_len(ctx->profile), iv,
                              wr_span_c_make(in.ptr + hl, ct_len),
                              out.ptr + hl);
            wr_crypto_hmac_sha1(ctx->auth, 20u,
                                wr_span_c_make(out.ptr, hl + ct_len), mac);
        }
        memcpy(out.ptr + hl + ct_len, mac, ctx->tag_len);
    }
    out.len = in.len + ctx->tag_len;
    return WR_OK;
}

wr_status wr_srtp_unprotect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out)
{
    if (WR_UNLIKELY(!ctx || !ctx->initialized || !in.ptr)) {
        return WR_ERR_INVAL;
    }
    size_t hl = 0u;
    uint16_t seq = 0u;
    uint32_t ssrc = 0u;
    if (WR_UNLIKELY(!parse_rtp(in, &hl, &seq, &ssrc) ||
                    ssrc != ctx->ssrc)) {
        return WR_ERR_INVAL;
    }
    if (WR_UNLIKELY(in.len < hl + ctx->tag_len)) {
        return WR_ERR_TRUNCATED;
    }
    size_t ct_len = in.len - hl - ctx->tag_len;
    if (out.len < in.len - ctx->tag_len) {
        return WR_ERR_OVERFLOW;
    }

    uint32_t roc = ctx->roc;
    if (ctx->seq_valid && seq < ctx->last_seq &&
        (uint16_t)(ctx->last_seq - seq) > 0x8000u) {
        roc++;
    }
    uint64_t index = ((uint64_t)roc << 16) | seq;

    if (profile_gcm(ctx->profile)) {
        uint8_t nonce[12];
        gcm_nonce(ctx, index, nonce);
        wr_status st;
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->gcm_dec) {
            int len = 0;
            int total = 0;
            uint8_t tagbuf[16];
            memcpy(tagbuf, in.ptr + in.len - 16u, 16u);
            if (EVP_DecryptInit_ex(im->gcm_dec, NULL, NULL, NULL, nonce) != 1 ||
                (hl != 0u && EVP_DecryptUpdate(im->gcm_dec, NULL, &len, in.ptr,
                                               (int)hl) != 1) ||
                EVP_DecryptUpdate(im->gcm_dec, out.ptr + hl, &len,
                                  in.ptr + hl, (int)ct_len) != 1) {
                return WR_ERR_AUTH;
            }
            total = len;
            if (EVP_CIPHER_CTX_ctrl(im->gcm_dec, EVP_CTRL_GCM_SET_TAG, 16,
                                    tagbuf) != 1 ||
                EVP_DecryptFinal_ex(im->gcm_dec, out.ptr + hl + total,
                                    &len) != 1) {
                return WR_ERR_AUTH;
            }
            st = WR_OK;
        } else {
            st = wr_crypto_aead_decrypt(
                wr_crypto_openssl(), ctx->key, profile_key_len(ctx->profile), nonce,
                wr_span_c_make(in.ptr, hl),
                wr_span_c_make(in.ptr + hl, ct_len), out.ptr + hl,
                in.ptr + in.len - 16u, 16u);
        }
        if (st != WR_OK) {
            /* A failed decrypt may still have written plaintext into the
             * caller's buffer; do not leave it behind. */
            wr_secure_zero(out.ptr, in.len < out.len ? in.len : out.len);
            return WR_ERR_AUTH;
        }
    } else {
        uint8_t mac[20];
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->ctr) {
            hmac_sha1(im, in.ptr, in.len - ctx->tag_len, mac);
        } else {
            wr_crypto_hmac_sha1(ctx->auth, 20u,
                                wr_span_c_make(in.ptr,
                                               in.len - ctx->tag_len),
                                mac);
        }
        uint8_t diff = 0u;
        for (size_t i = 0; i < ctx->tag_len; ++i) {
            diff |= (uint8_t)(mac[i] ^ in.ptr[in.len - ctx->tag_len + i]);
        }
        if (diff != 0u) {
            wr_secure_zero(out.ptr, in.len < out.len ? in.len : out.len);
            return WR_ERR_AUTH;
        }
        uint8_t iv[16];
        aes_iv(ctx, index, iv);
        if (im && im->ctr) {
            int len = 0;
            if (EVP_DecryptInit_ex(im->ctr, NULL, NULL, NULL, iv) != 1 ||
                EVP_DecryptUpdate(im->ctr, out.ptr + hl, &len,
                                  in.ptr + hl, (int)ct_len) != 1) {
                return WR_ERR_CRYPTO;
            }
        } else {
            wr_crypto_aes_ctr(ctx->key, profile_key_len(ctx->profile), iv,
                              wr_span_c_make(in.ptr + hl, ct_len),
                              out.ptr + hl);
        }
    }

    if (!replay_update(ctx, index)) {
        return WR_ERR_AUTH;
    }
    memcpy(out.ptr, in.ptr, hl);
    ctx->roc = roc;
    ctx->last_seq = seq;
    ctx->seq_valid = true;
    out.len = in.len - ctx->tag_len;
    return WR_OK;
}
/* ------------------------------------------------------------------------- */
/* SRTCP                                                                      */
/* ------------------------------------------------------------------------- */

/* RFC 3711 3.4.1 / RFC 7714 17: the AES-CM IV for SRTCP is
 * (0000 || SSRC || 0000 || 31-bit index) XOR salt. */
static void srtcp_iv(wr_srtp_ctx *ctx, uint32_t index, uint8_t iv[16])
{
    memset(iv, 0, 16);
    memcpy(iv, ctx->salt, 14);
    uint32_t s = wr_load_be32(iv + 4u) ^ ctx->ssrc;
    wr_store_be32(iv + 4u, s);
    /* Bytes 6..7 stay zero; the index occupies bytes 8..11. */
    wr_store_be32(iv + 8u, wr_load_be32(iv + 8u) ^ (index & UINT32_C(0x7fffffff)));
}

/* RFC 7714 9 / 17: the GCM nonce is (0000 || SSRC || 0000 || index) XOR salt,
 * and the AAD is the first 8 octets of the RTCP packet plus the ESRTCP word. */
static void srtcp_nonce(wr_srtp_ctx *ctx, uint32_t index, uint8_t nonce[12])
{
    uint8_t base[12] = { 0 };
    wr_store_be32(base + 2u, ctx->ssrc);
    wr_store_be32(base + 8u, index & UINT32_C(0x7fffffff));
    for (size_t i = 0; i < 12u; ++i) {
        nonce[i] = (uint8_t)(base[i] ^ ctx->salt[i]);
    }
}

wr_status wr_srtcp_protect(wr_srtp_ctx *ctx, wr_span_c rtcp, wr_span out,
                           uint32_t index)
{
    if (WR_UNLIKELY(!ctx || !ctx->initialized || !ctx->srtcp || !rtcp.ptr)) {
        return WR_ERR_INVAL;
    }
    /* RFC 3711 3.4: the first 8 octets of the RTCP packet (length and SSRC)
     * stay in the clear; the rest is encrypted. */
    if (rtcp.len < 8u) {
        return WR_ERR_TRUNCATED;
    }
    uint32_t esrtcp = (1u << 31) | (index & UINT32_C(0x7fffffff));
    size_t ct_len = rtcp.len - 8u;
    size_t total = rtcp.len + 4u + ctx->tag_len;
    if (out.len < total) {
        return WR_ERR_OVERFLOW;
    }
    memcpy(out.ptr, rtcp.ptr, 8u);
    uint8_t *e_word = out.ptr + 8u + ct_len;
    wr_store_be32(e_word, esrtcp);

    if (profile_gcm(ctx->profile)) {
        uint8_t nonce[12];
        uint8_t tag[16];
        uint8_t aad[12];
        srtcp_nonce(ctx, index, nonce);
        memcpy(aad, rtcp.ptr, 8u);
        memcpy(aad + 8u, e_word, 4u);
        wr_status st;
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->gcm_enc) {
            int len = 0;
            int total_enc = 0;
            if (EVP_EncryptInit_ex(im->gcm_enc, NULL, NULL, NULL, nonce) != 1 ||
                EVP_EncryptUpdate(im->gcm_enc, NULL, &len, aad,
                                  (int)sizeof(aad)) != 1 ||
                EVP_EncryptUpdate(im->gcm_enc, out.ptr + 8u, &len,
                                  rtcp.ptr + 8u, (int)ct_len) != 1) {
                return WR_ERR_CRYPTO;
            }
            total_enc = len;
            if (EVP_EncryptFinal_ex(im->gcm_enc, out.ptr + 8u + total_enc,
                                    &len) != 1 ||
                EVP_CIPHER_CTX_ctrl(im->gcm_enc, EVP_CTRL_GCM_GET_TAG, 16,
                                    tag) != 1) {
                return WR_ERR_CRYPTO;
            }
            st = WR_OK;
        } else {
            st = wr_crypto_aead_encrypt(
                wr_crypto_openssl(), ctx->key, profile_key_len(ctx->profile), nonce,
                wr_span_c_make(aad, sizeof(aad)),
                wr_span_c_make(rtcp.ptr + 8u, ct_len), out.ptr + 8u, tag,
                sizeof(tag));
        }
        if (st != WR_OK) {
            return st;
        }
        memcpy(out.ptr + 8u + ct_len + 4u, tag, 16);
    } else {
        uint8_t iv[16];
        uint8_t mac[20];
        srtcp_iv(ctx, index, iv);
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->ctr) {
            int len = 0;
            if (EVP_EncryptInit_ex(im->ctr, NULL, NULL, NULL, iv) != 1 ||
                EVP_EncryptUpdate(im->ctr, out.ptr + 8u, &len,
                                  rtcp.ptr + 8u, (int)ct_len) != 1) {
                return WR_ERR_CRYPTO;
            }
            hmac_sha1(im, out.ptr, 8u + ct_len + 4u, mac);
        } else {
            wr_crypto_aes_ctr(ctx->key, profile_key_len(ctx->profile), iv,
                              wr_span_c_make(rtcp.ptr + 8u, ct_len),
                              out.ptr + 8u);
            wr_crypto_hmac_sha1(ctx->auth, 20u,
                                wr_span_c_make(out.ptr, 8u + ct_len + 4u),
                                mac);
        }
        memcpy(out.ptr + 8u + ct_len + 4u, mac, ctx->tag_len);
    }
    out.len = total;
    return WR_OK;
}

wr_status wr_srtcp_unprotect(wr_srtp_ctx *ctx, wr_span_c in, wr_span out,
                             uint32_t *index)
{
    if (WR_UNLIKELY(!ctx || !ctx->initialized || !ctx->srtcp || !in.ptr)) {
        return WR_ERR_INVAL;
    }
    /* 8 (header) + 4 (ESRTCP word) + tag. */
    if (in.len < 8u + 4u + ctx->tag_len) {
        return WR_ERR_TRUNCATED;
    }
    size_t ct_len = in.len - 8u - 4u - ctx->tag_len;
    if (out.len < in.len - ctx->tag_len) {
        return WR_ERR_OVERFLOW;
    }
    uint32_t esrtcp = wr_load_be32(in.ptr + 8u + ct_len);
    bool encrypted = (esrtcp & 0x80000000u) != 0u;
    uint32_t idx = esrtcp & 0x7fffffffu;

    /* Authenticate before touching the replay window: an unauthenticated
     * packet must not be able to burn a window slot. */
    if (profile_gcm(ctx->profile)) {
        uint8_t nonce[12];
        uint8_t aad[12];
        uint8_t tagbuf[16];
        srtcp_nonce(ctx, idx, nonce);
        memcpy(aad, in.ptr, 8u);
        memcpy(aad + 8u, in.ptr + 8u + ct_len, 4u);
        memcpy(tagbuf, in.ptr + 8u + ct_len + 4u, 16);
        wr_status st;
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->gcm_dec) {
            int len = 0;
            int total = 0;
            if (EVP_DecryptInit_ex(im->gcm_dec, NULL, NULL, NULL, nonce) != 1 ||
                EVP_DecryptUpdate(im->gcm_dec, NULL, &len, aad,
                                  (int)sizeof(aad)) != 1 ||
                EVP_DecryptUpdate(im->gcm_dec, out.ptr + 8u, &len,
                                  in.ptr + 8u, (int)ct_len) != 1) {
                return WR_ERR_AUTH;
            }
            total = len;
            if (EVP_CIPHER_CTX_ctrl(im->gcm_dec, EVP_CTRL_GCM_SET_TAG, 16,
                                    tagbuf) != 1 ||
                EVP_DecryptFinal_ex(im->gcm_dec, out.ptr + 8u + total,
                                    &len) != 1) {
                return WR_ERR_AUTH;
            }
            st = WR_OK;
        } else {
            st = wr_crypto_aead_decrypt(
                wr_crypto_openssl(), ctx->key, profile_key_len(ctx->profile), nonce,
                wr_span_c_make(aad, sizeof(aad)),
                wr_span_c_make(in.ptr + 8u, ct_len), out.ptr + 8u, tagbuf, 16);
        }
        if (st != WR_OK) {
            return WR_ERR_AUTH;
        }
    } else {
        uint8_t mac[20];
        uint8_t diff = 0u;
        wr_srtp_impl *im = (wr_srtp_impl *)ctx->impl;
        if (im && im->ctr) {
            hmac_sha1(im, in.ptr, 8u + ct_len + 4u, mac);
        } else {
            wr_crypto_hmac_sha1(ctx->auth, 20u,
                                wr_span_c_make(in.ptr, 8u + ct_len + 4u),
                                mac);
        }
        for (size_t i = 0; i < ctx->tag_len; ++i) {
            diff |= (uint8_t)(mac[i] ^ in.ptr[8u + ct_len + 4u + i]);
        }
        if (diff != 0u) {
            return WR_ERR_AUTH;
        }
        if (encrypted) {
            uint8_t iv[16];
            srtcp_iv(ctx, idx, iv);
            if (im && im->ctr) {
                int len = 0;
                if (EVP_DecryptInit_ex(im->ctr, NULL, NULL, NULL, iv) != 1 ||
                    EVP_DecryptUpdate(im->ctr, out.ptr + 8u, &len,
                                      in.ptr + 8u, (int)ct_len) != 1) {
                    return WR_ERR_CRYPTO;
                }
            } else {
                wr_crypto_aes_ctr(ctx->key, profile_key_len(ctx->profile), iv,
                                  wr_span_c_make(in.ptr + 8u, ct_len),
                                  out.ptr + 8u);
            }
        } else {
            memcpy(out.ptr + 8u, in.ptr + 8u, ct_len);
        }
    }

    /* Replay check on the 31-bit index (RFC 3711 3.3.2). */
    {
        uint64_t i = (uint64_t)idx;
        if (!ctx->replay_valid) {
            ctx->replay_valid = true;
            ctx->replay = 1ull;
            ctx->last_index = i;
        } else if (i == ctx->last_index) {
            return WR_ERR_AUTH;
        } else if (i > ctx->last_index) {
            uint64_t d = i - ctx->last_index;
            ctx->replay = d >= 64u ? 1ull : ((ctx->replay << d) | 1ull);
            ctx->last_index = i;
        } else {
            uint64_t d = ctx->last_index - i;
            if (d >= 64u || (ctx->replay & (UINT64_C(1) << d)) != 0u) {
                return WR_ERR_AUTH;
            }
            ctx->replay |= UINT64_C(1) << d;
        }
    }
    ctx->srtcp_index = idx;
    memcpy(out.ptr, in.ptr, 8u);
    out.len = in.len - ctx->tag_len;
    if (index) {
        *index = idx;
    }
    return WR_OK;
}
