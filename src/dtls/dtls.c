#include "wr/dtls.h"

#include "wr/crypto.h"

#include <string.h>

#include <openssl/evp.h>

wr_status wr_dtls_record_parse(wr_span_c pkt, wr_dtls_record *out)
{
    if (WR_UNLIKELY(!pkt.ptr || pkt.len < 13u || !out)) {
        return WR_ERR_TRUNCATED;
    }
    memset(out, 0, sizeof(*out));
    out->type = pkt.ptr[0];
    out->version = wr_load_be16(pkt.ptr + 1u);
    out->epoch = wr_load_be16(pkt.ptr + 3u);
    memcpy(out->seq, pkt.ptr + 5u, 6u);
    out->length = wr_load_be16(pkt.ptr + 11u);
    out->header_len = 13u;
    size_t total = 13u + (size_t)out->length;
    if (WR_UNLIKELY(total > pkt.len)) {
        return WR_ERR_TRUNCATED;
    }
    out->body = wr_span_c_sub(pkt, 13u, out->length);
    return WR_OK;
}

wr_status wr_dtls_record_serialize(const wr_dtls_record *r, char *buf,
                                   size_t cap, size_t *out_len)
{
    if (!r || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (r->body.len > UINT16_MAX) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = 13u + r->body.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    p[0] = r->type;
    wr_store_be16(p + 1u, r->version);
    wr_store_be16(p + 3u, r->epoch);
    memcpy(p + 5u, r->seq, 6u);
    wr_store_be16(p + 11u, (uint16_t)r->body.len);
    if (r->body.len) {
        memcpy(p + 13u, r->body.ptr, r->body.len);
    }
    *out_len = total;
    return WR_OK;
}

wr_status wr_dtls_hs_parse(wr_span_c pkt, wr_dtls_hs *out)
{
    if (WR_UNLIKELY(!pkt.ptr || pkt.len < 12u || !out)) {
        return WR_ERR_TRUNCATED;
    }
    memset(out, 0, sizeof(*out));
    out->type = pkt.ptr[0];
    out->length = ((uint32_t)pkt.ptr[1] << 16) |
                  ((uint32_t)pkt.ptr[2] << 8) | (uint32_t)pkt.ptr[3];
    out->msg_seq = wr_load_be16(pkt.ptr + 4u);
    out->frag_off = ((uint32_t)pkt.ptr[6] << 16) |
                    ((uint32_t)pkt.ptr[7] << 8) | (uint32_t)pkt.ptr[8];
    out->frag_len = ((uint32_t)pkt.ptr[9] << 16) |
                    ((uint32_t)pkt.ptr[10] << 8) | (uint32_t)pkt.ptr[11];
    out->header_len = 12u;
    if (WR_UNLIKELY(out->frag_off > out->length ||
                    out->frag_len > out->length - out->frag_off)) {
        return WR_ERR_INVAL;
    }
    size_t total = 12u + (size_t)out->frag_len;
    if (WR_UNLIKELY(total > pkt.len)) {
        return WR_ERR_TRUNCATED;
    }
    out->body = wr_span_c_sub(pkt, 12u, out->frag_len);
    return WR_OK;
}

static void put_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

wr_status wr_dtls_hs_serialize(const wr_dtls_hs *h, char *buf, size_t cap,
                               size_t *out_len)
{
    if (!h || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (h->body.len > SIZE_MAX - 12u) {
        return WR_ERR_OVERFLOW;
    }
    size_t total = 12u + h->body.len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    p[0] = h->type;
    put_u24(p + 1u, h->length);
    wr_store_be16(p + 4u, h->msg_seq);
    put_u24(p + 6u, h->frag_off);
    put_u24(p + 9u, h->frag_len);
    if (h->body.len) {
        memcpy(p + 12u, h->body.ptr, h->body.len);
    }
    *out_len = total;
    return WR_OK;
}

void wr_dtls_prf(const uint8_t *secret, size_t secret_len, wr_span_c label,
                 wr_span_c seed, uint8_t *out, size_t out_len)
{
    if (!out) {
        return;
    }
    if (!secret || out_len == 0u || label.len + seed.len > 400u) {
        memset(out, 0, out_len);
        return;
    }
    uint8_t label_seed[400];
    memcpy(label_seed, label.ptr, label.len);
    memcpy(label_seed + label.len, seed.ptr, seed.len);
    size_t ls_len = label.len + seed.len;
    uint8_t a[32];
    uint8_t tmp[32];
    wr_crypto_hmac_sha256(secret, secret_len,
                          wr_span_c_make(label_seed, ls_len), a);
    size_t off = 0u;
    while (off < out_len) {
        uint8_t in[432];
        memcpy(in, a, 32);
        memcpy(in + 32, label_seed, ls_len);
        wr_crypto_hmac_sha256(secret, secret_len, wr_span_c_make(in, 32u + ls_len),
                              tmp);
        size_t n = out_len - off < 32u ? out_len - off : 32u;
        memcpy(out + off, tmp, n);
        off += n;
        wr_crypto_hmac_sha256(secret, secret_len, wr_span_c_make(a, 32), a);
    }
    wr_secure_zero(a, sizeof(a));
    wr_secure_zero(tmp, sizeof(tmp));
}

bool wr_dtls_cipher_init(wr_dtls_cipher *c)
{
    if (!c) {
        return false;
    }
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec = EVP_CIPHER_CTX_new();
    if (!enc || !dec ||
        EVP_EncryptInit_ex(enc, EVP_aes_128_gcm(), NULL, c->key, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(dec, EVP_aes_128_gcm(), NULL, c->key, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(enc);
        EVP_CIPHER_CTX_free(dec);
        return false;
    }
    c->enc = enc;
    c->dec = dec;
    return true;
}

void wr_dtls_cipher_free(wr_dtls_cipher *c)
{
    if (!c) {
        return;
    }
    if (c->enc) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)c->enc);
        c->enc = NULL;
    }
    if (c->dec) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)c->dec);
        c->dec = NULL;
    }
}

wr_status wr_dtls_encrypt(const wr_dtls_cipher *c, uint8_t type,
                          uint16_t epoch, const uint8_t seq[6], wr_span_c plain,
                          char *buf, size_t cap, size_t *out_len)
{
    if (!c || !seq || !buf || !out_len) {
        return WR_ERR_INVAL;
    }
    if (plain.len > UINT16_MAX - 24u) {
        return WR_ERR_OVERFLOW;
    }
    size_t body_len = 8u + plain.len + 16u;
    size_t total = 13u + body_len;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    uint8_t *p = (uint8_t *)buf;
    p[0] = type;
    wr_store_be16(p + 1u, UINT16_C(0xfefd));
    wr_store_be16(p + 3u, epoch);
    memcpy(p + 5u, seq, 6u);
    wr_store_be16(p + 11u, (uint16_t)body_len);
    wr_store_be16(p + 13u, epoch);
    memcpy(p + 15u, seq, 6u);

    uint8_t nonce[12];
    memcpy(nonce, c->salt, 4u);
    memcpy(nonce + 4u, p + 13u, 8u);
    /* RFC 6347 4.1.2.1: the AEAD additional data is NOT the record header;
     * it is epoch || sequence || type || version || length. */
    uint8_t aad[13];
    memcpy(aad, p + 3u, 8u); /* epoch || seq */
    aad[8] = p[0];           /* type */
    memcpy(aad + 9u, p + 1u, 2u);   /* version */
    memcpy(aad + 11u, p + 11u, 2u); /* length */
    uint8_t tag[16];
    wr_status st;
    if (c->enc) {
        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)c->enc;
        int len = 0;
        int enc_total = 0;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1 ||
            EVP_EncryptUpdate(ctx, NULL, &len, aad, 13) != 1 ||
            EVP_EncryptUpdate(ctx, p + 21u, &len, plain.ptr,
                              (int)plain.len) != 1) {
            return WR_ERR_CRYPTO;
        }
        enc_total = len;
        if (EVP_EncryptFinal_ex(ctx, p + 21u + enc_total, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            return WR_ERR_CRYPTO;
        }
        st = WR_OK;
    } else {
        st = wr_crypto_aead_encrypt(
            wr_crypto_openssl(), c->key, 16u, nonce,
            wr_span_c_make(aad, 13u), plain, p + 21u, tag, 16u);
    }
    if (st != WR_OK) {
        return st;
    }
    memcpy(p + 21u + plain.len, tag, 16u);
    *out_len = total;
    return WR_OK;
}

wr_status wr_dtls_decrypt(const wr_dtls_cipher *c, wr_span_c pkt,
                          wr_span *out, wr_dtls_record *meta)
{
    if (!c || !pkt.ptr || !meta || !out) {
        return WR_ERR_INVAL;
    }
    wr_dtls_record r;
    wr_status st = wr_dtls_record_parse(pkt, &r);
    if (st != WR_OK) {
        return st;
    }
    if (r.body.len < 24u) {
        return WR_ERR_TRUNCATED;
    }
    uint8_t nonce[12];
    memcpy(nonce, c->salt, 4u);
    memcpy(nonce + 4u, r.body.ptr, 8u);
    size_t ct_len = r.body.len - 24u;
    if (out->len < ct_len) {
        return WR_ERR_OVERFLOW;
    }
    /* RFC 6347 4.1.2.1: AAD is epoch || sequence || type || version ||
     * length, not the record header order. */
    uint8_t aad[13];
    wr_store_be16(aad, r.epoch);
    memcpy(aad + 2u, r.seq, 6u);
    aad[8] = r.type;
    wr_store_be16(aad + 9u, r.version);
    wr_store_be16(aad + 11u, r.length);
    if (c->dec) {
        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)c->dec;
        int len = 0;
        int total = 0;
        uint8_t tagbuf[16];
        memcpy(tagbuf, r.body.ptr + r.body.len - 16u, 16u);
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1 ||
            EVP_DecryptUpdate(ctx, NULL, &len, aad, 13) != 1 ||
            EVP_DecryptUpdate(ctx, out->ptr, &len, r.body.ptr + 8u,
                              (int)ct_len) != 1) {
            return WR_ERR_AUTH;
        }
        total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagbuf) != 1 ||
            EVP_DecryptFinal_ex(ctx, out->ptr + total, &len) != 1) {
            return WR_ERR_AUTH;
        }
        st = WR_OK;
    } else {
        st = wr_crypto_aead_decrypt(
            wr_crypto_openssl(), c->key, 16u, nonce,
            wr_span_c_make(aad, 13u),
            wr_span_c_make(r.body.ptr + 8u, ct_len),
            out->ptr, r.body.ptr + r.body.len - 16u, 16u);
    }
    if (st != WR_OK) {
        return WR_ERR_AUTH;
    }
    out->len = ct_len;
    *meta = r;
    return WR_OK;
}