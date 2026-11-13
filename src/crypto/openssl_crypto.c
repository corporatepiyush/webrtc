#include "wr/crypto.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>

typedef struct {
    int dummy;
} wr_openssl_vtbl;

static const wr_openssl_vtbl g_openssl_vtbl = { 0 };
static wr_crypto g_openssl = { &g_openssl_vtbl, NULL };

wr_crypto *wr_crypto_openssl(void)
{
    return &g_openssl;
}

static const EVP_CIPHER *gcm_cipher(size_t key_len)
{
    return key_len == 32u ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

wr_status wr_crypto_aead_encrypt(const wr_crypto *c, const uint8_t *key,
                                 size_t key_len, const uint8_t nonce[12],
                                 wr_span_c aad, wr_span_c plain, uint8_t *out,
                                 uint8_t *tag, size_t tag_len)
{
    WR_UNUSED(c);
    if (!key || (key_len != 16u && key_len != 32u) || !nonce || !out || !tag ||
        tag_len == 0u || tag_len > 16u) {
        return WR_ERR_INVAL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return WR_ERR_NOMEM;
    }
    wr_status st = WR_ERR_CRYPTO;
    int len = 0;
    int total = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, gcm_cipher(key_len), NULL, NULL, NULL) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
            break;
        }
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
            break;
        }
        if (aad.len && EVP_EncryptUpdate(ctx, NULL, &len, aad.ptr, (int)aad.len) != 1) {
            break;
        }
        if (plain.len && EVP_EncryptUpdate(ctx, out, &len, plain.ptr, (int)plain.len) != 1) {
            break;
        }
        total = len;
        if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) != 1) {
            break;
        }
        st = WR_OK;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return st;
}

wr_status wr_crypto_aead_decrypt(const wr_crypto *c, const uint8_t *key,
                                 size_t key_len, const uint8_t nonce[12],
                                 wr_span_c aad, wr_span_c cipher, uint8_t *out,
                                 const uint8_t *tag, size_t tag_len)
{
    WR_UNUSED(c);
    if (!key || (key_len != 16u && key_len != 32u) || !nonce || !out || !tag ||
        tag_len == 0u || tag_len > 16u) {
        return WR_ERR_INVAL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return WR_ERR_NOMEM;
    }
    wr_status st = WR_ERR_CRYPTO;
    int len = 0;
    int total = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, gcm_cipher(key_len), NULL, NULL, NULL) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
            break;
        }
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
            break;
        }
        if (aad.len && EVP_DecryptUpdate(ctx, NULL, &len, aad.ptr, (int)aad.len) != 1) {
            break;
        }
        if (cipher.len && EVP_DecryptUpdate(ctx, out, &len, cipher.ptr, (int)cipher.len) != 1) {
            break;
        }
        total = len;
        uint8_t tagbuf[16];
        memcpy(tagbuf, tag, tag_len);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                                tagbuf) != 1) {
            break;
        }
        if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1) {
            st = WR_ERR_AUTH;
            break;
        }
        st = WR_OK;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return st;
}

void wr_crypto_hmac_sha1(const uint8_t *key, size_t key_len, wr_span_c data,
                         uint8_t out[20])
{
    unsigned int n = 0;
    if (!key || !data.ptr || !out) {
        return;
    }
    (void)HMAC(EVP_sha1(), key, (int)key_len, data.ptr, data.len, out, &n);
}

void wr_crypto_hmac_sha256(const uint8_t *key, size_t key_len, wr_span_c data,
                           uint8_t out[32])
{
    unsigned int n = 0;
    if (!key || !data.ptr || !out) {
        return;
    }
    (void)HMAC(EVP_sha256(), key, (int)key_len, data.ptr, data.len, out, &n);
}

void wr_crypto_sha256(wr_span_c data, uint8_t out[32])
{
    if (!data.ptr || !out) {
        return;
    }
    (void)SHA256(data.ptr, data.len, out);
}

void wr_crypto_aes_ctr(const uint8_t *key, size_t key_len,
                       const uint8_t iv[16], wr_span_c in, uint8_t *out)
{
    if (!key || (key_len != 16u && key_len != 32u) || !iv || !in.ptr || !out) {
        return;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;
    }
    const EVP_CIPHER *cipher = key_len == 32u ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
    int len = 0;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) == 1) {
        (void)EVP_EncryptUpdate(ctx, out, &len, in.ptr, (int)in.len);
    }
    EVP_CIPHER_CTX_free(ctx);
}

wr_status wr_crypto_ecdh_keygen(const wr_crypto *c, uint8_t priv[32],
                                uint8_t pub[65])
{
    WR_UNUSED(c);
    if (!priv || !pub) {
        return WR_ERR_INVAL;
    }
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) {
        return WR_ERR_NOMEM;
    }
    wr_status st = WR_ERR_CRYPTO;
    EVP_PKEY *pkey = NULL;
    do {
        if (EVP_PKEY_keygen_init(pctx) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
            break;
        }
        if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
            break;
        }
        size_t plen = 65;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                            pub, 65, &plen) != 1 ||
            plen != 65) {
            break;
        }
        BIGNUM *bn = NULL;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != 1 ||
            !bn || BN_bn2binpad(bn, priv, 32) != 32) {
            BN_free(bn);
            break;
        }
        BN_free(bn);
        st = WR_OK;
    } while (0);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return st;
}

wr_status wr_crypto_ecdh_derive(const wr_crypto *c, const uint8_t priv[32],
                                const uint8_t peer_pub[65], uint8_t shared[32])
{
    WR_UNUSED(c);
    if (!priv || !peer_pub || !shared) {
        return WR_ERR_INVAL;
    }
    char group[] = "prime256v1";
    uint8_t priv_le[32];
    uint8_t pub_copy[65];
    memcpy(pub_copy, peer_pub, 65);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    memcpy(priv_le, priv, 32);
#else
    for (size_t i = 0; i < 32u; ++i) {
        priv_le[i] = priv[31u - i];
    }
#endif
    EVP_PKEY *mine = NULL;
    EVP_PKEY *peer = NULL;
    wr_status st = WR_ERR_CRYPTO;

    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!gctx) {
        return WR_ERR_NOMEM;
    }
    do {
        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     group, 0u);
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                            priv_le, 32u);
        params[2] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata_init(gctx) != 1 ||
            EVP_PKEY_fromdata(gctx, &mine, EVP_PKEY_KEYPAIR, params) != 1 ||
            !mine) {
            break;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     group, 0u);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                      pub_copy, 65u);
        params[2] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata_init(gctx) != 1 ||
            EVP_PKEY_fromdata(gctx, &peer, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
            !peer) {
            break;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
        if (!ctx) {
            break;
        }
        size_t slen = 32;
        if (EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
            EVP_PKEY_derive(ctx, shared, &slen) == 1 && slen == 32) {
            st = WR_OK;
        }
        EVP_PKEY_CTX_free(ctx);
    } while (0);

    EVP_PKEY_free(mine);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(gctx);
    return st;
}
