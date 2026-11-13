#ifndef WR_CRYPTO_H
#define WR_CRYPTO_H

#include "wr/base.h"

typedef struct wr_crypto wr_crypto;
struct wr_crypto {
    const void *vt;
    void *ctx;
};

wr_crypto *wr_crypto_openssl(void);

wr_status wr_crypto_aead_encrypt(const wr_crypto *c, const uint8_t *key,
                                 size_t key_len, const uint8_t nonce[12],
                                 wr_span_c aad, wr_span_c plain, uint8_t *out,
                                 uint8_t *tag, size_t tag_len);
wr_status wr_crypto_aead_decrypt(const wr_crypto *c, const uint8_t *key,
                                 size_t key_len, const uint8_t nonce[12],
                                 wr_span_c aad, wr_span_c cipher, uint8_t *out,
                                 const uint8_t *tag, size_t tag_len);
void wr_crypto_hmac_sha1(const uint8_t *key, size_t key_len, wr_span_c data,
                         uint8_t out[20]);
void wr_crypto_hmac_sha256(const uint8_t *key, size_t key_len, wr_span_c data,
                           uint8_t out[32]);
void wr_crypto_sha256(wr_span_c data, uint8_t out[32]);
void wr_crypto_aes_ctr(const uint8_t *key, size_t key_len,
                       const uint8_t iv[16], wr_span_c in, uint8_t *out);
wr_status wr_crypto_ecdh_keygen(const wr_crypto *c, uint8_t priv[32],
                                uint8_t pub[65]);
wr_status wr_crypto_ecdh_derive(const wr_crypto *c, const uint8_t priv[32],
                                const uint8_t peer_pub[65], uint8_t shared[32]);

#endif /* WR_CRYPTO_H */