#include "test_util.h"

#include "wr/crypto.h"

static void test_aead(void)
{
    wr_crypto *c = wr_crypto_openssl();
    uint8_t key[16] = { 0 };
    uint8_t nonce[12] = { 0 };
    uint8_t tag[16];
    uint8_t out[32];
    uint8_t back[32];
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(0xa0 + i);

    WR_TEST_EQ_U64(wr_crypto_aead_encrypt(c, key, 16, nonce,
                                          wr_span_c_from_str("aad"),
                                          wr_span_c_from_str("hello"),
                                          out, tag, 16), WR_OK);
    WR_TEST_EQ_U64(wr_crypto_aead_decrypt(c, key, 16, nonce,
                                          wr_span_c_from_str("aad"),
                                          wr_span_c_make(out, 5), back, tag, 16),
                   WR_OK);
    WR_TEST_EQ_U64(memcmp(back, "hello", 5), 0);
    tag[0] ^= 1u;
    WR_TEST_CHECK(wr_crypto_aead_decrypt(c, key, 16, nonce,
                                         wr_span_c_from_str("aad"),
                                         wr_span_c_make(out, 5), back, tag, 16) ==
                  WR_ERR_AUTH);
}

static void test_ecdh(void)
{
    wr_crypto *c = wr_crypto_openssl();
    uint8_t priv1[32], pub1[65], priv2[32], pub2[65];
    uint8_t s1[32], s2[32];
    WR_TEST_EQ_U64(wr_crypto_ecdh_keygen(c, priv1, pub1), WR_OK);
    WR_TEST_EQ_U64(wr_crypto_ecdh_keygen(c, priv2, pub2), WR_OK);
    WR_TEST_EQ_U64(wr_crypto_ecdh_derive(c, priv1, pub2, s1), WR_OK);
    WR_TEST_EQ_U64(wr_crypto_ecdh_derive(c, priv2, pub1, s2), WR_OK);
    WR_TEST_EQ_U64(memcmp(s1, s2, 32), 0);
}

void test_crypto(void)
{
    test_aead();
    test_ecdh();
}
