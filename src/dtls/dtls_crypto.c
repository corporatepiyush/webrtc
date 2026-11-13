#include "dtls_internal.h"

#include "wr/crypto.h"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Certificate                                                               */
/* ------------------------------------------------------------------------- */

void wr_dtls_cert_free(wr_dtls *d)
{
    if (d->cert_key) {
        EVP_PKEY_free(d->cert_key);
        d->cert_key = NULL;
    }
    if (d->cert) {
        X509_free(d->cert);
        d->cert = NULL;
    }
    if (d->peer_pub) {
        EVP_PKEY_free(d->peer_pub);
        d->peer_pub = NULL;
    }
}

bool wr_dtls_make_cert(wr_dtls *d)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) {
        return false;
    }
    EVP_PKEY *key = NULL;
    bool ok = EVP_PKEY_keygen_init(pctx) == 1 &&
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                     NID_X9_62_prime256v1) == 1 &&
              EVP_PKEY_keygen(pctx, &key) == 1 && key != NULL;
    EVP_PKEY_CTX_free(pctx);
    if (!ok) {
        return false;
    }

    X509 *x = X509_new();
    if (!x) {
        EVP_PKEY_free(key);
        return false;
    }
    X509_set_version(x, 2u);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 31536000L);
    if (X509_set_pubkey(x, key) != 1) {
        X509_free(x);
        EVP_PKEY_free(key);
        return false;
    }
    X509_NAME *name = X509_get_subject_name(x);
    if (!name ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const uint8_t *)"WebRTC", -1, -1, 0) != 1 ||
        X509_set_issuer_name(x, name) != 1 ||
        X509_sign(x, key, EVP_sha256()) == 0) {
        X509_free(x);
        EVP_PKEY_free(key);
        return false;
    }

    uint8_t *der = NULL;
    int der_len = i2d_X509(x, &der);
    if (der_len <= 0 || !der || (size_t)der_len > sizeof(d->cert_der)) {
        OPENSSL_free(der);
        X509_free(x);
        EVP_PKEY_free(key);
        return false;
    }
    memcpy(d->cert_der, der, (size_t)der_len);
    d->cert_der_len = (size_t)der_len;
    OPENSSL_free(der);

    uint8_t hash[32];
    wr_crypto_sha256(wr_span_c_make(d->cert_der, d->cert_der_len), hash);
    memcpy(d->fp, hash, 32);

    d->cert_key = key;
    d->cert = x;
    return true;
}

bool wr_dtls_parse_certificate(wr_dtls *d, wr_span_c body)
{
    if (body.len < 6u) {
        return false;
    }
    uint32_t list_len = load_be24(body.ptr);
    uint32_t cert_len = load_be24(body.ptr + 3u);
    if (list_len != cert_len + 3u || 6u + cert_len > body.len) {
        return false;
    }
    const uint8_t *p = body.ptr + 6u;
    X509 *x = d2i_X509(NULL, &p, (long)cert_len);
    if (!x) {
        return false;
    }
    if (d->peer_pub) {
        EVP_PKEY_free(d->peer_pub);
    }
    d->peer_pub = X509_get_pubkey(x);
    uint8_t hash[32];
    wr_crypto_sha256(wr_span_c_make(body.ptr + 6u, cert_len), hash);
    if (d->have_peer_fp && memcmp(hash, d->peer_fp, 32) != 0) {
        X509_free(x);
        return false;
    }
    X509_free(x);
    return d->peer_pub != NULL;
}

bool wr_dtls_sign_ske(wr_dtls *d, wr_span_c signed_data, uint8_t *sig,
                     size_t cap, size_t *sig_len)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) {
        return false;
    }
    size_t n = cap;
    bool ok = EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, d->cert_key) == 1 &&
              EVP_DigestSign(md, sig, &n, signed_data.ptr,
                             (size_t)signed_data.len) == 1;
    EVP_MD_CTX_free(md);
    if (ok) {
        *sig_len = n;
    }
    return ok;
}

bool wr_dtls_verify_ske(wr_dtls *d, wr_span_c signed_data, wr_span_c sig)
{
    if (!d->peer_pub) {
        return false;
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) {
        return false;
    }
    bool ok = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL,
                                   d->peer_pub) == 1 &&
              EVP_DigestVerify(md, sig.ptr, sig.len, signed_data.ptr,
                               signed_data.len) == 1;
    EVP_MD_CTX_free(md);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Key schedule                                                              */
/* ------------------------------------------------------------------------- */

void wr_dtls_derive_keys(wr_dtls *d, wr_span_c shared)
{
    if (shared.len != 32u) {
        return;
    }
    uint8_t seed[64];
    memcpy(seed, d->client_random, 32);
    memcpy(seed + 32, d->server_random, 32);
    wr_dtls_prf(shared.ptr, 32, wr_span_c_from_str("master secret"),
                wr_span_c_make(seed, 64), d->master, sizeof(d->master));

    uint8_t seed2[64];
    memcpy(seed2, d->server_random, 32);
    memcpy(seed2 + 32, d->client_random, 32);
    uint8_t kb[40];
    wr_dtls_prf(d->master, sizeof(d->master),
                wr_span_c_from_str("key expansion"),
                wr_span_c_make(seed2, 64), kb, sizeof(kb));

    wr_dtls_cipher cli;
    wr_dtls_cipher srv;
    memset(&cli, 0, sizeof(cli));
    memset(&srv, 0, sizeof(srv));
    memcpy(cli.key, kb, 16);
    memcpy(srv.key, kb + 16, 16);
    memcpy(cli.salt, kb + 32, 4);
    memcpy(srv.salt, kb + 36, 4);
    cli.iv[0] = cli.salt[0];
    cli.iv[1] = cli.salt[1];
    cli.iv[2] = cli.salt[2];
    cli.iv[3] = cli.salt[3];
    srv.iv[0] = srv.salt[0];
    srv.iv[1] = srv.salt[1];
    srv.iv[2] = srv.salt[2];
    srv.iv[3] = srv.salt[3];

    if (d->role == WR_DTLS_ROLE_CLIENT) {
        d->cwrite = cli;
        d->cread = srv;
    } else {
        d->cwrite = srv;
        d->cread = cli;
    }
    wr_secure_zero(kb, sizeof(kb));
    if (!wr_dtls_cipher_init(&d->cwrite) ||
        !wr_dtls_cipher_init(&d->cread)) {
        return;
    }
    d->keys_ready = true;
}
