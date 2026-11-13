#include "wr/stun.h"

#include "wr/crc32.h"
#include "wr/crypto.h"

#include <stdlib.h>
#include <string.h>

wr_status wr_stun_append_integrity(wr_stun_msg *m, const uint8_t *key,
                                   size_t key_len, char *buf, size_t cap,
                                   size_t *out_len)
{
    size_t base_len = 0u;
    wr_status st = wr_stun_serialize(m, buf, cap, &base_len);
    if (st != WR_OK) {
        return st;
    }
    size_t mi_attr = 4u + 20u;
    if (base_len + mi_attr + 8u > cap ||
        base_len - WR_STUN_HEADER_LEN + mi_attr > UINT16_MAX) {
        return WR_ERR_OVERFLOW;
    }
    /* Header length includes MESSAGE-INTEGRITY. */
    wr_store_be16((uint8_t *)buf + 2, (uint16_t)(base_len - WR_STUN_HEADER_LEN + mi_attr));
    uint8_t mac[20];
    wr_crypto_hmac_sha1(key, key_len, wr_span_c_make(buf, base_len), mac);

    size_t off = base_len;
    wr_store_be16((uint8_t *)buf + off, WR_STUN_ATTR_MESSAGE_INTEGRITY);
    wr_store_be16((uint8_t *)buf + off + 2, 20u);
    memcpy(buf + off + 4, mac, 20);
    off += mi_attr;

    wr_store_be16((uint8_t *)buf + 2, (uint16_t)(off - WR_STUN_HEADER_LEN + 8u));
    uint32_t fp = wr_crc32(0u, buf, off) ^ WR_STUN_MAGIC_COOKIE;
    wr_store_be16((uint8_t *)buf + off, WR_STUN_ATTR_FINGERPRINT);
    wr_store_be16((uint8_t *)buf + off + 2, 4u);
    wr_store_be32((uint8_t *)buf + off + 4, fp);
    off += 8u;
    wr_store_be16((uint8_t *)buf + 2, (uint16_t)(off - WR_STUN_HEADER_LEN));
    *out_len = off;
    return WR_OK;
}

wr_status wr_stun_append_fingerprint(wr_stun_msg *m, char *buf, size_t cap,
                                     size_t *out_len)
{
    size_t base_len = 0u;
    wr_status st = wr_stun_serialize(m, buf, cap, &base_len);
    if (st != WR_OK) {
        return st;
    }
    if (base_len + 8u > cap ||
        base_len - WR_STUN_HEADER_LEN + 8u > UINT16_MAX) {
        return WR_ERR_OVERFLOW;
    }
    uint32_t fp = wr_crc32(0u, buf, base_len) ^ WR_STUN_MAGIC_COOKIE;
    wr_store_be16((uint8_t *)buf + base_len, WR_STUN_ATTR_FINGERPRINT);
    wr_store_be16((uint8_t *)buf + base_len + 2, 4u);
    wr_store_be32((uint8_t *)buf + base_len + 4, fp);
    wr_store_be16((uint8_t *)buf + 2,
                  (uint16_t)(base_len - WR_STUN_HEADER_LEN + 8u));
    *out_len = base_len + 8u;
    return WR_OK;
}

bool wr_stun_verify_integrity(const wr_stun_msg *m, const uint8_t *key,
                              size_t key_len)
{
    if (!m || !key) {
        return false;
    }
    const wr_stun_attr *mi = wr_stun_attr_find(m, WR_STUN_ATTR_MESSAGE_INTEGRITY);
    if (!mi || mi->value.len != 20u) {
        return false;
    }
    size_t hlen = mi->offset;
    if (hlen < WR_STUN_HEADER_LEN || hlen > m->raw_len) {
        return false;
    }
    uint8_t stack[1500];
    uint8_t *heap = NULL;
    uint8_t *buf = stack;
    if (hlen > sizeof(stack)) {
        heap = (uint8_t *)malloc(hlen);
        if (!heap) {
            return false;
        }
        buf = heap;
    }
    memcpy(buf, m->raw.ptr, hlen);
    wr_store_be16(buf + 2, (uint16_t)(hlen - WR_STUN_HEADER_LEN + 24u));
    uint8_t mac[20];
    wr_crypto_hmac_sha1(key, key_len, wr_span_c_make(buf, hlen), mac);
    free(heap);
    uint8_t diff = 0u;
    for (size_t i = 0; i < 20u; ++i) {
        diff |= (uint8_t)(mac[i] ^ mi->value.ptr[i]);
    }
    return diff == 0u;
}

bool wr_stun_verify_fingerprint(const wr_stun_msg *m)
{
    if (!m) {
        return false;
    }
    const wr_stun_attr *fp = wr_stun_attr_find(m, WR_STUN_ATTR_FINGERPRINT);
    if (!fp || fp->value.len != 4u) {
        return false;
    }
    size_t off = fp->offset;
    if (off < WR_STUN_HEADER_LEN || off > m->raw_len) {
        return false;
    }
    uint8_t hdr[20];
    memcpy(hdr, m->raw.ptr, WR_STUN_HEADER_LEN);
    wr_store_be16(hdr + 2, (uint16_t)(off - WR_STUN_HEADER_LEN + 8u));
    uint8_t stack[1500];
    uint8_t *heap = NULL;
    uint8_t *buf = stack;
    if (off > sizeof(stack)) {
        heap = (uint8_t *)malloc(off);
        if (!heap) {
            return false;
        }
        buf = heap;
    }
    memcpy(buf, m->raw.ptr, off);
    memcpy(buf, hdr, WR_STUN_HEADER_LEN);
    uint32_t want = wr_crc32(0u, buf, off) ^ WR_STUN_MAGIC_COOKIE;
    free(heap);
    uint32_t got = wr_load_be32(fp->value.ptr);
    return want == got;
}

