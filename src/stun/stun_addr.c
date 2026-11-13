#include "wr/stun.h"

#include <string.h>

bool wr_stun_addr_encode(uint8_t *out, size_t cap, const wr_endpoint *e,
                         bool xor_addr, const uint8_t txid[12],
                         size_t *out_len)
{
    if (!out || !e || !txid) {
        return false;
    }
    size_t alen = e->af == WR_AF_INET ? 8u : 20u;
    if (cap < alen) {
        return false;
    }
    memset(out, 0, alen);
    out[1] = e->af == WR_AF_INET ? 0x01 : 0x02;
    uint16_t port = e->port;
    uint32_t cookie = WR_STUN_MAGIC_COOKIE;
    if (xor_addr) {
        port = (uint16_t)(port ^ (cookie >> 16));
    }
    wr_store_be16(out + 2, port);
    if (e->af == WR_AF_INET) {
        uint32_t x = wr_load_be32(e->ip.b.v4);
        if (xor_addr) {
            x ^= cookie;
        }
        wr_store_be32(out + 4, x);
    } else {
        for (size_t i = 0; i < 16; ++i) {
            out[4 + i] = e->ip.b.v6[i];
        }
        if (xor_addr) {
            uint8_t mask[16];
            wr_store_be32(mask, cookie);
            memcpy(mask + 4, txid, 12);
            for (size_t i = 0; i < 16; ++i) {
                out[4 + i] ^= mask[i];
            }
        }
    }
    if (out_len) {
        *out_len = alen;
    }
    return true;
}

bool wr_stun_addr_decode(wr_span_c v, bool xor_addr, const uint8_t txid[12],
                         wr_endpoint *out)
{
    if (!v.ptr || v.len < 4u || !out || !txid) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    uint8_t family = v.ptr[1];
    uint16_t port = wr_load_be16(v.ptr + 2);
    uint32_t cookie = WR_STUN_MAGIC_COOKIE;
    if (xor_addr) {
        port = (uint16_t)(port ^ (cookie >> 16));
    }
    out->port = port;
    if (family == 0x01) {
        if (v.len < 8u) {
            return false;
        }
        uint32_t x = wr_load_be32(v.ptr + 4);
        if (xor_addr) {
            x ^= cookie;
        }
        wr_store_be32(out->ip.b.v4, x);
        out->af = WR_AF_INET;
        return true;
    }
    if (family == 0x02) {
        if (v.len < 20u) {
            return false;
        }
        for (size_t i = 0; i < 16; ++i) {
            out->ip.b.v6[i] = v.ptr[4 + i];
        }
        if (xor_addr) {
            uint8_t mask[16];
            wr_store_be32(mask, cookie);
            memcpy(mask + 4, txid, 12);
            for (size_t i = 0; i < 16; ++i) {
                out->ip.b.v6[i] ^= mask[i];
            }
        }
        out->af = WR_AF_INET6;
        return true;
    }
    return false;
}

