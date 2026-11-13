#include "wr/stun.h"
#include "stun_internal.h"

#include <string.h>

uint16_t wr_stun_type(wr_stun_method method, wr_stun_class cls)
{
    uint32_t m = (uint32_t)method;
    uint32_t c = (uint32_t)cls;
    return (uint16_t)((m & 0x000fu) | ((m & 0x0070u) << 1) |
                      ((m & 0x0f80u) << 2) | ((c & 0x2u) << 7) |
                      ((c & 0x1u) << 4));
}

void wr_stun_type_decode(uint16_t type, wr_stun_method *method,
                         wr_stun_class *cls)
{
    if (method) {
        *method = (wr_stun_method)((type & 0x000fu) |
                                   ((type & 0x00e0u) >> 1) |
                                   ((type & 0x3e00u) >> 2));
    }
    if (cls) {
        *cls = (wr_stun_class)(((type & 0x0100u) >> 7) |
                               ((type & 0x0010u) >> 4));
    }
}

bool wr_stun_is_response(uint16_t type)
{
    wr_stun_class cls;
    wr_stun_type_decode(type, NULL, &cls);
    return cls == WR_STUN_CLASS_SUCCESS || cls == WR_STUN_CLASS_ERROR;
}

wr_status wr_stun_parse(wr_arena *a, wr_span_c raw, unsigned flags,
                        wr_stun_msg *out)
{
    if (WR_UNLIKELY(!a || !out || !raw.ptr ||
                    raw.len < WR_STUN_HEADER_LEN)) {
        return WR_ERR_TRUNCATED;
    }
    memset(out, 0, sizeof(*out));
    out->a = a;
    out->raw = raw;
    out->raw_len = raw.len;
    out->type = wr_load_be16(raw.ptr);
    uint16_t msg_len = wr_load_be16(raw.ptr + 2);
    if (WR_UNLIKELY(wr_load_be32(raw.ptr + 4) != WR_STUN_MAGIC_COOKIE)) {
        return WR_ERR_INVAL;
    }
    if ((size_t)msg_len != raw.len - WR_STUN_HEADER_LEN) {
        if ((flags & WR_STUN_LIBERAL) == 0u || (size_t)msg_len > raw.len - WR_STUN_HEADER_LEN) {
            return WR_ERR_TRUNCATED;
        }
    }
    memcpy(out->txid, raw.ptr + 8, 12);

    wr_stun_attr_vec_init(&out->attr, a);
    if (!out->attr.a) {
        return WR_ERR_NOMEM;
    }
    (void)wr_stun_attr_vec_reserve(&out->attr, 8u);

    size_t off = WR_STUN_HEADER_LEN;
    size_t end = WR_STUN_HEADER_LEN + (size_t)msg_len;
    if (end > raw.len) {
        end = raw.len;
    }
    while (off < end) {
        if (end - off < 4u) {
            if ((flags & WR_STUN_LIBERAL) != 0u) {
                break;
            }
            return WR_ERR_TRUNCATED;
        }
        wr_stun_attr at;
        at.type = wr_load_be16(raw.ptr + off);
        uint16_t alen = wr_load_be16(raw.ptr + off + 2);
        size_t total = 4u + (size_t)alen;
        if (alen > end - off - 4u) {
            if ((flags & WR_STUN_LIBERAL) != 0u) {
                break;
            }
            return WR_ERR_TRUNCATED;
        }
        at.offset = off;
        at.value = wr_span_c_sub(raw, off + 4u, alen);
        if ((flags & WR_STUN_LIBERAL) == 0u) {
            size_t pad = (4u - (alen & 3u)) & 3u;
            if (WR_UNLIKELY(off + 4u + alen + pad > end)) {
                return WR_ERR_TRUNCATED;
            }
            for (size_t i = 0; i < pad; ++i) {
                if (raw.ptr[off + 4u + alen + i] != 0u) {
                    return WR_ERR_INVAL;
                }
            }
        }
        if (!wr_stun_attr_vec_push(&out->attr, at)) {
            return WR_ERR_NOMEM;
        }
        off += total;
        off = (off + 3u) & ~(size_t)3u;
    }
    return WR_OK;
}

wr_status wr_stun_serialize(const wr_stun_msg *m, char *buf, size_t cap,
                            size_t *out_len)
{
    if (!m || !buf || !out_len || !m->a) {
        return WR_ERR_INVAL;
    }
    size_t alen = 0u;
    for (size_t i = 0; i < m->attr.len; ++i) {
        alen += stun_attr_padded(m->attr.data[i].value.len);
        if (alen > UINT16_MAX) {
            return WR_ERR_OVERFLOW;
        }
    }
    size_t total = WR_STUN_HEADER_LEN + alen;
    if (total > cap) {
        return WR_ERR_OVERFLOW;
    }
    wr_store_be16((uint8_t *)buf, m->type);
    wr_store_be16((uint8_t *)buf + 2, (uint16_t)alen);
    wr_store_be32((uint8_t *)buf + 4, WR_STUN_MAGIC_COOKIE);
    memcpy(buf + 8, m->txid, 12);
    size_t off = WR_STUN_HEADER_LEN;
    for (size_t i = 0; i < m->attr.len; ++i) {
        wr_span_c v = m->attr.data[i].value;
        wr_store_be16((uint8_t *)buf + off, m->attr.data[i].type);
        wr_store_be16((uint8_t *)buf + off + 2, (uint16_t)v.len);
        if (v.len) {
            memcpy(buf + off + 4, v.ptr, v.len);
        }
        size_t pad = (4u - (v.len & 3u)) & 3u;
        memset(buf + off + 4 + v.len, 0, pad);
        off += stun_attr_padded(v.len);
    }
    *out_len = total;
    return WR_OK;
}

const wr_stun_attr *wr_stun_attr_find(const wr_stun_msg *m, uint16_t type)
{
    if (!m) {
        return NULL;
    }
    for (size_t i = 0; i < m->attr.len; ++i) {
        if (m->attr.data[i].type == type) {
            return &m->attr.data[i];
        }
    }
    return NULL;
}

bool wr_stun_attr_add(wr_stun_msg *m, uint16_t type, wr_span_c value)
{
    if (!m || !m->a) {
        return false;
    }
    wr_stun_attr at;
    at.type = type;
    at.offset = 0u;
    at.value = value;
    return wr_stun_attr_vec_push(&m->attr, at);
}

void wr_stun_msg_init(wr_stun_msg *m, wr_arena *a, uint16_t type,
                      const uint8_t txid[12])
{
    if (!m) {
        return;
    }
    memset(m, 0, sizeof(*m));
    m->a = a;
    m->type = type;
    if (txid) {
        memcpy(m->txid, txid, 12);
    }
    if (a) {
        wr_stun_attr_vec_init(&m->attr, a);
        (void)wr_stun_attr_vec_reserve(&m->attr, 8u);
    }
}

wr_status wr_stun_build_binding_request(wr_stun_msg *m, wr_arena *a,
                                        uint64_t txid_hi, uint64_t txid_lo,
                                        wr_span_c username, uint64_t priority,
                                        bool controlling, bool use_candidate)
{
    uint8_t txid[12];
    wr_store_be64(txid, txid_hi);
    wr_store_be64(txid + 4, txid_lo);
    wr_stun_msg_init(m, a, wr_stun_type(WR_STUN_METHOD_BINDING,
                                        WR_STUN_CLASS_REQUEST),
                     txid);
    if (!m->a) {
        return WR_ERR_NOMEM;
    }
    if (username.ptr && username.len) {
        uint8_t *uname = (uint8_t *)wr_arena_alloc(m->a, username.len);
        if (!uname) {
            return WR_ERR_NOMEM;
        }
        memcpy(uname, username.ptr, username.len);
        if (!wr_stun_attr_add(m, WR_STUN_ATTR_USERNAME,
                              wr_span_c_make(uname, username.len))) {
            return WR_ERR_NOMEM;
        }
    }
    /* Attributes borrow their value spans, and the message outlives this
     * function. These values must therefore live in the message arena, not in
     * stack locals. */
    uint8_t *pri = (uint8_t *)wr_arena_alloc(m->a, 4u);
    if (!pri) {
        return WR_ERR_NOMEM;
    }
    wr_store_be32(pri, (uint32_t)priority);
    if (!wr_stun_attr_add(m, WR_STUN_ATTR_PRIORITY,
                          wr_span_c_make(pri, 4))) {
        return WR_ERR_NOMEM;
    }
    uint8_t *tie = (uint8_t *)wr_arena_alloc(m->a, 8u);
    if (!tie) {
        return WR_ERR_NOMEM;
    }
    wr_store_be64(tie, controlling ? (txid_lo | 1u) : txid_lo);
    if (!wr_stun_attr_add(m, controlling ? WR_STUN_ATTR_ICE_CONTROLLING
                                         : WR_STUN_ATTR_ICE_CONTROLLED,
                          wr_span_c_make(tie, 8))) {
        return WR_ERR_NOMEM;
    }
    if (use_candidate) {
        if (!wr_stun_attr_add(m, WR_STUN_ATTR_USE_CANDIDATE,
                              wr_span_c_make(NULL, 0))) {
            return WR_ERR_NOMEM;
        }
    }
    return WR_OK;
}

