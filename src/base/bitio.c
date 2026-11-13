#include "wr/bitio.h"

static bool rd_bits(wr_bitrd *r, unsigned n, uint32_t *out)
{
    if (n == 0u) {
        *out = 0;
        return true;
    }
    if (n > 32u || r->bit_pos > r->bit_len || r->bit_len - r->bit_pos < n) {
        r->overrun = true;
        return false;
    }
    uint32_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
        size_t bit = r->bit_pos + i;
        uint8_t byte = r->p[bit >> 3];
        v = (v << 1) | (uint32_t)((byte >> (7u - (bit & 7u))) & 1u);
    }
    r->bit_pos += n;
    *out = v;
    return true;
}

void wr_bitrd_init(wr_bitrd *r, wr_span_c s)
{
    r->p = s.ptr;
    r->bit_len = s.len * 8u;
    r->bit_pos = 0u;
    r->overrun = false;
}

bool wr_bitrd_u1(wr_bitrd *r, uint8_t *out)
{
    uint32_t v;
    if (!rd_bits(r, 1u, &v)) {
        return false;
    }
    *out = (uint8_t)v;
    return true;
}

bool wr_bitrd_u8(wr_bitrd *r, uint8_t *out)
{
    uint32_t v;
    if (!rd_bits(r, 8u, &v)) {
        return false;
    }
    *out = (uint8_t)v;
    return true;
}

bool wr_bitrd_u16(wr_bitrd *r, uint16_t *out)
{
    uint32_t v;
    if (!rd_bits(r, 16u, &v)) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

bool wr_bitrd_u24(wr_bitrd *r, uint32_t *out)
{
    uint32_t v;
    if (!rd_bits(r, 24u, &v)) {
        return false;
    }
    *out = v;
    return true;
}

bool wr_bitrd_u32(wr_bitrd *r, uint32_t *out)
{
    uint32_t v;
    if (!rd_bits(r, 32u, &v)) {
        return false;
    }
    *out = v;
    return true;
}

bool wr_bitrd_skip(wr_bitrd *r, size_t bits)
{
    if (bits > r->bit_len || r->bit_pos > r->bit_len - bits) {
        r->overrun = true;
        return false;
    }
    r->bit_pos += bits;
    return true;
}

bool wr_bitrd_align(wr_bitrd *r)
{
    size_t rem = (8u - (r->bit_pos & 7u)) & 7u;
    return wr_bitrd_skip(r, rem);
}

size_t wr_bitrd_left(const wr_bitrd *r)
{
    if (r->bit_pos >= r->bit_len) {
        return 0u;
    }
    return r->bit_len - r->bit_pos;
}

static bool wr_bits(wr_bitwr *w, uint32_t v, unsigned n)
{
    if (w->bit_pos > w->bit_cap || w->bit_cap - w->bit_pos < n) {
        w->overrun = true;
        return false;
    }
    for (unsigned i = 0; i < n; ++i) {
        size_t bit = w->bit_pos + i;
        uint8_t mask = (uint8_t)(1u << (7u - (bit & 7u)));
        if ((v >> (n - 1u - i)) & 1u) {
            w->p[bit >> 3] |= mask;
        } else {
            w->p[bit >> 3] &= (uint8_t)~mask;
        }
    }
    w->bit_pos += n;
    return true;
}

void wr_bitwr_init(wr_bitwr *w, wr_span s)
{
    w->p = s.ptr;
    w->bit_cap = s.len * 8u;
    w->bit_pos = 0u;
    w->overrun = false;
}

bool wr_bitwr_u1(wr_bitwr *w, uint8_t v)
{
    return wr_bits(w, v & 1u, 1u);
}

bool wr_bitwr_u8(wr_bitwr *w, uint8_t v)
{
    return wr_bits(w, v, 8u);
}

bool wr_bitwr_u16(wr_bitwr *w, uint16_t v)
{
    return wr_bits(w, v, 16u);
}

bool wr_bitwr_u24(wr_bitwr *w, uint32_t v)
{
    return wr_bits(w, v & 0xffffffu, 24u);
}

bool wr_bitwr_u32(wr_bitwr *w, uint32_t v)
{
    return wr_bits(w, v, 32u);
}

bool wr_bitwr_bytes(wr_bitwr *w, wr_span_c bytes)
{
    if (w->bit_pos & 7u) {
        return false;
    }
    size_t n = bytes.len;
    if (n > (w->bit_cap - w->bit_pos) / 8u) {
        w->overrun = true;
        return false;
    }
    memcpy(w->p + (w->bit_pos >> 3), bytes.ptr, n);
    w->bit_pos += n * 8u;
    return true;
}

bool wr_bitwr_align_zero(wr_bitwr *w)
{
    size_t rem = (8u - (w->bit_pos & 7u)) & 7u;
    return wr_bits(w, 0, (unsigned)rem);
}

size_t wr_bitwr_used(const wr_bitwr *w)
{
    return (w->bit_pos + 7u) >> 3;
}