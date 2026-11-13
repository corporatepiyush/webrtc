#ifndef WR_BITIO_H
#define WR_BITIO_H

#include "wr/base.h"

/* MSB-first bit reader over a non-owning span. */
typedef struct {
    const uint8_t *p;
    size_t bit_len;
    size_t bit_pos;
    bool overrun;
} wr_bitrd;

void wr_bitrd_init(wr_bitrd *r, wr_span_c s);
bool wr_bitrd_u1(wr_bitrd *r, uint8_t *out);
bool wr_bitrd_u8(wr_bitrd *r, uint8_t *out);
bool wr_bitrd_u16(wr_bitrd *r, uint16_t *out);
bool wr_bitrd_u24(wr_bitrd *r, uint32_t *out);
bool wr_bitrd_u32(wr_bitrd *r, uint32_t *out);
bool wr_bitrd_skip(wr_bitrd *r, size_t bits);
bool wr_bitrd_align(wr_bitrd *r);
size_t wr_bitrd_left(const wr_bitrd *r);

/* MSB-first bit writer over a fixed buffer. */
typedef struct {
    uint8_t *p;
    size_t bit_cap;
    size_t bit_pos;
    bool overrun;
} wr_bitwr;

void wr_bitwr_init(wr_bitwr *w, wr_span s);
bool wr_bitwr_u1(wr_bitwr *w, uint8_t v);
bool wr_bitwr_u8(wr_bitwr *w, uint8_t v);
bool wr_bitwr_u16(wr_bitwr *w, uint16_t v);
bool wr_bitwr_u24(wr_bitwr *w, uint32_t v);
bool wr_bitwr_u32(wr_bitwr *w, uint32_t v);
bool wr_bitwr_bytes(wr_bitwr *w, wr_span_c bytes);
bool wr_bitwr_align_zero(wr_bitwr *w);
size_t wr_bitwr_used(const wr_bitwr *w);

#endif /* WR_BITIO_H */