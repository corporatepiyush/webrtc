#ifndef WR_CRC32C_H
#define WR_CRC32C_H

#include "wr/base.h"

/* Castagnoli CRC-32c, polynomial 0x1EDC6F41 (reflected). */
uint32_t wr_crc32c(uint32_t crc, const void *buf, size_t len);
uint32_t wr_crc32c_span(uint32_t crc, wr_span_c s);
uint32_t wr_crc32c_hw_available(void);

#endif /* WR_CRC32C_H */