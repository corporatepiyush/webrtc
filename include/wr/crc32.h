#ifndef WR_CRC32_H
#define WR_CRC32_H

#include "wr/base.h"

/* IEEE 802.3 CRC-32 (same as zlib), used by STUN FINGERPRINT. */
uint32_t wr_crc32(uint32_t crc, const void *buf, size_t len);

#endif /* WR_CRC32_H */