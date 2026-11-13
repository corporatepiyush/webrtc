#ifndef WR_STUN_INTERNAL_H
#define WR_STUN_INTERNAL_H

#include "wr/stun.h"

static inline size_t stun_attr_padded(size_t len)
{
    return 4u + ((len + 3u) & ~(size_t)3u);
}

#endif /* WR_STUN_INTERNAL_H */
