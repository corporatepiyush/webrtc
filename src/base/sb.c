#include "wr/sb.h"

void wr_sb_put_u64(wr_sb *s, uint64_t v)
{
    char tmp[20];
    char *end = tmp + sizeof(tmp);
    char *p = end;
    do {
        *--p = (char)('0' + (char)(v % 10u));
        v /= 10u;
    } while (v != 0u);
    wr_sb_put_n(s, p, (size_t)(end - p));
}

void wr_sb_put_ipv4(wr_sb *s, const uint8_t v4[4])
{
    if (!v4) {
        return;
    }
    char tmp[16];
    size_t n = 0u;
    for (size_t i = 0; i < 4u; ++i) {
        uint32_t v = v4[i];
        if (v >= 100u) {
            tmp[n++] = (char)('0' + (char)(v / 100u));
            v %= 100u;
            tmp[n++] = (char)('0' + (char)(v / 10u));
            tmp[n++] = (char)('0' + (char)(v % 10u));
        } else if (v >= 10u) {
            tmp[n++] = (char)('0' + (char)(v / 10u));
            tmp[n++] = (char)('0' + (char)(v % 10u));
        } else {
            tmp[n++] = (char)('0' + (char)v);
        }
        if (i != 3u) {
            tmp[n++] = '.';
        }
    }
    wr_sb_put_n(s, tmp, n);
}
