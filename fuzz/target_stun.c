#include "fuzz.h"
#include "wr/stun.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    if (!a) {
        return 0;
    }
    wr_stun_msg m;
    if (wr_stun_parse(a, wr_span_c_make(data, size), WR_STUN_LIBERAL, &m) ==
        WR_OK) {
        (void)wr_stun_verify_fingerprint(&m);
        static const uint8_t key[16] = { 0 };
        (void)wr_stun_verify_integrity(&m, key, sizeof(key));

        char buf[2048];
        size_t n = 0;
        (void)wr_stun_serialize(&m, buf, sizeof(buf), &n);
        if (n > 0u && n <= sizeof(buf)) {
            wr_stun_msg m2;
            (void)wr_stun_parse(a, wr_span_c_make(buf, n), WR_STUN_LIBERAL, &m2);
        }
    }
    /* Strict mode exercises the padding checks that liberal mode skips. */
    wr_stun_msg strict;
    (void)wr_stun_parse(a, wr_span_c_make(data, size), WR_STUN_STRICT, &strict);
    wr_arena_destroy(a);
    return 0;
}