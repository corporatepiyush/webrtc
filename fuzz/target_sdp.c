#include "fuzz.h"
#include "wr/sdp.h"

#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    if (!a) {
        return 0;
    }
    wr_sdp_session s;
    if (wr_sdp_parse(a, wr_span_c_make(data, size), WR_SDP_LIBERAL, &s) ==
        WR_OK) {
        size_t n = 0;
        (void)wr_sdp_serialize(&s, NULL, 0, &n);
        if (n > 0u && n < 512u * 1024u) {
            char *buf = (char *)malloc(n + 1u);
            if (buf) {
                if (wr_sdp_serialize(&s, buf, n + 1u, &n) == WR_OK) {
                    wr_sdp_session s2;
                    wr_arena *a2 = wr_arena_create(128u * 1024u);
                    if (a2 &&
                        wr_sdp_parse(a2, wr_span_c_make(buf, n),
                                     WR_SDP_LIBERAL, &s2) != WR_OK) {
                        /* Parse must accept its own serializer output. */
                        __builtin_trap();
                    }
                    wr_arena_destroy(a2);
                }
                free(buf);
            }
        }
    }
    wr_sdp_session strict;
    (void)wr_sdp_parse(a, wr_span_c_make(data, size), WR_SDP_STRICT, &strict);
    wr_arena_destroy(a);
    return 0;
}