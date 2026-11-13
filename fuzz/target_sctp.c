#include "fuzz.h"

#include "wr/arena.h"
#include "wr/sctp.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    if (!a) {
        return 0;
    }
    wr_sctp_msg m;
    (void)wr_sctp_parse(a, wr_span_c_make(data, size), &m);
    wr_arena_destroy(a);
    return 0;
}
