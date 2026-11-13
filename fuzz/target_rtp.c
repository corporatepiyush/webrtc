#include "fuzz.h"

#include "wr/rtp.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_rtp_hdr h;
    (void)wr_rtp_parse(wr_span_c_make(data, size), &h);
    if (size >= 4u) {
        wr_rtcp_hdr pkts[8];
        size_t count = 0;
        (void)wr_rtcp_compound_parse(wr_span_c_make(data, size), 8, pkts,
                                     &count);
    }
    return 0;
}
