#include "fuzz.h"

#include "wr/arena.h"
#include "wr/rng.h"
#include "wr/sctp.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_arena *a = wr_arena_create(128u * 1024u);
    if (!a) {
        return 0;
    }
    wr_rng *rng = wr_rng_create();
    if (!rng) {
        wr_arena_destroy(a);
        return 0;
    }
    wr_sctp_assoc *as = wr_sctp_create(a, 1000u, 2000u, rng);
    if (!as) {
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return 0;
    }
    wr_sctp_start_established(as, 0x1000u, 0x2000u, 0x2000u);

    /* Raw fuzz: must be rejected by CRC or length checks. */
    (void)wr_sctp_input(as, 0u, wr_span_c_make(data, size));

    /* Structured DATA: build a valid packet from the tail of the input. */
    if (size >= 8u) {
        uint32_t tsn = 0x2001u + ((uint32_t)data[0] << 8 | data[1]) % 64u;
        uint16_t stream = (uint16_t)(data[2] | (data[3] << 8));
        uint32_t ppid = 50u;
        wr_span_c payload = wr_span_c_make(data + 4u, size - 4u);
        char body[1024];
        size_t blen = 0u;
        if (wr_sctp_data_body(tsn, stream, 0u, ppid, payload, body,
                              sizeof(body), &blen) == WR_OK) {
            char chunk[1088];
            size_t clen = 0u;
            if (wr_sctp_chunk_serialize(WR_SCTP_DATA, 0x03u,
                                        wr_span_c_make(body, blen), chunk,
                                        sizeof(chunk), &clen) == WR_OK) {
                wr_sctp_packet pkt;
                memset(&pkt, 0, sizeof(pkt));
                pkt.src_port = 2000u;
                pkt.dst_port = 1000u;
                pkt.vtag = 0x1000u;
                char raw[1152];
                size_t raw_len = 0u;
                if (wr_sctp_serialize(&pkt, wr_span_c_make(chunk, clen), raw,
                                      sizeof(raw), &raw_len) == WR_OK) {
                    (void)wr_sctp_input(as, 0u,
                                        wr_span_c_make(raw, raw_len));
                }
            }
        }
    }

    wr_sctp_delivery d;
    while (wr_sctp_recv(as, &d)) {
        /* Touch the delivery so the payload is observable to the fuzzer. */
        if (d.data.len > 0u && d.data.ptr[0] == 0xffu) {
            break;
        }
    }
    (void)wr_sctp_step(as, 1000u);
    (void)wr_sctp_last_ack(as);

    wr_sctp_close(as);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
    return 0;
}