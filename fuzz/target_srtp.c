#include "fuzz.h"

#include "wr/srtp.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12u) {
        return 0;
    }
    static uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                               9, 10, 11, 12, 13, 14, 15, 16 };
    static uint8_t salt[14] = { 1, 2, 3, 4, 5, 6, 7,
                                8, 9, 10, 11, 12, 13, 14 };
    wr_srtp_ctx c;
    if (wr_srtp_init(&c, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt,
                     wr_load_be32(data + 8)) != WR_OK) {
        return 0;
    }
    uint8_t out[2048];
    if (wr_srtp_protect(&c, wr_span_c_make(data, size),
                        wr_span_make(out, sizeof(out))) == WR_OK) {
        uint8_t back[2048];
        wr_srtp_ctx d;
        if (wr_srtp_init(&d, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt,
                         wr_load_be32(data + 8)) == WR_OK) {
            (void)wr_srtp_unprotect(&d, wr_span_c_make(out, size + 10),
                                    wr_span_make(back, sizeof(back)));
            wr_srtp_fini(&d);
        }
    }
    wr_srtp_fini(&c);
    return 0;
}
