#include "fuzz.h"

#include "wr/dtls.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wr_dtls_record r;
    if (wr_dtls_record_parse(wr_span_c_make(data, size), &r) == WR_OK) {
        static uint8_t key[16] = { 1 };
        static uint8_t salt[4] = { 2, 3, 4, 5 };
        wr_dtls_cipher c;
        memset(&c, 0, sizeof(c));
        for (int i = 0; i < 16; ++i) c.key[i] = key[i];
        for (int i = 0; i < 4; ++i) c.salt[i] = salt[i];
        uint8_t out[2048];
        wr_span os = wr_span_make(out, sizeof(out));
        wr_dtls_record meta;
        (void)wr_dtls_decrypt(&c, wr_span_c_make(data, size), &os, &meta);
        char buf[2048];
        size_t n = 0;
        (void)wr_dtls_encrypt(&c, WR_DTLS_APPDATA, 0, r.seq,
                              wr_span_c_make(out, 0), buf, sizeof(buf), &n);
    }
    wr_dtls_hs h;
    (void)wr_dtls_hs_parse(wr_span_c_make(data, size), &h);
    return 0;
}
