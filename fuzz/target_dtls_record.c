#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/dtls.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Cipher is shared between encrypt and decrypt, so init once. */
    wr_dtls_cipher c;
    memset(&c, 0, sizeof(c));
    size_t dlen = size ? size : 1u;
    for (size_t i = 0; i < sizeof(c.key); ++i) {
        uint8_t b = size ? data[i % dlen] : 0u;
        c.key[i] = (uint8_t)(b + i);
    }
    for (size_t i = 0; i < sizeof(c.salt); ++i) {
        uint8_t b = size ? data[(i + 5u) % dlen] : 0u;
        c.salt[i] = (uint8_t)(b ^ 0x5au);
    }
    if (!wr_dtls_cipher_init(&c)) {
        return 0;
    }

    /* Record parse/serialize round trip. */
    wr_dtls_record r;
    if (wr_dtls_record_parse(wr_span_c_make(data, size), &r) == WR_OK) {
        char buf[4096];
        size_t n = 0;
        if (wr_dtls_record_serialize(&r, buf, sizeof(buf), &n) == WR_OK) {
            wr_dtls_record r2;
            if (wr_dtls_record_parse(wr_span_c_make(buf, n), &r2) != WR_OK) {
                __builtin_trap();
            }
        }
    }

    /* Handshake parse/serialize. */
    wr_dtls_hs h;
    if (wr_dtls_hs_parse(wr_span_c_make(data, size), &h) == WR_OK) {
        char buf[4096];
        size_t n = 0;
        if (wr_dtls_hs_serialize(&h, buf, sizeof(buf), &n) == WR_OK) {
            wr_dtls_hs h2;
            if (wr_dtls_hs_parse(wr_span_c_make(buf, n), &h2) != WR_OK) {
                __builtin_trap();
            }
        }
    }

    /* Encrypt then decrypt; plaintext must survive byte-for-byte. */
    wr_fuzz_stream fs;
    wr_fuzz_stream_init(&fs, data, size);
    size_t plen = wr_fuzz_stream_below(&fs, 1024u);
    uint8_t plain[1024];
    for (size_t i = 0; i < plen; ++i) {
        plain[i] = wr_fuzz_stream_u8(&fs);
    }
    uint8_t seq[6];
    for (size_t i = 0; i < sizeof(seq); ++i) {
        seq[i] = wr_fuzz_stream_u8(&fs);
    }
    char rec[1200];
    size_t rec_n = 0;
    uint8_t type = (uint8_t)(wr_fuzz_stream_below(&fs, 4u) + 20u);
    uint16_t epoch = (uint16_t)wr_fuzz_stream_below(&fs, 4u);
    if (wr_dtls_encrypt(&c, type, epoch, seq, wr_span_c_make(plain, plen),
                        rec, sizeof(rec), &rec_n) == WR_OK) {
        uint8_t back[1024];
        wr_span back_s = wr_span_make(back, sizeof(back));
        wr_dtls_record meta;
        if (wr_dtls_decrypt(&c, wr_span_c_make(rec, rec_n), &back_s, &meta) !=
            WR_OK) {
            __builtin_trap();
        }
        if (back_s.len != plen || memcmp(back, plain, plen) != 0) {
            __builtin_trap();
        }
        /* Tampering with any ciphertext byte must fail authentication. */
        if (rec_n > 0u) {
            char bad[1200];
            memcpy(bad, rec, rec_n);
            bad[rec_n / 2u] ^= 0x01u;
            uint8_t sink[1024];
            wr_span sink_s = wr_span_make(sink, sizeof(sink));
            if (wr_dtls_decrypt(&c, wr_span_c_make(bad, rec_n), &sink_s,
                                &meta) == WR_OK) {
                __builtin_trap();
            }
        }
    }

    /* Arbitrary records must be rejected, never crash. */
    {
        uint8_t out[2048];
        wr_span os = wr_span_make(out, sizeof(out));
        wr_dtls_record meta;
        (void)wr_dtls_decrypt(&c, wr_span_c_make(data, size), &os, &meta);
    }

    wr_dtls_cipher_free(&c);
    return 0;
}