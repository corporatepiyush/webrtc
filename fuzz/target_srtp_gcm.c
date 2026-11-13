#include "fuzz.h"
#include "fuzz_util.h"
#include "wr/srtp.h"

#include <string.h>

static void run_profile(const uint8_t *data, size_t size, uint32_t ssrc,
                        wr_srtp_profile profile, const uint8_t *key,
                        const uint8_t *salt)
{
    wr_srtp_ctx c;
    if (wr_srtp_init(&c, profile, key, salt, ssrc) != WR_OK) {
        return;
    }
    if (size < 12u || (data[0] >> 6) != 2u) {
        wr_srtp_fini(&c);
        return;
    }

    uint8_t out[4096];
    size_t tag_len = profile == WR_SRTP_AES_GCM_128 ? 16u : 10u;
    wr_span out_s = wr_span_make(out, sizeof(out));
    if (wr_srtp_protect(&c, wr_span_c_make(data, size), out_s) != WR_OK) {
        wr_srtp_fini(&c);
        return;
    }
    size_t out_len = size + tag_len;

    wr_srtp_ctx d;
    if (wr_srtp_init(&d, profile, key, salt, ssrc) != WR_OK) {
        wr_srtp_fini(&c);
        return;
    }
    uint8_t back[4096];
    if (wr_srtp_unprotect(&d, wr_span_c_make(out, out_len),
                          wr_span_make(back, sizeof(back))) != WR_OK) {
        __builtin_trap();
    }
    if (memcmp(back, data, size) != 0) {
        __builtin_trap();
    }
    /* Same index twice is a replay. */
    uint8_t back2[4096];
    if (wr_srtp_unprotect(&d, wr_span_c_make(out, out_len),
                          wr_span_make(back2, sizeof(back2))) == WR_OK) {
        __builtin_trap();
    }
    (void)wr_srtp_get_roc(&d);
    wr_srtp_set_roc(&d, 7u);
    if (wr_srtp_get_roc(&d) != 7u) {
        __builtin_trap();
    }
    wr_srtp_fini(&d);

    /* Arbitrary unprotect must be rejected, never crash. */
    wr_srtp_ctx x;
    if (wr_srtp_init(&x, profile, key, salt, ssrc) == WR_OK) {
        uint8_t sink[4096];
        (void)wr_srtp_unprotect(&x, wr_span_c_make(data, size),
                                wr_span_make(sink, sizeof(sink)));
        wr_srtp_fini(&x);
    }
    wr_srtp_fini(&c);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t key[16];
    uint8_t salt[14];
    size_t dlen = size ? size : 1u;
    for (size_t i = 0; i < sizeof(key); ++i) {
        uint8_t b = size ? data[i % dlen] : 0u;
        key[i] = (uint8_t)(b + i * 7u);
    }
    for (size_t i = 0; i < sizeof(salt); ++i) {
        uint8_t b = size ? data[(i + 3u) % dlen] : 0u;
        salt[i] = (uint8_t)(b + i * 13u);
    }
    uint32_t ssrc = size >= 4u ? wr_load_be32(data) : 0x12345678u;
    run_profile(data, size, ssrc, WR_SRTP_AES_CM_128_HMAC_SHA1_80, key, salt);
    run_profile(data, size, ssrc, WR_SRTP_AES_GCM_128, key, salt);
    return 0;
}