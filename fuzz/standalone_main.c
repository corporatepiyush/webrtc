#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

static uint64_t rng_state = 0x123456789abcdef0ULL;

static uint64_t xorshift(void)
{
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    size_t cap = n > 0 ? (size_t)n : 1u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    *out_len = rd;
    return buf;
}

int main(int argc, char **argv)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)len);
    }
    return 0;
#else
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file> | --fuzz <seed-file> [iterations] [rng]\n",
                argv[0]);
        return 2;
    }
    bool fuzz_mode = strcmp(argv[1], "--fuzz") == 0;
    const char *path = fuzz_mode ? argv[2] : argv[1];
    if (!path) {
        return 2;
    }
    size_t rd = 0;
    uint8_t *buf = read_file(path, &rd);
    if (!buf) {
        perror("read");
        return 2;
    }
    size_t cap = rd ? rd : 1u;
    LLVMFuzzerTestOneInput(buf, rd);

    if (fuzz_mode) {
        unsigned long iters = (argc >= 4) ? strtoul(argv[3], NULL, 10) : 10000u;
        rng_state = (argc >= 5) ? (strtoull(argv[4], NULL, 0) | 1u)
                                : UINT64_C(0x123456789abcdef0);
        for (unsigned long i = 0; i < iters; ++i) {
            size_t len = rd;
            unsigned flips = 1u + (unsigned)(xorshift() & 3u);
            for (unsigned k = 0; k < flips; ++k) {
                size_t pos = (size_t)(xorshift() % (uint64_t)(len + 1u));
                if (pos == len) {
                    if (len < cap) {
                        buf[len] = (uint8_t)xorshift();
                        len++;
                    }
                } else {
                    buf[pos] ^= (uint8_t)(1u << (xorshift() & 7u));
                }
            }
            LLVMFuzzerTestOneInput(buf, len);
        }
    }
    free(buf);
    return 0;
#endif
}