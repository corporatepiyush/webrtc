#ifndef WR_TEST_UTIL_H
#define WR_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int wr_test_failures;
void test_base(void);
void test_sdp(void);
void test_stun(void);
void test_ice(void);
void test_srtp(void);
void test_rtp(void);
void test_sctp(void);
void test_dtls(void);
void test_dtls_hs(void);
void test_pc(void);
void test_turn(void);
void test_crypto(void);
void test_data(void);
void test_media(void);
void test_media_codec(void);

#define WR_TEST_CHECK(cond)                                                   \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            wr_test_failures++;                                               \
        }                                                                     \
    } while (0)

#define WR_TEST_EQ_U64(a, b)                                                  \
    do {                                                                      \
        unsigned long long _a = (unsigned long long)(a);                      \
        unsigned long long _b = (unsigned long long)(b);                      \
        if (_a != _b) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s (%llu) != %s (%llu)\n",           \
                    __FILE__, __LINE__, #a, _a, #b, _b);                      \
            wr_test_failures++;                                               \
        }                                                                     \
    } while (0)

#define WR_TEST_EQ_STR(a, b)                                                  \
    do {                                                                      \
        const char *_a = (a);                                                 \
        const char *_b = (b);                                                 \
        if (strcmp(_a, _b) != 0) {                                            \
            fprintf(stderr, "FAIL %s:%d: \"%s\" != \"%s\"\n",                 \
                    __FILE__, __LINE__, _a, _b);                              \
            wr_test_failures++;                                               \
        }                                                                     \
    } while (0)

#endif /* WR_TEST_UTIL_H */