#include "test_util.h"

void test_base(void);

int wr_test_failures;

int main(void)
{
    test_base();
    test_sdp();
    test_stun();
    test_ice();
    test_srtp();
    test_rtp();
    test_sctp();
    test_dtls();
    test_dtls_hs();
    test_dtls_dance();
    test_pc();
    test_turn();
    test_crypto();
    test_data();
    test_media();
#if defined(WR_MEDIA)
    test_media_codec();
#endif
    if (wr_test_failures) {
        fprintf(stderr, "%d test failure(s)\n", wr_test_failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}