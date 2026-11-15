#include "test_util.h"

#include "wr/stun.h"
#include "wr/turn.h"

#include <openssl/evp.h>

/* Receive one STUN message from the fake TURN server socket. */
static bool recv_stun(wr_io *io, wr_arena *a, wr_stun_msg *out)
{
    uint8_t buf[512];
    for (int i = 0; i < 4; ++i) {
        bool ready = false;
        if (wr_io_wait(io, 5u, &ready) != WR_OK || !ready) {
            return false;
        }
        wr_endpoint from;
        wr_span data;
        if (wr_io_recv(io, &from, wr_span_make(buf, sizeof(buf)), &data) !=
            WR_OK) {
            return false;
        }
        if (wr_stun_parse(a, wr_span_upcast(data), WR_STUN_LIBERAL, out) ==
            WR_OK) {
            return true;
        }
    }
    return false;
}

/* RFC 8656 9.2.4: long-term credential key = MD5(user ":" realm ":" pass). */
static void turn_key(const char *user, const char *realm, const char *pass,
                     uint8_t key[16])
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%s:%s:%s", user, realm, pass);
    unsigned int md_len = 0u;
    if (n <= 0 || EVP_Digest(buf, (size_t)n, key, &md_len, EVP_md5(), NULL) != 1 ||
        md_len != 16u) {
        memset(key, 0, 16);
    }
}

static void test_channel_queue(void)
{
    wr_arena *a = wr_arena_create(64u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 11);
    wr_endpoint lo;
    wr_endpoint_loopback(&lo, 0u);
    wr_io *io = wr_io_udp_create(&lo, true);
    WR_TEST_CHECK(io != NULL);
    wr_endpoint server;
    wr_endpoint_loopback(&server, 3478u);
    wr_turn *t = wr_turn_create(a, rng, io, &server,
                                wr_span_c_from_str("user"),
                                wr_span_c_from_str("pass"));
    WR_TEST_CHECK(t != NULL);
    if (!t) {
        wr_io_destroy(io);
        wr_rng_destroy(rng);
        wr_arena_destroy(a);
        return;
    }

    char one[16];
    size_t one_n = 0u;
    WR_TEST_EQ_U64(wr_turn_channel_serialize(one, sizeof(one), 0x4000u,
                                             wr_span_c_from_str("one"),
                                             &one_n), WR_OK);
    char two[16];
    size_t two_n = 0u;
    WR_TEST_EQ_U64(wr_turn_channel_serialize(two, sizeof(two), 0x4000u,
                                             wr_span_c_from_str("two"),
                                             &two_n), WR_OK);
    WR_TEST_EQ_U64(wr_turn_input(t, 1u, wr_span_c_make(one, one_n)), WR_OK);
    WR_TEST_EQ_U64(wr_turn_input(t, 1u, wr_span_c_make(two, two_n)), WR_OK);
    wr_span_c out;
    WR_TEST_CHECK(wr_turn_recv(t, &out));
    WR_TEST_EQ_U64(out.len, 3u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "one", 3), 0);
    WR_TEST_CHECK(wr_turn_recv(t, &out));
    WR_TEST_EQ_U64(out.len, 3u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "two", 3), 0);
    WR_TEST_CHECK(!wr_turn_recv(t, &out));

    wr_turn_destroy(t);
    wr_io_destroy(io);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}

void test_turn(void)
{
    test_channel_queue();
    wr_arena *a = wr_arena_create(256u * 1024u);
    wr_rng *rng = wr_rng_create();
    wr_rng_seed(rng, 5);
    wr_endpoint loop;
    wr_endpoint_loopback(&loop, 0u);
    wr_io *io_a = wr_io_udp_create(&loop, true);
    wr_io *io_b = wr_io_udp_create(&loop, true);
    wr_endpoint ep_a, ep_b;
    WR_TEST_CHECK(io_a && io_b);
    WR_TEST_CHECK(wr_io_local_addr(io_a, &ep_a));
    WR_TEST_CHECK(wr_io_local_addr(io_b, &ep_b));

    wr_turn *t = wr_turn_create(a, rng, io_a, &ep_b,
                                wr_span_c_from_str("user"),
                                wr_span_c_from_str("pass"));
    WR_TEST_CHECK(t != NULL);
    if (!t) {
        return;
    }
    WR_TEST_EQ_U64(wr_turn_start(t, 0u), WR_OK);
    WR_TEST_EQ_U64(wr_turn_get_status(t), WR_TURN_ALLOCATING);

    /* The first Allocate carries no credentials: answer 401 with a realm and
     * nonce, echoing the transaction id the client actually chose. */
    wr_stun_msg req;
    WR_TEST_CHECK(recv_stun(io_b, a, &req));
    char resp[512];
    size_t rn = 0u;
    wr_stun_msg m;
    wr_stun_msg_init(&m, a, wr_stun_type(WR_STUN_METHOD_ALLOCATE,
                                         WR_STUN_CLASS_ERROR),
                     req.txid);
    uint8_t err[4] = { 0, 0, 4, 1 };
    (void)wr_stun_attr_add(&m, WR_STUN_ATTR_ERROR_CODE,
                           wr_span_c_make(err, 4u));
    (void)wr_stun_attr_add(&m, WR_STUN_ATTR_REALM,
                           wr_span_c_from_str("example.org"));
    (void)wr_stun_attr_add(&m, WR_STUN_ATTR_NONCE,
                           wr_span_c_from_str("nonce"));
    WR_TEST_EQ_U64(wr_stun_serialize(&m, resp, sizeof(resp), &rn), WR_OK);
    WR_TEST_EQ_U64(wr_turn_input(t, 1u, wr_span_c_make(resp, rn)), WR_OK);
    WR_TEST_EQ_U64(wr_turn_get_status(t), WR_TURN_AUTHENTICATING);

    /* Authenticated Allocate; the server answers with an integrity-protected
     * success carrying the relayed address. */
    WR_TEST_CHECK(recv_stun(io_b, a, &req));
    wr_stun_msg_init(&m, a, wr_stun_type(WR_STUN_METHOD_ALLOCATE,
                                         WR_STUN_CLASS_SUCCESS),
                     req.txid);
    uint8_t peer[32];
    size_t plen = 0u;
    wr_endpoint relayed_ep;
    wr_endpoint_v4(&relayed_ep, (const uint8_t[4]){ 198, 51, 100, 1 }, 3478);
    WR_TEST_CHECK(wr_stun_addr_encode(peer, sizeof(peer), &relayed_ep, true,
                                      req.txid, &plen));
    (void)wr_stun_addr_decode(wr_span_c_make(peer, plen), true, req.txid,
                              &relayed_ep);
    uint8_t life[4];
    wr_store_be32(life, 600u);
    (void)wr_stun_attr_add(&m, WR_STUN_ATTR_XOR_RELAYED_ADDRESS,
                           wr_span_c_make(peer, plen));
    (void)wr_stun_attr_add(&m, WR_STUN_ATTR_LIFETIME,
                           wr_span_c_make(life, 4u));
    uint8_t key[16];
    turn_key("user", "example.org", "pass", key);
    WR_TEST_EQ_U64(wr_stun_append_integrity(&m, key, sizeof(key), resp,
                                            sizeof(resp), &rn),
                   WR_OK);
    WR_TEST_EQ_U64(wr_turn_input(t, 2u, wr_span_c_make(resp, rn)), WR_OK);
    WR_TEST_EQ_U64(wr_turn_get_status(t), WR_TURN_ALLOCATED);
    const wr_endpoint *r = wr_turn_relayed(t);
    WR_TEST_CHECK(r != NULL);
    if (r) {
        WR_TEST_EQ_U64(r->port, 3478u);
        WR_TEST_EQ_U64(r->af, WR_AF_INET);
    }

    wr_endpoint peer_ep;
    wr_endpoint_v4(&peer_ep, (const uint8_t[4]){ 192, 0, 2, 9 }, 5000);
    WR_TEST_EQ_U64(wr_turn_connect(t, &peer_ep, 0x4000u), WR_OK);

    /* CreatePermission and ChannelBind share the transaction id. Answer both
     * with integrity-protected successes. */
    WR_TEST_CHECK(recv_stun(io_b, a, &req));
    wr_stun_msg_init(&m, a, wr_stun_type(WR_STUN_METHOD_CREATE_PERMISSION,
                                         WR_STUN_CLASS_SUCCESS),
                     req.txid);
    (void)wr_stun_append_integrity(&m, key, sizeof(key), resp, sizeof(resp),
                                   &rn);
    (void)wr_turn_input(t, 3u, wr_span_c_make(resp, rn));
    WR_TEST_CHECK(recv_stun(io_b, a, &req));
    wr_stun_msg_init(&m, a, wr_stun_type(WR_STUN_METHOD_CHANNEL_BIND,
                                         WR_STUN_CLASS_SUCCESS),
                     req.txid);
    (void)wr_stun_append_integrity(&m, key, sizeof(key), resp, sizeof(resp),
                                   &rn);
    (void)wr_turn_input(t, 3u, wr_span_c_make(resp, rn));

    /* An unauthenticated success for an authenticated request must be
     * rejected: a spoofed relayed address would otherwise be accepted. */
    wr_stun_msg_init(&m, a, wr_stun_type(WR_STUN_METHOD_REFRESH,
                                         WR_STUN_CLASS_SUCCESS),
                     req.txid);
    WR_TEST_EQ_U64(wr_stun_serialize(&m, resp, sizeof(resp), &rn), WR_OK);
    WR_TEST_EQ_U64(wr_turn_input(t, 4u, wr_span_c_make(resp, rn)),
                   WR_ERR_AUTH);

    WR_TEST_EQ_U64(wr_turn_send(t, wr_span_c_from_str("turn")), WR_OK);
    uint8_t buf[128];
    wr_endpoint from;
    wr_span data;
    bool ready = false;
    WR_TEST_EQ_U64(wr_io_wait(io_b, 10u, &ready), WR_OK);
    WR_TEST_CHECK(ready);
    WR_TEST_EQ_U64(wr_io_recv(io_b, &from, wr_span_make(buf, sizeof(buf)),
                              &data), WR_OK);
    uint16_t num = 0u;
    wr_span_c out;
    WR_TEST_EQ_U64(wr_turn_channel_parse(wr_span_upcast(data), &num, &out),
                   WR_OK);
    WR_TEST_EQ_U64(num, 0x4000u);
    WR_TEST_EQ_U64(out.len, 4u);
    WR_TEST_EQ_U64(memcmp(out.ptr, "turn", 4), 0);

    wr_turn_destroy(t);
    wr_io_destroy(io_a);
    wr_io_destroy(io_b);
    wr_rng_destroy(rng);
    wr_arena_destroy(a);
}