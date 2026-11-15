#include "wr/turn.h"

#include "wr/stun.h"

#include <openssl/evp.h>

#include <string.h>

#define WR_TURN_LIFETIME 600u

static wr_stun_attr sattr(uint16_t type, wr_span_c value)
{
    wr_stun_attr a;
    memset(&a, 0, sizeof(a));
    a.type = type;
    a.value = value;
    return a;
}

struct wr_turn {
    wr_arena *a;
    wr_rng *rng;
    wr_io *io;
    wr_endpoint server;
    char user[64];
    char pass[64];
    wr_turn_status state;
    uint8_t txid[12];
    bool key_set;

    uint8_t realm[128];
    size_t realm_len;
    uint8_t nonce[128];
    size_t nonce_len;
    uint8_t key[16];

    wr_endpoint relayed;
    uint16_t channel;
    wr_endpoint peer;
    bool has_peer;
    bool channel_bound;
    bool permission_sent;
    uint64_t refresh_at_ms;
    uint64_t permission_at_ms;

    /* Outstanding request, for retransmission and response matching. */
    wr_stun_method pending_method;
    bool pending_auth;
    uint64_t pending_sent_ms;
    uint8_t pending_retx;
    bool pending_active;

    uint8_t queue[2048];
    size_t queue_len;
    size_t queue_off;
};

/* TURN permissions last 300 s by default; refresh well before expiry.
 * (RFC 8656 7.2: CreatePermission allocations default to 300 s.) */
#define WR_TURN_PERMISSION_LIFETIME 300u
#define WR_TURN_RETX_BASE_MS        500u
#define WR_TURN_MAX_RETX            5u

static void long_term_key(wr_turn *t)
{
    char buf[320];
    int n = snprintf(buf, sizeof(buf), "%s:%.*s:%s", t->user,
                     (int)t->realm_len, (const char *)t->realm, t->pass);
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        return;
    }
    unsigned int md_len = 0u;
    if (EVP_Digest(buf, (size_t)n, t->key, &md_len, EVP_md5(), NULL) == 1 &&
        md_len == 16u) {
        t->key_set = true;
        return;
    }
    memset(t->key, 0, sizeof(t->key));
    t->key_set = false;
}

static wr_status send_stun(wr_turn *t, uint16_t type, bool integrity,
                           const wr_stun_attr *attrs, size_t nattrs)
{
    wr_stun_msg m;
    wr_stun_msg_init(&m, t->a, type, t->txid);
    for (size_t i = 0; i < nattrs; ++i) {
        if (!wr_stun_attr_add(&m, attrs[i].type, attrs[i].value)) {
            return WR_ERR_NOMEM;
        }
    }
    char buf[512];
    size_t n = 0u;
    wr_status st = integrity && t->key_set
                       ? wr_stun_append_integrity(&m, t->key, sizeof(t->key),
                                                  buf, sizeof(buf), &n)
                       : wr_stun_serialize(&m, buf, sizeof(buf), &n);
    if (st != WR_OK) {
        return st;
    }
    size_t sent = 0u;
    st = wr_io_send(t->io, &t->server, wr_span_c_make(buf, n), &sent);
    if (st == WR_OK) {
        /* Remember what is outstanding so step() can retransmit it and
         * input() can tell a late response from a spoofed one. The timer
         * starts on the next step, which is the first moment a clock is
         * available. */
        wr_stun_class cls = WR_STUN_CLASS_REQUEST;
        wr_stun_type_decode(type, &t->pending_method, &cls);
        t->pending_auth = integrity;
        t->pending_active = true;
        t->pending_sent_ms = 0u;
        t->pending_retx = 0u;
    }
    return st;
}

static wr_status send_allocate(wr_turn *t, bool auth, uint64_t now_ms)
{
    (void)now_ms;
    if (wr_rng_fill(t->rng, t->txid, sizeof(t->txid)) != WR_OK) {
        return WR_ERR_STATE;
    }
    wr_stun_attr attrs[8];
    size_t n = 0u;
    uint8_t transport[4] = { 0, 0, 0, 17u };
    uint8_t lifetime[4];
    wr_store_be32(lifetime, WR_TURN_LIFETIME);
    attrs[n++] = sattr(WR_STUN_ATTR_REQUESTED_TRANSPORT,
                       wr_span_c_make(transport, 4u));
    attrs[n++] = sattr(WR_STUN_ATTR_LIFETIME,
                       wr_span_c_make(lifetime, 4u));
    if (auth) {
        attrs[n++] = sattr(WR_STUN_ATTR_USERNAME,
                           wr_span_c_from_str(t->user));
        attrs[n++] = sattr(WR_STUN_ATTR_REALM,
                           wr_span_c_make(t->realm, t->realm_len));
        attrs[n++] = sattr(WR_STUN_ATTR_NONCE,
                           wr_span_c_make(t->nonce, t->nonce_len));
    }
    t->state = auth ? WR_TURN_AUTHENTICATING : WR_TURN_ALLOCATING;
    return send_stun(t, wr_stun_type(WR_STUN_METHOD_ALLOCATE,
                                     WR_STUN_CLASS_REQUEST),
                     auth, attrs, n);
}

wr_turn *wr_turn_create(wr_arena *a, wr_rng *rng, wr_io *io,
                        const wr_endpoint *server, wr_span_c username,
                        wr_span_c password)
{
    if (!a || !io || !server) {
        return NULL;
    }
    wr_turn *t = (wr_turn *)wr_arena_calloc(a, 1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    t->a = a;
    t->rng = rng;
    t->io = io;
    t->server = *server;
    t->state = WR_TURN_NEW;
    if (username.ptr && username.len < sizeof(t->user)) {
        memcpy(t->user, username.ptr, username.len);
        t->user[username.len] = '\0';
    }
    if (password.ptr && password.len < sizeof(t->pass)) {
        memcpy(t->pass, password.ptr, password.len);
        t->pass[password.len] = '\0';
    }
    return t;
}

void wr_turn_destroy(wr_turn *t)
{
    if (!t) {
        return;
    }
    wr_secure_zero(t->key, sizeof(t->key));
    wr_secure_zero(t->pass, sizeof(t->pass));
    memset(t, 0, sizeof(*t));
}

wr_status wr_turn_start(wr_turn *t, uint64_t now_ms)
{
    if (!t || t->state != WR_TURN_NEW) {
        return WR_ERR_STATE;
    }
    return send_allocate(t, false, now_ms);
}

static bool parse_error(wr_turn *t, const wr_stun_msg *m)
{
    const wr_stun_attr *realm = wr_stun_attr_find(m, WR_STUN_ATTR_REALM);
    const wr_stun_attr *nonce = wr_stun_attr_find(m, WR_STUN_ATTR_NONCE);
    if (!realm || !nonce || realm->value.len >= sizeof(t->realm) ||
        nonce->value.len >= sizeof(t->nonce)) {
        return false;
    }
    memcpy(t->realm, realm->value.ptr, realm->value.len);
    t->realm_len = realm->value.len;
    memcpy(t->nonce, nonce->value.ptr, nonce->value.len);
    t->nonce_len = nonce->value.len;
    long_term_key(t);
    return true;
}

static void handle_allocate_success(wr_turn *t, const wr_stun_msg *m,
                                    uint64_t now_ms)
{
    const wr_stun_attr *relayed = wr_stun_attr_find(m,
                                                    WR_STUN_ATTR_XOR_RELAYED_ADDRESS);
    const wr_stun_attr *mapped = wr_stun_attr_find(m,
                                                   WR_STUN_ATTR_XOR_MAPPED_ADDRESS);
    const wr_stun_attr *life = wr_stun_attr_find(m, WR_STUN_ATTR_LIFETIME);
    wr_endpoint e;
    if (relayed && wr_stun_addr_decode(relayed->value, true, m->txid, &e)) {
        t->relayed = e;
    }
    (void)mapped;
    uint32_t lifetime = WR_TURN_LIFETIME;
    if (life && life->value.len >= 4u) {
        lifetime = wr_load_be32(life->value.ptr);
    }
    t->refresh_at_ms = now_ms + (uint64_t)lifetime * 800u;
    t->state = WR_TURN_ALLOCATED;
}

static wr_status send_refresh(wr_turn *t, uint64_t now_ms)
{
    (void)now_ms;
    uint8_t lifetime[4];
    wr_store_be32(lifetime, WR_TURN_LIFETIME);
    wr_stun_attr all[3];
    all[0] = sattr(WR_STUN_ATTR_LIFETIME, wr_span_c_make(lifetime, 4u));
    all[1] = sattr(WR_STUN_ATTR_REALM,
                   wr_span_c_make(t->realm, t->realm_len));
    all[2] = sattr(WR_STUN_ATTR_NONCE,
                   wr_span_c_make(t->nonce, t->nonce_len));
    return send_stun(t, wr_stun_type(WR_STUN_METHOD_REFRESH,
                                     WR_STUN_CLASS_REQUEST),
                     true, all, 3u);
}

static wr_status send_create_permission(wr_turn *t)
{
    uint8_t peer[32];
    size_t plen = 0u;
    if (!wr_stun_addr_encode(peer, sizeof(peer), &t->peer, true, t->txid,
                             &plen)) {
        return WR_ERR_INVAL;
    }
    wr_stun_attr all[4];
    all[0] = sattr(WR_STUN_ATTR_XOR_PEER_ADDRESS,
                   wr_span_c_make(peer, plen));
    all[1] = sattr(WR_STUN_ATTR_USERNAME, wr_span_c_from_str(t->user));
    all[2] = sattr(WR_STUN_ATTR_REALM,
                   wr_span_c_make(t->realm, t->realm_len));
    all[3] = sattr(WR_STUN_ATTR_NONCE,
                   wr_span_c_make(t->nonce, t->nonce_len));
    t->permission_sent = true;
    return send_stun(t, wr_stun_type(WR_STUN_METHOD_CREATE_PERMISSION,
                                     WR_STUN_CLASS_REQUEST),
                     true, all, 4u);
}

static wr_status send_channel_bind(wr_turn *t)
{
    uint8_t peer[32];
    size_t plen = 0u;
    if (!wr_stun_addr_encode(peer, sizeof(peer), &t->peer, true, t->txid,
                             &plen)) {
        return WR_ERR_INVAL;
    }
    uint8_t ch[4] = { (uint8_t)(t->channel >> 8), (uint8_t)t->channel, 0, 0 };
    wr_stun_attr all[5];
    all[0] = sattr(WR_STUN_ATTR_CHANNEL_NUMBER, wr_span_c_make(ch, 4u));
    all[1] = sattr(WR_STUN_ATTR_XOR_PEER_ADDRESS,
                   wr_span_c_make(peer, plen));
    all[2] = sattr(WR_STUN_ATTR_USERNAME, wr_span_c_from_str(t->user));
    all[3] = sattr(WR_STUN_ATTR_REALM,
                   wr_span_c_make(t->realm, t->realm_len));
    all[4] = sattr(WR_STUN_ATTR_NONCE,
                   wr_span_c_make(t->nonce, t->nonce_len));
    return send_stun(t, wr_stun_type(WR_STUN_METHOD_CHANNEL_BIND,
                                     WR_STUN_CLASS_REQUEST),
                     true, all, 5u);
}

wr_status wr_turn_connect(wr_turn *t, const wr_endpoint *peer,
                          uint16_t channel)
{
    if (!t || !peer || t->state != WR_TURN_ALLOCATED ||
        channel < 0x4000u || channel > 0x7fffu) {
        return WR_ERR_STATE;
    }
    t->peer = *peer;
    t->channel = channel;
    t->has_peer = true;
    t->permission_at_ms = 0u;
    wr_status st = send_create_permission(t);
    if (st != WR_OK) {
        return st;
    }
    return send_channel_bind(t);
}

wr_status wr_turn_send(wr_turn *t, wr_span_c data)
{
    if (!t || !data.ptr || t->state != WR_TURN_ALLOCATED ||
        !t->has_peer || !t->channel_bound) {
        return WR_ERR_STATE;
    }
    char buf[2048];
    size_t n = 0u;
    if (wr_turn_channel_serialize(buf, sizeof(buf), t->channel, data, &n) !=
        WR_OK) {
        return WR_ERR_OVERFLOW;
    }
    size_t sent = 0u;
    return wr_io_send(t->io, &t->server, wr_span_c_make(buf, n), &sent);
}

bool wr_turn_recv(wr_turn *t, wr_span_c *out)
{
    if (!t || !out) {
        return false;
    }
    if (t->queue_off >= t->queue_len) {
        t->queue_off = t->queue_len = 0u;
        return false;
    }
    uint16_t num = 0u;
    wr_span_c data;
    if (wr_turn_channel_parse(wr_span_c_make(t->queue + t->queue_off,
                                             t->queue_len - t->queue_off),
                              &num, &data) != WR_OK) {
        t->queue_off = t->queue_len = 0u;
        return false;
    }
    out->ptr = data.ptr;
    out->len = data.len;
    t->queue_off += 4u + ((data.len + 3u) & ~(size_t)3u);
    if (t->queue_off >= t->queue_len) {
        t->queue_off = t->queue_len = 0u;
    }
    return true;
}

wr_status wr_turn_input(wr_turn *t, uint64_t now_ms, wr_span_c pkt)
{
    if (!t || !pkt.ptr || pkt.len < 4u) {
        return WR_ERR_INVAL;
    }
    uint16_t first = wr_load_be16(pkt.ptr);
    if (first >= 0x4000u && first <= 0x7fffu) {
        uint16_t num = 0u;
        wr_span_c data;
        if (wr_turn_channel_parse(pkt, &num, &data) != WR_OK) {
            return WR_ERR_TRUNCATED;
        }
        size_t total = 4u + ((data.len + 3u) & ~(size_t)3u);
        if (total > pkt.len) {
            return WR_ERR_TRUNCATED;
        }
        if (t->queue_off == t->queue_len) {
            t->queue_off = t->queue_len = 0u;
        } else if (t->queue_off > 0u &&
                   t->queue_len + total > sizeof(t->queue)) {
            memmove(t->queue, t->queue + t->queue_off,
                    t->queue_len - t->queue_off);
            t->queue_len -= t->queue_off;
            t->queue_off = 0u;
        }
        if (t->queue_len + total > sizeof(t->queue)) {
            return WR_ERR_OVERFLOW;
        }
        memcpy(t->queue + t->queue_len, pkt.ptr, total);
        t->queue_len += total;
        return WR_OK;
    }

    wr_stun_msg m;
    if (wr_stun_parse(t->a, pkt, WR_STUN_LIBERAL, &m) != WR_OK) {
        return WR_ERR_TRUNCATED;
    }
    wr_stun_method method = WR_STUN_METHOD_BINDING;
    wr_stun_class cls = WR_STUN_CLASS_REQUEST;
    wr_stun_type_decode(m.type, &method, &cls);
    /* A response is only meaningful for the request we actually sent: bind it
     * to the outstanding transaction id. */
    if (cls != WR_STUN_CLASS_REQUEST &&
        memcmp(m.txid, t->txid, sizeof(t->txid)) != 0) {
        return WR_OK;
    }
    if (cls == WR_STUN_CLASS_ERROR) {
        const wr_stun_attr *code = wr_stun_attr_find(&m, WR_STUN_ATTR_ERROR_CODE);
        uint32_t ec = code && code->value.len >= 4u
                          ? ((uint32_t)(code->value.ptr[2] & 0x07u) * 100u +
                             (uint32_t)code->value.ptr[3])
                          : 0u;
        if (ec == 401u || ec == 438u) {
            if (!parse_error(t, &m)) {
                t->state = WR_TURN_FAILED;
                return WR_ERR_AUTH;
            }
            return send_allocate(t, true, now_ms);
        }
        t->state = WR_TURN_FAILED;
        return WR_ERR_STATE;
    }
    if (cls != WR_STUN_CLASS_SUCCESS) {
        return WR_OK;
    }
    /* Once long-term credentials are in play the server must protect its
     * responses; an unauthenticated Allocate success (a relayed address) would
     * let an off-path attacker choose our relay endpoint. */
    if (t->key_set && !wr_stun_verify_integrity(&m, t->key, sizeof(t->key))) {
        return WR_ERR_AUTH;
    }
    t->pending_active = false;
    t->pending_retx = 0u;
    if (method == WR_STUN_METHOD_ALLOCATE) {
        handle_allocate_success(t, &m, now_ms);
        return WR_OK;
    }
    if (method == WR_STUN_METHOD_CHANNEL_BIND) {
        t->channel_bound = true;
        return WR_OK;
    }
    if (method == WR_STUN_METHOD_REFRESH) {
        t->refresh_at_ms = now_ms + WR_TURN_LIFETIME * 800u;
        return WR_OK;
    }
    return WR_OK;
}

static wr_status resend_pending(wr_turn *t)
{
    if (!t->pending_active) {
        return WR_OK;
    }
    switch (t->pending_method) {
    case WR_STUN_METHOD_ALLOCATE:
        return send_allocate(t, t->pending_auth, 0u);
    case WR_STUN_METHOD_REFRESH:
        return send_refresh(t, 0u);
    case WR_STUN_METHOD_CREATE_PERMISSION:
        return send_create_permission(t);
    case WR_STUN_METHOD_CHANNEL_BIND:
        return send_channel_bind(t);
    case WR_STUN_METHOD_BINDING:
    case WR_STUN_METHOD_SEND:
    case WR_STUN_METHOD_DATA:
    default:
        return WR_OK;
    }
}

wr_status wr_turn_step(wr_turn *t, uint64_t now_ms)
{
    if (!t || t->state == WR_TURN_NEW || t->state == WR_TURN_CLOSED ||
        t->state == WR_TURN_FAILED) {
        return WR_OK;
    }
    /* Retransmit the outstanding request if it has not been answered. */
    if (t->pending_active && t->pending_sent_ms != 0u) {
        uint64_t rto = WR_TURN_RETX_BASE_MS << (t->pending_retx < 3u
                                                    ? t->pending_retx
                                                    : 3u);
        if (now_ms - t->pending_sent_ms >= rto) {
            if (t->pending_retx >= WR_TURN_MAX_RETX) {
                t->pending_active = false;
                t->state = WR_TURN_FAILED;
                return WR_ERR_TIMEOUT;
            }
            t->pending_retx++;
            t->pending_sent_ms = now_ms;
            return resend_pending(t);
        }
    } else if (t->pending_active) {
        t->pending_sent_ms = now_ms;
    }
    if (t->state != WR_TURN_ALLOCATED) {
        return WR_OK;
    }
    if (now_ms >= t->refresh_at_ms) {
        return send_refresh(t, now_ms);
    }
    /* Permissions expire on their own schedule and are not covered by the
     * allocation Refresh request. */
    if (t->has_peer && t->permission_sent && now_ms >= t->permission_at_ms) {
        t->permission_at_ms = now_ms + WR_TURN_PERMISSION_LIFETIME * 800u;
        return send_create_permission(t);
    }
    return WR_OK;
}

wr_turn_status wr_turn_get_status(const wr_turn *t)
{
    return t ? t->state : WR_TURN_CLOSED;
}

const wr_endpoint *wr_turn_relayed(const wr_turn *t)
{
    if (!t || t->state != WR_TURN_ALLOCATED) {
        return NULL;
    }
    return &t->relayed;
}