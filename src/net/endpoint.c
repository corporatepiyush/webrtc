#include "wr/net.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void wr_endpoint_v4(wr_endpoint *e, const uint8_t b[4], uint16_t port)
{
    memset(e, 0, sizeof(*e));
    e->af = WR_AF_INET;
    e->port = port;
    memcpy(e->ip.b.v4, b, 4);
}

void wr_endpoint_v6(wr_endpoint *e, const uint8_t b[16], uint32_t scope,
                    uint16_t port)
{
    memset(e, 0, sizeof(*e));
    e->af = WR_AF_INET6;
    e->port = port;
    e->ip.scope_id = scope;
    memcpy(e->ip.b.v6, b, 16);
}

void wr_endpoint_loopback(wr_endpoint *e, uint16_t port)
{
    uint8_t v4[4] = { 127, 0, 0, 1 };
    wr_endpoint_v4(e, v4, port);
}

bool wr_endpoint_parse(wr_span_c s, uint16_t default_port, wr_endpoint *out)
{
    if (!out || s.len == 0u || s.ptr == NULL) {
        return false;
    }
    char buf[128];
    if (s.len >= sizeof(buf)) {
        return false;
    }
    memcpy(buf, s.ptr, s.len);
    buf[s.len] = '\0';

    wr_endpoint e;
    memset(&e, 0, sizeof(e));

    if (buf[0] == '[') {
        char *close = strchr(buf, ']');
        if (!close) {
            return false;
        }
        *close = '\0';
        if (inet_pton(AF_INET6, buf + 1, e.ip.b.v6) != 1) {
            return false;
        }
        e.af = WR_AF_INET6;
        if (close[1] == ':') {
            char *end = NULL;
            unsigned long p = strtoul(close + 2, &end, 10);
            if (!end || *end != '\0' || p > UINT16_MAX) {
                return false;
            }
            e.port = (uint16_t)p;
        } else if (close[1] != '\0') {
            return false;
        } else {
            e.port = default_port;
        }
        *out = e;
        return true;
    }

    char *colon = strrchr(buf, ':');
    bool v6 = false;
    for (const char *p = buf; *p; ++p) {
        if (*p == ':') {
            v6 = true;
            break;
        }
    }
    if (v6 && (colon == buf || strchr(buf, ':') != colon)) {
        /* Bare IPv6 without brackets: whole string is the address. */
        if (inet_pton(AF_INET6, buf, e.ip.b.v6) != 1) {
            return false;
        }
        e.af = WR_AF_INET6;
        e.port = default_port;
        *out = e;
        return true;
    }
    if (colon) {
        *colon = '\0';
        char *end = NULL;
        unsigned long p = strtoul(colon + 1, &end, 10);
        if (!end || *end != '\0' || p > UINT16_MAX) {
            return false;
        }
        e.port = (uint16_t)p;
        if (inet_pton(AF_INET, buf, e.ip.b.v4) != 1) {
            return false;
        }
        e.af = WR_AF_INET;
        *out = e;
        return true;
    }

    if (inet_pton(AF_INET, buf, e.ip.b.v4) == 1) {
        e.af = WR_AF_INET;
        e.port = default_port;
        *out = e;
        return true;
    }
    return false;
}

size_t wr_endpoint_format(const wr_endpoint *e, char *buf, size_t cap)
{
    if (!e || !buf || cap == 0u) {
        return 0u;
    }
    char addr[INET6_ADDRSTRLEN];
    if (e->af == WR_AF_INET) {
        if (!inet_ntop(AF_INET, e->ip.b.v4, addr, sizeof(addr))) {
            return 0u;
        }
        return (size_t)snprintf(buf, cap, "%s:%u", addr, (unsigned)e->port);
    }
    if (!inet_ntop(AF_INET6, e->ip.b.v6, addr, sizeof(addr))) {
        return 0u;
    }
    return (size_t)snprintf(buf, cap, "[%s]:%u", addr, (unsigned)e->port);
}

bool wr_endpoint_eq(const wr_endpoint *a, const wr_endpoint *b)
{
    if (!a || !b || a->af != b->af || a->port != b->port) {
        return false;
    }
    if (a->af == WR_AF_INET) {
        return memcmp(a->ip.b.v4, b->ip.b.v4, 4) == 0;
    }
    return a->ip.scope_id == b->ip.scope_id &&
           memcmp(a->ip.b.v6, b->ip.b.v6, 16) == 0;
}

bool wr_endpoint_is_loopback(const wr_endpoint *e)
{
    if (!e) {
        return false;
    }
    if (e->af == WR_AF_INET) {
        return e->ip.b.v4[0] == 127;
    }
    static const uint8_t lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 1 };
    return memcmp(e->ip.b.v6, lo, 16) == 0;
}

bool wr_endpoint_is_unspec(const wr_endpoint *e)
{
    static const uint8_t z[16] = { 0 };
    if (!e) {
        return true;
    }
    return memcmp(e->ip.b.v6, z, 16) == 0;
}

size_t wr_endpoint_to_sockaddr(const wr_endpoint *e, struct sockaddr_storage *ss)
{
    if (!e || !ss) {
        return 0u;
    }
    memset(ss, 0, sizeof(*ss));
    if (e->af == WR_AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
#ifdef __APPLE__
        sin->sin_len = (uint8_t)sizeof(struct sockaddr_in);
#endif
        sin->sin_port = htons(e->port);
        memcpy(&sin->sin_addr, e->ip.b.v4, 4);
        return sizeof(*sin);
    }
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    sin6->sin6_family = AF_INET6;
#ifdef __APPLE__
    sin6->sin6_len = (uint8_t)sizeof(struct sockaddr_in6);
#endif
    sin6->sin6_port = htons(e->port);
    sin6->sin6_scope_id = e->ip.scope_id;
    memcpy(&sin6->sin6_addr, e->ip.b.v6, 16);
    return sizeof(*sin6);
}

bool wr_endpoint_from_sockaddr(const struct sockaddr *sa, wr_endpoint *out)
{
    if (!sa || !out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)sa;
        out->af = WR_AF_INET;
        out->port = ntohs(sin->sin_port);
        memcpy(out->ip.b.v4, &sin->sin_addr, 4);
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)(const void *)sa;
        out->af = WR_AF_INET6;
        out->port = ntohs(sin6->sin6_port);
        out->ip.scope_id = sin6->sin6_scope_id;
        memcpy(out->ip.b.v6, &sin6->sin6_addr, 16);
        return true;
    }
    return false;
}