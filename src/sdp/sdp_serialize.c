#include "wr/sdp.h"
#include "wr/sb.h"

#include <arpa/inet.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Serializer                                                                */
/* ------------------------------------------------------------------------- */

static void sb_conn(wr_sb *s, wr_span_c raw, const wr_endpoint *e)
{
    char addr[INET6_ADDRSTRLEN];
    if (e->af == WR_AF_INET6) {
        wr_sb_put_n(s, "c=IN IP6 ", 9u);
        if (inet_ntop(AF_INET6, e->ip.b.v6, addr, sizeof(addr))) {
            wr_sb_put(s, addr);
        } else if (raw.ptr) {
            wr_sb_put_span(s, raw);
        }
    } else {
        wr_sb_put_n(s, "c=IN IP4 ", 9u);
        wr_sb_put_ipv4(s, e->ip.b.v4);
    }
    wr_sb_crlf(s);
}

static void serialize_attrs(wr_sb *s, const wr_sdp_attr_vec *attrs)
{
    if (!attrs) {
        return;
    }
    for (size_t i = 0; i < attrs->len; ++i) {
        wr_sb_put_n(s, "a=", 2u);
        wr_sb_put_span(s, attrs->data[i].name);
        if (attrs->data[i].value.ptr && attrs->data[i].value.len) {
            wr_sb_put_u8(s, ':');
            wr_sb_put_span(s, attrs->data[i].value);
        }
        wr_sb_crlf(s);
    }
}

static void serialize_media(wr_sb *s, const wr_sdp_media *m)
{
    wr_sb_put_n(s, "m=", 2u);
    wr_sb_put_span(s, m->type);
    wr_sb_put_u8(s, ' ');
    wr_sb_put_u64(s, m->port);
    if (m->port_count > 1u) {
        wr_sb_put_u8(s, '/');
        wr_sb_put_u64(s, m->port_count);
    }
    wr_sb_put_u8(s, ' ');
    wr_sb_put_span(s, m->proto);
    for (size_t i = 0; i < m->fmt.len; ++i) {
        wr_sb_put_u8(s, ' ');
        wr_sb_put_span(s, m->fmt.data[i]);
    }
    wr_sb_crlf(s);
    if (m->has_conn) {
        sb_conn(s, m->origin, &m->conn);
    }
    serialize_attrs(s, &m->attr);
}

wr_status wr_sdp_serialize(const wr_sdp_session *s, char *buf, size_t cap,
                           size_t *out_len)
{
    if (!s || !out_len || (!buf && cap != 0u)) {
        return WR_ERR_INVAL;
    }
    wr_sb sb;
    wr_sb_init(&sb, buf, cap);
    wr_sb_put_n(&sb, "v=0\r\n", 5u);
    wr_sb_put_n(&sb, "o=", 2u);
    if (s->origin.ptr && s->origin.len) {
        wr_sb_put_span(&sb, s->origin);
    } else {
        wr_sb_put_n(&sb, "- - - - -", 9u);
    }
    wr_sb_crlf(&sb);
    wr_sb_put_n(&sb, "s=", 2u);
    if (s->name.ptr && s->name.len) {
        wr_sb_put_span(&sb, s->name);
    } else {
        wr_sb_put_n(&sb, "-", 1u);
    }
    wr_sb_crlf(&sb);
    wr_sb_put_n(&sb, "t=", 2u);
    if (s->timing.ptr && s->timing.len) {
        wr_sb_put_span(&sb, s->timing);
    } else {
        wr_sb_put_n(&sb, "0 0", 3u);
    }
    wr_sb_crlf(&sb);
    if (s->has_conn) {
        sb_conn(&sb, s->origin_conn, &s->conn);
    }
    serialize_attrs(&sb, &s->attr);
    for (size_t i = 0; i < s->media.len; ++i) {
        serialize_media(&sb, &s->media.data[i]);
    }
    *out_len = sb.len;
    if (sb.len > cap) {
        return WR_ERR_OVERFLOW;
    }
    return WR_OK;
}

