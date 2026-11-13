#include "wr/sdp.h"
#include "sdp_internal.h"

#include <arpa/inet.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

bool sdp_tok_next(wr_span_c *rest, wr_span_c *tok)
{
    while (rest->len && (*rest->ptr == ' ' || *rest->ptr == '\t')) {
        rest->ptr++;
        rest->len--;
    }
    if (!rest->len) {
        tok->ptr = NULL;
        tok->len = 0;
        return false;
    }
    size_t i = 0;
    while (i < rest->len && rest->ptr[i] != ' ' && rest->ptr[i] != '\t') {
        i++;
    }
    tok->ptr = rest->ptr;
    tok->len = i;
    rest->ptr += i;
    rest->len -= i;
    return true;
}

static bool split_n(wr_span_c s, wr_span_c *out, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (!sdp_tok_next(&s, &out[i])) {
            return false;
        }
    }
    return true;
}

bool sdp_parse_hex(uint8_t c, uint8_t *out)
{
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

/* Canonical dotted-quad only, no leading zeros. Anything else falls back to
 * inet_pton so platform-specific acceptance (e.g. "192.168.001.042" on
 * macOS) is preserved. */
static bool parse_ipv4_canonical(wr_span_c s, uint8_t out[4])
{
    if (s.len < 7u || s.len > 15u) {
        return false;
    }
    const uint8_t *p = s.ptr;
    size_t i = 0u;
    for (size_t part = 0; part < 4u; ++part) {
        if (i >= s.len) {
            return false;
        }
        uint8_t c = p[i];
        if (c < (uint8_t)'0' || c > (uint8_t)'9') {
            return false;
        }
        uint32_t v = (uint32_t)(c - (uint8_t)'0');
        i++;
        if (i < s.len && p[i] >= (uint8_t)'0' && p[i] <= (uint8_t)'9') {
            if (c == (uint8_t)'0') {
                return false; /* leading zero: defer to inet_pton */
            }
            v = v * 10u + (uint32_t)(p[i] - (uint8_t)'0');
            i++;
            if (i < s.len && p[i] >= (uint8_t)'0' && p[i] <= (uint8_t)'9') {
                v = v * 10u + (uint32_t)(p[i] - (uint8_t)'0');
                i++;
                if (i < s.len && p[i] >= (uint8_t)'0' && p[i] <= (uint8_t)'9') {
                    return false;
                }
            }
        }
        if (v > 255u) {
            return false;
        }
        out[part] = (uint8_t)v;
        if (part != 3u) {
            if (i >= s.len || p[i] != (uint8_t)'.') {
                return false;
            }
            i++;
        }
    }
    return i == s.len;
}

bool sdp_parse_addr(wr_span_c s, wr_endpoint *out)
{
    if (!out || s.len == 0u) {
        return false;
    }
    bool v6 = memchr(s.ptr, ':', s.len) != NULL;
    if (v6) {
        char buf[64];
        if (s.len >= sizeof(buf)) return false;
        memcpy(buf, s.ptr, s.len);
        buf[s.len] = '\0';
        if (inet_pton(AF_INET6, buf, out->ip.b.v6) != 1) {
            return false;
        }
        out->af = WR_AF_INET6;
        out->port = 0;
        out->ip.scope_id = 0;
        return true;
    }
    if (parse_ipv4_canonical(s, out->ip.b.v4)) {
        out->af = WR_AF_INET;
        out->port = 0;
        out->ip.scope_id = 0;
        return true;
    }
    char buf[32];
    if (s.len >= sizeof(buf)) return false;
    memcpy(buf, s.ptr, s.len);
    buf[s.len] = '\0';
    if (inet_pton(AF_INET, buf, out->ip.b.v4) != 1) {
        return false;
    }
    out->af = WR_AF_INET;
    out->port = 0;
    out->ip.scope_id = 0;
    return true;
}

static bool parse_connection(wr_span_c v, wr_endpoint *out, wr_span_c *raw)
{
    wr_span_c t[3];
    if (!split_n(v, t, 3)) {
        return false;
    }
    if (!wr_span_c_case_eq(t[0], wr_span_c_from_str("IN"))) {
        return false;
    }
    if (wr_span_c_case_eq(t[1], wr_span_c_from_str("IP4"))) {
        if (!sdp_parse_addr(t[2], out)) return false;
        out->af = WR_AF_INET;
    } else if (wr_span_c_case_eq(t[1], wr_span_c_from_str("IP6"))) {
        if (!sdp_parse_addr(t[2], out)) return false;
        out->af = WR_AF_INET6;
    } else {
        return false;
    }
    if (raw) {
        *raw = v;
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Parser                                                                    */
/* ------------------------------------------------------------------------- */

/* Typical WebRTC media sections carry 8-20 attributes and a handful of
 * formats. Reserving once avoids the 8 -> 16 regrowth copies and one arena
 * allocation per media section. */
static bool media_vectors_init(wr_sdp_media *m, wr_arena *a)
{
    wr_span_c_vec_init(&m->fmt, a);
    wr_sdp_attr_vec_init(&m->attr, a);
    return wr_span_c_vec_reserve(&m->fmt, 16u) &&
           wr_sdp_attr_vec_reserve(&m->attr, 16u);
}

static bool parse_media_line(wr_arena *a, wr_span_c v, wr_sdp_media *m)
{
    WR_UNUSED(a);
    wr_span_c rest = v;
    wr_span_c type, portfield, proto;
    if (!sdp_tok_next(&rest, &type) || !sdp_tok_next(&rest, &portfield) ||
        !sdp_tok_next(&rest, &proto)) {
        return false;
    }
    m->type = type;
    m->port_count = 1u;

    const uint8_t *slashp = memchr(portfield.ptr, '/', portfield.len);
    if (slashp) {
        wr_span_c pc = wr_span_c_sub(portfield, 0,
                                     (size_t)(slashp - portfield.ptr));
        wr_span_c cc = wr_span_c_sub(portfield,
                                     (size_t)(slashp - portfield.ptr) + 1u,
                                     portfield.len -
                                         (size_t)(slashp - portfield.ptr) - 1u);
        uint32_t pcv, ccv;
        if (!wr_parse_u32(pc, &pcv) || !wr_parse_u32(cc, &ccv) ||
            ccv == 0u || ccv > 64u) {
            return false;
        }
        m->port = pcv;
        m->port_count = (uint16_t)ccv;
    } else {
        uint32_t p;
        if (!wr_parse_u32(portfield, &p)) {
            return false;
        }
        m->port = p;
    }
    m->proto = proto;

    while (sdp_tok_next(&rest, &type)) {
        if (!wr_span_c_vec_push(&m->fmt, type)) {
            return false;
        }
    }
    return m->fmt.len > 0u;
}

wr_status wr_sdp_parse(wr_arena *a, wr_span_c input, unsigned flags,
                       wr_sdp_session *out)
{
    if (WR_UNLIKELY(!a || !input.ptr || !out)) {
        return WR_ERR_INVAL;
    }
    bool liberal = (flags & WR_SDP_LIBERAL) != 0u;
    if (WR_UNLIKELY(input.len == SIZE_MAX)) {
        return WR_ERR_INVAL;
    }
    memset(out, 0, sizeof(*out));

    char *text = (char *)wr_arena_alloc(a, input.len + 1u);
    if (!text) {
        return WR_ERR_NOMEM;
    }
    memcpy(text, input.ptr, input.len);
    text[input.len] = '\0';

    wr_sdp_media_vec_init(&out->media, a);
    wr_sdp_attr_vec_init(&out->attr, a);
    if (!out->media.a || !out->attr.a) {
        return WR_ERR_NOMEM;
    }

    bool seen_v = false, seen_o = false, seen_s = false, seen_t = false;
    bool in_media = false;
    wr_sdp_media cur;
    memset(&cur, 0, sizeof(cur));
    if (!media_vectors_init(&cur, a)) {
        return WR_ERR_NOMEM;
    }

    char *p = text;
    while (*p) {
        char *e = strchr(p, '\n');
        char *line = p;
        size_t line_len = e ? (size_t)(e - p) : strlen(p);
        if (e) {
            *e = '\0';
            p = e + 1;
        } else {
            p += line_len;
        }
        if (line_len && line[line_len - 1u] == '\r') {
            line[line_len - 1u] = '\0';
            line_len--;
        }
        if (line_len == 0u) {
            if (!liberal) {
                return WR_ERR_INVAL;
            }
            continue;
        }
        if (WR_UNLIKELY(line_len > 8192u)) {
            return WR_ERR_LIMIT;
        }
        if (WR_UNLIKELY(line_len < 2u || line[1] != '=')) {
            if (liberal) {
                continue;
            }
            return WR_ERR_INVAL;
        }
        char key = line[0];
        wr_span_c value = wr_span_c_make((const uint8_t *)line + 2,
                                         line_len - 2u);

        if (in_media) {
            switch (key) {
            case 'm':
                if (cur.type.ptr) {
                    if (!wr_sdp_media_vec_push(&out->media, cur)) {
                        return WR_ERR_NOMEM;
                    }
                    memset(&cur, 0, sizeof(cur));
                    if (!media_vectors_init(&cur, a)) {
                        return WR_ERR_NOMEM;
                    }
                }
                if (!parse_media_line(a, value, &cur)) {
                    return WR_ERR_INVAL;
                }
                break;
            case 'c':
                if (cur.has_conn) {
                    return WR_ERR_INVAL;
                }
                cur.origin = value;
                if (!parse_connection(value, &cur.conn, NULL)) {
                    return WR_ERR_INVAL;
                }
                cur.has_conn = true;
                break;
            case 'a': {
                wr_sdp_attr at;
                const uint8_t *colon = memchr(value.ptr, ':', value.len);
                if (!colon) {
                    at.name = value;
                    at.value = wr_span_c_make(NULL, 0);
                } else {
                    size_t off = (size_t)(colon - value.ptr);
                    at.name = wr_span_c_sub(value, 0, off);
                    at.value = wr_span_c_sub(value, off + 1u,
                                             value.len - off - 1u);
                }
                if (!wr_sdp_attr_vec_push(&cur.attr, at)) {
                    return WR_ERR_NOMEM;
                }
                break;
            }
            case 'b':
            case 'i':
            case 'k':
                break;
            default:
                if (!liberal) {
                    return WR_ERR_INVAL;
                }
                break;
            }
            continue;
        }

        switch (key) {
        case 'v':
            if (seen_v) return WR_ERR_INVAL;
            if (!wr_span_c_case_eq(value, wr_span_c_from_str("0"))) {
                return WR_ERR_INVAL;
            }
            seen_v = true;
            out->version = value;
            break;
        case 'o':
            if (seen_o) return WR_ERR_INVAL;
            seen_o = true;
            out->origin = value;
            break;
        case 's':
            if (seen_s) return WR_ERR_INVAL;
            seen_s = true;
            out->name = value;
            break;
        case 't':
            if (seen_t) return WR_ERR_INVAL;
            seen_t = true;
            out->timing = value;
            break;
        case 'c':
            if (out->has_conn) return WR_ERR_INVAL;
            out->origin_conn = value;
            if (!parse_connection(value, &out->conn, NULL)) {
                return WR_ERR_INVAL;
            }
            out->has_conn = true;
            break;
        case 'a':
            if (!wr_sdp_attr_add(&out->attr, value, wr_span_c_make(NULL, 0))) {
                return WR_ERR_NOMEM;
            }
            {
                const uint8_t *colon = memchr(value.ptr, ':', value.len);
                if (!colon) {
                    out->attr.data[out->attr.len - 1u].name = value;
                } else {
                    size_t off = (size_t)(colon - value.ptr);
                    out->attr.data[out->attr.len - 1u].name =
                        wr_span_c_sub(value, 0, off);
                    out->attr.data[out->attr.len - 1u].value =
                        wr_span_c_sub(value, off + 1u, value.len - off - 1u);
                }
            }
            break;
        case 'm':
            if (!seen_v || !seen_o || !seen_s) {
                return WR_ERR_INVAL;
            }
            in_media = true;
            if (!parse_media_line(a, value, &cur)) {
                return WR_ERR_INVAL;
            }
            break;
        case 'i':
        case 'u':
        case 'e':
        case 'p':
        case 'b':
        case 'r':
        case 'z':
        case 'k':
            break;
        default:
            if (!liberal) {
                return WR_ERR_INVAL;
            }
            break;
        }
    }

    if (in_media && cur.type.ptr) {
        if (!wr_sdp_media_vec_push(&out->media, cur)) {
            return WR_ERR_NOMEM;
        }
    }
    if (!seen_v || !seen_o || !seen_s || !seen_t || !in_media) {
        return WR_ERR_INVAL;
    }
    return WR_OK;
}

