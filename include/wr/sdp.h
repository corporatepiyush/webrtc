#ifndef WR_SDP_H
#define WR_SDP_H

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/vec.h"

typedef struct { wr_span_c name; wr_span_c value; } wr_sdp_attr;
WR_VEC_DEF(wr_sdp_attr_vec, wr_sdp_attr)
WR_VEC_DEF(wr_span_c_vec, wr_span_c)

typedef struct {
    wr_span_c type;          /* audio | video | application | text */
    uint32_t port;
    uint16_t port_count;     /* 1 when absent */
    wr_span_c proto;
    wr_span_c_vec fmt;       /* payload types / format tokens */
    bool has_conn;
    wr_endpoint conn;
    wr_span_c origin;        /* raw c= value */
    wr_sdp_attr_vec attr;
} wr_sdp_media;
WR_VEC_DEF(wr_sdp_media_vec, wr_sdp_media)

typedef struct {
    wr_span_c version;       /* v= */
    wr_span_c origin;        /* o= */
    wr_span_c name;          /* s= */
    wr_span_c timing;        /* t= */
    bool has_conn;
    wr_endpoint conn;
    wr_span_c origin_conn;   /* raw c= */
    wr_sdp_attr_vec attr;
    wr_sdp_media_vec media;
} wr_sdp_session;

typedef enum {
    WR_SDP_STRICT = 0,
    WR_SDP_LIBERAL = 1u << 0,
} wr_sdp_flags;

wr_status wr_sdp_parse(wr_arena *a, wr_span_c input, unsigned flags,
                       wr_sdp_session *out);
wr_status wr_sdp_serialize(const wr_sdp_session *s, char *buf, size_t cap,
                           size_t *out_len);

const wr_sdp_attr *wr_sdp_attr_find(const wr_sdp_attr_vec *attrs,
                                    wr_span_c name);
const wr_sdp_attr *wr_sdp_attr_find_last(const wr_sdp_attr_vec *attrs,
                                         wr_span_c name);
bool wr_sdp_attr_add(wr_sdp_attr_vec *attrs, wr_span_c name, wr_span_c value);
bool wr_sdp_attr_set(wr_sdp_attr_vec *attrs, wr_span_c name, wr_span_c value);

static inline bool wr_sdp_media_has_attr(const wr_sdp_media *m, wr_span_c n)
{
    return m && wr_sdp_attr_find(&m->attr, n) != NULL;
}

/* ------------------------------------------------------------------------- */
/* JSEP helpers                                                              */
/* ------------------------------------------------------------------------- */

typedef enum { WR_SDP_CAND_HOST, WR_SDP_CAND_SRFLX, WR_SDP_CAND_PRFLX,
               WR_SDP_CAND_RELAY } wr_sdp_cand_type;

typedef struct {
    wr_span_c foundation;
    uint32_t component;
    wr_span_c transport;
    uint64_t priority;
    wr_endpoint addr;
    wr_sdp_cand_type type;
    bool has_raddr;
    wr_endpoint raddr;
    bool has_ufrag;
    wr_span_c ufrag;
} wr_sdp_candidate;

typedef struct {
    bool present; /* both ufrag and pwd were present and non-empty */
    bool has_ufrag;
    bool has_pwd;
    wr_span_c ufrag;
    wr_span_c pwd;
    wr_span_c options;
    bool ice_lite;
    bool end_of_candidates;
} wr_sdp_ice;

typedef struct {
    bool present;
    wr_span_c hash;
    uint8_t value[32];
    size_t len;
} wr_sdp_fingerprint;

typedef enum {
    WR_SDP_SETUP_UNSET = 0,
    WR_SDP_SETUP_ACTIVE,
    WR_SDP_SETUP_PASSIVE,
    WR_SDP_SETUP_ACTPASS,
    WR_SDP_SETUP_HOLDCON,
} wr_sdp_setup;

typedef struct {
    uint32_t id;
    wr_span_c uri;
} wr_sdp_extmap;

typedef struct {
    uint32_t fmt;
    wr_span_c type;
    wr_span_c param;
} wr_sdp_rtcp_fb;

bool wr_sdp_candidate_parse(wr_span_c value, wr_sdp_candidate *out);
wr_status wr_sdp_ice_parse(const wr_sdp_session *s, const wr_sdp_media *m,
                           wr_sdp_ice *out);
bool wr_sdp_fingerprint_parse(wr_span_c value, wr_sdp_fingerprint *out);
wr_sdp_setup wr_sdp_setup_parse(wr_span_c value);
const char *wr_sdp_setup_str(wr_sdp_setup setup);
bool wr_sdp_extmap_parse(wr_span_c value, wr_sdp_extmap *out);
bool wr_sdp_rtcp_fb_parse(wr_span_c value, wr_sdp_rtcp_fb *out);
const wr_sdp_media *wr_sdp_find_media(const wr_sdp_session *s, wr_span_c mid);
const wr_sdp_media *wr_sdp_find_media_by_type(const wr_sdp_session *s,
                                              wr_span_c type);

#endif /* WR_SDP_H */