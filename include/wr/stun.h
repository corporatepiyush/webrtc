#ifndef WR_STUN_H
#define WR_STUN_H

#include "wr/arena.h"
#include "wr/net.h"
#include "wr/vec.h"

#define WR_STUN_STRICT 0u
#define WR_STUN_LIBERAL 1u

typedef enum {
    WR_STUN_CLASS_REQUEST = 0x0,
    WR_STUN_CLASS_INDICATION = 0x1,
    WR_STUN_CLASS_SUCCESS = 0x2,
    WR_STUN_CLASS_ERROR = 0x3,
} wr_stun_class;

typedef enum {
    WR_STUN_METHOD_BINDING = 0x001,
    WR_STUN_METHOD_ALLOCATE = 0x003,
    WR_STUN_METHOD_REFRESH = 0x004,
    WR_STUN_METHOD_SEND = 0x006,
    WR_STUN_METHOD_DATA = 0x007,
    WR_STUN_METHOD_CREATE_PERMISSION = 0x008,
    WR_STUN_METHOD_CHANNEL_BIND = 0x009,
} wr_stun_method;

enum {
    WR_STUN_ATTR_MAPPED_ADDRESS = 0x0001,
    WR_STUN_ATTR_USERNAME = 0x0006,
    WR_STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    WR_STUN_ATTR_ERROR_CODE = 0x0009,
    WR_STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000a,
    WR_STUN_ATTR_REALM = 0x0014,
    WR_STUN_ATTR_NONCE = 0x0015,
    WR_STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016,
    WR_STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    WR_STUN_ATTR_PRIORITY = 0x0024,
    WR_STUN_ATTR_USE_CANDIDATE = 0x0025,
    WR_STUN_ATTR_SOFTWARE = 0x8022,
    WR_STUN_ATTR_ALTERNATE_SERVER = 0x8023,
    WR_STUN_ATTR_FINGERPRINT = 0x8028,
    WR_STUN_ATTR_ICE_CONTROLLING = 0x802a,
    WR_STUN_ATTR_ICE_CONTROLLED = 0x802b,
    WR_STUN_ATTR_CHANNEL_NUMBER = 0x000c,
    WR_STUN_ATTR_LIFETIME = 0x000d,
    WR_STUN_ATTR_XOR_PEER_ADDRESS = 0x0012,
    WR_STUN_ATTR_DATA = 0x0013,
    WR_STUN_ATTR_REQUESTED_TRANSPORT = 0x0019,
    WR_STUN_ATTR_DONT_FRAGMENT = 0x001a,
};

#define WR_STUN_MAGIC_COOKIE UINT32_C(0x2112a442)
#define WR_STUN_HEADER_LEN 20u

typedef struct {
    uint16_t type;
    size_t offset;
    wr_span_c value;
} wr_stun_attr;
WR_VEC_DEF(wr_stun_attr_vec, wr_stun_attr)

typedef struct {
    uint16_t type;
    uint8_t txid[12];
    size_t raw_len;
    wr_span_c raw;
    wr_stun_attr_vec attr;
    wr_arena *a;
} wr_stun_msg;

uint16_t wr_stun_type(wr_stun_method method, wr_stun_class cls);
void wr_stun_type_decode(uint16_t type, wr_stun_method *method,
                         wr_stun_class *cls);
bool wr_stun_is_response(uint16_t type);

wr_status wr_stun_parse(wr_arena *a, wr_span_c raw, unsigned flags,
                        wr_stun_msg *out);
wr_status wr_stun_serialize(const wr_stun_msg *m, char *buf, size_t cap,
                            size_t *out_len);
const wr_stun_attr *wr_stun_attr_find(const wr_stun_msg *m, uint16_t type);
bool wr_stun_attr_add(wr_stun_msg *m, uint16_t type, wr_span_c value);
void wr_stun_msg_init(wr_stun_msg *m, wr_arena *a, uint16_t type,
                      const uint8_t txid[12]);

wr_status wr_stun_append_integrity(wr_stun_msg *m, const uint8_t *key,
                                   size_t key_len, char *buf, size_t cap,
                                   size_t *out_len);
wr_status wr_stun_append_fingerprint(wr_stun_msg *m, char *buf, size_t cap,
                                     size_t *out_len);
bool wr_stun_verify_integrity(const wr_stun_msg *m, const uint8_t *key,
                              size_t key_len);
bool wr_stun_verify_fingerprint(const wr_stun_msg *m);

/* Address helpers. */
bool wr_stun_addr_encode(uint8_t *out, size_t cap, const wr_endpoint *e,
                         bool xor_addr, const uint8_t txid[12], size_t *out_len);
bool wr_stun_addr_decode(wr_span_c v, bool xor_addr, const uint8_t txid[12],
                         wr_endpoint *out);

wr_status wr_stun_build_binding_request(wr_stun_msg *m, wr_arena *a,
                                        uint64_t txid_hi, uint64_t txid_lo,
                                        wr_span_c username, uint64_t priority,
                                        bool controlling,
                                        bool use_candidate);

/* TURN ChannelData framing. */
wr_status wr_turn_channel_parse(wr_span_c raw, uint16_t *num,
                                wr_span_c *data);
wr_status wr_turn_channel_serialize(char *buf, size_t cap, uint16_t num,
                                    wr_span_c data, size_t *out_len);

#endif /* WR_STUN_H */