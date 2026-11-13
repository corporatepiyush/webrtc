# API notes

All symbols use the `wr_` prefix. Headers are C17; `extern "C"` guards are only
for FFI consumers, not for C++ compilation of the library. The library is not a
stable C ABI: structs are exposed for callers that need the fields, but the
layout is not frozen.

## Ownership

- **Arena-owned.** SDP sessions, STUN messages, SCTP associations, ICE agents,
  DTLS objects, TURN clients, and PC objects are allocated from a
  caller-provided `wr_arena`. Destroying the arena destroys them. Do not
  `free` individual protocol objects.
- **Parsed span lifetime is per-parser:**
  - `wr_sdp_parse` copies the full input into the arena. Attribute values,
    media entries, and session strings remain valid even if the caller's buffer
    is reused.
  - `wr_stun_parse`, `wr_sctp_parse`, `wr_rtp_parse`, and the RTCP parsers
    return spans into the caller's packet buffer. The buffer must outlive the
    result. Variable-length metadata vectors are arena-owned.
- **Caller-owned.** `wr_io`, `wr_rng`, `wr_crypto`, and raw buffers passed to
  serializers.

## Status

Every fallible function returns `wr_status`. Out-parameters are untouched on
error unless documented otherwise. `WR_OK` is 0. Use `wr_status_str` /
`wr_status_module` for diagnostics.

## Typical data-channel flow

```c
wr_arena *a = wr_arena_create(1 << 20);
wr_rng *rng = wr_rng_create();
wr_endpoint lo; wr_endpoint_loopback(&lo, 0);
wr_io *io = wr_io_udp_create(&lo, true);
wr_endpoint local, remote;
wr_io_local_addr(io, &local);

wr_pc *pc = wr_pc_create(a, rng, io, &local, &remote, WR_ICE_ROLE_CONTROLLING);
wr_pc_set_credentials(pc, ufrag_l, pwd_l, ufrag_r, pwd_r);
wr_pc_start(pc, now_ms);

while (!wr_pc_ready(pc)) {
    wr_pc_step(pc, now_ms);
    now_ms += 5;
}

wr_pc_send(pc, wr_span_c_from_str("hello"));
wr_sctp_delivery d;
if (wr_pc_recv(pc, &d)) { /* d.data, d.ppid */ }
```

When DTLS is required, call `wr_pc_enable_dtls` before `wr_pc_start` so the
fingerprint is available for the offer, set the peer fingerprint from the
answer, then pump `wr_pc_step` as above.

## SDP

```c
wr_sdp_session s;
wr_sdp_parse(arena, span, WR_SDP_STRICT, &s);
const wr_sdp_attr *a = wr_sdp_attr_find(&s.attr, wr_span_c_from_str("group"));
wr_sdp_ice ice;
wr_sdp_ice_parse(&s, NULL, &ice);
size_t n;
wr_sdp_serialize(&s, NULL, 0, &n);      /* size query */
wr_sdp_serialize(&s, buf, sizeof(buf), &n);
```

`WR_SDP_STRICT` rejects malformed lines and duplicate required sections;
`WR_SDP_LIBERAL` ignores trailing whitespace and unknown session-level lines.
The parser is a subset (see `docs/STATUS.md`): `i/u/e/p/b/k/r/z` are skipped on
serialize, and unknown attributes are retained only as raw `a=` pairs.

## STUN

```c
wr_stun_msg m;
wr_stun_parse(arena, packet, WR_STUN_LIBERAL, &m);
if (wr_stun_verify_fingerprint(&m) && wr_stun_verify_integrity(&m, key, key_len)) {
    /* trusted */
}
wr_stun_append_integrity(&m, key, key_len, buf, sizeof(buf), &n);
```

`wr_stun_build_binding_request` copies PRIORITY and ICE-CONTROLLING/CONTROLLED
values into the message arena, so the returned message is self-contained. Do
not keep the builder's stack locals around.

## ICE

```c
wr_ice_config cfg; wr_ice_config_defaults(&cfg);
cfg.role = WR_ICE_ROLE_CONTROLLING;
wr_ice_agent *ice = wr_ice_create(arena, &cfg, rng);
wr_ice_set_local_credentials(ice, ufrag, pwd);
wr_ice_set_remote_credentials(ice, remote_ufrag, remote_pwd);
wr_ice_add_local_candidate(ice, local_addr, WR_ICE_CAND_HOST, 1);
wr_ice_add_remote_candidate(ice, remote_addr, WR_ICE_CAND_HOST, 1);
wr_ice_start(ice, now);
while (!wr_ice_is_complete(ice)) { wr_ice_step(ice, now); now += 5; }
```

Host/srflx/prflx candidates, a checklist, nomination, and consent timers are
implemented. Restart resets pair state but does not preserve learned srflx
addresses across restarts.

## SCTP

```c
wr_sctp_assoc *as = wr_sctp_create(arena, local_port, remote_port, rng);
wr_sctp_attach_io(as, io, &remote_addr);
wr_sctp_start_established(as, my_vtag, peer_vtag, peer_initial_tsn);
wr_sctp_send_data(as, stream, ppid, payload, now);
wr_sctp_input(as, now, packet);
wr_sctp_step(as, now);
wr_sctp_delivery d;
if (wr_sctp_recv(as, &d)) { /* ... */ }
```

`wr_sctp_start` drives INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK over `wr_io`.
`wr_sctp_start_established` skips the handshake for tests and for a transport
that is already established. DATA payloads are capped at 2020 bytes per send
(12-byte DATA body + 4-byte chunk + 12-byte header, padded); a larger payload
returns `WR_ERR_OVERFLOW` before any copy.

## DTLS record layer

```c
wr_dtls_cipher c; /* key + salt from the handshake */
wr_dtls_encrypt(&c, WR_DTLS_APPDATA, epoch, seq, plain, buf, cap, &n);
wr_dtls_record meta;
wr_dtls_decrypt(&c, record, out, &meta);
```

Only authenticated records advance the replay window. A forged high-sequence
record does not suppress a later valid record with the same sequence.

## DTLS 1.2 handshake

```c
wr_dtls *client = wr_dtls_create(arena, rng, WR_DTLS_ROLE_CLIENT, io, &peer);
wr_dtls *server = wr_dtls_create(arena, rng, WR_DTLS_ROLE_SERVER, io, &peer);
size_t fp_len;
const uint8_t *fp = wr_dtls_fingerprint(server, &fp_len);
wr_dtls_set_peer_fingerprint(client, fp, fp_len);
wr_dtls_set_peer_fingerprint(server, wr_dtls_fingerprint(client, &fp_len), fp_len);
wr_dtls_start(client, now_ms);
while (!wr_dtls_ready(client) || !wr_dtls_ready(server)) {
    /* pump UDP into wr_dtls_input on both sides */
    wr_dtls_step(client, now_ms);
    wr_dtls_step(server, now_ms);
}
wr_dtls_send(client, wr_span_c_from_str("payload"));
wr_dtls_recv(server, &out);
```

Certificates are self-signed ECDSA P-256; the fingerprint is SHA-256 of the DER
certificate. `wr_dtls_destroy` frees the OpenSSL key/certificate state.

## SRTP

```c
wr_srtp_ctx ctx;
wr_srtp_init(&ctx, WR_SRTP_AES_GCM_128, key, salt, ssrc);
wr_srtp_protect(&ctx, rtp, out);
wr_srtp_unprotect(&ctx, srtp, out);
wr_srtp_fini(&ctx);
```

`wr_srtp_init` allocates per-stream cached cipher/HMAC contexts; call
`wr_srtp_fini` on teardown or the contexts leak. Contexts are single-threaded
per `wr_srtp_ctx`. AES-CM carries a 64-entry replay bitmap; AES-GCM uses the
RFC 7714 nonce construction.

## Hot-path data structures

```c
wr_u64_map m;
wr_u64_map_init(&m, arena, 1024);
wr_u64_map_put(&m, ssrc, slot_index);
uint32_t *v = wr_u64_map_find(&m, ssrc);

wr_str_map sm;
wr_str_map_init(&sm, arena, 64);
wr_str_map_put(&sm, wr_span_c_from_str("mid-0"), 0u);

wr_pool p;
wr_pool_init(&p, arena, 256u, sizeof(obj), 64u);
void *o = wr_pool_alloc(&p);
wr_pool_free(&p, o);

wr_rtp_stream_table *st = wr_rtp_stream_table_create(arena, 128u);
wr_rtp_stream *s = wr_rtp_stream_get_or_create(st, ssrc);
wr_rtp_stream_update(s, &hdr, bytes, now_ms);
```

Maps and pools are arena-backed; `destroy` only clears the handle. The pool
never moves objects, so pointers stay valid until `wr_pool_free`. `wr_u64_map`
uses open addressing with no tombstones (backward-shift erase). `wr_str_map`
copies keys into the arena and returns stable value pointers. Both maps use a
0.7 load factor; `wr_u64_map` keys use a fixed-key hash path (`*_hash`) to avoid
re-hashing.

## Media

```c
wr_media_enc_config cfg = { WR_MEDIA_H264, 640, 360, 30, 800, 30 };
wr_media_enc *enc = wr_media_enc_create(arena, &cfg);
uint8_t yuv[640 * 360 * 3 / 2];
wr_media_packet pkts[16];
uint32_t n;
wr_media_enc_push(enc, wr_span_c_make(yuv, sizeof(yuv)), pts_ms, pkts, 16, &n);

wr_rtp_pay_cfg pc = { .mtu = 1200, .pt = 96, .seq = 1, .ts = 0, .ssrc = 1 };
wr_rtp_out out[32];
for (uint32_t i = 0; i < 32; ++i) { out[i].ptr = bufs[i]; out[i].cap = sizeof(bufs[i]); }
uint32_t np;
wr_h264_packetize(pkts[0].data, &pc, out, 32, &np);
```

`WR_MEDIA=ON` links libavcodec/libavutil/libavformat/libswscale. The payload
layer (`wr_h264_packetize`, `wr_vp8_*`, `wr_opus_packetize`) is always built
and has no FFmpeg dependency. Media wrappers are fixed-vector tested, not
fuzzed.

## TURN client

```c
wr_turn *t = wr_turn_create(arena, rng, io, &server,
                            wr_span_c_from_str("user"),
                            wr_span_c_from_str("pass"));
wr_turn_start(t, now_ms);
/* feed wr_turn_input from the UDP socket; on 401 the client retries with
 * long-term credentials. */
while (wr_turn_get_status(t) != WR_TURN_ALLOCATED) wr_turn_step(t, now_ms);
wr_turn_connect(t, &peer, 0x4000);
/* after ChannelBind success: */
wr_turn_send(t, data);
wr_turn_recv(t, &out);
```

ChannelData input stores complete frames; `wr_turn_recv` returns one payload at
a time and compacts the queue. TCP allocations and a TURN server are not
implemented.

## Threading

The core is single-threaded and reentrant only in the sense that separate
engine instances do not share global state. OpenSSL is used without explicit
locks; OpenSSL 3.x is thread-safe for these primitives. Do not call a protocol
object from multiple threads without external synchronization.