# Architecture

## Layers

```
+--------------------------------------------------------------------------------+
| wr_pc: JSEP offer/answer, ICE -> DTLS -> SCTP orchestration, data channels     |
+------------------+------------------+-------------------+----------------------+
| media            | rtp / rtcp       | sctp / tsn / dcep | srtp                 |
| payload + codecs | header, feedback | DATA/SACK, TSN    | AES-CM / AES-GCM     |
+------------------+------------------+-------------------+----------------------+
| ice              | stun / turn      | dtls              | sdp        | net      |
| checklist        | messages, auth   | record, handshake | text AST   | UDP/DTLS |
+------------------+------------------+-------------------+------------+----------+
| base: arena, span, vec, bitmap, bitio, crc32/crc32c, hash, maps, pool, sb, log |
+--------------------------------------------------------------------------------+
```

The core is single-threaded and event-driven. Protocol code never reads the
wall clock: `now_ms` is passed into `step`/`input`, and I/O is injected through
`wr_io`, so the same state machine runs over UDP, DTLS, a mock queue, or a
fuzz schedule.

## Module contracts

| Module | Input | Output | State |
|---|---|---|---|
| `base` | bytes, sizes | spans, status, arena objects | none (caller-owned arena) |
| `net` | endpoints, datagrams | UDP/DTLS datagrams, timers | fd, DTLS queue, timer slots |
| `sdp` | SDP text (copied into arena) | session/media/attribute AST | arena-owned AST |
| `stun` | datagram | message view, attributes, integrity result | none |
| `turn` | STUN responses/events | Allocate/permission/channel state | client FSM, queue |
| `ice` | candidates, STUN datagrams | checks, selected pair, state | checklist, pairs, txids |
| `dtls` | records/events | records, plaintext, handshake messages | cipher, epoch, replay, FSM |
| `srtp` | RTP packet | SRTP packet | per-SSRC ROC, replay window, cached crypto |
| `rtp` | packet | RTP header/RTCP blocks | RTP SSRC stream table |
| `sctp` | datagram | DATA/SACK events, deliveries | TSN set, TX/RX queues, congestion state |
| `media` | RTP payload / raw frames | payload fragments / frames | depacketizer/codec state |
| `pc` | endpoints, SDP, events | data-channel events | ICE + DTLS + SCTP |

## Translation-unit layout

The library is 43 C translation units. Splits follow protocol seams, not line
counts, so each unit has one reason to change and the build can compile them in
parallel.

| Area | Files | Seam |
|---|---|---|
| base | `arena.c`, `span.c`, `bitio.c`, `bitmap.c`, `crc32.c`, `crc32c.c`, `hash.c`, `rng.c`, `log.c`, `status.c`, `sb.c` | independent primitives |
| base maps/pool | `map_u64.c`, `map_str.c`, `pool.c` | key type / allocator |
| sdp | `sdp_parse.c`, `sdp_serialize.c`, `sdp_attr.c`, `sdp_jsep.c` | parse, emit, attribute helpers, JSEP helpers |
| stun | `stun_msg.c`, `stun_integrity.c`, `stun_addr.c` | framing, auth, address codec |
| turn | `turn.c`, `channel.c` | client FSM, ChannelData framing |
| ice | `ice.c`, `ice_cand.c`, `ice_check.c` | lifecycle, candidates, checklist/checks |
| rtp | `rtp.c`, `rtcp.c`, `streams.c` | RTP codec, RTCP codec, SSRC table |
| sctp | `sctp.c`, `tsn.c`, `dcep.c` | association/chunks, TSN set, DCEP |
| dtls | `dtls.c`, `handshake.c`, `dtls_crypto.c` | record layer, handshake FSM, cert/key schedule |
| pc | `pc.c`, `pc_jsep.c` | transport orchestration, SDP offer/answer |
| media | `payload.c`, `codec.c` | always-built payload layer, optional FFmpeg |
| net | `endpoint.c`, `io.c`, `timer.c` | address codec, transport, timers |
| crypto | `openssl_crypto.c` | OpenSSL backend |

Shared private state lives in `*_internal.h` (`sdp`, `stun`, `ice`, `dtls`,
`pc`). Internal cross-unit functions use the module prefix (`wr_ice_*`,
`wr_dtls_*`) so they do not leak into the public API. `wr_sb` is the single
bounded serializer sink used by SDP and RTCP; it keeps fixed-width big-endian
writes on direct stores.

## Data flow: send

```
application bytes
  -> wr_pc_send
  -> wr_sctp_send_data        DATA chunk, CRC-32c, TSN, retransmit queue
  -> wr_dtls_send             record encrypt (AES-GCM)
  -> wr_io_send               UDP datagram
```

When DTLS is not enabled, the same SCTP path can run directly over the `wr_io`
transport (as the SCTP loopback tests do).

## Data flow: receive

```
UDP datagram
  -> wr_pc_recv / wr_pc_step
  -> wr_dtls_input            authenticate, replay-check, decrypt
  -> wr_sctp_input            CRC, chunk walk, DATA/SACK/INIT/COOKIE
  -> wr_sctp_recv             ordered delivery, per-stream sequencing
  -> wr_pc_recv               application delivery
```

ICE is pumped first; DTLS is only fed after `wr_ice_is_complete`. STUN traffic
is never routed into DTLS.

## Memory and ownership

- One `wr_arena` per engine/PC/association (or a shared arena for the whole
  engine). Protocol objects are allocated from it and are destroyed with it.
- `wr_sdp_parse` copies the complete input into the arena. Parsed spans and
  attribute values remain valid even if the caller's receive buffer is reused.
- `wr_stun_parse`, `wr_sctp_parse`, `wr_rtp_parse`, and the RTCP parsers return
  spans into the caller's packet buffer. The buffer must outlive the result.
  Metadata vectors and copied variable-length values live in the arena.
- Serializers write into caller buffers; no allocation on the wire path.
  `wr_sb` clamps writes but tracks the intended length so overflow is detected
  with `wr_sb_ok()` after building.
- OpenSSL allocations are the main hidden allocation. STUN
  integrity/fingerprint verification uses a stack buffer up to 1500 covered
  bytes and falls back to `malloc` above that.

## Error model

`wr_status` is a packed `(module, code)` u32. `WR_OK` is 0. Out-parameters are
untouched on error unless the API explicitly documents a partial result. There
are no exceptions, no `longjmp`, and no `errno` leakage.

## Determinism

- `wr_rng` can be seeded (xoshiro256**); tests and fuzz schedules use that.
- Time is passed in as `now_ms`; no `clock_gettime` inside protocol code.
- I/O is injected (`wr_io`); tests use loopback UDP or a mock queue.
- Fuzz artifacts are raw bytes; replay is deterministic.

## Threading

Single-threaded engine. Separate engines do not share globals. OpenSSL 3.x
primitives are thread-safe; protocol objects are not internally synchronized.
A future thread-per-transport split can use per-engine arenas, but the current
API makes no locking promises.

## Extension points

- `wr_crypto` vtable: add mbedTLS or a hardware backend.
- `wr_io` vtable: add TCP/TURN transports or a deterministic simulation link.
- `wr_media`: add capture/render adapters; the payload layer already has no
  FFmpeg dependency.
- `wr_turn`: add a TURN server and TCP allocations; the client FSM is present.
- `wr_pc`: add full JSEP rollback/renegotiation, trickle ICE, jitter buffer,
  NACK/PLI scheduling, and TWCC feedback.
