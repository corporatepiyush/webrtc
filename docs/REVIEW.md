# Skeptical review pass — findings and fixes

This document is the running audit log. Each pass re-read the implementation
against the RFCs and the test oracles instead of trusting the green build. Every
defect below has a regression test or a fuzz target that would have caught it.

## Pass index

| Pass | Focus | Found |
|---|---|---|
| 1 | Wire correctness (SRTP/DTLS/SCTP/RTP) | 6 |
| 2 | Data structures, media, SRTP contexts | 7 |
| 3 | Record/handshake/TSN/Opus | 6 |
| 4 | Transport integration, JSEP, TURN | 5 |
| 5 | Missed optimizations | 4 + 1 harness bug |
| 6 | CRC, chunk vector, bitmap, branch hints | 6 |
| 7 | 28-target fuzz campaign, then optimization | 3 + 2 harness bugs |
| 8 | Adversarial black-box audit | 8 + hardening |
| 9 | SACK gap semantics + module split | 1 + build/coverage evidence |
| 10 | Real-peer gap analysis (OpenSSL DTLS, burst sends) | 7, all measured |

---

# Pass 1 — wire correctness

## Fixed

### 1. SRTP KDF label was in the wrong salt octet

`kdf_n()` XORed the derivation label into `iv[13]`. RFC 3711 Appendix B.3 and
libsrtp place the label in octet **7** for the initial KDF (`kdr = 0`), with
the label right-aligned in the 112-bit master salt.

Impact: the SRTP auth key and session salt were wrong, so a real WebRTC peer
would reject every packet. Self-consistency tests passed because both sides
derived the same wrong keys.

Fix: `iv[7] ^= label`. Regression: RFC 3711 B.3 cipher-key/salt/auth-key
vector.

### 2. SRTP AES-GCM nonce was shifted by two octets

RFC 7714 Section 8.1 defines the 12-octet nonce as:

```
IV = (00 00 || SSRC || ROC || SEQ) XOR salt
```

The old code put SSRC at octets 0..3 and the index at 4..9. It must be
octets 2..5 for SSRC, 6..9 for ROC, and 10..11 for SEQ.

Impact: AES-GCM would never interoperate with a real peer.

Fix: build the 12-byte base exactly as specified and XOR the 12-byte salt.
Regression: RFC 7714 Section 16.1.1 encryption vector (ciphertext + tag).

### 3. SRTP AES-CM IV overwrote the salt with the SSRC

`aes_iv()` did `wr_store_be32(iv + 4, ssrc)` instead of XORing the SSRC into
the existing salt bytes. Encrypt and decrypt used the same wrong IV, so the
round-trip test passed.

Fix: `iv32 = load_be32(iv+4) ^ ssrc; store_be32(iv+4, iv32)`.
Regression: RFC 3711 B.2 first AES-CM keystream block.

### 4. EC ECDH was broken on OpenSSL 3/4

`EVP_PKEY_get_raw_public_key()` returns 0 for EC keys in the OpenSSL provider
used here, and `EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)` is the legacy path.
Both key generation and derivation failed.

Fix: use the provider path (`EVP_PKEY_CTX_new_from_name("EC")`,
`EVP_PKEY_get_octet_string_param(PUB_KEY)`,
`EVP_PKEY_get_bn_param(PRIV_KEY)`, `EVP_PKEY_fromdata` with native-endian BN).
Regression: ECDH keygen + derive agreement test.

### 5. SCTP cumulative TSN never advanced

`handle_data()` set `peer_initial_tsn = received_tsn` on every DATA and SACKed
that value, so an out-of-order or duplicate TSN could move the cumulative ack
forward incorrectly. `next_tsn` was also initialized from the peer's initial
TSN instead of our own.

Fix: track `peer_cum_tsn` separately; advance only on `tsn == cum + 1`;
initialize `next_tsn = my_vtag`; `peer_cum_tsn = peer_initial_tsn - 1`.
Regression: `wr_sctp_last_ack` after a successful DATA exchange.

### 6. RTP serializer silently dropped CC/CSRC and extensions

`wr_rtp_serialize()` computed a header length that included CSRC/extension
bytes but never wrote them, producing malformed packets for `CC > 0` or `X=1`.

Fix: return `WR_ERR_UNSUPPORTED` for layouts the serializer cannot emit;
CSRC/extension writing is a separate milestone.

## Hardening (no known exploit, but fixed)

- `wr_bitmap_init`: reject `nbits` near `UINT32_MAX` (addition overflow).
- `wr_stun_serialize` / `append_integrity` / `append_fingerprint`: reject
  `!buf && cap != 0` and messages over the 16-bit length field.
- `wr_sctp_walk` / `wr_sctp_parse`: reject a zero-length raw span.
- `wr_endpoint_format`: reject a null buffer with a non-zero capacity.
- `wr_parse_u64`: reject a null output pointer.

## Verification after fixes

- `wr_tests`: pass (unit + RFC 3711 KDF/AES-CM + RFC 7714 GCM + ECDH + loopback).
- ASan/UBSan: clean.
- libFuzzer: 0.28M-2.9M execs per target, no crashes.
- Standalone mutational driver: 15k execs per target, no crashes.

## Still open at that point

- DTLS 1.2 handshake FSM and certificate generation.
- SCTP 4-way INIT/COOKIE handshake, stream reassembly, congestion control.
- ICE state-machine structured fuzzing (event schedule).
- TURN client FSM, JSEP full offer/answer state machine.
- `wr_stun_verify_integrity` uses a 1500-byte stack buffer and `malloc`s
  above that for the HMAC copy.

---

# Pass 2 — data structures, media, SRTP contexts

## Fixed

### 1. Arena chunks were not cache-line aligned

`chunk_alloc` used the malloc block directly after a 64-byte header. `malloc`
guarantees 16-byte alignment, so `WR_MAX_ALIGN == 64` was a lie and pool
objects were 16-byte aligned. Chunks now over-allocate and align the data
region to 64 bytes. `chunk_bump` and `wr_arena_mark_save` use the aligned
pointer.

### 2. `wr_u64_map` erase corrupted probe chains

The first backward-shift loop moved the hole to `i = j` even when the entry at
`j` could not legally move. That left a permanent hole and later inserts could
not find their slot. Fixed to keep the hole at the deleted slot and only move
an entry whose home is outside the cyclic interval `(hole, j]`. Test: insert
2000 keys, erase the first 1000, verify the remaining 1000.

### 3. H.264 FU-A end bit was tied to the access unit

`wr_h264_packetize` set the FU-A end bit only for the last NAL of an access
unit. SPS/PPS/SEI fragments therefore never ended, and the depacketizer
returned `AGAIN` forever. The end bit now marks the last fragment of every NAL;
the RTP marker bit remains access-unit-scoped.

### 4. VP8/H.264 packetizers wrote the RTP header over their own payload

Both packetizers placed the payload in `out[n].ptr` and then called
`wr_rtp_serialize` into the same buffer, overwriting the first 12 bytes.

Fix: write the header at the start of the destination buffer, then copy the
payload after the header length. Regression: round-trip packetize ->
depacketize for both codecs.

### 5. FFmpeg encoder packets were unref'd while tests still pointed at them

`wr_media_enc_push` called `av_packet_unref` on a packet the test had already
retained, so the test read freed data.

Fix: hand the packet to the caller and only unref the internal copy. Regression:
`test_media_codec.c` uses the returned packet after the call.

### 6. SCTP reassembly delivered out-of-order and duplicate DATA

The receive cursor advanced on any DATA, and a duplicate TSN was copied again.

Fix: accept DATA only above `peer_cum_tsn`, hold out-of-order TSNs in the TSN
set, and deliver strictly in order. Regression: `test_reassembly` feeds
1001/1003/1002 and expects ordered delivery.

### 7. SRTP cached-context paths had a missing length argument

A refactor passed the wrong length to the cached HMAC path, so the auth tag
covered the wrong number of bytes.

Fix: pass the actual packet length. Regression: RFC 3711 B.2 vector.

## Verification after fixes

- Debug, media, ASan, standalone fuzz, and `sctp_fsm` pass.
- Arena alignment probe: pool objects start on 64-byte boundaries.
- Map erase probe: 2000 inserts, 1000 erases, 1000 remaining lookups.

---

# Pass 3 — record/handshake/TSN/Opus

## Fixed

### 1. `wr_dtls_decrypt` could not report plaintext length

`wr_span` was passed by value, so the function set `out.len` on a local copy.
Callers always saw the buffer capacity (2048) instead of the decrypted length.
Changed to `wr_span *out`. This was a real API bug, not a test artifact.

### 2. DTLS client never generated an ECDH key

The client built `ClientHello` with an all-zero private key and only generated
a key pair in `build_ske` (server-side). Every ECDHE derivation failed.
The client now generates its key pair while building `ClientHello`.

### 3. DTLS Finished transcript included itself

`handle_record` appended every handshake message, including Finished, to the
transcript before `handle_handshake` verified it. Both sides therefore hashed a
different transcript and every handshake failed. Finished is now appended only
after verification (client) or after receiving it (server).

### 4. SCTP conflated two cumulative TSNs

`peer_cum_tsn` was used both for the peer's DATA cumulative ack and for the
peer's ack of our DATA. A SACK overwrote the reassembly cursor, so out-of-order
DATA was misdelivered. Split into `peer_cum_tsn` (peer DATA) and `ack_tsn`
(our send TSNs acked).

### 5. SCTP used the verification tag as the initial TSN

`next_tsn` was seeded from `my_vtag`, while `INIT` advertised
`my_initial_tsn`. A real peer would reject the first DATA. The handshake now
seeds `next_tsn` from `my_initial_tsn`.

### 6. Opus encoder sample format

The libopus encoder rejected `AV_SAMPLE_FMT_FLTP`; it requires interleaved
S16. The encoder now converts planar float to interleaved S16 before
`avcodec_send_frame`. Decoder output is FLTP for tests.

## Verification after fixes

- DTLS loopback: client/server reach `WR_DTLS_DONE`, encrypted app data both ways.
- SCTP handshake: INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, then DATA delivery.
- SCTP reassembly: out-of-order, duplicate, in-order TSNs.
- Opus: encode/decode, 48 kHz stereo, 960-sample frames.
- Debug, media, ASan, standalone fuzz, and `sctp_fsm` all pass.

---

# Pass 4 — transport integration

### 1. `wr_io` could not represent DTLS

SCTP is written against `wr_io`; DTLS is a record protocol, not a socket. Added
`wr_io_dtls_create(underlying, dtls)` and DTLS branches in send/recv/wait. The
wrapper owns a small decrypted-datagram queue and leaves the UDP socket owned
by the underlying `wr_io`.

### 2. `wr_pc` fed STUN into DTLS before ICE finished

Creating the DTLS object early made `pump` route every STUN request into DTLS.
`pump` now routes to DTLS only after `wr_ice_is_complete`; before that it stays
on ICE. DTLS is created at `wr_pc_enable_dtls` so the fingerprint is available
for the SDP offer.

### 3. SCTP ran both sides in INIT_SENT

Both peers called `wr_sctp_start`, so both sent INIT and neither accepted the
other's INIT. Only the controlling/DTLS-client side initiates; the controlled
side waits for INIT. The SCTP FSM now completes the 4-way handshake over DTLS.

### 4. JSEP remote description freed its own credentials

`wr_pc_set_remote_description` parsed into `pc->a` inside an arena mark and
released it before `wr_pc_start`. The remote ufrag/pwd and candidate array were
allocated after the mark, so `wr_ice_start` saw a freed/NULL remote ufrag.
Removed the mark/release; the SDP parse now lives for the PC lifetime (small,
bounded by the SDP size).

### 5. TURN long-term credentials

Added `wr_turn` with Allocate/401 retry, Refresh, CreatePermission, ChannelBind,
and ChannelData. Long-term key is MD5(username:realm:password); the test drives
a fake server response and checks the ChannelData payload.

## Verification after fixes

- `test_pc_dtls`: ICE -> DTLS -> SCTP 4-way -> app data.
- `test_jsep`: offer/answer SDP -> ICE creds/fingerprint -> DTLS -> data.
- `test_turn`: 401 -> auth -> Allocate success -> connect -> ChannelData.
- `wr_fuzz_ice_fsm`: 20k execs clean.
- Debug, media, ASan, standalone fuzz, libFuzzer: pass.

---

# Pass 5 — missed optimizations

### 1. SRTP AES-CM still re-keyed HMAC every packet

The first cached-context pass cached `EVP_CIPHER_CTX` but still called
`HMAC_Init_ex` per packet. The auth key is fixed for the stream, so
`wr_srtp_impl` now stores the post-ipad and post-opad `SHA_CTX` states and the
per-packet path copies them instead of re-initializing. Measured: AES-CM
protect **826 -> 723 ns**, unprotect **759 -> 724 ns**. The context is zeroed
on `wr_srtp_fini`.

### 2. DTLS records allocated an EVP context per record

Each record encrypt/decrypt built a fresh context. The context is now cached in
the cipher and reset per record. DTLS 1200 B stayed at ~222-231 ns, but the
per-record allocation and key setup disappeared.

### 3. Vector reserve was a false win

`wr_vec` growth was changed to reserve in the same allocation as the data.
The benchmark showed no measurable improvement for the sizes used here (tens of
elements), so the extra complexity was not kept as a general policy; the vector
keeps a simple doubling path.

### 4. `wr_u64_map` hashed 8-byte keys through the generic byte hash

A 64-bit key was hashed through the byte-wise hash, which did the same work as
the dedicated 64-bit hash but with a loop. The map now offers a
`*_hash` entry point so callers that already have a hash (or want the 64-bit
hash) avoid re-hashing. Measured hit lookup: 7.9-8.0 ns on a fully populated
table.

### 5. DTLS fuzz target used an uninitialized cipher

Harness bug, not a library bug: `target_dtls.c` called `wr_dtls_decrypt` with
an uninitialized `wr_dtls_cipher`, producing nondeterministic auth failures.
The target now initializes the cipher.

## Current hot-path numbers

As measured after this pass:

| Path | ns/op |
|---|---:|
| SRTP AES-CM protect | ~828 |
| SRTP AES-CM unprotect | ~704 |
| SRTP AES-GCM protect | ~231 |
| DTLS encrypt 1200 B | ~223 |
| DTLS decrypt 1200 B | ~222 |
| RTP parse | 2.6 |
| STUN parse | 18.9 |
| SDP parse | ~751 |
| SCTP parse | ~114 |
| `parse_u64` 19 digits | 5.5 |
| CRC-32c 1200 B | 121 |
| `u64_map` hit | 7.9 |
| pool alloc/free | 5.1 |

These were superseded by later runs in the same pass. The current ranges are in
`docs/PERFORMANCE.md`: AES-CM protect 701.5-783.3 ns, SDP parse 681.4-710.5 ns,
SCTP parse 112.5-116.2 ns. The 751 ns SDP figure was a single run, not a stable
value; the ~828 ns AES-CM figure was a single run before the machine settled.

The earlier `u64_map` hit figure (~14 ns) was invalid: the benchmark's 1 MiB
arena filled after ~11.5k of 100k inserts, so the loop was mostly missing. The
benchmark now uses 64 MiB, pre-sizes the maps, and fails loudly.

## What this does not prove

- Real-browser interop (Chrome/Firefox/libwebrtc) is still untested here.
- TURN server integration and TCP allocations are untested.
- TSAN and long-duration soak runs were not completed in this environment.
- Media codec fuzzing is limited to the RTP payload layer; FFmpeg encode/decode
  is tested with fixed vectors, not fuzzed.

---

# Pass 6 — CRC, chunk vector, bitmap, branch hints

### 1. CRC was byte-at-a-time table lookup

CRC-32c and CRC-32 now use the ARM CRC32 instructions on Apple Silicon
(runtime `_mm_crc32_*` on x86 SSE4.2), with a slice-by-8 table fallback.
CRC-32c on 1200 B: ~121 ns (~9.9 GB/s).

### 2. SCTP input allocated a chunk vector per packet

`wr_sctp_input` now walks up to 16 chunks in a stack array and only falls back
to the arena parser for larger packets. SCTP parse dropped from ~199 ns to
~114 ns.

### 3. Bitmap range set was per-bit

`wr_bitmap_set_range` is word-at-a-time for whole words, with a bit loop only
at the edges. The range sweep test covers every boundary.

### 4. Branch hints / check ordering

Added `WR_UNLIKELY` to the remaining hot validation paths in SDP, DTLS
handshake/record parsing, SCTP parse, SRTP protect/unprotect, and STUN. Error
blocks are now cold; the success path falls through.

### 5. Allocation tracking

`wr_arena` tracks allocation count and requested bytes
(`wr_arena_alloc_count`, `wr_arena_alloc_bytes`). `wr_bench` prints these per
operation. Note that they do not count OpenSSL or FFmpeg `malloc`.

### 6. Measurement bug

The `allocs` column was passed as a literal `0` at every call site, and the map
benchmark used a 1 MiB arena that filled after ~11.5k of 100k inserts. Both
were fixed: allocations are measured, and the map benchmark uses 64 MiB with a
loud failure on any missed insert or lookup.

## Remaining SIMD opportunities

- Custom AES-GCM/GHASH (the cached EVP path is already ~5.2 GB/s for 1200 B).
- SWAR digit parsing is implemented for `wr_parse_u64`. Case-insensitive
  compares remain byte loops; attribute names are short and `memcmp` is
  already vectorized for the equality path.
- A SIMD scan of SDP/ICE/SCTP arrays was prototyped and rejected: the arrays
  are short and the tail handling cost more than the scan saved.

### 7. Fuzzing alone is not enough — deterministic fault injection

Parsers are fuzzed, but fuzzing does not prove protocol behavior under loss.
`test_sctp.c::test_lossy` deterministically drops every 5th datagram and
duplicates every 7th; SCTP RTO/retransmit still delivers the payload.

---

# Pass 7 — broad fuzz campaign, then optimization

## Fuzzing first: 28 targets

Added 19 targets on top of the original nine:

- `sdp_jsep`, `stun_ext`, `rtcp`, `rtp_ext`, `srtp_gcm`, `dtls_record`,
  `dtls_hs_fsm`, `sctp_chunks`, `sctp_fsm2`, `ice_ext`, `turn_fsm`, `pc_jsep`,
  `base_bitmap`, `base_bitio`, `base_map`, `base_pool`, `timer`, `endpoint`,
  `misc`.

The campaign found and fixed:

1. **`wr_rtp_serialize` emitted a padding bit without padding bytes.** Any
   packet parsed with `P=1` serialized to a packet the parser rejected. The
   serializer now rejects `cc`, `ext`, and `padding` as unsupported (the
   header struct does not carry a pad count).
2. **DTLS delivered duplicate application records twice.** `handle_record`
   decrypted and appended every epoch-1 record with no replay window. Added a
   64-entry sliding window and a regression test that feeds the same record
   twice and expects one delivery.
3. **`wr_tsn_set_gaps` could spin on an empty gap.** The first word-scan
   rewrite could compute `run <= i` and fail to advance. Added a
   forward-progress guard and tests for the empty and fully populated windows.

Fuzz-harness bugs (not library bugs): uninitialized `wr_dtls_cipher`,
`wr_span` length after `wr_srtp_protect` (span is by value), missing bounds
checks on `wr_load_be64(data + 8)`, FIR output arrays, and a `str_map` model
that could exceed its tracking array.

## Optimization pass

### SWAR decimal parsing

`wr_parse_u64` parsed one digit at a time. Added `parse8_swar`: load eight
ASCII digits, validate all bytes in parallel with the classic
`(y + 0x4646...) & 0x8080...` test, then fold base-10 -> base-100 ->
base-10000 -> base-1e8. Inputs >= 16 digits use two SWAR words; the remaining
digits fall back to the byte loop. 19 digits: 5.5-5.8 ns.

### SCTP SACK gap scan

`wr_tsn_set_gaps` tested all 8192 bits one at a time. Rewrote it to skip set
runs with `ctz`, and added a naive-reference comparison test
(`test_tsn_gaps`). SACK generation now costs O(words + gaps), not O(bits).

### SDP attribute parsing

Attribute names are short; the parser uses a length-prefixed compare rather
than `strncmp`, and avoids re-scanning the line. SDP parse is ~710 ns for a
1.2 KiB offer with 2 m-lines.

### Allocation reduction

SDP's arena copy of the input is retained deliberately so parsed spans stay
self-contained. STUN and SCTP borrow the packet buffer instead and allocate one
metadata vector. The per-operation counts are in `docs/PERFORMANCE.md`.

### HMAC-SHA1 pad states precomputed

See pass 5; measured 826 -> 723 ns for AES-CM protect.

### Branch hints

See pass 6.

## What the fuzz pass does not prove

- Real-browser interop is untested.
- TURN server and TCP allocations are untested.
- TSAN and soak runs were not done.
- FFmpeg codecs are fixed-vector tested, not fuzzed.

---

# Pass 8 — adversarial black-box audit

The earlier passes trusted their own tests. This pass treated every green test
as a hypothesis and re-probed each parser and state machine with exhaustive or
adversarial input. It found eight defects, three of them memory-safety bugs.

## Fixed

### 1. SWAR decimal parsing accepted non-digit bytes

The lower-bound half of the digit test compared the per-byte flag mask against
zero (`== 0`) instead of requiring every byte's flag to be set. That only
rejected strings in which *all* bytes were below `'0'`, so `wr_parse_u64`
accepted inputs such as `1234567/`, `1234567:`, and `1234567@`. The upper-bound
test alone cannot catch bytes below `'0'`.

Fix: require `((x + 0x5050...) & 0x8080...) == 0x8080...` before the
upper-bound check. Regression: `test_base.c::test_parse_swar` now tries every
byte value 0..255 in all 16 positions of the two-word path, in addition to the
100k-value encoded comparison.

### 2. STUN strict-mode padding check read past the message

An attribute whose value length is not a multiple of four and which ends exactly
at the message boundary passed the value-length check, then the padding loop
read up to three bytes beyond `end`. Liberal mode was unaffected; strict mode
could read past the input buffer.

Fix: validate `off + 4 + alen + pad <= end` before inspecting padding bytes.
Regression: `test_stun.c::test_strict_padding`, with strict mode also enabled
in the `stun` and `stun_ext` fuzz targets.

### 3. DTLS replay window advanced before authentication

`handle_record` called `replay_ok()` before `wr_dtls_decrypt()`. A forged record
with a high sequence number and an invalid tag therefore marked that range as
seen, and a later valid record with the same sequence was silently dropped — a
remote DoS with no key material.

Fix: decrypt and authenticate first; only authenticated records may advance the
window. Regression in `test_dtls_hs.c` feeds an unauthenticated high sequence
followed by the valid record and requires delivery of the valid one.

### 4. SCTP chunk and SACK body lengths overflowed the 16-bit field

`wr_sctp_chunk_serialize` accepted a body larger than `UINT16_MAX - 4`, so the
encoded chunk length wrapped and the receiver mis-split the packet.
`wr_sctp_sack_body` had the same problem when the gap list grew past 65535
bytes.

Fix: reject bodies and SACK bodies above `UINT16_MAX - 4`. Regression:
`test_sctp.c::test_chunk_limits`.

### 5. SCTP `wr_sctp_send_data` could overflow the 2048-byte send buffer

The function copied an application payload into `send_packet`'s fixed buffer
without checking the payload length. A caller passing more than 2020 bytes
overwrote adjacent state.

Fix: reject `data.len > 2020` (12 DATA body + 4 chunk + 12 packet header,
padded) with `WR_ERR_OVERFLOW` before allocating or copying.

### 6. TURN ChannelData receive queue dropped and misparsed datagrams

`wr_turn_recv` zeroed the queue after the first delivery, so a second datagram
already in the queue was lost. Input also stored only the ChannelData payload,
but `recv` ran the framing parser over it, so the next call misread arbitrary
payload bytes as a ChannelData header.

Fix: input stores the complete framed ChannelData; the queue keeps
`queue_off`/`queue_len`, and `recv` parses one frame at a time and compacts
remaining data. Regression: `test_turn.c::test_channel_queue` queues two
datagrams and requires both payloads in order.

### 7. RTCP NACK/FIR length field wrapped at maximum size

RTCP's length field is 16-bit words minus one, but the serializers only checked
the caller's buffer capacity. A NACK with 65535 entries and a FIR with 32768
entries serialized successfully with wrapped length fields (`0` and `1`),
producing a malformed compound packet that the parser would mis-split. Same
class as the SCTP 16-bit length bug.

Fix: `finish()` rejects packets whose word count exceeds `UINT16_MAX + 1`, and
NACK/FIR reject counts above 65534/32767 before their loops. Regression:
`test_rtp.c::test_rtcp_length_limits` checks the largest valid packet and the
first invalid count.

### 8. STUN binding-request builder kept spans to dead stack locals

`wr_stun_build_binding_request` added PRIORITY and ICE-CONTROLLING/CONTROLLED
attributes whose value spans pointed at its own `pri[4]` and `tie[8]` locals.
The returned message outlives the builder, so a later serialize read a dead
stack frame. Invisible to the existing tests because the values happened to be
present, and invisible to the Apple-clang ASan build because
use-after-scope was not enabled. Homebrew clang ASan with
`-fsanitize-address-use-after-scope` reported it immediately.

Fix: allocate and copy the 4/8-byte values from the message arena. Regression:
`test_stun.c::test_roundtrip` clobbers the stack between build and serialize;
`target_stun_ext` serializes and reparses the builder output. The ASan gate
enables use-after-scope for every sanitizer build.

## Additional hardening and cleanup

- SRTP init failure path: `ctx->impl` was left indeterminate if the initial
  `calloc` failed, while the error path calls `wr_srtp_fini`. Set
  `ctx->impl = NULL` before allocating, then publish the partial impl before
  the cleanup call.
- Null guards added to `wr_parse_u64`, `wr_rtp_parse`, `wr_stun_parse`,
  `wr_sctp_walk`/`wr_sctp_parse`, `wr_sdp_serialize` (`!buf && cap != 0`), and
  `wr_endpoint_format`.
- scan-build triage removed dead stores in `openssl_crypto.c`, `handshake.c`,
  and `sctp.c`; fixed an uninitialized `bad[]` read in `test_dtls_hs.c`. One
  benign harness-only `malloc`/`errno` report remains in
  `fuzz/standalone_main.c`.
- Strict-mode coverage added to `target_stun.c` and `target_stun_ext.c`.

## Verification

- Debug, ASan/UBSan (with use-after-scope), `-DWR_MEDIA=ON`, and fresh
  `RelWithDebInfo` builds pass.
- `scripts/build_all.sh`: full `wr_tests` pass in Debug, ASan/UBSan, and
  strict `-O2`.
- All 28 fuzz targets ran clean in the 5 s libFuzzer campaign against this
  code.
- Merged corpus coverage at the time: 73.1% lines, 86.9% functions, 61.0%
  branches. Superseded by the pass-9 measurement in `docs/FUZZING.md`.
- ECDH probe confirmed the derived shared secret matches OpenSSL's
  big-endian representation, independent of the library's own round trip.
- Arena mark/release probe confirmed exact restoration of the bump pointer.
- SCTP scaling probe: draining 1k/5k/10k queued deliveries took
  0.6/16.9/49.6 ms; `wr_sctp_step` scans acknowledged TX history at
  ~0.5-0.7 us per 1k entries.

## Benchmark measurement fixes

Two benchmark defects made earlier numbers untrustworthy:

1. The `allocs` column was a literal `0` at every call site. It now reports
   measured arena bump allocations; it still does not count OpenSSL/FFmpeg.
2. The map benchmark used a 1 MiB arena, which filled after ~11.5k of 100k
   inserts; `wr_u64_map_put` then returned false and the "hit" loop mostly
   missed. The benchmark now uses 64 MiB, pre-sizes the maps, and warns on any
   failed insert or lookup.

Measured after the fix: STUN parse 1.00 arena allocation/op, SDP parse 7.00,
SCTP parse 1.00, zero for RTP/SRTP/DTLS/CRC. `u64_map` hit lookup dropped from
the bogus 14.3 ns to 7.8-8.0 ns on a fully populated table.

## Benchmark-build pitfall

An apparent `parse_u64` regression (5.1 -> 22.6 ns) and SDP regression
(750 -> 2045 ns) was a build-type artifact: `scripts/build_all.sh` leaves
`build/` configured as Debug. A fresh `RelWithDebInfo` build in `build-rel`
measures 5.8 ns for 19-digit `wr_parse_u64` and 710 ns for the 1.2 KiB SDP
parse. Benchmarks must come from the strict `-O2` build.

---

# Pass 10 — real-peer gap analysis (measured)

The first nine passes checked the code against its own tests. This pass checked
it against OpenSSL's DTLS stack and against a realistic message pattern, and
found that several "DONE" items do not survive contact with a real peer. Full
detail and runnable probes are in `docs/GAPS.md` and `docs/probes/`.

The three that matter most:

1. **DTLS cannot interop with OpenSSL.** The server's first flight is a
   `HelloVerifyRequest`; the client has no cookie exchange and ignores handshake
   type 3, so the handshake stalls. The ClientHello also carries no extensions
   at all, so `use_srtp`, `supported_groups`, and `signature_algorithms` are
   missing. Measured: server logs `DTLS1 write hello verify request` and nothing
   else.
2. **DTLS concatenates application records.** Two records in one datagram are
   returned as one span (`'AAAA'` + `'BBBB'` -> `'AAAABBBB'`). The upper layer
   cannot tell where one record ends, so SCTP's CRC covers trailing bytes and
   fails.
3. **That concatenation loses real data.** Through the full
   `wr_pc` -> ICE -> DTLS -> SCTP stack, one message is delivered and three
   back-to-back messages deliver zero. This is not a corner case; it is the
   normal case for any burst.

Two SCTP bugs of the same class as earlier passes:

4. `wr_sctp_input` accepts DATA on an association in `CLOSED`, with an
   arbitrary verification tag, and delivers it to the application.
5. `send_sack` truncates the gap list at 8 blocks; 20 disjoint received runs
   produce `ngaps=8`, so the peer cannot learn about the other 12.

And two performance cliffs:

6. `wr_sctp_step` scans every queued TX entry; with 21k unacked it takes 70 ms
   per call, and the first RTO makes every entry eligible at once.
7. `wr_pc_step` blocks for 10 ms in `wr_io_wait` on every call, so an idle step
   costs 11 ms (22 ms with DTLS).

What this does not change: the codecs, the arena/maps/pool, and the parser
fuzzing results are still valid. What it does change is the claim that the core
is usable as a peer. It is not yet; the blockers are enumerated in
`docs/GAPS.md` with the probes that demonstrate them.

# Pass 9 — SACK gap semantics, module split, measured builds

## 1. SACK gap ack blocks were missing ranges, not received runs

RFC 4960 Section 3.3.4 defines gap ack blocks as contiguous ranges of TSNs
**received** after the cumulative ack point, not the holes between received
TSNs. The original implementation reported the missing ranges. A peer would
have interpreted each block as received and re-SACKed data that had never
arrived, or failed to retransmit genuinely missing chunks.

Fix: `wr_tsn_set_gaps` walks set runs in the receive bitmap and emits
`{cum + 1 + run_start, cum + run_end}` for each contiguous received run. An
empty receive window emits zero gap blocks.

Regression: `test_sctp.c::test_tsn_gaps` compares the optimized scan against a
naive bit-at-a-time reference over a mixed pattern and checks the empty and
fully populated windows. `test_sack_gaps` drives a real association: it feeds
TSNs 1001 and 1003 out of order, reads the wire, parses the SACK chunk, and
requires `cum = 999`, two gap blocks, and `(1001,1001)` plus `(1003,1003)`.

Measured on the final tree (best of 9 runs): empty window ~1.2-1.3 ns, one
received TSN ~4.3-7.9 ns, two received TSNs ~8.7-11.7 ns, 200 singleton runs
~1530 ns. The pre-fix figures were ~102 ns for the empty window and ~76 ns for
one gap. The earlier 19 ns for two gaps was a single mid-range observation; the
best-of-9 value is lower, and the table above reports the measured range.

## 2. Module split along real seams

The library was one large translation unit per protocol. It is now 43 TUs,
split only where the code already had a seam:

| Module | Split |
|---|---|
| sdp | `sdp_parse`, `sdp_serialize`, `sdp_attr`, `sdp_jsep` |
| stun | `stun_msg`, `stun_integrity`, `stun_addr` |
| rtp | `rtp`, `rtcp`, `streams` |
| sctp | `sctp`, `tsn`, `dcep` |
| ice | `ice`, `ice_cand`, `ice_check` |
| dtls | `dtls`, `handshake`, `dtls_crypto` |
| pc | `pc`, `pc_jsep` |
| base | `map_u64`, `map_str`, `pool`, `sb` |

Tightly coupled protocol cores stayed intact: `sctp.c` (886 lines) and
`handshake.c` (809 lines) are still state machines that share too much mutable
state to split without inventing interfaces. Shared private state lives in
`*_internal.h`, and cross-unit functions use the module prefix.

Build evidence: clean `wr` build on 10 cores, `build-rel`, steady state
**0.49-0.50 s** wall across 44 build steps. The 0.55 s figure quoted earlier
includes the first-run overhead.

## 3. Shared builder extraction and the RTCP regression

SDP and RTCP each had their own bounded-buffer writer. Extracted to `wr_sb`
(`include/wr/sb.h` / `src/base/sb.c`). The first version routed BE16/32/64
writes through the variable-size path, which regressed RTCP RR serialization
by roughly 4x (7.8 -> ~31 ns). The builder now keeps a direct-store fast path
for fixed widths, and RTCP RR stays at 7.7-10.2 ns for one report block
(16.1-16.2 ns for four), `parse_one` ~2.2 ns,
`rr_parse` 4.1-4.6 ns for one block and 9.4-9.5 ns for four.

Regression: `test_base.c::test_sb` covers decimal, IPv4, BE writes, truncation
behavior, and zero capacity.

## 4. Parallel fuzz campaign

`fuzz_all.sh` ran targets serially, leaving most cores idle. Targets are
independent processes and each fuzzer is single-threaded, so the fix is
target-level parallelism (`xargs -P`), not worker threads inside each target.
`scripts/fuzz_one.sh` runs one target with its dictionary and log; `fuzz_all.sh`
rebuilds and fans out. Latest campaign: 28 targets, 10 jobs, ~15.05M executions,
clean.

## 5. Coverage refreshed after the split

The 73.1% figure predated the split and the SACK work. Re-measured with the
procedure in `docs/TESTING.md`: **77.69% lines, 86.97% functions, 73.30%
branches, 61.46% regions**. The uncovered list is still not empty: SCTP
INIT/COOKIE, TURN auth/send, DTLS-over-`wr_io`, the `wr_pc` SCTP pump, arena
mark/query, and logging are not fuzzed. Those gaps are listed in
`docs/FUZZING.md` and are not claimed as covered.

## Still not proven

- Real-browser interop, a real TURN server, TCP TURN allocations, TSAN, and
  long-duration soak tests remain outside this environment.
- LeakSanitizer is unavailable on this macOS runtime; no leaks were observed in
  the manual failure-path probes.
- FFmpeg codec wrappers are covered by fixed vectors, not fuzzed.
- No cache-miss `perf` counters; layout claims are inferred from structure and
  scaling.