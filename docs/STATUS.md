# Status matrix

Legend: **DONE** = implemented + tests/fuzz; **PARTIAL** = some codec/state
parts done, not complete; **MISSING** = not implemented in this pass.

Read `docs/GAPS.md` before treating any **DONE** below as "works with a real
peer". The matrix describes the code's own tests and fuzzers; the gaps doc
describes what happens against OpenSSL and a browser.

| Area | Status | Notes |
|---|---|---|
| C17 build, CMake, warnings | DONE | `-O2`, strict warnings, stack/fortify/PIE; OpenSSL 3.5 LTS; 43 library TUs |
| Arena / span / vec / bitmap / bitio | DONE | Bounded arenas, cache-aligned chunks, arena-backed vectors, MSB bit I/O |
| Hash / map / pool | DONE | wyhash-style 64/32-bit hash, arena open-addressing `wr_u64_map`/`wr_str_map`, fixed-size `wr_pool` |
| RTP SSRC stream table | DONE | Pooled `wr_rtp_stream` + SSRC map; seq/timestamp/rollover counters |
| SCTP reassembly | PARTIAL | 8192-bit TSN window and in-order delivery; SACK gap list truncates at 8 blocks, no DATA fragmentation |
| CRC-32 (STUN fingerprint) | DONE | ARM CRC32 / slice-by-8 |
| CRC-32c (SCTP) | DONE | ARM CRC32c / SSE4.2 / slice-by-8 |
| RNG / clock / logging / stats | DONE | OpenSSL RNG; deterministic xoshiro for tests |
| UDP I/O, poll, timers | DONE | Nonblocking UDP, poll wrapper, timer array |
| SDP parser/serializer | DONE | RFC 8866 subset + JSEP attrs; round-trip tests; arena-copied input |
| SDP: full grammar | PARTIAL | `i/u/e/p/b/k/r/z` ignored on serialize; unknown attrs retained only as raw `a=` |
| STUN message codec | DONE | RFC 8489 subset, integrity, fingerprint |
| STUN TURN framing | DONE | ChannelData + Allocate/Refresh/CreatePermission/ChannelBind client FSM |
| ICE agent | DONE | Host/srflx/prflx candidates, checklist, nomination, consent, loopback |
| ICE trickle / restart | PARTIAL | Remote candidates can be added incrementally; restart resets pairs |
| DTLS 1.2 record layer | DONE | Parse/serialize, epoch/seq, AES-GCM encrypt/decrypt, anti-replay fields |
| DTLS handshake FSM | DONE | ClientHello/ServerHello/certificate/ECDHE/Finished over UDP; loopback test |
| DTLS certificate generation/verification | DONE | Self-signed ECDSA P-256, SHA-256 fingerprint, optional peer fingerprint check |
| SRTP AES-CM/HMAC-SHA1-80 | DONE | Protect/unprotect, replay, ROC wrap, RFC 3711 B.2/B.3 vectors, cached AES + HMAC-SHA1 pads |
| SRTP AES-GCM (RFC 7714) | DONE | Protect/unprotect, AAD = RTP header, RFC 7714 16.1.1 vector, cached contexts |
| SRTP key derivation | DONE | RFC 3711 KDF labels 0/1/2 |
| RTP header/ext | DONE | V=2 validation, CSRC, one-byte extensions |
| RTCP compound | DONE | SR/RR/SDES/BYE/NACK/PLI/FIR parse + serialize |
| RTCP: XR, APP, full SDES items | MISSING | Generic APP not exposed |
| Jitter buffer / NACK scheduler | MISSING | Hooks exist in API design; no full implementation |
| SCTP packet/chunk codec | DONE | CRC-32c, all common chunk types parsed; word-scan SACK gaps |
| SCTP association | PARTIAL | 4-way handshake and replay/dedup work; DATA accepted on an unestablished association, RTO retransmits the whole queue, `rwnd` is hardcoded 65535 |
| SCTP congestion control | PARTIAL | Slow start/CA, cwnd/ssthresh on SACK/RTO; fixed 1 s RTO |
| DCEP | DONE | OPEN/ACK serialize/parse |
| Data channels | PARTIAL | In-memory DATA over SCTP in tests; no DCEP channel registry |
| PeerConnection | PARTIAL | ICE -> DTLS -> SCTP works for a single message; back-to-back sends are lost to DTLS record concatenation; no RTP/RTCP/SRTP path |
| JSEP offer/answer state machine | DONE (minimal) | offer/answer SDP, ICE creds/candidates/fingerprint, DTLS + SCTP negotiation |
| Media payload (RTP) | DONE | RFC 6184 H.264 single NAL/FU-A, RFC 7741 VP8, RFC 7587 Opus; fuzzed |
| Media codecs (FFmpeg) | DONE (audio+video) | H.264, VP8, Opus encode/decode; no capture/render |
| TURN server | MISSING | Client FSM only; no TURN server |
| Fuzz: parsers + data structures | DONE | 28 targets, standalone + libFuzzer |
| Fuzz: ICE/DTLS/SCTP state machines | PARTIAL | ICE/SCTP/DTLS FSM targets with drop/duplicate/replay schedules; SCTP INIT/COOKIE and DTLS-over-`wr_io` are deterministic-test-only |
| AFL++ | DONE (harness) | Persistent-mode harness; AFL++ not installed in this environment |

## Measured results

| Check | Result |
|---|---|
| Debug, ASan/UBSan, strict `-O2` tests | all pass |
| FFmpeg media build (`-DWR_MEDIA=ON`) | passes fixed-vector codec tests |
| Clean library build on 10 cores | ~0.49-0.50 s wall (43 TUs) |
| Parallel fuzz campaign, 28 targets, 10 jobs | clean, ~15.05M executions |
| Merged corpus coverage | 77.69% lines, 86.97% functions, 73.30% branches, 61.46% regions |

This is the current measurement. Refresh coverage with the command in
`docs/TESTING.md` after any code change; do not copy the table forward.

## What "done" means here

- Compiles clean with `-Werror` under clang and AppleClang.
- Unit + RFC-vector + loopback tests pass under ASan/UBSan.
- Each parser is reachable from a fuzz target and has run clean under
  libFuzzer with coverage guidance. Coverage is measured, not assumed; see
  `docs/FUZZING.md`.
- `scan-build` reports are triaged; only a benign harness-only `malloc`/`errno`
  diagnostic remains.
- No known crash, OOB, or leak in the fuzzed surface.

## Review findings

See `docs/REVIEW.md` for the skeptical audits. The latest adversarial pass
found and fixed: SWAR decimal parsing accepting non-digits, a strict-mode STUN
padding OOB read, a DTLS replay-window DoS before authentication, SCTP 16-bit
chunk/SACK length overflow, an SCTP send-buffer overflow, TURN ChannelData
queue corruption, RTCP NACK/FIR length-field wrapping, and STUN binding-request
attributes retaining spans to dead stack locals. SACK gap generation was
corrected to emit received TSN runs per RFC 4960. Earlier passes fixed SRTP
KDF/IV/nonce bugs, EC ECDH on OpenSSL 3/4, and SCTP cumulative TSN handling.

## Next milestones

Ordered by measured impact; see `docs/GAPS.md` for the probes and the evidence
behind each item.

1. **DTLS record framing** so multiple records in one datagram are delivered
   separately. This is the cause of the measured data-channel loss on
   back-to-back sends.
2. **DTLS cookie exchange (HelloVerifyRequest)** and a real extensions block
   (`use_srtp`, `supported_groups`, `signature_algorithms`,
   `extended_master_secret`). Without these, no OpenSSL or browser peer can
   complete a handshake.
3. **SCTP state check before DATA** and **complete SACK gap reporting**. A DATA
   chunk on an unestablished association is currently delivered to the app.
4. **SCTP retransmission queue, real `rwnd`, and fragmentation** so a step does
   not scan all queued TX and a message can exceed one MTU.
5. **ICE STUN gathering** for server-reflexive candidates, plus role-conflict
   handling.
6. **Non-blocking `wr_pc_step`** (currently 11-22 ms when idle).
7. TURN TCP allocation and a TURN server for integration tests.
8. Full JSEP rollback/renegotiation and trickle ICE.
9. Jitter buffer, NACK/PLI scheduling, TWCC feedback.
10. Capture/render adapters and cached certificate reuse.
11. Real-browser interop and TSAN/soak runs.