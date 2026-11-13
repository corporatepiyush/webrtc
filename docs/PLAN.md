# webrtc-c17 — Design plan (historical)

Status: **superseded as an active plan.** The core described here is implemented;
`docs/STATUS.md` is the current feature matrix and `docs/REVIEW.md` is the
current defect log. This file is kept for the design rationale (interfaces,
memory model, parsing policy, milestones) and for the parts that were not built.

Target: a dependency-light, C17, data-oriented implementation of the WebRTC
protocol core, with aggressive fuzzing of every parser and state machine.

Revision 4 (implementation pass): OpenSSL pinned to the 3.5 LTS line, strict
security build flags, a hot-path data-structure layer (wyhash-style hash,
arena-backed open-addressing maps, fixed-size pool, SSRC stream table, SCTP
TSN bitmap with in-order reassembly), an FFmpeg-backed H.264/VP8 codec and RTP
payload layer, and a reproducible benchmark harness.

Revision 5 (what actually shipped): the library is split into 43 translation
units, fuzzing runs targets in parallel through `scripts/fuzz_all.sh`, SACK gap
blocks report received TSN runs per RFC 4960, and coverage is 77.69% of lines
over the merged corpus. The milestone table below is the plan, not a claim about
current state.

## 2. Walking skeleton (M0+M1)

Goal: a runnable program that creates an SDP offer/answer pair, parses it,
gathers a host candidate, sends a STUN binding request over UDP, forms an ICE
check, and reports success.

Exit criteria: `wr_sdp_parse` and `wr_stun_parse` pass RFC vectors; two
`wr_ice_agent`s exchange checks over UDP and reach `SUCCEEDED`; ASan/UBSan
clean. This forces the arena/span/status/timer/socket layers to be real before
any large protocol module is written.

## 3. Layer interfaces

### 3.1 `wr_io` (transport port)

```c
typedef struct wr_io wr_io;

wr_io *wr_io_udp_create(const wr_endpoint *bind, bool nonblocking);
wr_io *wr_io_udp_wrap(int fd);
wr_io *wr_io_dtls_create(wr_io *underlying, struct wr_dtls *dtls);
int wr_io_fd(const wr_io *io);
bool wr_io_local_addr(const wr_io *io, wr_endpoint *out);
wr_status wr_io_send(wr_io *io, const wr_endpoint *dst, wr_span_c data, size_t *sent);
wr_status wr_io_recv(wr_io *io, wr_endpoint *src, wr_span buf, wr_span *out);
wr_status wr_io_wait(wr_io *io, uint32_t timeout_ms, bool *ready);
void wr_io_destroy(wr_io *io);
```

The UDP and DTLS wrappers are implemented. A TCP/TURN transport is an extension
point, not a shipped backend.

### 3.2 `wr_clock`

Time is injected: `wr_pc_step(pc, now_ms)`, `wr_ice_step(ag, now_ms)`,
`wr_dtls_step(d, now_ms)`. Protocol code does not call `clock_gettime`. This is
what makes loopback tests and fuzz schedules deterministic.

### 3.2.1 `wr_rng`

`wr_rng_create` returns an OpenSSL-backed generator. `wr_rng_seed` switches to
xoshiro256** so tests and fuzz targets replay exactly. `wr_rng_fill` and
`wr_rng_u64` are the only entry points used by protocol code.

### 3.3 `wr_crypto`

AEAD, HMAC-SHA1, HMAC-SHA256, SHA-256, AES-CTR, and ECDH keygen/derive are
implemented against OpenSSL 3.x through a vtable in `include/wr/crypto.h`.
Nonce construction, tag-length validation, and key erasure are the caller's
responsibility at this layer; SRTP/DTLS build their own nonces on top.

### 3.4 Memory model

- `wr_arena` uses 64 KiB chunks, 64-byte hot alignment, mark/release, a budget,
  and high-water/allocation counters.
- `wr_vec<T>` is a macro-generated arena-backed vector (`u8`, `u16`, `u32`,
  `u64`, `wr_span_c`, `wr_cand`, `wr_pair`, `wr_chunk_view`, `wr_rtcp_block`,
  and others).
- `wr_bitmap` is a word array with `set`/`clear`/`test`/`set_range`/
  `find_first`/`count`/`iter`.
- There is no `wr_scratch` thread-local arena in the shipped tree; each
  component takes the caller's arena.

### 3.5 Error model

`wr_status` is a packed `(module, code)` u32. `WR_OK` is 0. Out-parameters are
untouched on error. No exceptions, no `longjmp`, no `errno` leakage.

### 3.6 ABI/API policy

The library is a C library, not a frozen C ABI. Headers are C17; `extern "C"`
guards exist for FFI consumers. Struct layouts are not versioned.

## 4. Data structures (v2 detail)

### 4.1 ICE

Candidates and pairs are flat arrays (`wr_ice_cand` is 64 B, `wr_ice_pair`
48 B, `wr_ice_check` 32 B on this build). Lookups are linear scans over arrays that hold single
digits to low tens of entries. State is `NOT_STARTED`, `CHECKING`, `CONNECTED`,
`COMPLETED`, `FAILED`, `CLOSED`. Consent freshness is a timer check, not a
separate thread.

### 4.2 SRTP

`wr_srtp_ctx` holds the profile, keys, salt, ROC, replay bitmap, and an opaque
`impl` pointer to cached cipher/HMAC contexts. `wr_srtp_init` allocates the
contexts; `wr_srtp_fini` frees them. Protect/unprotect do not allocate.

### 4.3 SCTP

`wr_sctp_assoc` holds the TSN set (8192-bit receive window), TX/RX queues
(48/32 B entries), congestion state, and the handshake buffers. DATA is
delivered strictly in TSN order; out-of-order TSNs wait in the set.

### 4.4 DTLS

The record layer is stateless per call (`wr_dtls_cipher` carries the key and
salt). The handshake is a small FSM with an ECDSA P-256 self-signed certificate
and a sliding replay window on epoch-1 records.

## 5. Build matrix

| Build | Purpose | Command |
|---|---|---|
| Debug | fast iteration | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug` |
| ASan/UBSan | memory safety | `-DWR_SANITIZERS=asan` |
| Strict -O2 | benchmarks + release | `scripts/build.sh` -> `build-rel` |
| Coverage | measured line/function/branch | Homebrew clang + profile flags |
| libFuzzer | coverage-guided fuzz | `-DWR_FUZZ_ENGINE=libfuzzer` |
| Media | FFmpeg codecs | `-DWR_MEDIA=ON` |

`scripts/build_all.sh` runs the first three test suites. Fuzzing and coverage
are separate invocations because they need different compilers or engines.

## 6. Fuzzing (v2 refinements)

### 6.1 Deep-state strategy

Stateful targets interpret the input as a schedule of events and drive real
objects: ICE candidate/checklist steps, SCTP DATA/SACK with loss and
duplication, DTLS records with drop/duplicate/replay/reorder, and TURN request
flows. Stateless targets fuzz the codec directly and check round-trip or
bounds invariants.

### 6.2 Invariant checks (compiled in fuzz builds)

SACK gap blocks are sorted and non-overlapping; TSN advance is monotonic;
bitmap counts match a naive reference; maps and pools match a model; RTCP
compound packets walk to exactly the buffer end; RTP headers with unsupported
`CC`/`X`/`P` are rejected rather than emitted malformed.

### 6.3 Failure artifact

libFuzzer writes crashing inputs under `fuzz/artifacts/` with the target
prefix. The standalone driver can replay a single file. There is no per-artifact
trace/hex bundle; the raw input plus the sanitizer log is the reproduction
record.

### 6.4 AFL++ support

The CMake option and harness hooks exist, but AFL++ was not installed in the
authoring environment, so the persistent-mode path is unverified here.

## 7. Test plan

- `tests/test_*.c`: one file per area, linked into a single `wr_tests` binary
  with a small assert harness.
- Shared setup/teardown and assert macros live in `tests/test_util.h`.
- RFC vectors: RFC 3711 (KDF, AES-CM), RFC 7714 (AES-GCM nonce), RFC 8489
  (STUN framing), CRC-32c known values.
- Loopback integration: ICE, SCTP, DTLS, and PC tests open real UDP sockets on
  `127.0.0.1` and use `wr_io_wait` before reads.
- Fault injection: `test_sctp.c::test_lossy` drops/duplicates deterministically;
  `test_dtls_hs.c` does the same for records.
- No CI configuration is checked in. The local gate is
  `scripts/build_all.sh` plus `scripts/fuzz_all.sh`.

## 8. Milestones (plan)

This table is the design target. Delivered status per item is in
`docs/STATUS.md`; nothing here is a claim about the current tree.

| M | Deliverable | Exit criteria |
|---|---|---|
| M0 | Base: status, span, arena, vec, bitmap, bitio, crc32c, io/clock/rng/crypto vtbls, stats, build | unit tests pass; ASan clean; base fuzz targets run clean |
| M1a | SDP parser/serializer | parse/serialize/round-trip; fuzz |
| M1b | STUN message codec + integrity + fingerprint | vectors; fuzz |
| M1c | ICE loopback: host candidates, checklist, binding requests, nomination | two agents SUCCEED over UDP |
| M2 | JSEP offer/answer, BUNDLE, rtcp-mux | deterministic offer/answer; restart |
| M3 | DTLS record layer | epochs, fragmentation, anti-replay |
| M4 | DTLS 1.2 handshake + OpenSSL backend | loopback handshake; encrypted data |
| M5 | SRTP/SRTCP | RFC vectors; replay; ROC wrap |
| M6 | RTP/RTCP + feedback | parse/generate; NACK/PLI/FIR |
| M7 | SCTP packet + CRC32c + association | TSN/retransmit; loss/reorder |
| M8 | DCEP + data channels | open/close/messages |
| M9 | PeerConnection orchestration | offer/answer, data channel e2e |
| M10 | Fuzz matrix, CI, benchmarks, coverage | all green; budgets met or revised with data |

Delivered status per milestone is in `docs/STATUS.md`; the parts that were not
built are the TURN server, TCP TURN, full JSEP renegotiation, jitter buffer/NACK
scheduling, TWCC, capture/render, and real-browser interop.

## 9. Performance budgets (initial)

| Path | Budget |
|---|---|
| SDP parse (10 codecs, 2 m-lines) | < 20 us, < 8 KiB arena |
| STUN parse | < 500 ns, 0 allocations |
| ICE check send | < 1 us, 0 allocations |
| SRTP protect 1200 B | < 2 us |
| RTP parse | < 200 ns, 0 allocations |
| SCTP chunk parse | < 300 ns, 0 allocations |
| DTLS record decrypt | < 2 us |

Measured values are in `docs/PERFORMANCE.md`; all current paths are inside
budget. The numbers come from `build-rel` on an Apple M-series laptop, not from
`perf stat`, because `perf` counters are unavailable there.

## 10. Risks and mitigations

| Risk | Mitigation | Status |
|---|---|---|
| DTLS handshake never converges | implement against RFC + OpenSSL traces; loopback tests | done |
| SCTP state explosion | table-driven chunk dispatch; caps on chunks/gaps | done, partial CC |
| Arena fragmentation | mark/release; budget; high-water tracking | done |
| OpenSSL hidden allocation | document it; measure arena separately | documented |
| Fuzzer stuck at shallow states | dictionaries, seeds, state-machine targets | done for parsers |
| "Complete" creep | non-goals list; status matrix | enforced in docs |
| ABI breakage | no frozen ABI promised | accepted |

## 11. Open questions (historical)

- Should the public API be a stable C ABI? No: C library first, ABI not frozen.
- Is TURN client required for M1? No; client FSM shipped later.
- Which RTCP feedback set is mandatory? NACK, PLI, FIR are implemented; REMB and
  TWCC are not.
- IPv6 link-local with scope IDs? `wr_endpoint` carries a scope, and
  `wr_endpoint_parse`/format handle it, but loopback tests are IPv4-only.
- mbedTLS backend? Future; the `wr_crypto` vtable exists.

## Acceptance checklist (as applied)

- [x] Public headers document ownership and thread-safety (`docs/API.md`).
- [x] Unit tests cover success, truncation, overflow, auth failure, state error.
- [x] Fuzz targets exist for every parser and state machine; run under ASan.
- [x] RFC vectors pass where applicable.
- [x] Round-trip/differential tests pass.
- [x] Zero arena allocations on the per-packet path (measured in `wr_bench`).
- [x] Allocation counters exist and are reported.
- [x] Graceful shutdown path tested for SCTP/DTLS/ICE.
- [x] Benchmark baseline recorded in `docs/PERFORMANCE.md`.
- [ ] 1-hour-per-target fuzz run: not done; latest campaign is 5 s per target
  in parallel (~15.05M execs).
- [ ] LSan leak check: unavailable on this macOS runtime.

## Implementation rules

- One module at a time; compile and test before the next.
- No `TODO` in shipped code.
- Every `malloc`/`free` outside the arena requires a comment and a counter.
- `const` correctness; no aliasing-breaking casts.
- Endian conversion only at the boundary (`wr_load_be*` / `wr_store_be*`).
- No VLAs; fixed caps or arena.
- Error paths free/reset partial state (arena mark/release).
- Fuzz builds define `WR_FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`.

## Deliverables

- [x] `libwr.a`, public headers, CMake target. No `install()` rule or
  package config is shipped; consumers add this tree as a subdirectory.
- [x] `wr_tests` (unit, vector, loopback, media).
- [x] `wr_fuzz_<target>` for 28 targets, standalone and libFuzzer.
- [x] Dictionaries under `fuzz/dict/`.
- [ ] AFL++ scripts: harness hooks exist, runner unverified.
- [x] `docs/ARCHITECTURE.md`, `docs/FUZZING.md`, `docs/TESTING.md`,
  `docs/PERFORMANCE.md`, `docs/API.md`, `docs/STATUS.md`, `docs/REVIEW.md`.
- [x] `scripts/build_all.sh`, `scripts/fuzz_all.sh`, `scripts/fuzz_one.sh`,
  `scripts/build.sh`.
- [x] Loopback demo: two peer connections exchanging a data channel message
  (`tests/test_pc.c`).