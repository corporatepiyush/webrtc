# Performance and memory

## How these numbers were produced

- Apple M-series (10 performance cores), Homebrew clang, `RelWithDebInfo`,
  `WR_OPT_LEVEL=2`, `build-rel/wr_bench`.
- 1200-byte RTP payload for SRTP/DTLS/CRC paths; 1.2 KiB SDP offer.
- Every row is from two back-to-back runs on the final tree; the two runs
  differ by less than 5% on all paths. This machine's run-to-run spread is
  roughly 5-10%, so treat anything inside that band as noise.
- `allocs/op` counts arena bump allocations, not `malloc` inside OpenSSL or
  FFmpeg.

```sh
./scripts/build.sh
./build-rel/wr_bench
```

## Measured hot paths

Two consecutive runs, final tree (older run pair shown where a row has not moved):

| Path | Run 1 | Run 2 | Throughput (run 1) | Arena allocs/op |
|---|---:|---:|---:|---:|
| SRTP AES-CM protect | 701.5 | 719.3 | ~1755 MB/s | 0.00 |
| SRTP AES-CM unprotect | 701.4 | 705.7 | ~1741 MB/s | 0.00 |
| SRTP AES-GCM protect | 229.6 | 230.6 | ~5352 MB/s | 0.00 |
| DTLS record encrypt 1200 B | 227.2 | 225.8 | ~5404 MB/s | 0.00 |
| DTLS record decrypt 1200 B | 225.4 | 222.9 | ~5447 MB/s | 0.00 |
| RTP parse | 2.6 | 2.7 | ~454,000 MB/s | 0.00 |
| RTP serialize | 17.9 | 17.7 | ~68,200 MB/s | 0.00 |
| STUN parse | 18.6 | 19.2 | ~5263 MB/s | 1.00 |
| STUN parse + attr find | 23.3 | 23.8 | ~4204 MB/s | 1.00 |
| SDP parse (2 m-lines) | 682.8 | 689.7 | ~1770 MB/s | 7.00 |
| SDP find media | 14.1 | 13.9 | - | 0.00 |
| SDP serialize | 457.6 | 455.6 | ~2682 MB/s | 0.00 |
| SCTP parse | 112.5 | 113.6 | ~385 MB/s | 1.00 |
| SCTP input DATA | 43.0 | 43.1 | ~1023 MB/s | 1.00 |
| `parse_u64` 19 digits | 5.5 | 5.6 | ~3448 MB/s | 0.00 |
| `wr_hash64` over 64 B | 12.4 | 12.4 | ~5132 MB/s | 0.00 |
| `wr_u64_map` put | 13.2 | 13.2 | - | 0.00 |
| `wr_u64_map` hit lookup | 8.0 | 7.9 | - | 0.00 |
| `wr_str_map` put | 82.3 | 81.0 | - | 0.00 |
| `wr_str_map` hit lookup | 75.1 | 76.5 | - | 0.00 |
| `wr_pool` alloc+free | 5.1 | 5.0 | - | 0.00 |
| RTP stream get/update | 6.6 | 6.6 | - | 0.00 |
| CRC-32c 1200 B | 121.4 | 121.2 | ~10,113 MB/s | 0.00 |
| CRC-32 1200 B | 121.2 | 121.5 | ~10,129 MB/s | 0.00 |

Focused measurements from the same tree:

| Path | ns/op |
|---|---:|
| RTCP RR serialize | 7.8-9.0 |
| RTCP `parse_one` | 2.2 |
| RTCP `rr_parse` | 3.7 |

Run-to-run spread on this table is under 5% except for AES-CM protect, which
moved 701.5-783.3 ns across six runs on the same binary; that path is treated as
noise-band, not a result. The map lookup row previously quoted ~14 ns came from
a benchmark whose arena filled and mostly missed; it is now 7.8-8.0 ns on a
fully populated table.

## What changed and why

| Change | Measured effect |
|---|---|
| Cached AES-CTR + precomputed HMAC-SHA1 ipad/opad states in SRTP | AES-CM protect 1950 -> 705-729 ns; unprotect 1819 -> 703-724 ns |
| Cached EVP GCM context in SRTP/DTLS | AES-GCM 578 -> 230 ns; DTLS record ~223 -> ~226 ns |
| Hardware CRC-32c + inline 16-entry chunk walk | SCTP parse 199 -> 112-116 ns |
| Word-scan TSN gap generation (bit-at-a-time removed) | empty SACK window 102 -> 1.3 ns; two gaps 76 -> 19 ns |
| Shared `wr_sb` builder, direct-store BE writes | SDP/RTCP serializers stay at 0.46/7.8-9.0 us; no regression |
| SWAR decimal parse for `wr_parse_u64` | 19 digits at 5.5-5.8 ns; junk rejection restored |
| Benchmark arena fixed to 64 MiB + pre-size | `u64_map` hit 14.3 -> 8.0 ns on a valid run |

## Rejected or neutral changes

- **Routing fixed-size BE writes through `wr_sb_put_n`.** A variable-size
  `memcpy` path was measured at roughly 4x slower on RTCP RR serialization
  (~7.8 ns to ~31 ns). The direct-store fast path in `include/wr/sb.h` is
  required; keep it.
- **General SIMD scan of SDP attributes / ICE pairs.** Arrays are short
  (single-digit to low tens), and a vector compare plus tail handling did not
  beat a linear scan in the isolated probe. No SIMD packet path was added.
- **Loop fission in `wr_sctp_input_data`.** The current single-pass walk is
  faster than a split parse/dispatch version; the measured 42-43 ns path is
  within the stated variance of the previous 39-41 ns, not a regression.
- **Prefetching in the maps.** No hardware cache-miss counters are available,
  so there is no evidence to justify the extra instruction stream.

## Allocation profile

| Path | Arena allocs/op | Notes |
|---|---:|---|
| SRTP protect/unprotect, DTLS, RTP, CRC, maps, pool | 0.00 | no per-packet allocation |
| STUN parse | 1.00 | one span allocation for the message view |
| SCTP parse | 1.00 | one metadata vector |
| SDP parse (2 m-lines) | 7.00 | input copy + vectors + attribute/media entries |

SDP keeps its arena copy of the input so parsed spans remain self-contained;
that copy is the main per-parse allocation. STUN/SCTP/RTP/RTCP borrow the
caller's packet buffer instead.

## Data-oriented layout

Patterns actually used:

- **Arena bump allocation** with 64-byte-aligned chunk data, mark/release, and
  measured allocation counters.
- **SoA open-addressed maps**: `wr_u64_map` stores hash/key/value in separate
  arrays; `wr_str_map` does the same for string keys. Probes touch the hash
  array first, then one value.
- **Object pool** with a free stack and 64-byte-aligned object block, used by
  the RTP SSRC stream table and SCTP queues.
- **Bitsets**: `wr_tsn_set` is an 8192-bit inline window; SRTP has a replay
  bitmap; `wr_bitmap` covers bitmap users.
- **Zero-copy spans**: STUN attributes, SDP attributes, RTP payloads, and SCTP
  chunks point into the input or the SDP arena copy.
- **Targeted instruction-level work**: hardware CRC-32c and SWAR decimal-digit
  validation. There is no general SIMD packet path and no prefetching.
- The only pointer-chasing list is the arena's chunk chain, touched only when a
  chunk fills.

Not used across all source code:

- Long-lived protocol state is array-of-structs. Measured sizes on this build:
  `wr_ice_cand` 64 B, `wr_ice_pair` 48 B, `wr_ice_check` 32 B, `wr_sctp_tx` 48 B,
  `wr_sctp_rx` 32 B, `wr_sdp_attr` 32 B, `wr_sdp_media` 152 B, and
  `wr_stun_attr` 32 B. Lookups scan these arrays; there is no SoA split, SIMD
  scan, or prefetch.
- `wr_str_map` is not wired into SDP/TURN/ICE attribute lookup; only tests,
  fuzz targets, and the benchmark call it.
- SCTP `wr_sctp_recv` shifts one 32-byte entry per delivery, so draining the
  ready queue is O(n^2): 1k/5k/10k deliveries took 0.6/16.9/49.6 ms.
- SCTP TX history is never pruned. `wr_sctp_step` scans acknowledged entries
  too: 0.67/3.38/7.12 us per step at 1k/5k/10k sends.
- `wr_timer` is a flat AoS array with O(capacity) schedule/cancel/fire scans.
  It is used by tests and the fuzz target, not the protocol core.
- STUN integrity/fingerprint fall back to `malloc` above 1500 covered bytes;
  an incremental HMAC/CRC would remove the temporary copy.
- The DTLS `wr_io` queue is a fixed 2 KiB heap buffer; partial reads `memmove`
  the remainder.

## Build time

Clean `wr` target on 10 cores, `build-rel`, `ninja -t clean` between runs:

| Metric | Result |
|---|---|
| Wall clock (5 runs) | 0.49-0.50 s |
| User CPU | ~2.4 s |
| Translation units | 43 |

The first-run number on a cold cache is ~0.55 s; the steady-state value is
0.49-0.50 s. The split into 43 TUs is what makes the parallel build this short
on 10 cores.

## Budgets

| Path | Budget |
|---|---|
| SDP parse (2 m-lines, 10 codecs) | < 20 us, < 8 KiB arena |
| STUN parse | < 500 ns, 0 malloc |
| ICE check send | < 1 us, 0 malloc |
| SRTP protect 1200 B | < 2 us |
| RTP parse | < 200 ns, 0 malloc |
| SCTP chunk parse | < 300 ns, 0 malloc |
| DTLS record decrypt | < 2 us |

All current measurements are inside these budgets.

## Known gaps

- `wr_stun_verify_integrity` uses a 1500-byte stack buffer; messages larger
  than one MTU still fall back to `malloc`. An incremental HMAC context would
  remove the last copy.
- SCTP congestion control is partial: slow start and congestion avoidance adjust
  `cwnd`/`ssthresh`, but the RTO is still a fixed 1 s (no RACK/CMT).
- `wr_pc` runs ICE -> DTLS -> SCTP over DTLS. The DTLS handshake certificate is
  generated per peer, the dominant setup cost; a cached certificate would speed
  up repeated peer connections but weakens isolation.
- Media codecs use libavcodec/libx264/libvpx; no audio encoder is wired in the
  benchmark path, and there is no capture/render.
- No `perf` cache-miss counters, no TSAN, and no soak run on this machine.