# Performance and memory

## How these numbers were produced

- Apple M-series (10 performance cores), Homebrew clang, `RelWithDebInfo`,
  `WR_OPT_LEVEL=2`, `build-rel/wr_bench`.
- 1200-byte RTP payload for SRTP/DTLS/CRC paths; 1.2 KiB SDP offer.
- The table reports one run plus the range observed across repeated runs of the
  same binary. Spread is roughly 5-10% on most paths, and wider on SRTP AES-CM
  protect and the string map; treat anything inside the stated range as noise.
- `allocs/op` counts arena bump allocations, not `malloc` inside OpenSSL or
  FFmpeg.

```sh
./scripts/build.sh
./build-rel/wr_bench
```

## Measured hot paths

Single run on the final tree, `build-rel/wr_bench`. The "range" column is the
spread observed across repeated runs of the same binary, including a final
three-run sequence.

| Path | ns/op | Observed range | Throughput | Arena allocs/op |
|---|---:|---:|---:|---:|
| SRTP AES-CM protect | 701.5 | 701.5-783.3 | ~1755 MB/s | 0.00 |
| SRTP AES-CM unprotect | 701.4 | 701.4-707.2 | ~1741 MB/s | 0.00 |
| SRTP AES-GCM protect | 229.6 | 228.4-231.4 | ~5352 MB/s | 0.00 |
| DTLS record encrypt 1200 B | 222.3 | 222.3-231.1 | ~5526 MB/s | 0.00 |
| DTLS record decrypt 1200 B | 221.9 | 221.9-229.2 | ~5536 MB/s | 0.00 |
| RTP parse | 2.6 | 2.6-2.8 | ~471,000 MB/s | 0.00 |
| RTP serialize | 17.9 | 17.6-18.2 | ~68,200 MB/s | 0.00 |
| STUN parse | 18.6 | 18.6-19.3 | ~5263 MB/s | 1.00 |
| STUN parse + attr find | 23.3 | 23.3-24.6 | ~4204 MB/s | 1.00 |
| SDP parse (2 m-lines) | 682.8 | 681.4-710.5 | ~1770 MB/s | 7.00 |
| SDP find media | 14.1 | 13.9-14.8 | - | 0.00 |
| SDP serialize | 457.6 | 455.6-464.6 | ~2682 MB/s | 0.00 |
| SCTP parse | 112.5 | 112.5-116.2 | ~385 MB/s | 1.00 |
| SCTP input DATA | 42.5 | 42.4-43.2 | ~1030 MB/s | 1.00 |
| `parse_u64` 19 digits | 5.5 | 5.5-5.8 | ~3448 MB/s | 0.00 |
| `wr_hash64` over 64 B | 12.4 | 12.4-12.8 | ~5132 MB/s | 0.00 |
| `wr_u64_map` put | 13.2 | 12.7-14.4 | - | 0.00 |
| `wr_u64_map` hit lookup | 7.8 | 7.8-8.0 | - | 0.00 |
| `wr_str_map` put | 82.3 | 80.8-103.2 | - | 0.00 |
| `wr_str_map` hit lookup | 74.0 | 73.6-90.6 | - | 0.00 |
| `wr_pool` alloc+free | 5.0 | 5.0-5.3 | - | 0.00 |
| RTP stream get/update | 6.6 | 6.6-6.9 | - | 0.00 |
| CRC-32c 1200 B | 121.0 | 121.0-126.0 | ~10,141 MB/s | 0.00 |
| CRC-32 1200 B | 121.2 | 121.2-124.5 | ~10,125 MB/s | 0.00 |

The AES-CM protect path is the noisiest: it moved 701.5-783.3 ns across six runs
on the same binary, so only the ~700 ns floor is trustworthy. `str_map_put` and
`str_map_find_hit` also show a wider spread than the other rows because the
benchmark hashes and compares 8-byte keys.

An earlier run on the same machine measured SDP parse at 710 ns and
`str_map_put` at 103 ns. Both are the top of the ranges above, not a regression.
The map lookup row previously quoted ~14 ns came from a benchmark whose arena
filled and mostly missed; it is now 7.8-8.0 ns on a fully populated table.

Focused measurements from the same tree (best of 9 runs, `-O2`, 1 report block):

| Path | ns/op |
|---|---:|
| RTCP RR serialize, 1 block | 7.7-10.2 |
| RTCP RR serialize, 2 blocks | 10.6 |
| RTCP RR serialize, 4 blocks | 16.1-16.2 |
| RTCP `parse_one` | 2.2 |
| RTCP `rr_parse`, 1 block | 4.1-4.6 |
| RTCP `rr_parse`, 4 blocks | 9.4-9.5 |

SCTP gap generation (`wr_tsn_set_gaps`), best of 9 runs:

| Receive state | ns/op | Gap blocks |
|---|---:|---:|
| empty window | 1.2-1.3 | 0 |
| one received TSN | 4.3-7.9 | 1 |
| two received TSNs | 8.7-11.7 | 2 |
| 200 singleton runs | ~1530 | 200 |

## What changed and why

| Change | Measured effect |
|---|---|
| Cached AES-CTR + precomputed HMAC-SHA1 ipad/opad states in SRTP | AES-CM protect 1950 -> 705-729 ns; unprotect 1819 -> 703-724 ns |
| Cached EVP GCM context in SRTP/DTLS | AES-GCM 578 -> 230 ns; DTLS record ~223 -> ~226 ns |
| Hardware CRC-32c + inline 16-entry chunk walk | SCTP parse 199 -> 112-116 ns |
| Word-scan TSN gap generation (bit-at-a-time removed) | empty window ~102 -> 1.2-1.3 ns; one run ~76 -> 4.3-7.9 ns; two runs ~19 -> 8.7-11.7 ns |
| Shared `wr_sb` builder, direct-store BE writes | SDP serialize 0.456-0.465 us; RTCP RR 7.7-10.2 ns for 1 block, 16.1-16.2 ns for 4 |
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