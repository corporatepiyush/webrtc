# wr — WebRTC protocol core in C17

A from-scratch, C17, data-oriented implementation of the WebRTC transport
protocol core, with a broad fuzz harness and measured, reproducible tests.

This is **not** a complete WebRTC stack. It is a deep, buildable core covering
signalling data (SDP/JSEP), ICE, STUN/TURN client framing, a DTLS 1.2
handshake, SRTP, RTP/RTCP, SCTP/DCEP, a PeerConnection that runs SCTP over
DTLS, and an FFmpeg-backed H.264/VP8/Opus media path. Capture/render and a TURN
server are out of scope for this pass; see `docs/STATUS.md` for the exact
matrix.

## Current status

- **Build:** C17, strict warnings (`-Werror`), `-O2`, hardening; OpenSSL 3.5
  LTS. The library is split into 43 translation units for parallel builds.
- **Tests:** Debug, ASan/UBSan, strict `-O2`, and optional FFmpeg builds pass.
- **Fuzzing:** 28 targets, clean in the latest parallel libFuzzer campaign
  (ASan+UBSan, ~15.05M executions).
- **Coverage:** 77.69% of lines, 86.97% of functions, 73.30% of branches,
  61.46% of regions over the merged corpus. Handshake/auth/integration gaps
  remain and are listed in `docs/FUZZING.md`.
- **Hot paths:** measured from `build-rel/wr_bench`; see
  `docs/PERFORMANCE.md`. RTP parse is ~2.8 ns, STUN parse ~19 ns, SDP parse
  ~0.7 us, SRTP AES-GCM ~236 ns for 1200 B.

## Layout

```
include/wr/      public headers
src/base/        arena, span, vec, bitmap, bitio, CRC32/CRC32c, RNG, hash,
                 maps, pool, log, bounded builder (`sb`)
src/net/         endpoints, UDP/DTLS I/O, timers
src/crypto/      OpenSSL backend (AEAD, HMAC, SHA, AES-CTR, ECDH)
src/sdp/         parser, serializer, attribute helpers, JSEP helpers
src/stun/        message codec, integrity/fingerprint, address codec
src/ice/         candidate pairs, checklist, nomination, consent
src/dtls/        record layer, handshake, certificate/key schedule
src/srtp/        AES-CM/HMAC-SHA1-80 and AES-GCM, replay, ROC
src/rtp/         RTP header/ext, RTCP compound, SSRC stream table
src/sctp/        packet/chunk codec, TSN set, DATA/SACK/retransmit, DCEP
src/turn/        TURN client + ChannelData framing
src/media/       RFC 6184/7741/7587 payloaders, H.264/VP8/Opus wrappers
src/pc/          PeerConnection, DTLS transport, JSEP offer/answer
bench/           hot-path benchmark (ns/op, MB/s, allocation counts)
tests/           unit, RFC-vector, loopback, and media integration tests
fuzz/            libFuzzer/AFL-compatible targets + standalone replay driver
docs/            architecture, API, status, review, performance, fuzzing, tests
```

The larger modules are split along real seams — for example `stun_msg.c` /
`stun_integrity.c` / `stun_addr.c`, `rtp.c` / `rtcp.c`, `sctp.c` / `tsn.c` /
`dcep.c`, `ice.c` / `ice_cand.c` / `ice_check.c`, and `handshake.c` /
`dtls_crypto.c`. Tightly coupled state machines stay intact.

## Build and test

Requirements: CMake 3.20+, a C17 compiler, OpenSSL 3.5 LTS (libcrypto).
FFmpeg 7+ is optional and only needed for `-DWR_MEDIA=ON`.

```sh
./scripts/build.sh          # hw-parallel, strict warnings, hardening, -O2
./build-rel/wr_tests
./build-rel/wr_bench
```

The release build lives in `build-rel/` by default. `scripts/build_all.sh`
runs tests in Debug, ASan/UBSan, and strict `-O2` configurations; benchmarks
must be taken from `build-rel/` (or another explicit optimized `BUILD_DIR`).
The strict set is `-Wall -Wextra -Wpedantic -Werror` plus the security
warnings in `cmake/Warnings.cmake`; hardening adds
`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, hidden visibility, and
PIE/RELRO on ELF. To enable the media path:

```sh
cmake -S . -B build-media -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWR_MEDIA=ON
cmake --build build-media --parallel 10
./build-media/wr_tests
```

Sanitizer build:

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DWR_SANITIZERS=asan -DWR_BUILD_FUZZ=ON -DWR_FUZZ_ENGINE=none
cmake --build build-asan
./build-asan/wr_tests
```

Fuzz (standalone mutational driver, works without libFuzzer/AFL):

```sh
./build/wr_fuzz_sdp --fuzz fuzz/corpus/sdp/offer.sdp 100000 1
./build/wr_fuzz_stun --fuzz fuzz/corpus/stun/binding.bin 100000 2
./build/wr_fuzz_srtp --fuzz fuzz/corpus/srtp/rtp.bin 100000 3
./build/wr_fuzz_rtp --fuzz fuzz/corpus/rtp/rtp.bin 100000 4
./build/wr_fuzz_sctp --fuzz fuzz/corpus/sctp/pkt.bin 100000 5
./build/wr_fuzz_dtls --fuzz fuzz/corpus/dtls/rec.bin 100000 6
```

Coverage-guided libFuzzer (requires Homebrew LLVM's clang on macOS):

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
  -DWR_FUZZ_ENGINE=libfuzzer -DWR_SANITIZERS=asan
cmake --build build-fuzz
./scripts/fuzz_all.sh 5          # all 28 targets, parallel
FUZZ_JOBS=4 ./scripts/fuzz_all.sh 30
```

`scripts/fuzz_one.sh` is the per-target runner used by `fuzz_all.sh`; it applies
the correct dictionary and writes `fuzz/run/<target>.log`.

AFL++: build the library and harnesses with `CC=afl-clang-fast`, then run
`afl-fuzz -i fuzz/corpus/<target> -o out -- ./wr_fuzz_<target>`. The harness
implements AFL persistent mode when compiled with `afl-clang-fast`. AFL++ was
not installed in the authoring environment, so that path is unverified here.

## Design notes

- **Arena allocation.** Every protocol object is arena-backed. No per-packet
  `malloc` on the RTP/SRTP/SCTP/ICE hot paths. `wr_arena_mark/release` gives
  O(1) parse scoping, and chunks are cache-line aligned.
- **Parsed-input lifetimes.** SDP copies its input into the arena so parsed
  spans stay self-contained. STUN, SCTP, RTP, and RTCP return spans into the
  caller's packet buffer; keep that buffer alive while using the result.
- **Hot-path data structures.** `wr_u64_map` (open addressing, backward-shift
  deletion, SoA hash/key/value arrays), `wr_str_map` (arena-copied keys),
  `wr_pool` (fixed-capacity free-list pool), and `wr_tsn_set` (8192-bit SCTP
  receive window) replace linear scans. The RTP stream table maps SSRC to a
  pooled `wr_rtp_stream` slot; SRTP keeps reusable cipher/HMAC contexts.
- **Shared bounded builder.** `wr_sb` in `include/wr/sb.h` is the common
  serializer sink. Fixed-width big-endian writes use direct stores; routing
  them through the variable-size path was a measured ~4x regression on RTCP.
- **Zero-copy views.** SDP/STUN/RTP/RTCP/SCTP parsers return spans into the
  input or the arena copy; serializers write into caller buffers with an
  out-length.
- **SoA + bitmaps.** ICE candidates/pairs, SCTP TX/RX queues, SRTP replay, and
  RTP/RTCP report blocks are flat arrays or bitsets, not pointer-chasing lists.
- **Deterministic.** Injectable RNG/clock/I/O; no wall-clock or pointer values
  in protocol decisions. Fuzz artifacts replay byte-for-byte.
- **Strict parsing.** All length fields are validated before use; integer
  overflow is checked; unknown comprehension-required data is rejected in
  strict mode and ignored in liberal mode.
- **Fuzz oracles.** ASan/UBSan (and LSan where the runtime supports it),
  allocation caps, round-trip idempotence, and state-machine assertions.

## Contributing

- Run `./scripts/build_all.sh` and the relevant fuzz targets before
  opening a change; both are the local gate.
- Benchmarks come from `build-rel/`, never from `build/`.
- Do not hand-edit numbers in `docs/`; re-measure and paste the new result.

## Documentation

| File | Contents |
|---|---|
| `docs/ARCHITECTURE.md` | layers, module contracts, translation-unit layout, data flow |
| `docs/API.md` | ownership, status, and usage examples per module |
| `docs/STATUS.md` | feature matrix, measured coverage, remaining gaps |
| `docs/TESTING.md` | test inventory, sanitizers, coverage commands |
| `docs/FUZZING.md` | 28 targets, parallel campaign, corpus, measured coverage |
| `docs/PERFORMANCE.md` | hot-path numbers, allocation profile, build time, budgets |
| `docs/REVIEW.md` | skeptical audit history and fixes |
| `docs/PLAN.md` | historical design plan and milestone mapping |

## License

MIT. See `LICENSE`. OpenSSL is linked for crypto primitives; its license applies
to the linked library.
