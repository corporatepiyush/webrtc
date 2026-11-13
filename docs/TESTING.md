# Testing

## Test binary

`wr_tests` contains all unit, vector, and loopback tests. It is a single binary
with a tiny assert harness (no external test framework).

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/wr_tests
```

The release, Debug, ASan/UBSan, and optional media builds use the same test
binary; only the compiler flags differ.

## Test inventory

| File | Covers |
|---|---|
| `tests/test_base.c` | spans, integer parse (incl. exhaustive SWAR), arena budget/mark/counters, bitmap, bit I/O, CRC-32c lengths, CRC-32, hashes, endpoint parse/format, RNG, `wr_sb` builder |
| `tests/test_data.c` | hash determinism, `wr_u64_map` insert/lookup/erase stress, `wr_str_map` insert/update, pool alignment/index round-trip, RTP stream rollover, SCTP TSN window ordering |
| `tests/test_sdp.c` | realistic offer, media/attr parsing, ICE/fingerprint/candidate/extmap/rtcp-fb, serialize round-trip, malformed input |
| `tests/test_stun.c` | type encode/decode, XOR-MAPPED v4/v6, Binding Request + integrity + fingerprint, tamper/replay, strict padding, builder stack-clobber, TURN ChannelData |
| `tests/test_ice.c` | two agents over loopback UDP reach COMPLETED; candidate pair priority |
| `tests/test_srtp.c` | AES-CM protect/unprotect, replay, tamper, ROC wrap, AES-GCM round-trip |
| `tests/test_rtp.c` | RTP parse/serialize/ext, RTCP SR/RR/compound/SDES, NACK/PLI/FIR, RTCP length limits |
| `tests/test_sctp.c` | chunk codec, CRC, DCEP open/ack, two associations over UDP, handshake, DATA/SACK/retransmit, out-of-order/duplicate reassembly, lossy pump, TSN gap scan, SACK gap wire format, chunk/send limits |
| `tests/test_dtls.c` | record parse/serialize, AES-GCM encrypt/decrypt/tamper, handshake framing, PRF determinism |
| `tests/test_dtls_hs.c` | two DTLS instances over UDP loopback; certificate fingerprints, ECDHE, Finished, encrypted app data, replay window |
| `tests/test_crypto.c` | AEAD, AES-CM keystream, AES-GCM vector, ECDH agreement |
| `tests/test_pc.c` | two PeerConnections: ICE -> SCTP -> data channel "hello"/"world"; PC over DTLS; JSEP offer/answer |
| `tests/test_turn.c` | TURN Allocate 401 retry, success, connect, ChannelData, queued ChannelData order |
| `tests/test_media.c` | H.264 single NAL/FU-A, VP8 fragmentation, Opus passthrough |
| `tests/test_media_codec.c` | `-DWR_MEDIA=ON`: H.264/VP8/Opus encode -> RTP packetize -> depacketize -> decode |

## Shared test helpers

`tests/test_util.h` holds the common assert macros and setup/teardown helpers.
Protocol tests share loopback and arena setup there rather than copying it, so
a new test adds assertions and not another private harness.

## Loopback tests

The ICE, SCTP, DTLS, and PC tests create real UDP sockets on `127.0.0.1` and
exchange packets in-process. They use `wr_io_wait` before each read to avoid the
loopback "packet not queued yet" race. They are deterministic in protocol
decisions; only the ephemeral port numbers vary.

## Sanitizers

```sh
cmake -S . -B build-asan -G Ninja -DWR_SANITIZERS=asan
cmake --build build-asan
./build-asan/wr_tests
```

ASan+UBSan pass clean. The ASan configuration enables
`-fsanitize-address-use-after-scope`; this is required to catch a builder that
stores a span to its own stack frame, which the default Apple-clang ASan build
did not report. LSan is not supported by the macOS runtime used here; run on
Linux with `ASAN_OPTIONS=detect_leaks=1` for leak checking. TSAN is not
configured or run.

## Fuzz regression

Each parser has a libFuzzer target and a seed. Before merging a parser change:

```sh
./build-fuzz/wr_fuzz_<name> fuzz/corpus/<name> -max_total_time=60
```

Run the standalone mutational driver too; it catches crashes without needing
libFuzzer installed.

## Coverage

The 77.69% line / 86.97% function figures in the docs come from executing the
merged fuzz corpus, not from the unit tests. To reproduce them after any code
change:

```sh
# 1. Coverage build with Homebrew clang (the Apple clang does not ship llvm-cov).
cmake -S . -B build-cov -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
  -DCMAKE_C_FLAGS='-fprofile-instr-generate -fcoverage-mapping' \
  -DWR_FUZZ_ENGINE=libfuzzer -DWR_SANITIZERS=asan

# 2. Run every target over its retained corpus once.
rm -rf build-cov/prof && mkdir -p build-cov/prof
TARGETS="sdp stun srtp rtp sctp dtls rtppay sctp_fsm ice_fsm
sdp_jsep stun_ext rtcp rtp_ext srtp_gcm dtls_record dtls_hs_fsm
sctp_chunks sctp_fsm2 ice_ext turn_fsm pc_jsep
base_bitmap base_bitio base_map base_pool timer endpoint misc"
printf '%s\n' $TARGETS | xargs -n1 -P "$(sysctl -n hw.ncpu)" sh -c \
  'ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 LLVM_PROFILE_FILE="build-cov/prof/$1-%p-%m.profraw" ./build-cov/wr_fuzz_$1 "fuzz/corpus/$1" -runs=0 -timeout=10 >/dev/null 2>&1 || echo "$1 FAILED"' sh

# 3. Link a whole-archive coverage binary and report.
/opt/homebrew/opt/llvm/bin/clang -arch arm64 \
  -fprofile-instr-generate -fcoverage-mapping -fsanitize=address \
  build-cov/cov_main.c -Wl,-all_load build-cov/libwr.a \
  -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o build-cov/wr_cov_all
/opt/homebrew/opt/llvm/bin/llvm-profdata merge -sparse build-cov/prof/*.profraw \
  -o build-cov/merged.profdata
/opt/homebrew/opt/llvm/bin/llvm-cov report build-cov/wr_cov_all \
  -instr-profile=build-cov/merged.profdata \
  -ignore-filename-regex='(tests|fuzz|bench)/'
```

The `cov_main.c` entry point is a trivial `main`; it exists only so the static
library can be linked and profiled as a whole. Coverage is corpus-based and
therefore an undercount: paths only reachable with a live socket, a TURN
server, or FFmpeg are not exercised.

## Measurement rules

- Benchmarks come from `build-rel/` (strict `-O2`, `RelWithDebInfo`). The
  Debug build is 3-4x slower and is not comparable.
- Run-to-run variance on this laptop is roughly 5-10%; do not treat a
  sub-10% change as a result.
- Allocation counts in `wr_bench` are arena bump allocations, not OpenSSL or
  FFmpeg `malloc`s.
- Cache-miss `perf` counters were not available; layout claims are inferred
  from structure and scaling, not hardware counters.

## Verification commands

```sh
./scripts/build_all.sh          # Debug + ASan/UBSan + strict -O2 tests
./scripts/fuzz_all.sh 15        # 28 libFuzzer targets, parallel
./scripts/build.sh && ./build-rel/wr_tests && ./build-rel/wr_bench
```