# Fuzzing

## Targets

| Target | Entry point | Oracle |
|---|---|---|
| `wr_fuzz_sdp` | `wr_sdp_parse` + serialize/reparse | No crash/leak; serializer output must re-parse |
| `wr_fuzz_sdp_jsep` | SDP parse/serialize, JSEP helpers, attr mutation | round-trip, no OOB |
| `wr_fuzz_stun` | `wr_stun_parse` + fingerprint/integrity/serialize | verify never reads OOB |
| `wr_fuzz_stun_ext` | structured attr build, integrity/fingerprint, address, ChannelData, builder serialize | no dangling spans |
| `wr_fuzz_srtp` | `wr_srtp_init/protect/unprotect` | auth failure never returns OK |
| `wr_fuzz_srtp_gcm` | AES-GCM protect/unprotect/replay/ROC | no OOB, replay enforced |
| `wr_fuzz_rtp` | `wr_rtp_parse` + compound parse | length fields validated |
| `wr_fuzz_rtp_ext` | RTP serialize/reparse, extensions, stream table | header/length invariants |
| `wr_fuzz_rtcp` | compound walk, SR/RR/SDES/BYE/NACK/PLI/FIR | packet boundaries |
| `wr_fuzz_rtppay` | H.264/VP8 depacketize + packetize | FU-A/STAP lengths validated |
| `wr_fuzz_sctp` | `wr_sctp_parse` | CRC checked before chunk iteration |
| `wr_fuzz_sctp_chunks` | chunk builders, DCEP, TSN set | length limits, TSN invariants |
| `wr_fuzz_sctp_fsm` | DATA/SACK FSM on established associations | state/ack invariants |
| `wr_fuzz_sctp_fsm2` | two associations, lossy/duplicating pumps, timers | no OOB, progress |
| `wr_fuzz_ice_fsm` | candidate/checklist/start/step FSM | state transitions |
| `wr_fuzz_ice_ext` | candidate churn, restart, consent | no OOB |
| `wr_fuzz_dtls` | record parse/decrypt/encrypt, handshake parse | tag check before output |
| `wr_fuzz_dtls_record` | record/handshake codec, encrypt/decrypt/tamper | auth failure path |
| `wr_fuzz_dtls_hs_fsm` | two DTLS instances, drop/duplicate/replay/reorder | handshake converges |
| `wr_fuzz_turn_fsm` | TURN allocate/auth/permission/channel | no OOB, status invariants |
| `wr_fuzz_pc_jsep` | offer/answer/remote description + `wr_pc` lifecycle | no crash, state valid |
| `wr_fuzz_base_bitmap` | bitmap model comparison | model equality |
| `wr_fuzz_base_bitio` | bit reader/writer + truncation sweep | read/write agreement |
| `wr_fuzz_base_map` | u64/str map model comparison | model equality |
| `wr_fuzz_base_pool` | pool alloc/free/index/at invariants | no alias |
| `wr_fuzz_timer` | schedule/cancel/fire/next-deadline model | model equality |
| `wr_fuzz_endpoint` | text/sockaddr round-trips, truncation | no OOB |
| `wr_fuzz_misc` | spans, decimal parse, hashes, CRC vectors, status | no crash |

All targets are built with ASan+UBSan in `build-fuzz`. Each is single-threaded;
concurrency comes from running targets in parallel, not from fuzzer workers.

## Run

### One target

```sh
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
  -DWR_FUZZ_ENGINE=libfuzzer -DWR_SANITIZERS=asan
cmake --build build-fuzz
mkdir -p fuzz/run/stun
./build-fuzz/wr_fuzz_stun fuzz/corpus/stun fuzz/run/stun -max_total_time=300 \
  -dict=fuzz/dict/stun.dict -artifact_prefix=fuzz/artifacts/
```

### All targets, in parallel

```sh
./scripts/fuzz_all.sh 5           # 5 s per target
FUZZ_JOBS=4 ./scripts/fuzz_all.sh 60
```

`fuzz_all.sh` always reconfigures and rebuilds `build-fuzz` first: fuzzing a
stale binary after a source edit produces meaningless coverage. It then invokes
`scripts/fuzz_one.sh` through `xargs -P "$JOBS"`; `FUZZ_JOBS` defaults to the
CPU count. Per-target logs land in `fuzz/run/<target>.log`, and the runner
prints the final `Done N runs` line.

### Standalone mutational driver (no engine required)

```sh
./build-asan/wr_fuzz_sdp --fuzz fuzz/corpus/sdp/offer.sdp 100000 1
```

The driver reads a seed, applies deterministic bit flips/insertions, and calls
`LLVMFuzzerTestOneInput` in-process. Exit on sanitizer abort.

### AFL++

AFL++ was not installed in the authoring environment, so this path is
unverified here. The harness supports persistent mode (`__AFL_LOOP`):

```sh
CC=afl-clang-fast cmake -S . -B build-afl -G Ninja -DWR_FUZZ_ENGINE=afl
cmake --build build-afl
afl-fuzz -i fuzz/corpus/stun -o out -m none -d -- ./build-afl/wr_fuzz_stun
```

## Corpus

- `fuzz/corpus/sdp/offer.sdp` — realistic BUNDLE offer
- `fuzz/corpus/stun/binding.bin` — minimal Binding Request
- `fuzz/corpus/srtp/rtp.bin` — RTP packet
- `fuzz/corpus/rtp/rtp.bin` — RTP packet
- `fuzz/corpus/sctp/pkt.bin` — CRC-valid DATA packet
- `fuzz/corpus/dtls/rec.bin` — DTLS record
- `fuzz/corpus/rtppay/seed.bin` — RTP packet
- `fuzz/corpus/sctp_fsm/seed.bin` — valid SCTP DATA packet
- `fuzz/corpus/ice_fsm/seed.bin` — STUN Binding seed

Every coverage-increasing input is retained, so a corpus is both a seed set and
a regression set. Corpus sizes are uneven: `sdp` and `sdp_jsep` have thousands
of inputs, while `srtp`, `dtls`, and `srtp_gcm` have tens.

## Dictionaries

`fuzz/dict/*.dict` contain STUN attribute/method tokens, SDP lines, RTCP
payload types, SCTP chunk types, and DTLS content/handshake types. `fuzz_one.sh`
applies `fuzz/dict/<base>.dict` when it exists.

## Latest campaign

28 targets, 10 parallel jobs, 5 s per target, ASan+UBSan+libFuzzer, fresh
rebuild. **~15.05M executions, no crashes.**

| Target | Runs | Target | Runs |
|---|---:|---|---:|
| `rtp` | 3,435,632 | `dtls` | 2,830,499 |
| `sctp` | 1,765,290 | `misc` | 857,228 |
| `stun` | 833,845 | `rtcp` | 719,759 |
| `srtp` | 645,557 | `rtppay` | 536,956 |
| `endpoint` | 464,955 | `sctp_fsm` | 443,353 |
| `dtls_record` | 431,894 | `rtp_ext` | 360,150 |
| `srtp_gcm` | 328,265 | `timer` | 292,363 |
| `base_pool` | 206,964 | `sdp` | 197,502 |
| `stun_ext` | 190,875 | `sctp_chunks` | 147,226 |
| `sdp_jsep` | 102,393 | `base_bitmap` | 85,035 |
| `ice_fsm` | 56,255 | `ice_ext` | 50,440 |
| `turn_fsm` | 29,151 | `base_map` | 24,728 |
| `base_bitio` | 8,957 | `pc_jsep` | 4,670 |
| `sctp_fsm2` | 1,305 | `dtls_hs_fsm` | 985 |

An earlier run on the same tree produced ~13.1M executions with the same clean
result; the difference is scheduling, not code. The earlier 15 s serial campaign
produced a different shape (rtp 14.15M, dtls 11.08M, sctp 6.28M) but took far
longer wall-clock for the same target count. Stateful targets do socket/DTLS/
arena setup per input, so they receive two to three orders of magnitude fewer
mutations than the stateless parsers.

## Measured coverage, not run counts

Corpus execution is not the same as fuzzing, but it is what the fuzzer learned:
every coverage-increasing input is retained. Coverage was measured by building
with Homebrew clang, `-fprofile-instr-generate -fcoverage-mapping`, executing
each target with `-runs=0` over its corpus (seeds plus all discovered inputs),
merging all `.profraw` files, and reporting with `llvm-cov` against a
whole-archive link of the library. The exact command is in `docs/TESTING.md`.

Merged library coverage (tests/fuzz/bench excluded):

| Metric | Covered | Total | Percent |
|---|---:|---:|---:|
| Lines | 5,959 | 7,670 | 77.69% |
| Functions | 414 | 476 | 86.97% |
| Branches | 2,845 | 3,888 | 73.30% |
| Regions | 6,295 | 7,974 | 61.46% |

This is the current measurement. The 73.1% / 86.9% / 61.0% / 77.4% figures
in older documents predate the module split and the SACK/TSN work. Re-run the
procedure above after any code change; do not copy the table forward.

Lowest per-file line coverage:

| File | Lines | Percent |
|---|---:|---:|
| `src/base/log.c` | 0/37 | 0.0% |
| `src/ice/ice_check.c` | 62/265 | 25.8% |
| `src/turn/turn.c` | 133/325 | 47.8% |
| `src/net/io.c` | 91/224 | 44.3% |
| `src/base/arena.c` | 87/158 | 54.2% |
| `src/sdp/sdp_attr.c` | 25/43 | 58.1% |
| `src/pc/pc.c` | 127/240 | 57.4% |

## What the fuzzer does not reach

- **SCTP INIT/COOKIE**: `handle_init`, `handle_init_ack`,
  `handle_cookie_echo`, `handle_cookie_ack`, `send_init`, `send_handshake`,
  and `wr_sctp_start` have no fuzz coverage. They are driven by
  `test_sctp.c::test_handshake` and the loopback PC test.
- **TURN auth/send paths**: `long_term_key`, `parse_error`,
  `send_create_permission`, `send_channel_bind`.
- **ICE helpers**: `all_pairs_done`, `find_local_for_addr`,
  `find_remote_for_addr`, `is_valid_username`, `mark_pair_success`.
- **PC data path**: `pump_sctp`, `start_sctp`.
- **IO wrappers**: `wr_io_dtls_create`, `wr_io_fd`, `wr_io_udp_wrap`.
- **Arena mark/query and logging**: `wr_arena_mark_save/release/reset`,
  `wr_log_*`.
- **FFmpeg codec wrappers**: fixed-vector tested, not fuzzed.
- **Large-parameter paths**: `target_rtcp` parses at most one NACK FCI;
  `target_sctp_chunks` caps a chunk body at 256 bytes. The RTCP maximum and
  the 2,020-byte SCTP send boundary are covered by deterministic tests only.

## Fuzzing is not sufficient

The campaign is paired with deterministic oracles: RFC vectors, model-based
bitmap/map/pool/timer checks, lossy SCTP/DTLS pumps, and a full loopback
`test_pc`. Interop with real WebRTC stacks and a real TURN server are still
outside this environment. LeakSanitizer is unavailable on this macOS runtime,
TSAN is not run, and the FFmpeg path is fixed-vector tested rather than fuzzed.