#!/bin/sh
# Run every libFuzzer target for a bounded time. Usage:
#   scripts/fuzz_all.sh [seconds_per_target]
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SECS=${1:-15}
JOBS=${FUZZ_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}
TARGETS="sdp stun srtp rtp sctp dtls rtppay sctp_fsm ice_fsm
sdp_jsep stun_ext rtcp rtp_ext srtp_gcm dtls_record dtls_hs_fsm
sctp_chunks sctp_fsm2 ice_ext turn_fsm pc_jsep
base_bitmap base_bitio base_map base_pool timer endpoint misc"

# Always reconfigure and rebuild: fuzzing a stale binary after a source edit
# produces meaningless coverage results.
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWR_FUZZ_ENGINE=libfuzzer \
  -DWR_SANITIZERS=asan \
  -DWR_BUILD_FUZZ=ON \
  -DWR_WERROR=ON \
  -DWR_HARDENING=ON \
  -DWR_OPT_LEVEL=2
cmake --build build-fuzz --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

mkdir -p fuzz/artifacts
COUNT=$(printf '%s\n' $TARGETS | wc -l | tr -d ' ')
echo "Fuzzing $COUNT targets with $JOBS parallel jobs"
printf '%s\n' $TARGETS | xargs -n1 -P "$JOBS" "$ROOT/scripts/fuzz_one.sh" "$SECS"