#!/bin/sh
# Run one libFuzzer target. Invoked by fuzz_all.sh through xargs -P so targets
# fuzz concurrently without oversubscribing each single-threaded process.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
SECS=${1:-5}
T=${2:?target required}

dict=""
case "$T" in
  sdp*|stun*|sctp*|dtls*|rtp*|rtcp)
    base=${T%%_*}
    if [ -f "fuzz/dict/$base.dict" ]; then
      dict="-dict=fuzz/dict/$base.dict"
    fi
    ;;
esac

mkdir -p "fuzz/corpus/$T" "fuzz/run/$T"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  timeout $((SECS + 30)) "./build-fuzz/wr_fuzz_$T" \
  "fuzz/corpus/$T" "fuzz/run/$T" \
  -max_total_time="$SECS" -timeout=5 -rss_limit_mb=2048 \
  -artifact_prefix=fuzz/artifacts/ $dict \
  >"fuzz/run/$T.log" 2>&1
st=$?
if [ "$st" -ne 0 ]; then
  echo "$T: FAILED (exit $st)"
  tail -20 "fuzz/run/$T.log"
  exit 1
fi
runs=$(grep -a -o 'Done [0-9]* runs' "fuzz/run/$T.log" | tail -1)
echo "$T: ${runs:-clean}"
