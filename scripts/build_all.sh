#!/bin/sh
# Full gate: Debug tests, ASan/UBSan tests, then strict -O2 tests.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc)

echo "== Debug =="
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DWR_BUILD_FUZZ=ON -DWR_FUZZ_ENGINE=none
cmake --build build --parallel "$JOBS"
./build/wr_tests

echo "== ASan/UBSan =="
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DWR_SANITIZERS=asan -DWR_BUILD_FUZZ=ON -DWR_FUZZ_ENGINE=none
cmake --build build-asan --parallel "$JOBS"
./build-asan/wr_tests

echo "== Strict -O2 =="
cmake -S . -B build-rel -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWR_WERROR=ON \
  -DWR_HARDENING=ON \
  -DWR_OPT_LEVEL=2 \
  -DWR_BUILD_BENCH=ON
cmake --build build-rel --parallel "$JOBS"
./build-rel/wr_tests
