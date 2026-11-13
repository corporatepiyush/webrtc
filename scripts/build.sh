#!/bin/sh
# Parallel optimized build with the supported OpenSSL LTS backend.
# Uses -O2, the strict warning set with -Werror, and hardening flags.
# Kept separate from build/ (Debug) and build-asan/ so benchmark numbers
# are never taken from an unoptimized configuration.
set -eu
: "${BUILD_DIR:=build-rel}"
: "${JOBS:=$(sysctl -n hw.ncpu 2>/dev/null || nproc)}"
: "${OPENSSL_ROOT_DIR:=/opt/homebrew/opt/openssl@3}"

cmake -S . -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR" \
  -DWR_BUILD_BENCH=ON \
  -DWR_WERROR=ON \
  -DWR_HARDENING=ON \
  -DWR_OPT_LEVEL=2
cmake --build "$BUILD_DIR" --parallel "$JOBS"
