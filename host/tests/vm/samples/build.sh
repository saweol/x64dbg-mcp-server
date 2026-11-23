#!/usr/bin/env bash
# Build the benign E2E samples (x64 + x32 Windows console exe) into $1 (default: ./out).
set -euo pipefail
ZIG=${ZIG:-zig}
OUT=${1:-"$(dirname "$0")/out"}
mkdir -p "$OUT"
for t in x86_64 x86; do
  "$ZIG" build-exe "$(dirname "$0")/hello.zig" -target "$t-windows-gnu" -O ReleaseSmall -fno-strip \
    --name "e2e_sample_$t" -femit-bin="$OUT/e2e_sample_$t.exe"
done
ls -la "$OUT"/e2e_sample_*.exe
