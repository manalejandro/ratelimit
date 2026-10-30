#!/usr/bin/env bash
# Build ASan/UBSan and TSan variants and run the reload-under-load stress
# scenario (scripts/sanitize_stress.py) against both.
#
#   make sanitize
#
# Requires gcc + python3 on the host; no Docker needed.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d "${TMPDIR:-/tmp}/rl-sanitize.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

echo "==> Building with ASan + UBSan…"
make clean >/dev/null
CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=address,undefined" make >/dev/null
cp ratelimit "$TMP/ratelimit-asan"

echo "==> Building with TSan…"
make clean >/dev/null
CFLAGS="-fsanitize=thread -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=thread" make >/dev/null
cp ratelimit "$TMP/ratelimit-tsan"

echo "==> Restoring normal build…"
make clean >/dev/null
make >/dev/null

echo "==> Stress: reloads under load (ASan/UBSan)…"
python3 scripts/sanitize_stress.py "$TMP/ratelimit-asan"
echo "==> Stress: reloads under load (TSan)…"
python3 scripts/sanitize_stress.py "$TMP/ratelimit-tsan"

echo "==> SANITIZERS CLEAN"
