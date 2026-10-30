#!/usr/bin/env bash
# Build the ratelimit .deb inside Docker and export it to ./dist
set -euo pipefail
cd "$(dirname "$0")/.."

V_CODE="$(sed -nE 's/.*RATELIMIT_VERSION[[:space:]]*"([^"]+)".*/\1/p' src/common.h)"
V_DEB="$(sed -nE '1s/^ratelimit \(([^)]+)\).*/\1/p' debian/changelog)"

if [[ -z "$V_CODE" || -z "$V_DEB" || "$V_CODE" != "$V_DEB" ]]; then
    echo "ERROR: version mismatch: src/common.h='$V_CODE' debian/changelog='$V_DEB'" >&2
    exit 1
fi

echo "==> Building ratelimit ${V_CODE} .deb in Docker (debian:bookworm)…"
mkdir -p dist
rm -f dist/ratelimit*.deb dist/ratelimit*.changes dist/ratelimit*.buildinfo

DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile.build \
    --target dist --output type=local,dest=dist .

echo
echo "==> Artifacts:"
ls -l dist/
test -n "$(ls dist/ratelimit_*.deb 2>/dev/null)" || { echo "ERROR: no .deb produced" >&2; exit 1; }
