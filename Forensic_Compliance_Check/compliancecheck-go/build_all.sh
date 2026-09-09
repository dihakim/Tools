#!/usr/bin/env bash
# build_all.sh — builds a single static binary per OS/arch, all from this one
# machine. No target OS needed, no install step for the end user: they just
# run the binary for their platform.
set -euo pipefail
cd "$(dirname "$0")"

OUT=dist
rm -rf "$OUT" && mkdir -p "$OUT"

targets=(
  "linux   amd64  compliancecheck-linux-amd64"
  "linux   arm64  compliancecheck-linux-arm64"
  "darwin  amd64  compliancecheck-macos-amd64"
  "darwin  arm64  compliancecheck-macos-arm64"
  "windows amd64  compliancecheck-windows-amd64.exe"
)

for t in "${targets[@]}"; do
  read -r os arch name <<< "$t"
  echo "Building $name ..."
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" \
    -o "$OUT/$name" ./cmd/compliancecheck
done

echo
echo "Done. Binaries in $OUT/:"
ls -lh "$OUT"
