#!/usr/bin/env bash
# Build the deb and the rpm from installer/linux/nfpm.yaml.
#
#   installer/linux/build.sh <version> [outdir]      # after ./build.sh; needs nfpm on PATH
#
# BIN_DIR (default target/release) holds the three binaries. Files in installer/payload/linux
# (README.md and .gitkeep excepted) are installed under /usr/lib/socketguard/third_party/
# (installer/payload/README.md).
set -euo pipefail
cd "$(dirname "$0")/../.."

version="${1:?usage: build.sh <version> [outdir]}"
out="${2:-dist}"
export VERSION="$version" BIN_DIR="${BIN_DIR:-target/release}"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

line=""
if [ -n "$(find installer/payload/linux -type f ! -name .gitkeep ! -name README.md -print -quit)" ]; then
    mkdir "$work/third_party"
    cp -a installer/payload/linux/. "$work/third_party/"
    rm -f "$work/third_party/.gitkeep" "$work/third_party/README.md"
    line="  - src: $work/third_party/
    dst: /usr/lib/socketguard/third_party/
    type: tree"
fi
printf '%s\n' "$line" > "$work/line"
# Replace the marker line with the entry (or with nothing).
awk -v f="$work/line" '/# THIRD_PARTY/ { while ((getline l < f) > 0) if (l != "") print l; next } { print }' \
    installer/linux/nfpm.yaml > "$work/nfpm.yaml"

for t in deb rpm; do
    nfpm package -f "$work/nfpm.yaml" -p "$t" -t "$out"
done
ls -l "$out"
