#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

CARGO_FLAG="--release"
PROFILE="release"
for arg in "$@"; do
    case "$arg" in
        --debug) CARGO_FLAG=""; PROFILE="debug" ;;
        -h|--help) echo "Usage: ./build.sh [--debug]"; exit 0 ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# Fix MSVC linker PATH on Windows (same as cargo.sh)
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
    MSVC_BIN="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
    if [[ -d "$MSVC_BIN" ]]; then
        export PATH="$MSVC_BIN:$(echo "$PATH" | sed 's|/usr/bin:||')"
    fi
fi

if command -v npm.cmd &>/dev/null; then NPM="npm.cmd"; else NPM="npm"; fi

echo "=== Building frontend ==="
(cd ui && $NPM run build)

echo "=== Building all crates ($PROFILE) ==="
cargo build $CARGO_FLAG

echo "=== Done ($PROFILE) ==="
