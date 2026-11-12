#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

CARGO_FLAG="--release"
PROFILE="release"
WITH_BUNDLED=0
for arg in "$@"; do
    case "$arg" in
        --debug) CARGO_FLAG=""; PROFILE="debug" ;;
        --with-bundled) WITH_BUNDLED=1 ;;
        -h|--help) echo "Usage: ./build.sh [--debug] [--with-bundled]"; exit 0 ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# On Windows the Bash /usr/bin/link.exe shadows the MSVC linker: put the MSVC bin dir first on PATH.
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
    MSVC_BIN="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
    if [[ -d "$MSVC_BIN" ]]; then
        export PATH="$MSVC_BIN:$(echo "$PATH" | sed 's|/usr/bin:||')"
    fi
fi

echo "=== Checking versions ==="
bash deploy/ci/check-version.sh

if command -v npm.cmd &>/dev/null; then NPM="npm.cmd"; else NPM="npm"; fi

echo "=== Building frontend ==="
(cd ui && $NPM run build)

echo "=== Building all crates ($PROFILE) ==="
cargo build $CARGO_FLAG

# Optional, needs network, git and Go: fetch the pinned Tor, Yggdrasil and Wintun (ADR 0052).
if [[ $WITH_BUNDLED -eq 1 ]]; then
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) HOST_OS="windows" ;;
        Linux) HOST_OS="linux" ;;
        Darwin) HOST_OS="macos" ;;
        *) echo "Unsupported OS for --with-bundled: $(uname -s)" >&2; exit 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) HOST_ARCH="x86_64" ;;
        aarch64|arm64) HOST_ARCH="aarch64" ;;
        *) echo "Unsupported CPU for --with-bundled: $(uname -m)" >&2; exit 1 ;;
    esac
    echo "=== Fetching bundled Tor and Yggdrasil ($HOST_OS-$HOST_ARCH) ==="
    bash deploy/bundle/fetch.sh --build-yggdrasil "$HOST_OS-$HOST_ARCH" "target/$PROFILE/third_party"
fi

echo "=== Done ($PROFILE) ==="
