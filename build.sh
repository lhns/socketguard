#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

CARGO_FLAG="--release"
PROFILE="release"
WITH_BUNDLED=0
STAGE=0
STAGE_DIR="dist/stage"
REQUIRE_SIGNATURE=0
usage() {
    cat <<'EOF'
Usage: ./build.sh [--debug] [--with-bundled] [--stage [dir]] [--require-signature]

  --debug               debug build
  --with-bundled        also fetch the pinned Tor, Yggdrasil and Wintun into target/<profile>/third_party,
                        for running the daemon from the build tree (needs network, git, Go)
  --stage [dir]         the tree every package ships (default dist/stage), see docs/packaging.md:
                        the three programs, third_party/ (fetched as above), LICENSE and
                        THIRD_PARTY_NOTICES.md. The directory is emptied first.
  --require-signature   with --stage: fail unless the Tor Project signature of the Tor download is
                        verified (needs gpg; CI sets it)
EOF
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug) CARGO_FLAG=""; PROFILE="debug" ;;
        --with-bundled) WITH_BUNDLED=1 ;;
        --stage)
            STAGE=1
            if [[ $# -gt 1 && "$2" != -* ]]; then STAGE_DIR="$2"; shift; fi
            ;;
        --require-signature) REQUIRE_SIGNATURE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown flag: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
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

# Needs network, git and Go: fetch the pinned Tor, Yggdrasil and Wintun (ADR 0052).
if [[ $WITH_BUNDLED -eq 1 || $STAGE -eq 1 ]]; then
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) HOST_OS="windows"; EXE=".exe" ;;
        Linux) HOST_OS="linux"; EXE="" ;;
        Darwin) HOST_OS="macos"; EXE="" ;;
        *) echo "Unsupported OS for the bundled files: $(uname -s)" >&2; exit 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) HOST_ARCH="x86_64" ;;
        aarch64|arm64) HOST_ARCH="aarch64" ;;
        *) echo "Unsupported CPU for the bundled files: $(uname -m)" >&2; exit 1 ;;
    esac
    FETCH=(bash deploy/bundle/fetch.sh --build-yggdrasil)
    [[ $REQUIRE_SIGNATURE -eq 1 ]] && FETCH+=(--require-signature)
fi

if [[ $WITH_BUNDLED -eq 1 ]]; then
    echo "=== Fetching bundled Tor and Yggdrasil ($HOST_OS-$HOST_ARCH) ==="
    "${FETCH[@]}" "$HOST_OS-$HOST_ARCH" "target/$PROFILE/third_party"
fi

# The staged tree: what every package of this system ships (docs/packaging.md). Packages are made
# from it by installer/*/build.*; the daemon also finds its third_party/ beside itself there.
if [[ $STAGE -eq 1 ]]; then
    echo "=== Staging in $STAGE_DIR ($HOST_OS-$HOST_ARCH) ==="
    [[ -n "$STAGE_DIR" && "$STAGE_DIR" != "/" && "$STAGE_DIR" != "." ]] || { echo "Refusing to empty '$STAGE_DIR'" >&2; exit 1; }
    rm -rf "$STAGE_DIR"
    mkdir -p "$STAGE_DIR"
    for p in socketguard-daemon socketguard socketguard-ui; do
        install -m 0755 "target/$PROFILE/$p$EXE" "$STAGE_DIR/"
    done
    install -m 0644 LICENSE THIRD_PARTY_NOTICES.md "$STAGE_DIR/"
    "${FETCH[@]}" "$HOST_OS-$HOST_ARCH" "$STAGE_DIR/third_party"
    # Tor runs as an unprivileged account (ADR 0052): everyone reads the tree and runs the
    # programs, only the owner writes. Archives extracted by fetch.sh may have left files
    # owner-only.
    chmod -R u+rwX,go+rX,go-w "$STAGE_DIR/third_party"
    echo "--- $STAGE_DIR/third_party/VERSIONS"
    cat "$STAGE_DIR/third_party/VERSIONS"
fi

echo "=== Done ($PROFILE) ==="
