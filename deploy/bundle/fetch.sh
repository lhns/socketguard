#!/bin/bash
# Fetch the pinned third-party files SocketGuard ships (ADR 0052) and lay them out:
#
#   <outdir>/tor/tor(.exe) + libs        Tor Expert Bundle, checksum- and signature-verified
#   <outdir>/yggdrasil/yggdrasil(.exe)   built from the pinned commit (--build-yggdrasil)
#   <outdir>/yggdrasil/wintun.dll        Windows only, pinned checksum
#   <outdir>/licenses/<name>.txt
#   <outdir>/VERSIONS
#
# Pins live in versions.toml next to this script. Nothing is installed or run.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: fetch.sh [--require-signature] [--build-yggdrasil] [--skip-tor] [--skip-yggdrasil] <os>-<arch> <outdir>

  <os>-<arch>          windows-x86_64 | linux-x86_64 | linux-aarch64 | macos-x86_64 | macos-aarch64
  --require-signature  fail if gpg is missing or the Tor checksum signature cannot be verified
  --build-yggdrasil    build yggdrasil from the pinned commit (needs git and Go)
  --skip-tor           do not fetch Tor
  --skip-yggdrasil     skip Yggdrasil and Wintun entirely

Environment: SOCKETGUARD_BUNDLE_CACHE (default <repo>/target/bundle-cache),
             SOCKETGUARD_GPG (gpg command, default gpg).
EOF
}

die() { echo "fetch.sh: error: $*" >&2; exit 1; }
say() { echo "fetch.sh: $*"; }

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TOML="$HERE/versions.toml"
CACHE="${SOCKETGUARD_BUNDLE_CACHE:-$REPO/target/bundle-cache}"
GPG="${SOCKETGUARD_GPG:-gpg}"

REQUIRE_SIG=0; BUILD_YGG=0; SKIP_TOR=0; SKIP_YGG=0
POS=()
for arg in "$@"; do
    case "$arg" in
        --require-signature) REQUIRE_SIG=1 ;;
        --build-yggdrasil) BUILD_YGG=1 ;;
        --skip-tor) SKIP_TOR=1 ;;
        --skip-yggdrasil) SKIP_YGG=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; die "unknown flag: $arg" ;;
        *) POS+=("$arg") ;;
    esac
done
[[ ${#POS[@]} -eq 2 ]] || { usage >&2; exit 1; }
TARGET="${POS[0]}"
mkdir -p "${POS[1]}" "$CACHE"
OUT="$(cd "${POS[1]}" && pwd)"
CACHE="$(cd "$CACHE" && pwd)"

case "$TARGET" in
    windows-x86_64) GOOS=windows; GOARCH=amd64; EXE=.exe ;;
    windows-aarch64) GOOS=windows; GOARCH=arm64; EXE=.exe ;;
    linux-x86_64) GOOS=linux; GOARCH=amd64; EXE= ;;
    linux-aarch64) GOOS=linux; GOARCH=arm64; EXE= ;;
    macos-x86_64) GOOS=darwin; GOARCH=amd64; EXE= ;;
    macos-aarch64) GOOS=darwin; GOARCH=arm64; EXE= ;;
    *) die "unknown target '$TARGET'" ;;
esac

TMPS=()
GNUPGHOME_TMP=""
cleanup() {
    if [[ -n "$GNUPGHOME_TMP" ]]; then
        GNUPGHOME="$GNUPGHOME_TMP" gpgconf --kill all >/dev/null 2>&1 || true
    fi
    local d
    for d in ${TMPS[@]+"${TMPS[@]}"}; do rm -rf "$d"; done
}
trap cleanup EXIT
mktmp() { MK="$(mktemp -d)"; TMPS+=("$MK"); }

# --- versions.toml: toml_get <section> <key> prints the string value, or nothing.
toml_get() {
    awk -v sec="$1" -v key="$2" '
        { sub(/\r$/, "") }
        /^\[/ { cur = $0; sub(/^\[/, "", cur); sub(/\][ \t]*$/, "", cur); next }
        cur == sec && match($0, "^[ \t]*" key "[ \t]*=[ \t]*\"") {
            v = substr($0, RLENGTH + 1); sub(/"[ \t]*(#.*)?$/, "", v); print v; exit
        }' "$TOML"
}
pin() { # pin <section> <key>: required value
    local v; v="$(toml_get "$1" "$2")"
    [[ -n "$v" ]] || die "versions.toml: missing [$1] $2"
    echo "$v"
}

# --- helpers
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
else
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

download() { # download <url> <file>; keeps an existing file
    if [[ -f "$2" ]]; then say "cached: ${2#"$CACHE"/}"; return; fi
    say "downloading $1"
    curl -fsSL --retry 3 -o "$2.part" "$1" || { rm -f "$2.part"; die "download failed: $1"; }
    mv "$2.part" "$2"
}

check_sha() { # check_sha <file> <expected> <what>
    local got; got="$(sha256_of "$1")"
    [[ "$got" == "$2" ]] || die "sha256 mismatch for $3: expected $2, got $got (delete $1 to re-download)"
    say "sha256 ok: $3"
}

unzip_to() { # unzip_to <zip> <dir>
    if command -v unzip >/dev/null 2>&1; then unzip -q -o "$1" -d "$2"
    elif command -v bsdtar >/dev/null 2>&1; then bsdtar -xf "$1" -C "$2"
    else die "need unzip (or bsdtar) to extract $1; please install unzip"; fi
}

# Previous VERSIONS line of a component, kept when that component is skipped.
OLD_VERSIONS=""
[[ -f "$OUT/VERSIONS" ]] && OLD_VERSIONS="$(cat "$OUT/VERSIONS")"
NEW_VERSIONS=()
keep_old() { # keep_old <name>
    local l; l="$(printf '%s\n' "$OLD_VERSIONS" | awk -v n="$1" '$1 == n')"
    [[ -z "$l" ]] || NEW_VERSIONS+=("$l")
}

put_license() { # put_license <name> <source file>
    mkdir -p "$OUT/licenses"
    cp "$2" "$OUT/licenses/$1.txt"
}

# --- Tor signature: 0 verified, 2 not possible (no gpg / no key), else fatal.
verify_signature() { # verify_signature <sums> <asc> <fingerprint> <key url>
    local sums="$1" asc="$2" fpr="$3" keyurl="$4"
    if ! command -v "$GPG" >/dev/null 2>&1; then
        [[ $REQUIRE_SIG -eq 0 ]] || die "--require-signature: gpg not found"
        echo "fetch.sh: WARNING: gpg not found; the Tor bundle is only checked against the checksum pinned in versions.toml, not against the Tor Project signature" >&2
        return 2
    fi
    mktmp; GNUPGHOME_TMP="$MK"
    chmod 700 "$GNUPGHOME_TMP"
    export GNUPGHOME="$GNUPGHOME_TMP"
    say "importing Tor Browser signing key (WKD, then keys.openpgp.org)"
    if ! "$GPG" --batch --quiet --auto-key-locate clear,wkd --locate-keys torbrowser@torproject.org >/dev/null 2>&1; then
        curl -fsSL "$keyurl" 2>/dev/null | "$GPG" --batch --quiet --import >/dev/null 2>&1 || true
    fi
    if ! "$GPG" --batch --list-keys "$fpr" >/dev/null 2>&1; then
        [[ $REQUIRE_SIG -eq 0 ]] || die "--require-signature: could not obtain the signing key $fpr"
        echo "fetch.sh: WARNING: could not obtain the Tor signing key; signature not verified" >&2
        return 2
    fi
    local status
    status="$("$GPG" --batch --status-fd 1 --verify "$asc" "$sums" 2>/dev/null)" \
        || die "signature of $(basename "$sums") is BAD or not verifiable"
    grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" || die "no good signature on $(basename "$sums")"
    if grep -qE '^\[GNUPG:\] (BADSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|ERRSIG) ' <<<"$status"; then
        die "signature on $(basename "$sums") is bad, expired or from a revoked key"
    fi
    # VALIDSIG <fpr> <date> <ts> <expire> <ver> <rsv> <pk> <hash> <class> <primary-fpr>
    local got
    got="$(awk '$2 == "VALIDSIG" { print $NF; exit }' <<<"$status")"
    [[ "$got" == "$fpr" ]] || die "signing key mismatch: primary fingerprint is '$got', pinned '$fpr'"
    say "signature ok: $(basename "$sums") signed by key with primary fingerprint $fpr"
    return 0
}

# --- Tor
fetch_tor() {
    local ver url sha files licenses dir archive
    ver="$(pin tor version)"
    url="$(pin "tor.$TARGET" url)"
    sha="$(pin "tor.$TARGET" sha256)"
    files="$(pin "tor.$TARGET" files)"
    licenses="$(pin "tor.$TARGET" licenses)"
    dir="$CACHE/tor-$ver"; mkdir -p "$dir"
    archive="$dir/$(basename "$url")"

    download "$url" "$archive"
    check_sha "$archive" "$sha" "$(basename "$archive")"

    local sums="$dir/sha256sums-signed-build.txt" asc="$dir/sha256sums-signed-build.txt.asc" rc=0
    download "$(pin tor signed_sums_url)" "$sums"
    download "$(pin tor signed_sums_asc_url)" "$asc"
    verify_signature "$sums" "$asc" "$(pin tor signing_key_fingerprint)" "$(pin tor signing_key_url)" || rc=$?
    if [[ $rc -eq 0 ]]; then
        awk -v h="$sha" -v n="$(basename "$archive")" '{ f = $2; sub(/^\*/, "", f) } $1 == h && f == n { ok = 1 } END { exit !ok }' "$sums" \
            || die "the signed checksum file does not list $sha for $(basename "$archive")"
        say "archive hash is listed in the signed checksum file"
    fi

    local x f l
    mktmp; x="$MK"
    tar -xzf "$archive" -C "$x"
    rm -rf "$OUT/tor"; mkdir -p "$OUT/tor"
    for f in $files; do
        [[ -f "$x/tor/$f" ]] || die "$f not found in $(basename "$archive")"
        cp "$x/tor/$f" "$OUT/tor/$f"
    done
    for l in $licenses; do
        [[ -f "$x/${l#*:}" ]] || die "${l#*:} not found in $(basename "$archive")"
        put_license "${l%%:*}" "$x/${l#*:}"
    done
    say "tor $ver laid out in $OUT/tor ($files)"
    NEW_VERSIONS+=("tor $ver")
}

# --- Wintun (Windows)
fetch_wintun() {
    local ver zip dll x
    ver="$(pin wintun version)"
    zip="$CACHE/wintun-$ver.zip"
    download "$(pin wintun url)" "$zip"
    check_sha "$zip" "$(pin wintun sha256)" "wintun-$ver.zip"
    mktmp; x="$MK"
    unzip_to "$zip" "$x"
    dll="$(pin "wintun.$TARGET" dll)"
    [[ -f "$x/$dll" ]] || die "$dll not found in wintun-$ver.zip"
    check_sha "$x/$dll" "$(pin "wintun.$TARGET" sha256)" "$dll"
    check_sha "$x/$(pin wintun license)" "$(pin wintun license_sha256)" "wintun LICENSE.txt"
    mkdir -p "$OUT/yggdrasil"
    cp "$x/$dll" "$OUT/yggdrasil/wintun.dll"
    put_license wintun "$x/$(pin wintun license)"
    say "wintun $ver laid out in $OUT/yggdrasil/wintun.dll"
    NEW_VERSIONS+=("wintun $ver")
}

# --- Yggdrasil, built from the pinned commit
build_yggdrasil() {
    command -v go >/dev/null 2>&1 || die "--build-yggdrasil needs Go $(pin yggdrasil go) or newer on PATH (https://go.dev/dl/)"
    command -v git >/dev/null 2>&1 || die "--build-yggdrasil needs git"
    local tag commit need have repo src
    tag="$(pin yggdrasil tag)"; commit="$(pin yggdrasil commit)"; need="$(pin yggdrasil go)"; repo="$(pin yggdrasil repo)"
    have="$(go env GOVERSION)"; have="${have#go}"
    [[ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" == "$need" ]] \
        || die "Go $need or newer is required, found $have"

    src="$CACHE/yggdrasil-$commit"
    if [[ "$(git -c safe.directory="$src" -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]]; then
        say "fetching $repo at $commit"
        rm -rf "$src"; mkdir -p "$src"
        git -c safe.directory="$src" -C "$src" init -q
        git -c safe.directory="$src" -C "$src" remote add origin "$repo"
        git -c safe.directory="$src" -C "$src" fetch -q --depth 1 origin "$commit" || die "could not fetch commit $commit from $repo"
        git -c safe.directory="$src" -C "$src" checkout -q FETCH_HEAD
    else
        say "cached: yggdrasil-$commit"
    fi
    [[ "$(git -c safe.directory="$src" -C "$src" rev-parse HEAD)" == "$commit" ]] || die "checked-out commit differs from the pinned $commit"

    # Same as the repo's ./build: version stamped via -ldflags, stripped, only the yggdrasil command.
    local pkg="github.com/yggdrasil-network/yggdrasil-go/src/version" ver="${tag#v}" x
    mktmp; x="$MK"
    say "building yggdrasil $tag ($GOOS/$GOARCH, CGO off)"
    (cd "$src" && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -buildvcs=false -ldflags "-X $pkg.buildName=yggdrasil -X $pkg.buildVersion=$ver -s -w" -o "$x/yggdrasil$EXE" ./cmd/yggdrasil) \
        || die "go build failed"
    mkdir -p "$OUT/yggdrasil"
    cp "$x/yggdrasil$EXE" "$OUT/yggdrasil/yggdrasil$EXE"
    put_license yggdrasil "$src/LICENSE"
    say "yggdrasil $tag laid out in $OUT/yggdrasil/yggdrasil$EXE"
    NEW_VERSIONS+=("yggdrasil $tag $commit")
}

# --- main
if [[ $SKIP_TOR -eq 0 ]]; then fetch_tor; else keep_old tor; fi

if [[ $SKIP_YGG -eq 0 ]]; then
    if [[ $BUILD_YGG -eq 1 ]]; then
        build_yggdrasil
    else
        say "yggdrasil binary not built (pass --build-yggdrasil)"
        keep_old yggdrasil
    fi
    if [[ "$GOOS" == windows ]]; then fetch_wintun; fi
else
    keep_old yggdrasil; keep_old wintun
fi

if [[ ${#NEW_VERSIONS[@]} -gt 0 ]]; then
    printf '%s\n' "${NEW_VERSIONS[@]}" > "$OUT/VERSIONS"
else
    rm -f "$OUT/VERSIONS"
fi
say "done: $OUT"
