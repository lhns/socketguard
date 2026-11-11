#!/usr/bin/env bash
# Fail unless one version drives everything: [workspace.package] version in Cargo.toml is the
# source; every crate must inherit it (`version.workspace = true`), and ui/package.json and
# ui/src-tauri/tauri.conf.json must carry the same string. No jq needed.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0
err() { echo "version mismatch: $*" >&2; fail=1; }

# First `version = "x"` line inside the [workspace.package] table.
ws=$(bash deploy/ci/version.sh)

# Only the [package] table counts (up to the next table header).
for f in crates/*/Cargo.toml ui/src-tauri/Cargo.toml; do
    pkg=$(sed -n '/^\[package\]/,/^\[/p' "$f")
    if echo "$pkg" | grep -Eq '^version\.workspace[[:space:]]*=[[:space:]]*true'; then
        continue
    fi
    v=$(echo "$pkg" | sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    err "$f has ${v:-no version}, expected 'version.workspace = true' ($ws)"
done

# Top-level "version": "x" of a JSON file (first match).
for f in ui/package.json ui/src-tauri/tauri.conf.json; do
    v=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n1)
    [ "$v" = "$ws" ] || err "$f has '${v:-none}', workspace is '$ws'"
done

if [ "$fail" = 0 ]; then echo "versions ok: $ws"; fi
exit "$fail"
