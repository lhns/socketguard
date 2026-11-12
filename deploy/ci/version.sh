#!/usr/bin/env bash
# Print the workspace version ([workspace.package] in Cargo.toml), or with --next the same with
# the patch number raised by one (the version of the second package the upgrade tests install).
# POSIX awk, so it runs the same on Linux, macOS and Git Bash.
set -euo pipefail
cd "$(dirname "$0")/../.."
v=$(awk '/^\[workspace\.package\]/ { f = 1; next } /^\[/ { f = 0 }
         f && /^version[ \t]*=/ { gsub(/^[^"]*"|".*$/, ""); print; exit }' Cargo.toml)
[ -n "$v" ] || { echo "no [workspace.package] version in Cargo.toml" >&2; exit 1; }
if [ "${1:-}" = "--next" ]; then
    echo "${v%.*}.$(( ${v##*.} + 1 ))"
else
    echo "$v"
fi
