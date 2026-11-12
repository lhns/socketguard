#!/usr/bin/env bash
# Build the deb and the rpm from installer/linux/nfpm.yaml.
#
#   installer/linux/build.sh <version> <stage> [outdir]      # after ./build.sh --stage; needs nfpm
#
# <stage> is the staged tree (docs/packaging.md): the three programs, third_party/, LICENSE and
# THIRD_PARTY_NOTICES.md. The deb's postrm is made here from the list the staged daemon prints
# of what purge deletes (installer/linux/scripts/deb-postrm.in, ADR 0057).
set -euo pipefail
cd "$(dirname "$0")/../.."

version="${1:?usage: build.sh <version> <stage> [outdir]}"
stage="${2:?usage: build.sh <version> <stage> [outdir]}"
out="${3:-dist}"
for f in socketguard-daemon socketguard socketguard-ui LICENSE THIRD_PARTY_NOTICES.md third_party/VERSIONS; do
    [ -e "$stage/$f" ] || { echo "missing $f in $stage (run ./build.sh --stage)" >&2; exit 1; }
done
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The list comes from the daemon that goes into the package, for Linux whatever this host is.
"$stage/socketguard-daemon" uninstall --print-purge-list --os linux > "$work/purge-list"
[ -s "$work/purge-list" ] || { echo "the daemon printed an empty purge list" >&2; exit 1; }
awk -v f="$work/purge-list" '/^@PURGE_LIST@$/ { while ((getline l < f) > 0) print l; next } { print }' \
    installer/linux/scripts/deb-postrm.in > "$work/deb-postrm"
sh -n "$work/deb-postrm"

sed -e "s|\${STAGE}|$stage|g" -e "s|\${VERSION}|$version|g" -e "s|\${POSTRM}|$work/deb-postrm|g" \
    installer/linux/nfpm.yaml > "$work/nfpm.yaml"

for t in deb rpm; do
    nfpm package -f "$work/nfpm.yaml" -p "$t" -t "$out"
done
ls -l "$out"
