#!/usr/bin/env bash
# The rpm in a Fedora container. There is no systemd in the container, so the scriptlets take
# their "systemd is not running" path and the service is NOT started or removed here; what this
# verifies is the metadata (dependencies resolve in Fedora), the file list, the scriptlets as
# installed, that the binaries run on Fedora's libc, and that erase leaves the files gone.
#
#   test/rpm.sh dist/socketguard-0.1.0-1.x86_64.rpm
set -euo pipefail
rpmfile="$(readlink -f "$1")"
docker run --rm -v "$rpmfile:/pkg.rpm:ro" fedora:latest bash -euxo pipefail -c '
    dnf install -y /pkg.rpm
    rpm -q socketguard
    rpm -qR socketguard
    rpm -ql socketguard | tee /tmp/files
    for f in /usr/bin/socketguard-daemon /usr/bin/socketguard /usr/bin/socketguard-ui /usr/share/applications/socketguard.desktop; do
        grep -qx "$f" /tmp/files
    done
    ! grep -q "systemd/system" /tmp/files    # the unit is written by "service install", not shipped
    rpm -q --scripts socketguard | tee /tmp/scripts
    grep -q "service install" /tmp/scripts
    grep -q "uninstall --keep-data --yes" /tmp/scripts
    ldd /usr/bin/socketguard-daemon | tee /tmp/ldd; ! grep -q "not found" /tmp/ldd
    ldd /usr/bin/socketguard-ui | tee /tmp/ldd; ! grep -q "not found" /tmp/ldd
    # The bundled Tor and Yggdrasil (ADR 0052): in the package, readable and runnable by an unprivileged
    # account (the daemon runs them as socketguard-net), with the libz they need, and the notices.
    TP=/usr/lib/socketguard/third_party
    grep -qx "$TP/tor/tor" /tmp/files
    grep -qx "$TP/yggdrasil/yggdrasil" /tmp/files
    grep -qx "$TP/VERSIONS" /tmp/files
    grep -qx "$TP/licenses/tor.txt" /tmp/files
    grep -qx /usr/share/doc/socketguard/THIRD_PARTY_NOTICES.md /tmp/files
    rpm -qR socketguard | grep -qx zlib
    LD_LIBRARY_PATH=$TP/tor ldd $TP/tor/tor | tee /tmp/ldd; ! grep -q "not found" /tmp/ldd
    command -v setpriv >/dev/null || dnf install -y -q util-linux-core util-linux >/dev/null
    setpriv --reuid=65534 --regid=65534 --clear-groups env LD_LIBRARY_PATH=$TP/tor $TP/tor/tor --version
    setpriv --reuid=65534 --regid=65534 --clear-groups $TP/yggdrasil/yggdrasil -version
    cat $TP/VERSIONS
    socketguard-daemon --help | head -3
    socketguard --version
    rpm -e socketguard
    ! test -e /usr/bin/socketguard-daemon
'
echo OK
