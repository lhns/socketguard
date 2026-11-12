#!/usr/bin/env bash
# The rpm's full life cycle in a Fedora container that runs systemd as PID 1 (privileged, on the
# CI VM, so nftables is the host kernel's):
#
#   test/rpm-systemd.sh dist/socketguard-0.1.0-1.x86_64.rpm dist/next/socketguard-0.1.1-1.x86_64.rpm
#
# install -> unit active, socket answers, nft table, footprint present; upgrade -> daemon
# restarted, data kept; dnf remove -> service and rules gone, data kept; rpm has no purge, so
# `socketguard-daemon uninstall --purge --yes` is run BEFORE erasing (the documented way) in a
# second round: install, purge, erase, footprint absent.
set -euo pipefail
rpm1="$(readlink -f "$1")"; rpm2="$(readlink -f "$2")"
here="$(cd "$(dirname "$0")/.." && pwd)"
name=sg-fedora
img="${FEDORA_IMAGE:-fedora:latest}"

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() {
    echo "FAIL: $*" >&2
    docker exec "$name" journalctl -u socketguard --no-pager -n 60 2>&1 || true
    docker exec "$name" systemctl status socketguard --no-pager 2>&1 || true
    exit 1
}
x() { docker exec "$name" bash -euo pipefail -c "$*"; }

# The base image has no systemd and no sudo-ish tools; add systemd (and nothing the rpm should bring).
printf 'FROM %s
RUN dnf install -y systemd && dnf clean all
' "$img" | docker build -t sg-fedora-systemd -
img=sg-fedora-systemd
docker run -d --name "$name" --privileged --cgroupns=host --tmpfs /run --tmpfs /tmp \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$here:/repo:ro" -v "$rpm1:/p1.rpm:ro" -v "$rpm2:/p2.rpm:ro" "$img" /sbin/init >/dev/null
for _ in $(seq 1 60); do
    s=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running|degraded) break ;; esac
    sleep 1
done
echo "systemd in the container: $s"
case "$s" in running|degraded) ;; *) fail "systemd did not come up ($s)" ;; esac
docker exec "$name" nft --version >/dev/null 2>&1 || true

fp() { docker exec "$name" bash /repo/deploy/ci/footprint-check.sh "$@"; }
answers() { for _ in $(seq 1 60); do docker exec "$name" socketguard status --json >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
active() { for _ in $(seq 1 40); do docker exec "$name" systemctl is-active --quiet socketguard && return 0; sleep 1; done; return 1; }
mainpid() { docker exec "$name" systemctl show -p MainPID --value socketguard; }
db=/var/lib/socketguard/socketguard.db

echo "== install"
x "dnf install -y /p1.rpm"
# Type=notify (ADR 0051): the start returned only after the first ruleset, so the table exists
# now, with no waiting in between.
[ "$(x "systemctl show socketguard -p Type --value")" = notify ] || fail "the unit is not Type=notify"
x "systemctl is-active --quiet socketguard" || fail "unit not active right after install"
x "nft list table inet socketguard >/dev/null" || fail "no nft table at the moment the install returned"
active || fail "unit not active after install"
answers || fail "socket does not answer"
x "nft list table inet socketguard >/dev/null" || fail "no nft table"
x "systemctl is-enabled --quiet socketguard"
x "grep -q 'ExecStart=/usr/bin/socketguard-daemon' /etc/systemd/system/socketguard.service"
fp expect-present --require nft-table-inet,socket
x "socketguard port-groups add 7000-7010/tcp --label upgrade-marker >/dev/null"
inode=$(x "stat -c %i $db"); pid1=$(mainpid)

echo "== restart ordering"
# `systemctl restart` must return only after the rules are back: delete the table, restart,
# list at once (no sleep). A real reboot cannot be simulated in this container (systemd is PID 1
# of a container sharing the host kernel, whose nftables state survives the daemon), so this
# stands in for "the network waits for the rules": the same Type=notify readiness gates both.
x "nft delete table inet socketguard"
x "! nft list table inet socketguard >/dev/null 2>&1" || fail "the table could not be removed for the restart check"
x "systemctl restart socketguard"
x "nft list table inet socketguard >/dev/null" || fail "no nft table at the moment the restart returned"
active || fail "unit not active after the restart"
answers || fail "no answer after the restart"
pid1=$(mainpid)

echo "== upgrade"
x "dnf install -y /p2.rpm || dnf upgrade -y /p2.rpm"
x "rpm -q socketguard"
active || fail "unit not active after the upgrade"
answers || fail "no answer after the upgrade"
[ "$pid1" != "$(mainpid)" ] || fail "daemon not restarted by the upgrade"
[ "$(x "stat -c %i $db")" = "$inode" ] || fail "database replaced"
x 'grep -q upgrade-marker <<<"$(socketguard port-groups list)"' || fail "state lost"
x "nft list table inet socketguard >/dev/null"

echo "== dnf remove (data kept)"
x "dnf remove -y socketguard"
x "! systemctl is-active --quiet socketguard"
x "! test -e /etc/systemd/system/socketguard.service"
x "! nft list table inet socketguard >/dev/null 2>&1" || fail "nft table left after remove"
x "test -e $db" || fail "remove deleted the data"
fp expect-absent --allow-data

echo "== round two: install, purge by command, erase"
x "dnf install -y /p1.rpm"
active || fail "unit not active (round two)"
answers || fail "no answer (round two)"
x "socketguard-daemon uninstall --purge --yes"
x "dnf remove -y socketguard"
fp expect-absent
echo OK
