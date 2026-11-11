#!/usr/bin/env bash
# The deb, end to end, on a throwaway Ubuntu VM with systemd (the CI runner):
#
#   test/deb.sh dist/socketguard_0.1.0_amd64.deb dist/socketguard_0.1.1_amd64.deb
#
# install -> service active, answers on the socket, nft table, footprint present;
# upgrade -> data kept, service restarted onto the new binary, no uninstall;
# remove  -> service and rules gone, data kept; purge -> nothing left.
set -euo pipefail
deb="$(readlink -f "$1")"; next="$(readlink -f "$2")"
here="$(cd "$(dirname "$0")/.." && pwd)"
fp="$here/deploy/ci/footprint-check.sh"
db=/var/lib/socketguard/socketguard.db

step() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- journal ---"; sudo journalctl -u socketguard --no-pager -n 60 || true
    echo "--- status ---"; systemctl status socketguard --no-pager || true
    exit 1
}
wait_active() { for _ in $(seq 1 40); do systemctl is-active --quiet socketguard && return 0; sleep 0.5; done; return 1; }
wait_answers() { for _ in $(seq 1 60); do sudo socketguard status --json >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
mainpid() { systemctl show -p MainPID --value socketguard; }

step "install"
sudo apt-get install -y "$deb"
wait_active || fail "the unit is not active after install"
wait_answers || fail "socketguard status does not answer over the socket"
sudo socketguard status --json | head -c 400; echo
sudo nft list table inet socketguard >/dev/null || fail "no nft table inet socketguard"
grep -q 'ExecStart=/usr/bin/socketguard-daemon' /etc/systemd/system/socketguard.service || fail "the unit does not name /usr/bin/socketguard-daemon"
getent group socketguard >/dev/null || fail "no group socketguard"
test -e "$db" || fail "no database"
systemctl is-enabled --quiet socketguard || fail "the unit is not enabled"
sudo "$fp" expect-present --require nft-table-inet,socket
test -f /usr/share/applications/socketguard.desktop || fail "no .desktop file"
# A marker that only the data survives.
sudo socketguard port-groups add 7000-7010/tcp --label upgrade-marker >/dev/null || fail "cannot create the marker port group"
inode=$(sudo stat -c %i "$db"); pid1=$(mainpid)

step "upgrade"
sudo apt-get install -y "$next"
wait_active || fail "the unit is not active after the upgrade"
wait_answers || fail "no answer after the upgrade"
pid2=$(mainpid)
[ "$pid1" != "$pid2" ] || fail "the daemon was not restarted by the upgrade (pid $pid1)"
[ "$(sudo stat -c %i "$db")" = "$inode" ] || fail "the database file was replaced by the upgrade"
sudo socketguard port-groups list | grep -q upgrade-marker || fail "the stored state is gone after the upgrade"
sudo nft list table inet socketguard >/dev/null || fail "the rules are gone after the upgrade"
dpkg-query -W -f='${Version}\n' socketguard
sudo "$fp" expect-present --require nft-table-inet,socket

step "remove (data kept)"
sudo apt-get remove -y socketguard
systemctl is-active --quiet socketguard && fail "the service still runs after remove"
test -e /etc/systemd/system/socketguard.service && fail "the unit file is still there"
sudo nft list table inet socketguard >/dev/null 2>&1 && fail "the nft table is still there after remove"
test -e "$db" || fail "remove deleted the database"
sudo "$fp" expect-absent --allow-data

step "purge"
sudo apt-get purge -y socketguard
sudo "$fp" expect-absent
echo OK
