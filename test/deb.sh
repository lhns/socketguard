#!/usr/bin/env bash
# The deb, end to end, on a throwaway Ubuntu VM with systemd (the CI runner):
#
#   test/deb.sh dist/socketguard_0.1.0_amd64.deb dist/socketguard_0.1.1_amd64.deb
#
# install -> service active, answers on the socket, nft table, footprint present;
# upgrade -> data kept, service restarted onto the new binary, no uninstall;
# managed networks (test/managed.sh, ADR 0052): the bundled versions in `status`, a managed Tor
#           that bootstraps and runs as socketguard-net, a managed Yggdrasil whose address is
#           blocked before its adapter exists;
# remove  -> service, rules and children gone, data (incl. <state>/tor, /yggdrasil) kept;
# purge   -> nothing left, the account the install created removed.
set -euo pipefail
deb="$(readlink -f "$1")"; next="$(readlink -f "$2")"
here="$(cd "$(dirname "$0")/.." && pwd)"
fp="bash $here/deploy/ci/footprint-check.sh"
db=/var/lib/socketguard/socketguard.db


# The managed networks section (test/managed.sh): the installed files, and what it reads of the host.
SG="sudo socketguard"
TP=/usr/lib/socketguard/third_party
STATE=/var/lib/socketguard
ADAPTER=sgygg0
mn_daemon_log() {
    sudo journalctl -u socketguard --no-pager -n 100 || true
    echo "--- nft table inet socketguard ---"; sudo nft list table inet socketguard 2>&1 | head -80 || true
}
mn_adapter_exists() { ip link show "$ADAPTER" >/dev/null 2>&1; }
# The ruleset names the node's address or its /64 (nft prints addresses compressed, like python).
mn_block_in_force() {
    local r; r="$(sudo nft list table inet socketguard 2>/dev/null)" || return 1
    printf '%s' "$r" | grep -qiF -e "$1" -e "${2%/64}"
}
# shellcheck source=test/managed.sh
. "$here/test/managed.sh"

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
sudo $fp expect-present --require nft-table-inet,socket
test -f /usr/share/applications/socketguard.desktop || fail "no .desktop file"
test -f /usr/share/doc/socketguard/THIRD_PARTY_NOTICES.md || fail "no THIRD_PARTY_NOTICES.md in /usr/share/doc/socketguard"
dpkg-query -W -f='${Depends}\n' socketguard | grep -q zlib1g || fail "the package does not depend on zlib1g"
mn_bundled
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
sudo $fp expect-present --require nft-table-inet,socket

# ---- managed networks (ADR 0052): a Tor and a Yggdrasil run from the installed files ----------
mn_step "Tor"
mn_tor
mn_step "Yggdrasil"
if [ -e /dev/net/tun ]; then
    mn_ygg_start
    mn_ygg_up
    ygg_pid=$(mn_pid '/third_party/yggdrasil/yggdrasil')
    [ -n "$ygg_pid" ] || mn_die "the network is up but no yggdrasil from third_party is running"
    # Yggdrasil creates its adapter as root and then drops to the unprivileged account.
    ygg_dropped() { [ "$(mn_uid "$ygg_pid")" = "$(id -u socketguard-net)" ]; }
    mn_until 30 ygg_dropped \
        || mn_die "yggdrasil (pid $ygg_pid) runs as uid $(mn_uid "$ygg_pid"), expected socketguard-net"
    mn_ok "yggdrasil runs as socketguard-net after creating $ADAPTER"
    ip -6 addr show dev "$ADAPTER" | grep -qiF "$MN_YGG_ADDR" || mn_die "$ADAPTER does not hold $MN_YGG_ADDR"
    mn_ok "$ADAPTER holds the node's address"
else
    mn_skip "managed Yggdrasil: this runner has no /dev/net/tun"
fi
mn_summary
sudo cp /etc/socketguard/setup-log.json "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"
sudo chmod 644 "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"
if mn_account_created "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"; then account_created=1; else account_created=0; fi

step "remove (data kept)"
sudo apt-get remove -y socketguard
systemctl is-active --quiet socketguard && fail "the service still runs after remove"
test -e /etc/systemd/system/socketguard.service && fail "the unit file is still there"
sudo nft list table inet socketguard >/dev/null 2>&1 && fail "the nft table is still there after remove"
test -e "$db" || fail "remove deleted the database"
mn_children_stopped
mn_adapter_exists && fail "the adapter $ADAPTER is still there after remove"
mn_data_kept
sudo $fp expect-absent --allow-data

step "purge"
sudo apt-get purge -y socketguard
mn_data_purged
mn_account_after_purge "$account_created"
sudo $fp expect-absent
mn_summary
echo OK
