#!/usr/bin/env bash
# The deb, end to end, on a throwaway Ubuntu VM with systemd (the CI runner):
#
#   test/deb.sh dist/socketguard_0.1.0_amd64.deb dist/socketguard_0.1.1_amd64.deb
#
# install -> service active, answers on the socket, nft table, footprint present;
# upgrade -> data kept, service restarted onto the new binary, no uninstall;
# networks (test/networks.sh, ADR 0052): the bundled versions in `status`, Tor
#           that bootstraps and runs as socketguard-net, Yggdrasil whose address is
#           blocked before its adapter exists;
# remove  -> service, rules and children gone, data (incl. <state>/tor, /yggdrasil) kept;
# purge   -> nothing left, the account the install created removed.
set -euo pipefail
deb="$(readlink -f "$1")"; next="$(readlink -f "$2")"
here="$(cd "$(dirname "$0")/.." && pwd)"
fp="bash $here/deploy/ci/footprint-check.sh"
db=/var/lib/socketguard/socketguard.db


# shellcheck source=test/lib.sh
. "$here/test/lib.sh"

# The networks section (test/networks.sh): the installed files, and what it reads of the host.
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
on_fail() {
    echo "--- journal ---"; sudo journalctl -u socketguard --no-pager -n 60 || true
    echo "--- status ---"; systemctl status socketguard --no-pager || true
}
# shellcheck source=test/networks.sh
. "$here/test/networks.sh"

wait_active() { wait_until 20 systemctl is-active --quiet socketguard; }
wait_answers() { wait_until 30 sudo socketguard status --json; }
mainpid() { systemctl show -p MainPID --value socketguard; }

# The IPv6 addresses SocketGuard could add, before the first install; every expect-absent below
# fails if one is still on an interface afterwards (deploy/ci/footprint-check.sh, "Address baseline").
addr_base="${RUNNER_TEMP:-/tmp}/sg-addrs-before.txt"
bash "$here/deploy/ci/footprint-check.sh" --save-addresses "$addr_base"

step "install"
sudo apt-get install -y "$deb"
# Type=notify (ADR 0051): the start returned only after the first ruleset, so the table exists
# now, with no waiting in between.
[ "$(systemctl show socketguard -p Type --value)" = notify ] || fail "the unit is not Type=notify"
systemctl is-active --quiet socketguard || fail "the unit is not active right after install"
sudo nft list table inet socketguard >/dev/null || fail "no nft table at the moment the install returned"
wait_active || fail "the unit is not active after install"
wait_answers || fail "socketguard status does not answer over the socket"
status_json="$(sudo socketguard status --json)"; printf '%s\n' "${status_json:0:400}"
sudo nft list table inet socketguard >/dev/null || fail "no nft table inet socketguard"
grep -q 'ExecStart=/usr/bin/socketguard-daemon' /etc/systemd/system/socketguard.service || fail "the unit does not name /usr/bin/socketguard-daemon"
getent group socketguard >/dev/null || fail "no group socketguard"
test -e "$db" || fail "no database"
systemctl is-enabled --quiet socketguard || fail "the unit is not enabled"
sudo $fp expect-present --require nft-table-inet,socket
test -f /usr/share/applications/socketguard.desktop || fail "no .desktop file"
test -f /usr/share/doc/socketguard/THIRD_PARTY_NOTICES.md || fail "no THIRD_PARTY_NOTICES.md in /usr/share/doc/socketguard"
grep -q zlib1g <<<"$(dpkg-query -W -f='${Depends}\n' socketguard)" || fail "the package does not depend on zlib1g"
mn_bundled
# A marker that only the data survives.
sudo socketguard port-groups add 7000-7010/tcp --label upgrade-marker >/dev/null || fail "cannot create the marker port group"
inode=$(sudo stat -c %i "$db"); pid1=$(mainpid)

step "upgrade"
sudo apt-get install -y "$next"
sudo nft list table inet socketguard >/dev/null || fail "no nft table at the moment the upgrade returned"
wait_active || fail "the unit is not active after the upgrade"
wait_answers || fail "no answer after the upgrade"
pid2=$(mainpid)
[ "$pid1" != "$pid2" ] || fail "the daemon was not restarted by the upgrade (pid $pid1)"
[ "$(sudo stat -c %i "$db")" = "$inode" ] || fail "the database file was replaced by the upgrade"
grep -q upgrade-marker <<<"$(sudo socketguard port-groups list)" || fail "the stored state is gone after the upgrade"
sudo nft list table inet socketguard >/dev/null || fail "the rules are gone after the upgrade"
dpkg-query -W -f='${Version}\n' socketguard
sudo $fp expect-present --require nft-table-inet,socket

# ---- networks (ADR 0052): a Tor and a Yggdrasil run from the installed files ----------
mn_step "Tor"
mn_tor
mn_step "Yggdrasil"
if [ -e /dev/net/tun ]; then
    mn_ygg_start
    mn_ygg_up
    ygg_pid=$(mn_ygg_pid)
    [ -n "$ygg_pid" ] || mn_die "the network is up but no yggdrasil from third_party is running"
    # Yggdrasil creates its adapter as root and then drops to the unprivileged account.
    ygg_dropped() { [ "$(mn_uid "$ygg_pid")" = "$(id -u socketguard-net)" ]; }
    wait_until 30 ygg_dropped \
        || mn_die "yggdrasil (pid $ygg_pid) runs as uid $(mn_uid "$ygg_pid"), expected socketguard-net"
    ok "yggdrasil runs as socketguard-net after creating $ADAPTER"
    grep -qiF "$MN_YGG_ADDR" <<<"$(ip -6 addr show dev "$ADAPTER")" || mn_die "$ADAPTER does not hold $MN_YGG_ADDR"
    ok "$ADAPTER holds the node's address"
else
    skip "Yggdrasil: this runner has no /dev/net/tun"
fi
summary networks
sudo cp /etc/socketguard/setup-log.json "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"
sudo chmod 644 "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"
if mn_account_created "${RUNNER_TEMP:-/tmp}/setup-log.before-remove.json"; then account_created=1; else account_created=0; fi

# A config that does not parse (a stale key) must not keep the rules on the host: the
# prerm's `uninstall` goes on with the built-in defaults and says so.
cfg=/etc/socketguard/socketguard.json
if sudo test -s "$cfg"; then
    sudo sed -i '0,/{/s/{/{"stale_setting": 1,/' "$cfg"
else
    echo '{"stale_setting": 1}' | sudo tee "$cfg" >/dev/null
fi
sudo grep -q stale_setting "$cfg" || fail "could not plant a stale key in $cfg"

step "remove (data kept, config does not parse)"
sudo apt-get remove -y socketguard
systemctl is-active --quiet socketguard && fail "the service still runs after remove"
test -e /etc/systemd/system/socketguard.service && fail "the unit file is still there"
sudo nft list table inet socketguard >/dev/null 2>&1 && fail "the nft table is still there after remove"
test -e "$db" || fail "remove deleted the database"
mn_children_stopped
mn_adapter_exists && fail "the adapter $ADAPTER is still there after remove"
mn_data_kept
sudo $fp expect-absent --allow-data --baseline "$addr_base"

step "purge"
sudo apt-get purge -y socketguard
mn_data_purged
mn_account_after_purge "$account_created"
sudo $fp expect-absent --baseline "$addr_base"
summary networks
echo OK
