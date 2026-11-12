#!/usr/bin/env bash
# The macOS package, end to end, on a throwaway runner (needs sudo):
#
#   test/pkg.sh dist/SocketGuard-0.1.0.pkg dist/SocketGuard-0.1.1.pkg
#
# install -> launchd daemon loaded and answering, pf anchor line, footprint present;
# install the next version over it -> daemon restarted, data kept;
# `uninstall --purge` -> footprint absent, pf.conf back to what it was; then the manual removal
# of the files a pkg cannot remove, and `pkgutil --forget`.
# Between the upgrade and the removal: the managed Tor and Yggdrasil networks (test/managed.sh, ADR 0052).
set -euo pipefail
pkg="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
next="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
here="$(cd "$(dirname "$0")/.." && pwd)"
fp="bash $here/deploy/ci/footprint-check.sh"
label=de.lhns.socketguard
db="/Library/Application Support/SocketGuard/socketguard.db"


# The managed networks section (test/managed.sh): the installed files, and what it reads of the host.
command -v jq >/dev/null 2>&1 || brew install jq
SG="sudo /usr/local/bin/socketguard"
TP=/usr/local/lib/socketguard/third_party
STATE="/Library/Application Support/SocketGuard"
mn_daemon_log() {
    sudo log show --last 20m --style compact --predicate 'process == "socketguard-daemon"' 2>&1 | tail -n 100 || true
    echo "--- pf anchor socketguard ---"; sudo pfctl -a socketguard -sr 2>&1 | head -60 || true
}
# The node's address on a utun interface (MN_YGG_ADDR is set once the network card shows it).
mn_adapter_exists() { [ -n "${MN_YGG_ADDR:-}" ] && ifconfig 2>/dev/null | grep -qiF "inet6 $MN_YGG_ADDR "; }
mn_block_in_force() { sudo pfctl -a socketguard -sr 2>/dev/null | grep -qiF -e "$1" -e "${2%/64}"; }
# shellcheck source=test/managed.sh
. "$here/test/managed.sh"

step() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- launchctl ---"; sudo launchctl print "system/$label" 2>&1 | head -40 || true
    echo "--- install log ---"; sudo tail -n 60 /var/log/install.log 2>/dev/null || true
    echo "--- pf.conf ---"; cat /etc/pf.conf || true
    # launchd keeps the daemon's output nowhere: run it in the foreground for a few seconds.
    echo "--- the daemon in the foreground ---"
    sudo launchctl bootout "system/$label" 2>&1 || true
    sudo /usr/local/bin/socketguard-daemon >/tmp/daemon-fg.log 2>&1 &
    fgpid=$!
    sleep 8
    sudo kill "$fgpid" 2>/dev/null || true
    head -60 /tmp/daemon-fg.log || true
    exit 1
}
wait_answers() { for _ in $(seq 1 60); do sudo /usr/local/bin/socketguard status --json >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
daemon_pid() { sudo launchctl print "system/$label" | awk '/^[[:space:]]*pid = /{print $3; exit}'; }

cp /etc/pf.conf "${RUNNER_TEMP:-/tmp}/pf.conf.before"
pf_state() { sudo pfctl -s info 2>&1 | awk '/^Status:/ {print $2}'; }
pf_before=$(pf_state)

step "install"
sudo installer -pkg "$pkg" -target / -verbose
sudo launchctl print "system/$label" >/dev/null || fail "the launchd daemon is not loaded"
wait_answers || fail "socketguard status does not answer"
sudo /usr/local/bin/socketguard status --json | head -c 400; echo
test -x /usr/local/bin/socketguard-daemon && test -x /usr/local/bin/socketguard || fail "binaries missing"
test -x /Applications/SocketGuard.app/Contents/MacOS/socketguard-ui || fail "the app is missing"
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' /Applications/SocketGuard.app/Contents/Info.plist
sudo pfctl -a socketguard -sr 2>&1 | head -5
grep -q 'anchor "socketguard"' /etc/pf.conf || fail "no anchor line in /etc/pf.conf"
sudo $fp expect-present --require pf-conf-anchor-line
for d in /Applications/SocketGuard.app/Contents/Resources /usr/local/share/doc/socketguard; do
    test -f "$d/THIRD_PARTY_NOTICES.md" && test -f "$d/LICENSE" || fail "no LICENSE and THIRD_PARTY_NOTICES.md in $d"
done
mn_bundled
sudo /usr/local/bin/socketguard port-groups add 7000-7010/tcp --label upgrade-marker >/dev/null || fail "cannot create the marker port group"
inode=$(sudo stat -f %i "$db"); pid1=$(daemon_pid)

step "install the next version over it"
sudo installer -pkg "$next" -target / -verbose
wait_answers || fail "no answer after the upgrade"
pid2=$(daemon_pid)
[ -n "$pid2" ] && [ "$pid1" != "$pid2" ] || fail "the daemon was not restarted (pid '$pid1' -> '$pid2')"
[ "$(sudo stat -f %i "$db")" = "$inode" ] || fail "the database was replaced"
sudo /usr/local/bin/socketguard port-groups list | grep -q upgrade-marker || fail "the stored state is gone"
[ "$(grep -c 'anchor "socketguard"' /etc/pf.conf)" = 1 ] || fail "the anchor line is there more than once"

# ---- managed networks (ADR 0052): a Tor and a Yggdrasil run from the installed files ----------
mn_step "Tor"
mn_tor
mn_step "Yggdrasil"
mn_ygg_start
mn_ygg_up
ygg_pid=$(mn_pid '/third_party/yggdrasil/yggdrasil')
[ -n "$ygg_pid" ] || mn_die "the network is up but no yggdrasil from third_party is running"
mn_note "yggdrasil runs as uid $(mn_uid "$ygg_pid") ($(ps -o user= -p "$ygg_pid" | tr -d ' ')); runs_as: $(mn_field ygg .managed.runs_as)"
mn_ok "the node address $MN_YGG_ADDR is on a utun interface: $(ifconfig | awk -v a="$MN_YGG_ADDR" '/^[a-z0-9]+:/ { i = $1 } index($0, "inet6 " a " ") { print i; exit }')"
mn_summary
sudo cp "$STATE/setup-log.json" "${RUNNER_TEMP:-/tmp}/setup-log.before-uninstall.json"
sudo chmod 644 "${RUNNER_TEMP:-/tmp}/setup-log.before-uninstall.json"
if mn_account_created "${RUNNER_TEMP:-/tmp}/setup-log.before-uninstall.json"; then account_created=1; else account_created=0; fi

step "uninstall (data kept)"
sudo /usr/local/bin/socketguard-daemon uninstall --keep-data --yes
mn_children_stopped
mn_data_kept

step "uninstall --purge"
sudo /usr/local/bin/socketguard-daemon uninstall --purge --yes
mn_data_purged
mn_account_after_purge "$account_created"
diff -u "${RUNNER_TEMP:-/tmp}/pf.conf.before" /etc/pf.conf || fail "/etc/pf.conf is not what it was before the install"
pf_after=$(pf_state)
echo "pf before: $pf_before, after: $pf_after"
[ "$pf_before" = "$pf_after" ] || fail "pf was $pf_before before the install and is $pf_after after the purge"

step "the files a pkg cannot remove"
sudo $fp expect-absent
sudo rm -rf /Applications/SocketGuard.app /usr/local/bin/socketguard-daemon /usr/local/bin/socketguard /usr/local/lib/socketguard /usr/local/share/doc/socketguard
sudo pkgutil --forget de.lhns.socketguard
! pkgutil --pkg-info de.lhns.socketguard >/dev/null 2>&1 || fail "the receipt is still there"
echo OK
