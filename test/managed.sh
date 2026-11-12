#!/usr/bin/env bash
# Managed Tor and Yggdrasil networks (ADR 0052) on an INSTALLED package, shared by test/deb.sh
# and test/pkg.sh (source it, do not run it). Needs jq and python3 on the runner.
#
# The caller defines, before calling anything here:
#   SG                  the CLI as a command prefix, e.g. "sudo socketguard"
#   TP                  the installed third_party directory
#   STATE               the daemon's state directory (<STATE>/tor, <STATE>/yggdrasil)
#   fail MSG            print the caller's own diagnostics and exit 1
#   mn_daemon_log       print the tail of the daemon's log
#   mn_adapter_exists   (Yggdrasil) true when the node's adapter exists
#   mn_block_in_force ADDR SUBNET   (Yggdrasil, Linux) true when the ruleset names the node
#   mn_node_on_adapter ADDR   (Yggdrasil) true when ADDR is on an interface
# Every check prints "  ok: ..." and counts; a check that cannot run on this runner is
# SKIPPED with its reason (never faked) and listed in mn_summary.

MN_OK=0
MN_SKIPPED=()

mn_step() { printf '\n== managed networks: %s\n' "$*"; }
mn_note() { echo "  $*"; }
mn_ok() { MN_OK=$((MN_OK + 1)); echo "  ok: $*"; }
mn_skip() { MN_SKIPPED+=("$*"); echo "  SKIPPED: $*"; echo "::warning::managed networks: SKIPPED: $*"; }
mn_die() {
    echo "FAIL (managed networks): $*" >&2
    echo "--- socketguard networks list ---"; $SG networks list 2>&1 || true
    echo "--- socketguard networks list --json ---"; $SG networks list --json 2>&1 || true
    echo "--- processes ---"; ps -axo pid,uid,user,command 2>/dev/null | grep -E 'tor|ygg|socketguard' | grep -v grep || true
    echo "--- daemon log ---"; mn_daemon_log 2>&1 || true
    fail "managed networks: $*"
}
mn_summary() {
    echo
    echo "managed networks: $MN_OK checks passed, ${#MN_SKIPPED[@]} skipped"
    local s
    for s in ${MN_SKIPPED[@]+"${MN_SKIPPED[@]}"}; do echo "  skipped: $s"; done
}

command -v jq >/dev/null 2>&1 || { echo "test/managed.sh needs jq" >&2; exit 1; }

mn_netjson() { $SG networks list --json; }
# mn_field ID JQ-EXPRESSION: a field of one network (empty when absent).
mn_field() { { mn_netjson 2>/dev/null | jq -r --arg id "$1" ".[] | select(.id == \$id) | ($2) // empty"; } || true; }
mn_pid() { pgrep -f "$1" | head -1 || true; }
# The yggdrasil process itself, not the child-guard whose command line also names it.
mn_ygg_pid() { pgrep -f "^/[^ ]*/third_party/yggdrasil/yggdrasil( |$)" | head -1 || true; }
mn_uid() { ps -o uid= -p "$1" 2>/dev/null | tr -d " " || true; }
mn_gone() { [ -z "$(mn_pid "$1")" ]; }
mn_running() { [ -n "$(mn_pid "$1")" ]; }
# mn_until SECONDS CMD...: poll every second.
mn_until() { local end=$((SECONDS + $1)); shift; until "$@" >/dev/null 2>&1; do [ "$SECONDS" -ge "$end" ] && return 1; sleep 1; done; }

# mn_wait_up ID SECONDS: the network's status is up; prints each distinct state on the way.
mn_wait_up() {
    local id=$1 end=$((SECONDS + $2)) last="" now
    while :; do
        mn_netjson 2>/dev/null | jq -e --arg id "$id" '.[] | select(.id == $id) | .status.state == "up"' >/dev/null 2>&1 && return 0
        now="$(mn_netjson 2>/dev/null | jq -r --arg id "$id" '.[] | select(.id == $id) | "\(.status.state) \(.status.reason // "") [\(.managed.state // "-")\(if .managed.progress then " " + (.managed.progress | tostring) + "%" else "" end)] \(.managed.detail // "")"' 2>/dev/null)" || now=""
        [ "$now" != "$last" ] && { mn_note "$id: $now"; last=$now; }
        [ "$SECONDS" -ge "$end" ] && return 1
        sleep 2
    done
}

# --- what the package ships ----------------------------------------------------------------

mn_bundled() {
    mn_step "the bundled files (status, account)"
    local j n want got
    j="$($SG status --json)" || mn_die "socketguard status --json failed"
    echo "$j" | jq -c '.bundled'
    echo "$j" | jq -e '(.bundled.dir != null) and ([.bundled.versions[].name] | (index("tor") != null) and (index("yggdrasil") != null))' >/dev/null \
        || mn_die "status does not name the bundled tor and yggdrasil"
    mn_ok "status names the bundled tor and yggdrasil"
    [ "$(echo "$j" | jq -r '.bundled.dir')" = "$TP" ] || mn_die "the daemon found its third_party directory at '$(echo "$j" | jq -r '.bundled.dir')', expected $TP"
    mn_ok "the daemon found $TP"
    for n in tor yggdrasil; do
        want="$(awk -v n="$n" '$1 == n { print $2; exit }' "$TP/VERSIONS")"
        got="$(echo "$j" | jq -r --arg n "$n" '.bundled.versions[] | select(.name == $n) | .version')"
        [ -n "$want" ] && [ "$want" = "$got" ] || mn_die "$n: status says '$got', $TP/VERSIONS says '$want'"
        mn_ok "$n $got (as in VERSIONS)"
    done
    test -f "$TP/licenses/tor.txt" && test -f "$TP/licenses/lyrebird.txt" && test -f "$TP/licenses/yggdrasil.txt" || mn_die "the licence texts are missing from $TP/licenses"
    mn_ok "licence texts in $TP/licenses"

    # The children run as an unprivileged account: it must be able to run what was installed.
    id socketguard-net >/dev/null 2>&1 || mn_die "no account socketguard-net after the install"
    local out
    out="$(sudo -u socketguard-net env LD_LIBRARY_PATH="$TP/tor" "$TP/tor/tor" --version 2>&1)" || mn_die "tor does not run as socketguard-net: $out"
    mn_ok "socketguard-net runs the installed tor: $(echo "$out" | head -1)"
    out="$(sudo -u socketguard-net sh -c "cd \"$TP/tor\" && ./pluggable_transports/lyrebird -version" 2>&1)" || mn_die "the obfs4 helper does not run as socketguard-net: $out"
    mn_ok "socketguard-net runs the installed obfs4 helper: $(echo "$out" | head -1)"
    out="$(sudo -u socketguard-net "$TP/yggdrasil/yggdrasil" -version 2>&1)" || mn_die "yggdrasil does not run as socketguard-net: $out"
    mn_ok "socketguard-net runs the installed yggdrasil: $(echo "$out" | head -1)"
}

# --- Tor -----------------------------------------------------------------------------------

mn_tor() {
    mn_step "managed Tor"
    $SG networks add tor --id tor || mn_die "networks add tor failed"
    mn_note "waiting for the bootstrap (up to 10 minutes)"
    mn_wait_up tor 600 || mn_die "the managed Tor network is not up after 10 minutes"
    mn_ok "the managed Tor network is up (bootstrapped)"
    local pid uid want runs
    pid="$(mn_pid '/third_party/tor/tor')"
    [ -n "$pid" ] || mn_die "the network is up but no tor from third_party is running"
    uid="$(mn_uid "$pid")"; want="$(id -u socketguard-net)"
    [ "$uid" = "$want" ] || mn_die "tor (pid $pid) runs as uid $uid ($(ps -o user= -p "$pid" | tr -d ' ')), expected socketguard-net ($want); runs_as: $(mn_field tor .managed.runs_as)"
    mn_ok "tor runs as socketguard-net (pid $pid)"
    runs="$(mn_field tor .managed.runs_as)"
    [ "$runs" = socketguard-net ] || mn_die "runs_as is '$runs'"
    mn_ok "the network card says it runs as $runs, version $(mn_field tor .managed.version)"
    mn_until 20 test -d "$STATE/tor" || mn_die "no $STATE/tor"

    $SG networks rm tor || mn_die "networks rm tor failed"
    mn_until 60 mn_gone '/third_party/tor/tor' || mn_die "tor is still running 60 s after the network was removed"
    mn_ok "removing the network ends tor"

    # Added again and left configured: the uninstall steps look at what a stop keeps and what a
    # purge removes. It does not need to bootstrap again for that.
    $SG networks add tor --id tor || mn_die "networks add tor (again) failed"
    mn_until 60 mn_running "/third_party/tor/tor" || mn_die "tor did not start again"
    mn_until 20 test -d "$STATE/tor" || mn_die "no $STATE/tor after adding the network again"
    mn_ok "added again; $STATE/tor exists"
}

# --- Yggdrasil -----------------------------------------------------------------------------

# mn_ygg_addresses ADDR: prints the compressed address and its /64 subnet (the first 8 bytes
# with the lowest bit of the first byte set), one per line.
mn_ygg_addresses() {
    python3 -c '
import ipaddress, sys
a = ipaddress.ip_address(sys.argv[1])
b = bytearray(a.packed); b[0] |= 1; b[8:] = bytes(8)
print(a.compressed); print(ipaddress.ip_address(bytes(b)).compressed)' "$1"
}

# mn_ygg_start: adds the network and watches the order of events: the node's address is known
# and in the firewall's ruleset (mn_block_in_force ADDR SUBNET) before the adapter exists.
# Sets MN_YGG_ADDR and MN_YGG_SUBNET.
mn_ygg_start() {
    $SG networks add yggdrasil --id ygg || mn_die "networks add yggdrasil failed"
    local i=0 addr="" adapter block_at="" adapter_at=""
    while [ "$i" -lt 600 ]; do
        i=$((i + 1))
        # The adapter first, then the ruleset: an adapter seen at poll N with the block seen
        # at poll N or earlier proves the block was in force when the adapter was there.
        if mn_adapter_exists; then adapter=1; else adapter=0; fi
        [ -n "$addr" ] || addr="$(mn_field ygg .managed.address)"
        if [ -n "$addr" ] && [ -z "$block_at" ]; then
            if [ -z "${MN_YGG_SUBNET:-}" ]; then
                { read -r MN_YGG_ADDR; read -r MN_YGG_SUBNET; } < <(mn_ygg_addresses "$addr")
            fi
            if mn_block_in_force "$MN_YGG_ADDR" "$MN_YGG_SUBNET"; then block_at=$i; fi
        fi
        if [ "$adapter" = 1 ] && [ -z "$adapter_at" ]; then
            adapter_at=$i
            [ -n "$addr" ] || mn_die "the adapter exists (poll $i) but the node's address is still unknown in the network card"
            [ -n "$block_at" ] || { type mn_dump_rules >/dev/null 2>&1 && mn_dump_rules; }
            [ -n "$block_at" ] || mn_die "the adapter appeared (poll $i) before the node's address $MN_YGG_ADDR / $MN_YGG_SUBNET was in the firewall ruleset"
        fi
        [ -n "$adapter_at" ] && [ -n "$block_at" ] && break
        sleep 0.2
    done
    [ -n "$adapter_at" ] || mn_die "no adapter after about 2 minutes; network: $(mn_field ygg '"\(.status.state) \(.status.reason // "") [\(.managed.state // "-")] \(.managed.detail // "")"')"
    mn_ok "the node address $MN_YGG_ADDR is known and its block ($MN_YGG_SUBNET) was in the ruleset at poll $block_at, the adapter appeared at poll $adapter_at (0.2 s apart)"
}

mn_ygg_up() {
    mn_note "waiting for the Yggdrasil network to be up (up to 2 minutes)"
    mn_wait_up ygg 120 || mn_die "the managed Yggdrasil network is not up after 2 minutes"
    mn_ok "the managed Yggdrasil network is up"
    mn_note "peers connected: $(mn_field ygg '.managed.peers_connected // "unknown"') (no peers are configured on the runner)"
    mn_note "runs as: $(mn_field ygg .managed.runs_as), version $(mn_field ygg .managed.version)"
}

# --- after the uninstall steps -------------------------------------------------------------

mn_children_stopped() {
    mn_until 60 mn_gone '/third_party/tor/tor' || mn_die "tor is still running after the removal"
    mn_until 60 mn_gone '/third_party/yggdrasil/yggdrasil' || mn_die "yggdrasil is still running after the removal"
    mn_ok "tor and yggdrasil are stopped"
}
mn_data_kept() {
    test -d "$STATE/tor" && test -d "$STATE/yggdrasil" || mn_die "the removal (keep data) deleted $STATE/tor or $STATE/yggdrasil"
    mn_ok "$STATE/tor and $STATE/yggdrasil are kept"
}
mn_data_purged() {
    test -e "$STATE/tor" && mn_die "$STATE/tor is still there after the purge"
    test -e "$STATE/yggdrasil" && mn_die "$STATE/yggdrasil is still there after the purge"
    mn_ok "$STATE/tor and $STATE/yggdrasil are gone"
}
# mn_account_created RECORD: whether the install record says the install created the account
# (read before the purge deletes the record).
mn_account_created() {
    jq -e '[.entries[] | select(.type == "unprivileged_account" and .name == "socketguard-net")][0].created == true' "$1" >/dev/null 2>&1
}
mn_account_after_purge() { # mn_account_after_purge CREATED(0|1)
    if [ "$1" = 1 ]; then
        id socketguard-net >/dev/null 2>&1 && mn_die "the install created socketguard-net and the purge left it"
        mn_ok "the account socketguard-net (created by the install) is removed"
    else
        mn_note "the install record does not say it created socketguard-net: not asserted"
    fi
}
