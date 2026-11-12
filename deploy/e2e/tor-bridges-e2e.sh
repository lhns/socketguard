#!/usr/bin/env bash
# End-to-end test of bridges for SocketGuard's Tor network (ADR 0052) with real Tor in Docker:
# a bridge line (documentation-range address, made-up fingerprint and cert) makes the daemon
# write the bridge lines into Tor's torrc and Tor start the obfs4 helper that ships with it;
# the bridge does not exist, so Tor does not bootstrap through it; clearing the bridges makes
# Tor bootstrap directly again. The daemon runs from a directory with a space in its name and
# keeps its state in one, as on macOS and Windows.
# Runs from Git Bash on Windows or from Linux. Needs internet access to the Tor network and to
# dist.torproject.org (the last step only). See README.md. Exit codes: 0 passed, 1 a step
# failed, 2 Tor could not bootstrap directly from this Docker network.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE=sg-tor-bridges-e2e-node
NET=sg-tor-bridges-e2e-net
NODE_A=sg-tor-bridges-e2e-a
NODE_B=sg-tor-bridges-e2e-b
DOCKERFILE=Dockerfile.tor
BOOTSTRAP_SECS=${BOOTSTRAP_SECS:-240}
NODE_ARGS="--init"
INSTALL="/opt/sg dir"                  # the daemon and third_party/ live here: a path with a space
STATE="/var/lib/sg state"              # the daemon's state directory, also with a space

. "$HERE/lib.sh"

cleanup() {
  if [ "$failures" -ne 0 ] && [ "$SKIPPED" -eq 0 ]; then
    echo "--- node A daemon log ---"; docker exec "$NODE_A" tail -n 60 /var/log/sg.log 2>/dev/null
    echo "--- node A torrc ---"; docker exec "$NODE_A" cat "$STATE/tor/torrc" 2>/dev/null
    echo "--- node A processes ---"; docker exec "$NODE_A" ps -eo pid,user,args 2>/dev/null | grep -E "tor|lyrebird|socketguard" | grep -v grep
  fi
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker rmi -f "$IMAGE" >/dev/null 2>&1
  if [ "${CLEAN_VOLUMES:-0}" = 1 ]; then docker volume rm -f "$TARGET_VOL" sg-cargo-registry >/dev/null 2>&1; fi
}
init_e2e

# ── Build, the shipped Tor and its obfs4 helper, the account ─────────────────
build_binaries

step "fetch the shipped Tor files" docker run --rm -v "$HOST_ROOT":/work -v ${TARGET_VOL}:/work/target \
  -e SOCKETGUARD_BUNDLE_CACHE=/work/target/bundle-cache "$IMAGE" \
  bash /work/deploy/bundle/fetch.sh --skip-yggdrasil linux-x86_64 /work/target/debug/third_party || exit 1

start_nodes
step "create the system account socketguard-net" A useradd --system --user-group --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin socketguard-net || exit 1
# The daemon finds third_party/ next to its executable.
step "install the daemon and third_party under a path with a space" A sh -c \
  "mkdir -p '$INSTALL' '$STATE' && cp /target/debug/socketguard-daemon '$INSTALL/' && cp -r /target/debug/third_party '$INSTALL/' && chmod -R go+rX '$INSTALL'" || exit 1
TP="$INSTALL/third_party"
step "the shipped files include the helper and its licence" A sh -c \
  "test -x '$TP/tor/pluggable_transports/lyrebird' && test -f '$TP/licenses/lyrebird.txt' && grep -q '^lyrebird ' '$TP/VERSIONS' && ! test -e '$TP/tor/pluggable_transports/conjure-client'" || exit 1
step "the helper runs as an unprivileged account from Tor's directory" A sh -c \
  "cd '$TP/tor' && runuser -u socketguard-net -- ./pluggable_transports/lyrebird -version" || exit 1

docker exec -i "$NODE_A" sh -c 'cat > /etc/sg.json' <<JSON
{
  "poll_interval_secs": 2,
  "db_path": "$STATE/sg.db", "log_level": "debug",
  "process_filter": {"mode": "allowlist", "patterns": ["python3*"]},
  "backends": [{"id": "tor", "type": "tor"}]
}
JSON
daemon_start() { docker exec -d "$NODE_A" sh -c "SOCKETGUARD_CONFIG=/etc/sg.json exec '$INSTALL/socketguard-daemon' >>/var/log/sg.log 2>&1"; }
daemon_start

# ── Helpers ──────────────────────────────────────────────────────────────────
TORRC="$STATE/tor/torrc"
FP=0123456789ABCDEF0123456789ABCDEF01234567
CERT=$(printf 'A%.0s' $(seq 70))
BRIDGE="obfs4 192.0.2.10:443 $FP cert=$CERT iat-mode=0"
BRIDGE2="obfs4 [2001:db8::5]:9001 $FP cert=$CERT iat-mode=2"

helper_pids() { docker exec "$NODE_A" sh -c "ps -eo pid=,user:32=,args= | awk '\$2 == \"socketguard-net\" && \$3 ~ /pluggable_transports\\/lyrebird\$/ { print \$1 }'" | grep .; }
helper_gone() { ! helper_pids >/dev/null; }
net_up() { net_json | jq -e '.[0].status.state == "up"' >/dev/null; }
net_reason() { net_json | jq -r '.[0] | (.status.reason // .status.state)'; }
torrc_tail() { docker exec "$NODE_A" sh -c "sed -n '/^Log notice stdout\$/,\$p' '$TORRC' | tail -n +2"; }
torrc_is() { [ "$(torrc_tail)" = "$1" ]; }
reason_says_bridges() { net_reason | grep -q "connecting through bridges"; }
bridges_json() { net_json | jq -c '.[0].child.bridges // []'; }
bridges_cli() { docker exec "$NODE_A" $SG networks bridges tor --json | jq -c .; }
is() { [ "$1" = "$2" ]; }                       # is ACTUAL EXPECTED
tor_changed_from() { [ "$(tor_pid)" != "$1" ]; }
net_down() { ! net_up; }
helper_by_relative_name() { # Tor ran the helper by the relative name, from the directory with a space in its path
  # (the container has no ptrace right, so /proc/PID/exe cannot be read; the only helper Tor can
  # reach by this name is the one in "$TP/tor", which is the cwd it was started in)
  local pid; pid="$(helper_pids | head -1)" && [ -n "$pid" ] && [ "$(docker exec "$NODE_A" ps -o args= -p "$pid" | tr -d ' ')" = "./pluggable_transports/lyrebird" ]
}

SG=/target/debug/socketguard
step "the daemon started a tor of its own, without bridges" retry 60 tor_pid || exit 1
step "no bridges: the torrc has no bridge lines and no transport" torrc_is ""
step "no bridges: no helper runs" helper_gone
FIRST_TOR="$(tor_pid)"

# ── Hostile lines are refused and change nothing ─────────────────────────────
refused() { ! A $SG networks bridges tor --add "$1" >/tmp/refused.out 2>&1; }
step "a line with a second option is refused" refused "$BRIDGE
SocksPort 9050"
step "a line with a carriage return is refused" refused "$BRIDGE"$'\r'"ControlPort 9051"
step "a snowflake line is refused" refused "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"
step "a line with trailing options is refused" refused "$BRIDGE SocksPort 9050"
step "refused lines changed nothing: no bridges" is "$(bridges_cli)" '[]'
step "refused lines changed nothing: the same tor" is "$(tor_pid)" "$FIRST_TOR"

# ── Set bridges ──────────────────────────────────────────────────────────────
step "set two bridges (one with the optional Bridge prefix and a lower-case fingerprint)" \
  A $SG networks bridges tor --add "Bridge obfs4 192.0.2.10:443 ${FP,,} cert=$CERT iat-mode=0" --add "$BRIDGE2"
step "the status lists them in canonical form" is "$(bridges_json)" "$(jq -nc --arg a "$BRIDGE" --arg b "$BRIDGE2" '[$a,$b]')"
step "the torrc ends with exactly the expected lines" torrc_is "UseBridges 1
ClientTransportPlugin obfs4 exec ./pluggable_transports/lyrebird
Bridge $BRIDGE
Bridge $BRIDGE2"
step "the torrc has no other transport and no other option from the lines" sh -c \
  "[ \$(docker exec $NODE_A grep -c ClientTransportPlugin '$TORRC') = 1 ] && [ \$(docker exec $NODE_A grep -c -E 'SocksPort [1-9]|ControlPort 9' '$TORRC') = 0 ]"
step "changing the bridges restarted Tor" retry 60 tor_changed_from "$FIRST_TOR"
step "Tor started the obfs4 helper, as the unprivileged account" retry 90 helper_pids
step "the helper was found by its relative name and is run by Tor from the directory with a space" helper_by_relative_name
step "the network says it is connecting through bridges" retry 60 reason_says_bridges
sleep 20
step "the bridge does not exist: the network is not up" net_down
step "still connecting through bridges" reason_says_bridges
BRIDGE_TOR="$(tor_pid)"

# ── Clear them: Tor bootstraps directly again ────────────────────────────────
step "clear the bridges" A $SG networks bridges tor --clear
step "the torrc has no bridge lines again" torrc_is ""
step "Tor restarted without the helper" retry 60 tor_changed_from "$BRIDGE_TOR"
step "the helper is gone" retry 30 helper_gone
step "the status lists no bridges" is "$(bridges_json)" '[]'

echo "      waiting for SocketGuard's Tor to bootstrap directly (up to ${BOOTSTRAP_SECS}s)"
end=$((SECONDS + BOOTSTRAP_SECS))
while ! net_up 2>/dev/null; do
  if [ "$SECONDS" -ge "$end" ]; then
    if [ "$failures" -eq 0 ]; then skip "SocketGuard's Tor could not bootstrap from this Docker network (no route to the Tor network?); the bridge checks above passed."; fi
    fail "normal bootstrap resumed after clearing the bridges"; break
  fi
  sleep 2
done
net_up 2>/dev/null && pass "normal bootstrap resumed after clearing the bridges"

step "stopping the daemon (SIGTERM) works" daemon_stop
step "nothing of tor or the helper is left" sh -c "! docker exec $NODE_A pgrep -x tor && ! docker exec $NODE_A pgrep -f pluggable_transports/lyrebird"

finish
