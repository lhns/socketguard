#!/usr/bin/env bash
# End-to-end test of the managed Yggdrasil network (ADR 0052) with the Yggdrasil that
# SocketGuard ships, in Docker: the daemon starts the yggdrasil it was given (built from the
# pinned source by deploy/bundle/fetch.sh --build-yggdrasil) as the unprivileged account
# socketguard-net, peered over TCP with a plain Yggdrasil node on a second container, and
# SocketGuard's firewall decides what that node can reach. Runs from Git Bash on Windows or
# from Linux. See README.md. No internet access is needed after the first build (the source
# and the Go modules are fetched once into the build cache volume).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE=sg-mygg-e2e-node
NET=sg-mygg-e2e-net
NODE_A=sg-mygg-e2e-a
NODE_B=sg-mygg-e2e-b
GO_IMAGE=${GO_IMAGE:-golang:1.26}      # builds yggdrasil; fetch.sh needs git, curl, bash and Go
PORT=8080
OTHER_PORT=8081
NODE_ARGS="--device /dev/net/tun --init"   # tun for both nodes; pid 1 reaps what the daemon leaves
STATE=/var/lib/sg                      # the daemon's state directory; Yggdrasil's is $STATE/yggdrasil
TP=/target/debug/third_party           # beside the daemon binary, where it looks for them
ADAPTER=sgygg0

. "$HERE/lib.sh"

# lib.sh's cleanup, plus the image this script builds. The build volumes are caches shared
# with the other e2e scripts and stay (CLEAN_VOLUMES=1 removes them).
cleanup() {
  if [ "$failures" -ne 0 ] && [ "$SKIPPED" -eq 0 ]; then
    echo "--- node A daemon log ---"; docker exec "$NODE_A" tail -n 60 /var/log/sg.log 2>/dev/null
    echo "--- node A processes ---"; docker exec "$NODE_A" ps -eo pid,user,args 2>/dev/null | grep -E "ygg|socketguard" | grep -v grep
    echo "--- node A interfaces ---"; docker exec "$NODE_A" ip -br link 2>/dev/null
    echo "--- node B yggdrasil log ---"; docker exec "$NODE_B" tail -n 15 /var/log/ygg-b.log 2>/dev/null
  fi
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker rmi -f "$IMAGE" >/dev/null 2>&1
  if [ "${CLEAN_VOLUMES:-0}" = 1 ]; then docker volume rm -f "$TARGET_VOL" sg-cargo-registry >/dev/null 2>&1; fi
}
init_e2e

# ── Build, the shipped Yggdrasil, the account ────────────────────────────────
build_binaries

# The pinned yggdrasil, built from source next to the daemon binary as an installer lays it
# out (a golang image instead of the node image: the node image has no Go).
step "build the shipped Yggdrasil (fetch.sh --build-yggdrasil)" \
  docker run --rm -v "$HOST_ROOT":/work -v ${TARGET_VOL}:/work/target \
    -e SOCKETGUARD_BUNDLE_CACHE=/work/target/bundle-cache "$GO_IMAGE" \
    bash /work/deploy/bundle/fetch.sh --build-yggdrasil --skip-tor linux-x86_64 /work/target/debug/third_party || exit 1

start_nodes

# `socketguard-daemon service install` creates the account too, but needs a service manager
# that a container does not have; this is the same command it runs (src/account.rs).
step "create the system account socketguard-net" A useradd --system --user-group --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin socketguard-net || exit 1
step "the shipped yggdrasil runs" A $TP/yggdrasil/yggdrasil -version || exit 1

# ── Node B: a plain Yggdrasil node that listens for the managed one ──────────
B_CONF=/etc/ygg-b.json
b_conf() {
  docker exec "$NODE_B" sh -c '
    yggdrasil -genconf -json | jq ".Listen=[\"tcp://0.0.0.0:9001\"] | .IfName=\"ygg0\" | .AdminListen=\"unix:///var/run/yggdrasil.sock\" | .MulticastInterfaces=[]" > '"$B_CONF"
}
step "node B: generate a Yggdrasil config" b_conf || exit 1
docker exec -d "$NODE_B" sh -c "yggdrasil -useconffile $B_CONF >>/var/log/ygg-b.log 2>&1"
b_ready() { docker exec "$NODE_B" sh -c "yggdrasilctl -json -endpoint unix:///var/run/yggdrasil.sock getSelf >/dev/null && ip link show ygg0 >/dev/null"; }
step "node B: Yggdrasil is up" retry 30 b_ready || exit 1
B_KEY="$(B yggdrasilctl -json -endpoint unix:///var/run/yggdrasil.sock getSelf | jq -r .key)"

# ── Daemon with a managed Yggdrasil network, and listeners ───────────────────
A sh -c "mkdir -p /srv/www && echo sg-e2e-ok > /srv/www/index.html"
docker exec -d "$NODE_A" sh -c "cd /srv/www && exec python3 -m http.server $PORT --bind ::"
docker exec -d "$NODE_A" sh -c "cd /srv/www && exec python3 -m http.server $OTHER_PORT --bind ::"
docker exec -i "$NODE_A" sh -c 'cat > /etc/sg.json' <<JSON
{
  "poll_interval_secs": 2,
  "db_path": "$STATE/sg.db", "log_level": "debug",
  "process_filter": {"mode": "allowlist", "patterns": ["python3*"]},
  "backends": [{"id": "ygg", "type": "yggdrasil", "managed": true, "peers": ["tcp://$NODE_B:9001"]}]
}
JSON
daemon_start

# The pid of the running yggdrasil of the daemon (a zombie has no command line).
ygg_pid() { docker exec "$NODE_A" pgrep -f "third_party/yggdrasil/yggdrasil -useconffile" | head -1 | grep .; }
ygg_gone() { ! ygg_pid >/dev/null; }
net_json() { docker exec "$NODE_A" $SG networks list --json; }
net_up() { net_json | jq -e '.[0].kind == "yggdrasil" and .[0].status.state == "up"' >/dev/null; }
net_reason() { net_json | jq -r '.[0] | (.status.reason // .status.state) + " [" + (.managed.state // "-") + "]"'; }
wait_up() { # wait_up SECONDS: net_up, printing each distinct reason on the way
  local end=$((SECONDS + $1)) last="" now
  while ! net_up 2>/dev/null; do
    now="$(net_reason 2>/dev/null)"
    [ "$now" != "$last" ] && { echo "      network: $now"; last="$now"; }
    [ "$SECONDS" -ge "$end" ] && return 1
    sleep 2
  done
}
on_adapter() { A ip -6 -j addr show dev $ADAPTER | jq -e --arg a "$1" '[.[].addr_info[].local] | index($a)' >/dev/null; }
in_subnet() { A python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$1" "$2"; }
table_exists() { A nft list table inet socketguard >/dev/null; }

step "the daemon started a yggdrasil of its own" retry 60 ygg_pid || exit 1
FIRST_YGG="$(ygg_pid)"
ygg_user() { [ "$(docker exec "$NODE_A" ps -o user= -p "$FIRST_YGG" | tr -d ' ')" = socketguard-net ]; }
step "yggdrasil dropped to socketguard-net after creating the tun" retry 20 ygg_user
step "the status names the account and the shipped version" sh -c "docker exec $NODE_A $SG networks list --json | jq -e '.[0].managed.runs_as == \"socketguard-net\" and (.[0].managed.version | length > 0)' >/dev/null"
step "the install record lists <state>/yggdrasil as an owned directory" sh -c "docker exec $NODE_A cat /etc/setup-log.json | jq -e --arg p '$STATE/yggdrasil' '[.entries[] | select(.type == \"owned_directory\" and .path == \$p)] | length == 1' >/dev/null"
step "yggdrasil.conf is the daemon's own and private (0600)" sh -c "[ \"\$(docker exec $NODE_A stat -c '%U %a' $STATE/yggdrasil/yggdrasil.conf)\" = 'root 600' ]"
step "the run directory (admin socket) belongs to socketguard-net" sh -c "[ \"\$(docker exec $NODE_A stat -c '%U %a' $STATE/yggdrasil/run)\" = 'socketguard-net 700' ]"
step "the conf leaves the multicast default alone" sh -c "! docker exec $NODE_A grep -q Multicast $STATE/yggdrasil/yggdrasil.conf"

echo "      waiting for the managed node to come up (up to 90s)"
if ! wait_up 90; then
  echo "      last network state: $(net_reason)"
  fail "the managed network came up"; exit 1
fi
pass "the managed network is up"
peers_connected() { net_json | jq -e '.[0].managed.peers_connected >= 1' >/dev/null; }
step "the status shows peers_connected >= 1" retry 40 peers_connected || exit 1
NODE_ADDR="$(net_json | jq -r '.[0].managed.address')"
# The /64 of a node: the first 8 bytes of its address with the lowest bit of the first byte set.
SUBNET="$(A python3 -c 'import ipaddress,sys; b=bytearray(ipaddress.ip_address(sys.argv[1]).packed); b[0]|=1; b[8:]=bytes(8); print(ipaddress.ip_address(bytes(b)).compressed+"/64")' "$NODE_ADDR")"
step "the adapter $ADAPTER holds the node's address" on_adapter "$NODE_ADDR"
echo "      node address $NODE_ADDR (subnet $SUBNET)"
step "node B has a route to the managed node (ping, always allowed)" retry 90 B ping -6 -c 1 -W 3 "$NODE_ADDR"

# ── Closed by default, then one port for one peer ────────────────────────────
step "daemon detected the listener" retry 60 app_id || exit 1
APP_ID="$(app_id)"
step "the daemon installed the nftables table" table_exists
fetch_node_addr() { B curl -fsS --max-time 5 "http://[$NODE_ADDR]:$PORT/" | grep -q sg-e2e-ok; }
step "before the grant: the node's address answers nothing" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"
SUBNET_PREFIX="${SUBNET%%/*}"
# An address of the /64 that SocketGuard did not give out: the wildcard listener would
# answer on it, the `overlay:<network>:subnet` scope must not let it.
step "plant an address of the node's /64 on the adapter" A ip -6 addr add "${SUBNET_PREFIX}1/128" dev $ADAPTER
step "before the grant: nothing in the node's /64 answers" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[${SUBNET_PREFIX}1]:$PORT/"

step "add a peer holding B's Yggdrasil key" A $SG peers add --label bnode --key "$B_KEY"
step "grant the listener's port to that peer" A $SG grant "$APP_ID:$PORT" bnode --network ygg
step "granted: the app got an address" retry 40 app_address ygg addr || exit 1
ADDR="$(app_address ygg addr)"
echo "      the listener got $ADDR"
step "the address is inside the node's /64" in_subnet "$ADDR" "$SUBNET"
step "the address is on $ADAPTER" retry 10 on_adapter "$ADDR"
fetch_granted() { B curl -fsS --max-time 5 "http://[$ADDR]:$PORT/" | grep -q sg-e2e-ok; }
step "the granted port answers on SocketGuard's address" retry 40 fetch_granted
step "another port on that address does not answer" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$ADDR]:$OTHER_PORT/"
step "the node's own address still answers nothing" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"

# ── Turned off and on ────────────────────────────────────────────────────────
step "socketguard disable succeeds" A $SG disable --yes
step "disabled: yggdrasil is gone" retry 30 ygg_gone
step "disabled: the adapter is gone" retry 15 sh -c "! docker exec $NODE_A ip link show $ADAPTER"
step "disabled: the network says it is turned off" sh -c "docker exec $NODE_A $SG networks list --json | jq -e '.[0].managed.state == \"stopped\" and .[0].status.state == \"down\"' >/dev/null"
step "disabled: the key and the configuration are kept" A test -f $STATE/yggdrasil/yggdrasil.conf
sleep 6
step "disabled: a reconcile pass did not start yggdrasil again" ygg_gone
step "socketguard enable succeeds" A $SG enable
step "enabled: yggdrasil is started again and the network comes back" wait_up 90
step "enabled: it is the same node (same address)" sh -c "[ \"\$(docker exec $NODE_A $SG networks list --json | jq -r '.[0].managed.address')\" = '$NODE_ADDR' ]"
step "enabled: peers are connected again" retry 40 peers_connected
step "enabled: the grant is in force again" retry 60 fetch_granted

# ── The daemon is killed ─────────────────────────────────────────────────────
# Yggdrasil changes its user id after creating the tun, which clears the parent-death
# signal: it outlives a killed daemon (the rules stay in force), and the next daemon ends
# the leftover through the pid file before starting its own.
OLD_YGG="$(ygg_pid)"
A pkill -9 -x socketguard-dae
sleep 3
step "yggdrasil outlives a killed daemon (the firewall rules stay)" sh -c "[ \"\$(docker exec $NODE_A pgrep -f 'third_party/yggdrasil/yggdrasil -useconffile' | head -1)\" = '$OLD_YGG' ]"
step "the table stays while the daemon is gone" table_exists
step "the granted port still answers" fetch_granted
step "the node's own address is still closed" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"
step "the daemon starts again" daemon_start
step "the leftover yggdrasil is ended and a new one runs" retry 60 sh -c "[ -n \"\$(docker exec $NODE_A pgrep -f 'third_party/yggdrasil/yggdrasil -useconffile' | head -1)\" ] && [ \"\$(docker exec $NODE_A pgrep -f 'third_party/yggdrasil/yggdrasil -useconffile' | head -1)\" != '$OLD_YGG' ]"
step "the network comes back" wait_up 90
step "the grant is in force again" retry 60 fetch_granted

# ── The daemon stops ─────────────────────────────────────────────────────────
step "stopping the daemon (SIGTERM) works" daemon_stop
step "yggdrasil is gone after a normal stop" retry 30 ygg_gone
step "the adapter is gone after a normal stop" retry 15 sh -c "! docker exec $NODE_A ip link show $ADAPTER"
step "socketguard-daemon --disable runs without a daemon" docker exec -e SOCKETGUARD_CONFIG=/etc/sg.json "$NODE_A" $DAEMON --disable

# ── One node per host ────────────────────────────────────────────────────────
# Another node (the plain Yggdrasil of the image) runs on A: the managed one is held back
# and says why; when it is gone, the managed one starts.
docker exec -i "$NODE_A" sh -c 'yggdrasil -genconf -json | jq ".IfName=\"ygg9\" | .AdminListen=\"none\" | .MulticastInterfaces=[]" > /etc/ygg-other.json'
docker exec -d "$NODE_A" sh -c "yggdrasil -useconffile /etc/ygg-other.json >>/var/log/ygg-other.log 2>&1"
other_up() { docker exec "$NODE_A" ip -6 addr show dev ygg9 | grep -q "inet6 [23]"; }
step "another Yggdrasil node runs on A (interface ygg9)" retry 20 other_up
daemon_start
step "the daemon is up" retry 20 daemon_running
step "socketguard enable succeeds (the latch from --disable)" A $SG enable
other_reason() { net_json | jq -e '.[0].managed.state == "waiting" and (.[0].managed.detail | startswith("another Yggdrasil node is running on this host"))' >/dev/null; }
step "with another node running, the managed one is held back and says why" retry 40 other_reason
sleep 4
step "no yggdrasil of the daemon was started" ygg_gone
A pkill -f "yggdrasil -useconffile /etc/ygg-other.json"
step "when the other node is gone, the managed one starts" wait_up 90

# ── Removing the network ─────────────────────────────────────────────────────
step "removing the network succeeds" A $SG networks rm ygg --yes
step "removed: yggdrasil is gone" retry 30 ygg_gone
step "removed: the adapter is gone" retry 15 sh -c "! docker exec $NODE_A ip link show $ADAPTER"
step "removed: the configuration with the key is gone" sh -c "! docker exec $NODE_A test -e $STATE/yggdrasil"
step "stop the daemon" daemon_stop
step "nothing of yggdrasil is left running" ygg_gone

finish
