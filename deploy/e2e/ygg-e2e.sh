#!/usr/bin/env bash
# End-to-end test of the Yggdrasil subnet backend with two real Yggdrasil nodes in Docker.
# Runs from Git Bash on Windows or from Linux. See README.md.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE=sg-e2e-node
NET=sg-e2e-net
NODE_A=sg-e2e-a
NODE_B=sg-e2e-b
NODE_ARGS="--device /dev/net/tun"
SOCK=unix:///var/run/yggdrasil.sock
PORT=8080

. "$HERE/lib.sh"
extra_logs() { echo "--- node A yggdrasil log ---"; docker exec "$NODE_A" tail -n 15 /var/log/ygg.log 2>/dev/null; }
init_e2e

# ── Build and nodes ──────────────────────────────────────────────────────────
build_binaries
start_nodes

# Generate a Yggdrasil config once per node (the key must survive restarts).
ygg_conf() { # ygg_conf container peer-uri
  docker exec "$1" sh -c '
    yggdrasil -genconf -json | jq --arg p "$1" "
      .Listen=[\"tcp://0.0.0.0:9001\"] | .Peers=(if \$p==\"\" then [] else [\$p] end)
      | .IfName=\"ygg0\" | .AdminListen=\"'"$SOCK"'\" | .MulticastInterfaces=[]" > /etc/ygg.json
  ' sh "$2"
}
ygg_start() { docker exec -d "$1" sh -c 'yggdrasil -useconffile /etc/ygg.json >>/var/log/ygg.log 2>&1'; }
ygg_ready() { docker exec "$1" sh -c "yggdrasilctl -json -endpoint $SOCK getSelf >/dev/null && ip link show ygg0 >/dev/null"; }

ygg_conf "$NODE_A" "" && ygg_conf "$NODE_B" "tcp://$NODE_A:9001" || { fail "generate Yggdrasil configs"; exit 1; }
ygg_start "$NODE_A"; ygg_start "$NODE_B"
step "Yggdrasil up on both nodes" retry 30 ygg_ready "$NODE_A" || exit 1
retry 30 ygg_ready "$NODE_B" || { fail "Yggdrasil up on B"; exit 1; }

get_self() { A yggdrasilctl -json -endpoint "$SOCK" getSelf; }
SUBNET="$(get_self | jq -r .subnet)"
NODE_ADDR="$(get_self | jq -r .address)"
echo "      node A: address $NODE_ADDR, subnet $SUBNET"

# Test listener and daemon on A.
A sh -c "mkdir -p /srv/www && echo sg-e2e-ok > /srv/www/index.html"
docker exec -d "$NODE_A" sh -c "cd /srv/www && exec python3 -m http.server $PORT --bind ::"
docker exec -i "$NODE_A" sh -c 'cat > /etc/sg.json' <<JSON
{
  "poll_interval_secs": 2,
  "db_path": "/var/lib/sg.db", "log_level": "debug",
  "process_filter": {"mode": "allowlist", "patterns": ["python3*"]},
  "backends": [{"id": "ygg", "type": "yggdrasil", "interface": "ygg0", "admin_endpoint": "$SOCK"}]
}
JSON

daemon_start

# ── Allocation ───────────────────────────────────────────────────────────────
# The listener's address, and whether that address is inside A's subnet.
# The CLI drives the model: find the listener's app, then its address on the ygg network.
sock_addr() { app_address ygg addr; }
in_subnet() { A python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$1" "$2"; }
on_ygg0()   { A ip -6 -j addr show dev ygg0 | jq -e --arg a "$1" '[.[].addr_info[].local] | index($a)' >/dev/null; }

step "daemon detected the listener" retry 40 sock_addr || exit 1
ADDR="$(sock_addr)"
echo "      the listener got $ADDR"
B_KEY="$(B yggdrasilctl -json -endpoint "$SOCK" getSelf | jq -r .key)"
step "address is inside A's 3xx::/64 subnet" in_subnet "$ADDR" "$SUBNET"
step "address is configured on ygg0" retry 10 on_ygg0 "$ADDR"

# ── Reachability ─────────────────────────────────────────────────────────────
fetch_from_b() { B curl -fsS --max-time 5 "http://[$ADDR]:$PORT/" | grep -q sg-e2e-ok; }
fetch_node_addr_from_b() { B curl -fsS --max-time 5 "http://[$NODE_ADDR]:$PORT/" | grep -q sg-e2e-ok; }
ping_node_from_b() { B ping -6 -c 1 -W 3 "$NODE_ADDR"; }
table_exists() { A nft list table inet socketguard >/dev/null; }

# The overlay works (control), and the daemon installed its table.
step "B reaches A over Yggdrasil (ping, always allowed)" retry 90 ping_node_from_b || exit 1
step "the daemon installed the nftables table" table_exists

# Secure by default: nothing is granted, so the allocated address is denied.
step "closed by default: B cannot fetch the allocated address" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$ADDR]:$PORT/"
step "closed address is still configured on ygg0" on_ygg0 "$ADDR"

APP_ID="$(app_id)"
step "add a peer holding B's Yggdrasil key" A $SG peers add bnode --key "$B_KEY"
step "grant the listener's port to that peer" A $SG grant "$APP_ID:$PORT" bnode --network ygg
step "the grant is verified on the overlay" sh -c "docker exec $NODE_A $SG grants --app $APP_ID --json | jq -e '.[0].reach[0].reach == \"verified\"' >/dev/null"
step "granted: B can fetch from the new address" retry 30 fetch_from_b

# The listener is bound to ::, so it also answers on A's own node address; the overlay
# scope denies that because no grant covers it.
step "wildcard listener is NOT reachable via A's 200: node address" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"

# ── Yggdrasil restart: same key, new tun ─────────────────────────────────────
A pkill -x yggdrasil
step "ygg0 disappears with Yggdrasil" retry 15 sh -c "! docker exec $NODE_A ip link show ygg0"
ygg_start "$NODE_A"
step "Yggdrasil is back on A with the same subnet" retry 30 sh -c "[ \"\$(docker exec $NODE_A yggdrasilctl -json -endpoint $SOCK getSelf | jq -r .subnet)\" = \"$SUBNET\" ]"
step "address came back on ygg0" retry 40 on_ygg0 "$ADDR"
step "B can fetch again" retry 90 fetch_from_b
step "the overlay scope still covers the new tun" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"

# ── Daemon stop freezes the state ────────────────────────────────────────────
step "stop the daemon" daemon_stop
step "stopped: the table stays" table_exists
step "stopped: the address stays on ygg0" on_ygg0 "$ADDR"
step "stopped: the grant stays in force" fetch_from_b
step "stopped: the node address stays closed" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"

# A restart is not an outage and replaces the ruleset instead of flushing it.
daemon_start
step "restarted: daemon is up" retry 20 daemon_running
step "restarted: the grant stays in force" fetch_from_b
# `disable` removes everything and keeps it off, also against the running daemon's reconcile.
step "socketguard disable succeeds" A $SG disable --yes
step "disabled: the table is gone" sh -c "! docker exec $NODE_A nft list table inet socketguard >/dev/null 2>&1"
step "disabled: the address left ygg0" sh -c "! docker exec $NODE_A ip -6 -j addr show dev ygg0 | jq -e --arg a '$ADDR' '[.[].addr_info[].local] | index(\$a)' >/dev/null"
sleep 6
step "disabled: a reconcile pass did not put the table back" sh -c "! docker exec $NODE_A nft list table inet socketguard >/dev/null 2>&1"
step "status reports disabled" sh -c "docker exec $NODE_A $SG status --json | jq -e .disabled >/dev/null"
step "socketguard enable succeeds" A $SG enable
step "enabled: the table is back" retry 20 table_exists
step "enabled: the address is back on ygg0" retry 20 on_ygg0 "$ADDR"
step "enabled: the grant is in force again" retry 30 fetch_from_b
step "enabled: the node address is closed again" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$NODE_ADDR]:$PORT/"

step "revoke the grant" A $SG revoke "$APP_ID:$PORT" bnode
step "revoked: B cannot fetch" retry 30 sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$ADDR]:$PORT/"
step "blocked attempts are listed by 'activity --blocked'" retry 150 sh -c "docker exec $NODE_B curl -s --max-time 2 http://[$ADDR]:$PORT/ >/dev/null; docker exec $NODE_A $SG activity --blocked --json | jq -e 'length > 0' >/dev/null"
step "stop the daemon again" daemon_stop
step "stopped: revoked stays closed" sh -c "! docker exec $NODE_B curl -fsS --max-time 4 http://[$ADDR]:$PORT/"
step "stopped: the table stays" table_exists

# ── Disable ──────────────────────────────────────────────────────────────────
step "daemon --disable succeeds" A sh -c "SOCKETGUARD_CONFIG=/etc/sg.json $DAEMON --disable"
step "disable removed the table" sh -c "! docker exec $NODE_A nft list table inet socketguard >/dev/null 2>&1"
step "disable removed the address from ygg0" sh -c "! docker exec $NODE_A ip -6 -j addr show dev ygg0 | jq -e --arg a '$ADDR' '[.[].addr_info[].local] | index(\$a)' >/dev/null"
step "disabled: the wildcard listener is reachable via the node address" retry 10 fetch_node_addr_from_b

# The latch is persistent: a daemon started afterwards leaves the host open until enabled.
daemon_start
step "latch: daemon is up" retry 20 daemon_running
sleep 6
step "latch: the restarted daemon did not reinstall the table" sh -c "! docker exec $NODE_A nft list table inet socketguard >/dev/null 2>&1"
step "latch: enable (CLI, running daemon) restores the table" sh -c "docker exec $NODE_A $SG enable && docker exec $NODE_A nft list table inet socketguard >/dev/null"

finish
