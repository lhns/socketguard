#!/usr/bin/env bash
# End-to-end test of the managed Tor network (ADR 0052) with real Tor in Docker: the daemon
# starts the Tor it ships (the Tor Expert Bundle fetched by deploy/bundle/fetch.sh) as the
# unprivileged account socketguard-net, publishes an onion service for a granted app, ends
# Tor with the daemon and keeps its data directory when SocketGuard is turned off.
# Runs from Git Bash on Windows or from Linux. Needs internet access to the Tor network
# and to dist.torproject.org. See README.md. Exit codes: 0 passed, 1 a step failed, 2 Tor
# could not bootstrap from this Docker network.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE=sg-mtor-e2e-node
NET=sg-mtor-e2e-net
NODE_A=sg-mtor-e2e-a
NODE_B=sg-mtor-e2e-b
DOCKERFILE=Dockerfile.tor
PORT=8080
BOOTSTRAP_SECS=${BOOTSTRAP_SECS:-240}
PUBLISH_SECS=${PUBLISH_SECS:-420}
FETCH_RETRY_SECS=${FETCH_RETRY_SECS:-10}
STATE=/var/lib/sg                      # the daemon's state directory; Tor's is $STATE/tor
TP=/target/debug/third_party           # beside the daemon binary, where it looks for them

. "$HERE/lib.sh"

# lib.sh's cleanup, plus the image: this script builds it. The build volumes are caches
# shared with the other e2e scripts and stay (CLEAN_VOLUMES=1 removes them).
cleanup() {
  if [ "$failures" -ne 0 ] && [ "$SKIPPED" -eq 0 ]; then
    echo "--- node A daemon log ---"; docker exec "$NODE_A" tail -n 60 /var/log/sg.log 2>/dev/null
    echo "--- node A processes ---"; docker exec "$NODE_A" ps -eo pid,user,args 2>/dev/null | grep -E "tor|socketguard" | grep -v grep
    echo "--- node B tor log ---"; docker exec "$NODE_B" tail -n 15 /var/log/tor-b.log 2>/dev/null
  fi
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker rmi -f "$IMAGE" >/dev/null 2>&1
  if [ "${CLEAN_VOLUMES:-0}" = 1 ]; then docker volume rm -f "$TARGET_VOL" sg-cargo-registry >/dev/null 2>&1; fi
}
init_e2e

# ── Build, the shipped Tor, the account ──────────────────────────────────────
build_binaries

# The pinned Tor Expert Bundle next to the daemon binary, as an installer lays it out.
# (No gpg in the image: the checksum pin is checked, the signature is not.)
step "fetch the shipped Tor files" docker run --rm -v "$HOST_ROOT":/work -v ${TARGET_VOL}:/work/target \
  -e SOCKETGUARD_BUNDLE_CACHE=/work/target/bundle-cache "$IMAGE" \
  bash /work/deploy/bundle/fetch.sh --skip-yggdrasil linux-x86_64 /work/target/debug/third_party || exit 1

start_nodes

# `socketguard-daemon service install` creates the account too, but needs a service manager
# that a container does not have; this is the same command it runs (src/account.rs).
step "create the system account socketguard-net" A useradd --system --user-group --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin socketguard-net || exit 1
step "the shipped tor starts (libraries found)" A env LD_LIBRARY_PATH=$TP/tor $TP/tor/tor --version || exit 1

# ── __OwningControllerProcess on its own (the daemon also uses a parent-death signal) ──
owner_check() {
  Ai sh -s <<EOF
set -e
install -d -o socketguard-net -g socketguard-net -m 700 /tmp/owned
printf 'DataDirectory /tmp/owned\nSocksPort 0\nDisableNetwork 1\nLog notice file /tmp/owned/log\n' > /tmp/owned/torrc
chown socketguard-net /tmp/owned/torrc
sleep 600 &
OWNER=\$!
runuser -u socketguard-net -- env LD_LIBRARY_PATH=$TP/tor $TP/tor/tor -f /tmp/owned/torrc --__OwningControllerProcess \$OWNER >/dev/null 2>&1 &
sleep 5
pgrep -x tor >/dev/null || { echo "tor did not start"; exit 1; }
kill \$OWNER
i=0
while pgrep -x tor >/dev/null; do
  i=\$((i + 1)); [ \$i -gt 60 ] && { echo "tor still running 60s after its owner died"; exit 1; }
  sleep 1
done
EOF
}
step "tor ends when the process named by __OwningControllerProcess dies" owner_check

# ── Node B: client tors (as in tor-e2e.sh) ───────────────────────────────────
docker exec -i "$NODE_B" sh -c 'cat > /etc/torrc-b' <<'TORRC'
DataDirectory /var/lib/tor-b
SocksPort 9050
ClientOnionAuthDir /var/lib/tor-b/onion_auth
Log notice file /var/log/tor-b.log
TORRC
docker exec -i "$NODE_B" sh -c 'cat > /etc/torrc-c' <<'TORRC'
DataDirectory /var/lib/tor-c
SocksPort 9060
Log notice file /var/log/tor-c.log
TORRC
tor_start() { # tor_start container dir torrc logfile
  docker exec "$1" sh -c "install -d -o debian-tor -g debian-tor -m 700 $2 $2/onion_auth && touch $4 && chown debian-tor $4"
  docker exec -d "$1" sh -c "runuser -u debian-tor -- tor -f $3 >/dev/null 2>&1"
}
bootstrapped() { docker exec "$1" grep -q "Bootstrapped 100%" "$2"; }

# ── Daemon with a managed Tor network, and a listener ────────────────────────
A sh -c "mkdir -p /srv/www && echo sg-e2e-ok > /srv/www/index.html"
docker exec -d "$NODE_A" sh -c "cd /srv/www && exec python3 -m http.server $PORT --bind ::"
docker exec -i "$NODE_A" sh -c 'cat > /etc/sg.json' <<JSON
{
  "poll_interval_secs": 2,
  "db_path": "$STATE/sg.db", "log_level": "debug",
  "process_filter": {"mode": "allowlist", "patterns": ["python3*"]},
  "backends": [{"id": "tor", "type": "tor", "managed": true}]
}
JSON
daemon_start

tor_pid() { A pgrep -x tor | head -n1; }
tor_gone() { ! docker exec "$NODE_A" pgrep -x tor >/dev/null; }
net_json() { docker exec "$NODE_A" $SG networks list --json; }
net_up() { net_json | jq -e '.[0].kind == "tor" and .[0].status.state == "up"' >/dev/null; }
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

step "the daemon started a tor of its own" retry 60 tor_pid || exit 1
step "tor runs as socketguard-net" sh -c "[ \"\$(docker exec $NODE_A ps -o user= -p $(tor_pid) | tr -d ' ')\" = socketguard-net ]"
step "the status names the account and the shipped version" sh -c "docker exec $NODE_A $SG networks list --json | jq -e '.[0].managed.runs_as == \"socketguard-net\" and (.[0].managed.version | length > 0)' >/dev/null"
step "tor's data directory is private to socketguard-net" sh -c "[ \"\$(docker exec $NODE_A stat -c '%U %a' $STATE/tor)\" = 'socketguard-net 700' ]"
step "the control socket is Tor's own and the cookie is 0600" sh -c "docker exec $NODE_A sh -c 'test -S $STATE/tor/control && [ \"\$(stat -c %a $STATE/tor/control_auth_cookie)\" = 600 ]'"

echo "      waiting for the managed Tor to bootstrap (up to ${BOOTSTRAP_SECS}s)"
if ! wait_up "$BOOTSTRAP_SECS"; then
  echo "      Last network state: $(net_reason)"
  A tail -n 8 /var/log/sg.log 2>/dev/null | sed 's/^/        /'
  skip "the managed Tor could not bootstrap from this Docker network (no route to the Tor network?)."
fi
pass "the managed Tor bootstrapped and the network is up"

# ── Grants and the onion service ─────────────────────────────────────────────
onion_of() { app_address tor hostname; }
# Service ids Tor runs as detached onion services, asked over the control socket.
detached() {
  Ai python3 - <<PY
import socket, sys
c = open("$STATE/tor/control_auth_cookie", "rb").read().hex()
s = socket.socket(socket.AF_UNIX)
s.connect("$STATE/tor/control")
s.sendall(f"AUTHENTICATE {c}\r\nGETINFO onions/detached\r\nQUIT\r\n".encode())
data = b""
while chunk := s.recv(4096):
    data += chunk
text = data.decode()
if "onions/detached" not in text:
    sys.exit("no usable reply from the control socket: " + repr(text))
for line in text.splitlines():
    line = line.strip()
    if line.startswith(("250-onions/detached=", "250+onions/detached=")):
        line = line.split("=", 1)[1]
    if len(line) == 56 and line.isalnum():
        print(line)
PY
}
nothing_published() { [ -z "$(detached)" ]; }
one_published() { [ "$(detached | wc -l)" -eq 1 ]; }

step "daemon detected the listener" retry 60 app_id || exit 1
APP_ID="$(app_id)"
step "no grant: nothing is published" nothing_published
step "add a peer for B without credentials" A $SG peers add --label bnode
step "the daemon generates a Tor client key for the peer" A $SG peers tor-key bnode
step "grant the listener's port to that peer" A $SG grant "$APP_ID:$PORT" bnode --network tor
step "granted: the app got an onion address" retry 60 onion_of || exit 1
ONION="$(onion_of)"
echo "      onion: $ONION"
AUTH_LINE="$(docker exec $NODE_A $SG share $APP_ID --network tor --json | jq -r '.[] | select(contains(":descriptor:x25519:"))')"
[ "${AUTH_LINE%%:descriptor:x25519:*}" = "${ONION%.onion}" ] && [ ${#AUTH_LINE} -gt 100 ] || { fail "share prints the client authorization line (got: $AUTH_LINE)"; exit 1; }
B sh -c "install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor-b /var/lib/tor-b/onion_auth"
B sh -c "echo '$AUTH_LINE' > /var/lib/tor-b/onion_auth/a.auth_private && chown debian-tor /var/lib/tor-b/onion_auth/a.auth_private && chmod 600 /var/lib/tor-b/onion_auth/a.auth_private"
tor_start "$NODE_B" /var/lib/tor-b /etc/torrc-b /var/log/tor-b.log
tor_start "$NODE_B" /var/lib/tor-c /etc/torrc-c /var/log/tor-c.log

step "granted: the service is published on the managed Tor" retry 30 one_published
service_is_local_name() { [ "$(detached)" = "${ONION%.onion}" ]; }
step "Tor's ServiceID equals the locally computed name" service_is_local_name

echo "      waiting for B's tor to bootstrap and for the onion service to publish (up to ${PUBLISH_SECS}s)"
retry "$BOOTSTRAP_SECS" bootstrapped "$NODE_B" /var/log/tor-b.log || { fail "tor bootstrapped on B"; exit 1; }
retry "$BOOTSTRAP_SECS" bootstrapped "$NODE_B" /var/log/tor-c.log || { fail "tor bootstrapped on the third client"; exit 1; }
fetch_retry() { RETRY_EVERY=$FETCH_RETRY_SECS retry "$@"; }
fetch_b() { B curl -fsS --max-time 60 --socks5-hostname 127.0.0.1:9050 "http://$ONION:$PORT/" | grep -q sg-e2e-ok; }
step "B (holding the client key) fetches the page over Tor" fetch_retry "$PUBLISH_SECS" fetch_b || exit 1
step "a third client without the key cannot fetch it" sh -c "! docker exec $NODE_B curl -fsS --max-time 60 --socks5-hostname 127.0.0.1:9060 http://$ONION:$PORT/"

# ── The daemon is killed: Tor goes with it ───────────────────────────────────
OLD_TOR="$(tor_pid)"
A pkill -9 -x socketguard-dae
step "tor ends when the daemon is killed (kill -9)" retry 90 tor_gone
step "the daemon starts again" daemon_start
step "a new tor is started and the network comes back" wait_up "$BOOTSTRAP_SECS"
[ "$(tor_pid)" != "$OLD_TOR" ] && pass "it is a new tor process" || fail "it is a new tor process"
step "the service is published again on the new tor" retry 60 one_published
step "with the same onion name" service_is_local_name

# ── Turned off and on ────────────────────────────────────────────────────────
step "socketguard disable succeeds" A $SG disable --yes
step "disabled: tor is gone" retry 30 tor_gone
step "disabled: the network says it is turned off" sh -c "docker exec $NODE_A $SG networks list --json | jq -e '.[0].managed.state == \"stopped\" and .[0].status.state == \"down\"' >/dev/null"
step "disabled: Tor's data directory is kept" A sh -c "test -d $STATE/tor && test -f $STATE/tor/torrc"
sleep 6
step "disabled: a reconcile pass did not start tor again" tor_gone
step "socketguard enable succeeds" A $SG enable
step "enabled: tor is started again and the network comes back" wait_up "$BOOTSTRAP_SECS"
step "enabled: the service is published again" retry 60 one_published

# ── The daemon stops ─────────────────────────────────────────────────────────
step "stopping the daemon (SIGTERM) stops tor" sh -c "docker exec $NODE_A pkill -TERM -x socketguard-dae && true"
step "tor is gone after a normal stop" retry 30 tor_gone
step "the data directory is kept" A test -d $STATE/tor
step "socketguard-daemon --disable runs without a daemon" docker exec -e SOCKETGUARD_CONFIG=/etc/sg.json "$NODE_A" $DAEMON --disable
step "nothing of tor is left running" tor_gone
step "the data directory is still kept" A test -d $STATE/tor

finish
