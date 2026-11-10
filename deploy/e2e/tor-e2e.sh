#!/usr/bin/env bash
# End-to-end test of the Tor (onion) network with real Tor daemons in Docker.
# Runs from Git Bash on Windows or from Linux. Needs internet access to the Tor network.
# See README.md. Exit codes: 0 passed, 1 a step failed, 2 the Tor network is not reachable
# (nothing was tested beyond the control port).
set -u
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOST_ROOT="$(cd "$ROOT" && pwd -W 2>/dev/null || pwd)"

TARGET_VOL=${TARGET_VOL:-sg-target}   # docker volume holding the Linux build
IMAGE=sg-tor-e2e-node
NET=sg-tor-e2e-net
NODE_A=sg-tor-e2e-a
NODE_B=sg-tor-e2e-b
PORT=8080
BOOTSTRAP_SECS=${BOOTSTRAP_SECS:-180}
PUBLISH_SECS=${PUBLISH_SECS:-420}      # onion service publication + descriptor fetch window
FETCH_RETRY_SECS=${FETCH_RETRY_SECS:-10} # pause between fetch attempts (each one waits up to 60s itself)
failures=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
step() { # step "description" command...
  local desc=$1; shift
  if "$@"; then pass "$desc"; else fail "$desc"; return 1; fi
}
retry() { # retry SECONDS command...  (pause between attempts: $RETRY_EVERY, default 2s)
  local secs=$1; shift
  local end=$((SECONDS + secs))
  while ! "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -ge "$end" ] && return 1
    sleep "${RETRY_EVERY:-2}"
  done
}

A() { docker exec "$NODE_A" "$@"; }
B() { docker exec "$NODE_B" "$@"; }
# With stdin (heredocs): docker exec needs -i for it to reach the process.
Ai() { docker exec -i "$NODE_A" "$@"; }
Bi() { docker exec -i "$NODE_B" "$@"; }
daemon_start() { docker exec -d "$NODE_A" sh -c "SOCKETGUARD_CONFIG=/etc/sg.json exec $DAEMON >>/var/log/sg.log 2>&1"; }

cleanup() {
  if [ "$failures" -ne 0 ]; then
    echo "--- node A daemon log ---"; docker exec "$NODE_A" tail -n 40 /var/log/sg.log 2>/dev/null
    echo "--- node A tor log ---"; docker exec "$NODE_A" tail -n 15 /var/log/tor-a.log 2>/dev/null
    echo "--- node B tor log ---"; docker exec "$NODE_B" tail -n 15 /var/log/tor-b.log 2>/dev/null
  fi
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1

# ── Build ────────────────────────────────────────────────────────────────────
docker build -q -t "$IMAGE" -f "$HOST_ROOT/deploy/e2e/Dockerfile.tor" "$HOST_ROOT/deploy/e2e" >/dev/null || { fail "build node image"; exit 1; }
pass "build node image"

docker run --rm -v "$HOST_ROOT":/work -w /work \
  -v sg-cargo-registry:/usr/local/cargo/registry -v ${TARGET_VOL}:/work/target \
  -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_INCREMENTAL=0 \
  rust:1-bookworm cargo build -p socketguard-daemon -p socketguard-cli \
  || { fail "build daemon and CLI"; exit 1; }
pass "build daemon and CLI"
DAEMON=/target/debug/socketguard-daemon
SG=/target/debug/socketguard

# ── Nodes ────────────────────────────────────────────────────────────────────
docker network create "$NET" >/dev/null || { fail "create network"; exit 1; }
for n in "$NODE_A" "$NODE_B"; do
  # NET_ADMIN: the daemon on A installs its (empty) nftables table like on any host.
  docker run -d --name "$n" --network "$NET" --cap-add NET_ADMIN -v ${TARGET_VOL}:/target:ro "$IMAGE" sleep infinity >/dev/null \
    || { fail "start $n"; exit 1; }
done

# Node A: tor with a control port and cookie authentication; the daemon talks to it.
docker exec -i "$NODE_A" sh -c 'cat > /etc/torrc-a' <<'TORRC'
DataDirectory /var/lib/tor-a
SocksPort 0
ControlPort 127.0.0.1:9051
CookieAuthentication 1
Log notice file /var/log/tor-a.log
TORRC
# Node B: a client tor that holds the authorization key (socks 9050), and a client tor
# without it (socks 9060).
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

tor_start "$NODE_A" /var/lib/tor-a /etc/torrc-a /var/log/tor-a.log
echo "      waiting for Tor to bootstrap on A (up to ${BOOTSTRAP_SECS}s)"
control_up() { A nc -z 127.0.0.1 9051; }
step "tor control port is up on A" retry 30 control_up || exit 1
if ! retry "$BOOTSTRAP_SECS" bootstrapped "$NODE_A" /var/log/tor-a.log; then
  echo "SKIP  Tor could not bootstrap from this Docker network (no route to the Tor network?)."
  echo "      Last log lines:"; A tail -n 8 /var/log/tor-a.log 2>/dev/null | sed 's/^/        /'
  echo "      The control-port logic is covered by the mock-server tests (cargo test -p socketguard-daemon)."
  failures=0
  exit 2
fi
pass "tor bootstrapped on A"

# ── Daemon and listener on A ─────────────────────────────────────────────────
A sh -c "mkdir -p /srv/www && echo sg-e2e-ok > /srv/www/index.html"
docker exec -d "$NODE_A" sh -c "cd /srv/www && exec python3 -m http.server $PORT --bind ::"
docker exec -i "$NODE_A" sh -c 'cat > /etc/sg.json' <<'JSON'
{
  "poll_interval_secs": 2,
  "db_path": "/var/lib/sg.db", "log_level": "debug",
  "process_filter": {"mode": "allowlist", "patterns": ["python3*"]},
  "backends": [{"id": "tor", "type": "tor", "control": "127.0.0.1:9051", "cookie_path": "/var/lib/tor-a/control_auth_cookie"}]
}
JSON
daemon_start

app_id() { A $SG apps list --json | jq -er --argjson p "$PORT" '[.[] | select(any(.ports[]; .port == $p))][0].id'; }
onion_of() { local id; id="$(app_id)" && A $SG apps show "$id" --json | jq -er '[.addresses[] | select(.network_id == "tor") | .locator.hostname][0]'; }
# Service ids Tor runs as detached onion services, asked over A's control port.
detached() {
  Ai python3 - <<'PY'
import socket, sys
c = open("/var/lib/tor-a/control_auth_cookie", "rb").read().hex()
s = socket.create_connection(("127.0.0.1", 9051))
s.sendall(f"AUTHENTICATE {c}\r\nGETINFO onions/detached\r\nQUIT\r\n".encode())
data = b""
while chunk := s.recv(4096):
    data += chunk
text = data.decode()
if "onions/detached" not in text:
    sys.exit("no usable reply from the control port: " + repr(text))
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

step "daemon gave the listener an onion address" retry 60 onion_of || exit 1
ONION="$(onion_of)"
echo "      onion: $ONION"
APP_ID="$(app_id)"
step "the tor network is up" sh -c "docker exec $NODE_A $SG networks list --json | jq -e '.[0].kind == \"tor\" and .[0].status.state == \"up\"' >/dev/null"
step "no grant: nothing is published" nothing_published
sleep 5
step "no grant: still nothing after a reconcile pass" nothing_published

# ── Keys for B ───────────────────────────────────────────────────────────────
KEYS="$(Bi python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
k = X25519PrivateKey.generate()
b32 = lambda b: base64.b32encode(b).decode().rstrip("=")
print(b32(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
print(b32(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())))
PY
)"
PUB="$(echo "$KEYS" | sed -n 1p)"; PRIV="$(echo "$KEYS" | sed -n 2p)"
[ ${#PUB} -eq 52 ] && [ ${#PRIV} -eq 52 ] || { fail "generate an x25519 key pair"; exit 1; }
pass "generated an x25519 key pair for B"

# B's client tor learns the key, the third client gets none; both bootstrap meanwhile.
# ClientOnionAuthDir is read when tor starts, so the key goes in first.
B sh -c "install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor-b /var/lib/tor-b/onion_auth"
B sh -c "echo '${ONION%.onion}:descriptor:x25519:$PRIV' > /var/lib/tor-b/onion_auth/a.auth_private && chown debian-tor /var/lib/tor-b/onion_auth/a.auth_private && chmod 600 /var/lib/tor-b/onion_auth/a.auth_private"
tor_start "$NODE_B" /var/lib/tor-b /etc/torrc-b /var/log/tor-b.log
tor_start "$NODE_B" /var/lib/tor-c /etc/torrc-c /var/log/tor-c.log

step "add a peer holding B's Tor key" A $SG peers add bnode --tor-key "$PUB"
step "the peer's key is stored normalized" sh -c "docker exec $NODE_A $SG peers show bnode --json | jq -e --arg k '$PUB' '.credentials[0].kind == \"tor_client_key\" and .credentials[0].value == \$k' >/dev/null"
step "grant the listener's port to that peer" A $SG grant "$APP_ID:$PORT" bnode --network tor
step "the grant is verified on Tor" sh -c "docker exec $NODE_A $SG grants --app $APP_ID --json | jq -e '.[0].reach[0].reach == \"verified\"' >/dev/null"
step "granted: the service is published" retry 30 one_published
# The daemon generated the key and name itself; the ServiceID Tor derived from that key on
# the first ADD_ONION must be the same name (`apps show` reports the local one).
service_is_local_name() { [ "$(detached)" = "${ONION%.onion}" ]; }
step "Tor's ServiceID equals the locally computed name" service_is_local_name
step "share prints the onion URL" sh -c "docker exec $NODE_A $SG share $APP_ID --network tor | grep -q 'http://$ONION:$PORT'"

echo "      waiting for B's tor to bootstrap and for the onion service to publish (up to ${PUBLISH_SECS}s)"
retry "$BOOTSTRAP_SECS" bootstrapped "$NODE_B" /var/log/tor-b.log || { fail "tor bootstrapped on B"; exit 1; }
retry "$BOOTSTRAP_SECS" bootstrapped "$NODE_B" /var/log/tor-c.log || { fail "tor bootstrapped on the third client"; exit 1; }
pass "tor bootstrapped on B and on the third client"

fetch_retry() { RETRY_EVERY=$FETCH_RETRY_SECS retry "$@"; }
fetch_b() { B curl -fsS --max-time 60 --socks5-hostname 127.0.0.1:9050 "http://$ONION:$PORT/" | grep -q sg-e2e-ok; }
fetch_c() { B curl -fsS --max-time 60 --socks5-hostname 127.0.0.1:9060 "http://$ONION:$PORT/" | grep -q sg-e2e-ok; }
step "B (holding the key) fetches the page over Tor" fetch_retry "$PUBLISH_SECS" fetch_b || exit 1
step "a third client without the key cannot fetch it" sh -c "! docker exec $NODE_B curl -fsS --max-time 60 --socks5-hostname 127.0.0.1:9060 http://$ONION:$PORT/"

# ── Revoke ───────────────────────────────────────────────────────────────────
step "revoke the grant" A $SG revoke "$APP_ID:$PORT" bnode
step "revoked: the service is removed from Tor" retry 30 nothing_published
step "revoked: B cannot fetch" retry 90 sh -c "! docker exec $NODE_B curl -fsS --max-time 30 --socks5-hostname 127.0.0.1:9050 http://$ONION:$PORT/"

# ── Disable ──────────────────────────────────────────────────────────────────
step "grant to the peer again" A $SG grant "$APP_ID:$PORT" bnode --network tor
step "granted again: published" retry 30 one_published
step "socketguard disable succeeds" A $SG disable --yes
step "disabled: the service is removed" retry 30 nothing_published
sleep 6
step "disabled: a reconcile pass did not republish" nothing_published
step "socketguard enable succeeds" A $SG enable
step "enabled: published again" retry 30 one_published

echo
if [ "$failures" -eq 0 ]; then echo "ALL STEPS PASSED"; else echo "$failures STEP(S) FAILED"; exit 1; fi
