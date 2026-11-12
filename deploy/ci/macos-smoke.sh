#!/usr/bin/env bash
# End-to-end smoke test on macOS (CI): run the real daemon with a ULA backend and pf,
# check that a listener is discovered, addressed and fenced, then that `--disable`
# leaves nothing behind. Needs sudo. Builds with cargo (debug); CI only.
set -euo pipefail

cd "$(dirname "$0")/../.."
cargo build -p socketguard-daemon -p socketguard-cli
DAEMON="$PWD/target/debug/socketguard-daemon"
CLI="$PWD/target/debug/socketguard"

TMP=$(mktemp -d)
PORT=18080
ANCHOR=socketguard
export SOCKETGUARD_CONFIG="$TMP/socketguard.json"
export SOCKETGUARD_SOCKET="$TMP/api.sock"
cat > "$SOCKETGUARD_CONFIG" <<JSON
{"poll_interval_secs":1,"db_path":"$TMP/sg.db","api_socket":"$SOCKETGUARD_SOCKET",
 "log_level":"debug",
 "process_filter":{"mode":"allowlist","patterns":["python*","Python*"]},
 "backends":[{"type":"ula"}]}
JSON

DPID=""; HPID=""
cleanup() {
  status=$?
  [ -n "$HPID" ] && kill "$HPID" 2>/dev/null || true
  [ -n "$DPID" ] && sudo kill "$DPID" 2>/dev/null || true
  if [ $status -ne 0 ]; then
    echo "--- daemon log"; cat "$TMP/daemon.log" 2>/dev/null || true
    echo "--- pf anchor"; sudo pfctl -a "$ANCHOR" -sr 2>&1 || true
    echo "--- pf main"; sudo pfctl -sr 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT

# pf must be enabled and the main ruleset must evaluate the anchor.
if ! sudo pfctl -sr 2>/dev/null | grep -q "anchor \"$ANCHOR\""; then
  { cat /etc/pf.conf; echo "anchor \"$ANCHOR\""; } > "$TMP/pf.conf"
  sudo pfctl -f "$TMP/pf.conf"
fi
sudo pfctl -e 2>&1 || true

sudo env SOCKETGUARD_CONFIG="$SOCKETGUARD_CONFIG" "$DAEMON" > "$TMP/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 30); do sudo test -S "$SOCKETGUARD_SOCKET" && break; sleep 1; done
sudo test -S "$SOCKETGUARD_SOCKET" || { echo "daemon socket never appeared"; exit 1; }

sg() { sudo env SOCKETGUARD_SOCKET="$SOCKETGUARD_SOCKET" "$CLI" "$@"; }

echo "== status"
sg status

python3 -m http.server "$PORT" --bind :: > "$TMP/http.log" 2>&1 &
HPID=$!

# Addresses exist only once a grant names a row (ADR 0047), except on Local over loopback,
# which takes no grants: there every app keeps an address, so none is granted here.
echo "== waiting for the listener to appear in apps list with an address that is up"
found=""
for _ in $(seq 30); do
  if sg --json apps list > "$TMP/apps.json" 2>/dev/null \
     && python3 -c '
import json, sys
apps = json.load(open(sys.argv[1]))
sys.exit(0 if any(any(p["port"] == int(sys.argv[2]) for p in a["ports"]) and any(ad["up"] for ad in a["addresses"]) for a in apps) else 1)
' "$TMP/apps.json" "$PORT"
  then found=1; break; fi
  sleep 1
done
[ -n "$found" ] || { echo "listener on :$PORT never got an address"; cat "$TMP/apps.json"; exit 1; }
cat "$TMP/apps.json"

echo "== pf anchor has rules"
rules=$(sudo pfctl -a "$ANCHOR" -sr)
echo "$rules"
[ -n "$rules" ] || { echo "anchor is empty"; exit 1; }

echo "== stop the daemon and disable"
sudo kill "$DPID"; wait "$DPID" 2>/dev/null || true; DPID=""
sudo env SOCKETGUARD_CONFIG="$SOCKETGUARD_CONFIG" "$DAEMON" --disable
left=$(sudo pfctl -a "$ANCHOR" -sr 2>/dev/null || true)
if [ -n "$left" ]; then echo "anchor not empty after disable:"; echo "$left"; exit 1; fi
echo "smoke OK"
