#!/usr/bin/env bash
# Shared harness of the end-to-end scripts (source it, do not run it): step reporting,
# the two docker nodes A and B, the build, the daemon and the CLI helpers.
#
# The script sets IMAGE, NET, NODE_A and NODE_B first, and optionally DOCKERFILE (default
# Dockerfile) and NODE_ARGS (extra `docker run` flags for the nodes). It defines
# `extra_logs` to print more logs when a step failed.
set -u
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Docker Desktop on Windows needs a Windows-style host path for bind mounts.
HOST_ROOT="$(cd "$ROOT" && pwd -W 2>/dev/null || pwd)"
TARGET_VOL=${TARGET_VOL:-sg-target}   # docker volume holding the Linux build
DOCKERFILE=${DOCKERFILE:-Dockerfile}
NODE_ARGS=${NODE_ARGS:-}
failures=0
SKIPPED=0

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
# skip REASON...: nothing could be tested here; exit code 2 (not a failure).
skip() {
  SKIPPED=1
  echo "SKIP  $*"
  exit 2
}
# finish: the summary line and the exit code.
finish() {
  echo
  if [ "$failures" -eq 0 ]; then echo "ALL STEPS PASSED"; else echo "$failures STEP(S) FAILED"; exit 1; fi
}

A() { docker exec "$NODE_A" "$@"; }
B() { docker exec "$NODE_B" "$@"; }
# With stdin (heredocs): docker exec needs -i for it to reach the process.
Ai() { docker exec -i "$NODE_A" "$@"; }
Bi() { docker exec -i "$NODE_B" "$@"; }

daemon_running() { A pgrep -x socketguard-dae; }
daemon_start() { docker exec -d "$NODE_A" sh -c "SOCKETGUARD_CONFIG=/etc/sg.json exec $DAEMON >>/var/log/sg.log 2>&1"; }
daemon_stop() { A pkill -x socketguard-dae; retry 15 sh -c "! docker exec $NODE_A pgrep -x socketguard-dae"; }

extra_logs() { :; }
cleanup() {
  if [ "$failures" -ne 0 ] && [ "$SKIPPED" -eq 0 ]; then
    echo "--- node A daemon log ---"; docker exec "$NODE_A" tail -n 40 /var/log/sg.log 2>/dev/null
    extra_logs
  fi
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}

# Remove leftovers of an earlier run and clean up on exit.
init_e2e() {
  trap cleanup EXIT
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}

# build_binaries: the node image, and the daemon and CLI (debug) into the $TARGET_VOL volume,
# which the nodes mount. Sets DAEMON and SG.
build_binaries() {
  docker build -q -t "$IMAGE" -f "$HOST_ROOT/deploy/e2e/$DOCKERFILE" "$HOST_ROOT/deploy/e2e" >/dev/null \
    || { fail "build node image"; exit 1; }
  pass "build node image"
  docker run --rm -v "$HOST_ROOT":/work -w /work \
    -v sg-cargo-registry:/usr/local/cargo/registry -v ${TARGET_VOL}:/work/target \
    -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_INCREMENTAL=0 \
    rust:1-bookworm cargo build -p socketguard-daemon -p socketguard-cli \
    || { fail "build daemon and CLI"; exit 1; }
  pass "build daemon and CLI"
  DAEMON=/target/debug/socketguard-daemon
  SG=/target/debug/socketguard
}

# start_nodes: the network and the nodes A and B, with the build mounted read-only.
start_nodes() {
  docker network create "$NET" >/dev/null || { fail "create network"; exit 1; }
  local n
  for n in "$NODE_A" "$NODE_B"; do
    # NET_ADMIN: the daemon on A installs its nftables table like on any host.
    docker run -d --name "$n" --network "$NET" --cap-add NET_ADMIN $NODE_ARGS \
      -v ${TARGET_VOL}:/target:ro "$IMAGE" sleep infinity >/dev/null || { fail "start $n"; exit 1; }
  done
}

# CLI helpers on node A. app_address NETWORK FIELD: a field of the locator of the listener's
# address on that network.
app_id() { A $SG apps list --json | jq -er --argjson p "$PORT" '[.[] | select(any(.ports[]; .port == $p))][0].id'; }
app_address() {
  local id; id="$(app_id)" \
    && A $SG apps show "$id" --json | jq -er --arg n "$1" --arg f "$2" '[.addresses[] | select(.network_id == $n) | .locator[$f]][0]'
}
