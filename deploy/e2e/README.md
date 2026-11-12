# End-to-end tests

- `ygg-e2e.sh`: Yggdrasil (below).
- `tor-e2e.sh`: the Tor network (below).
- `managed-tor-e2e.sh`: the Tor network with the Tor SocketGuard ships (below).
- `managed-ygg-e2e.sh`: the Yggdrasil network with the Yggdrasil SocketGuard ships (end of this file).
- `managed-tor-bridges-e2e.sh`: bridges for that Tor (section at the end of this file).

# Yggdrasil end-to-end test

`ygg-e2e.sh` checks the Yggdrasil backend against two real Yggdrasil nodes in Docker
(Linux containers; run from Git Bash on Windows or from Linux):

1. builds the daemon in `rust:1-bookworm` (cache volumes `sg-cargo-registry`, `sg-target`);
2. starts node A (Yggdrasil, the daemon, a test HTTP listener) and node B (Yggdrasil, peered to A);
3. asserts the daemon gave the listener a `300::/64` address on `ygg0` and installed its nftables table;
4. enforcement (ADR 0026/0029):
   - closed by default: B cannot fetch the allocated address; after a grant to a peer holding
     B's Yggdrasil key it can, and after the grant is revoked it cannot;
   - the wildcard listener is not reachable via A's own `200:` node address (overlay scope);
   - restarting Yggdrasil on A (same key, new tun) brings the address back and the scope still applies;
5. frozen state: after stopping the daemon, a grant stays in force and a revoked one stays closed (the table and
   address stay), and a restart does not interrupt access;
6. `socketguard-daemon --disable` removes the table and the address.

It prints PASS/FAIL per step, removes its containers and network, and exits non-zero on failure.

The test drives the daemon through the `socketguard` CLI (`peers add`, `grant`, `revoke`, `activity --blocked`,
`disable`/`enable`), so it covers the API v1 and the CLI as well. The disabled latch is checked against the
running daemon (a reconcile pass must not undo `disable`) and across a daemon restart.

# Tor end-to-end test

`tor-e2e.sh` checks the onion network against real Tor daemons in Docker (image from
`Dockerfile.tor`; needs internet access to the Tor network, the first bootstrap takes a minute or two):

1. node A runs tor (ControlPort with cookie authentication), the daemon with a `tor` network and an HTTP
   listener on 8080; node B runs a client tor with `ClientOnionAuthDir` (socks 9050) and a second client
   tor without a key (socks 9060);
2. with no grant, A publishes nothing (`GETINFO onions/detached` is empty);
3. B's x25519 key (generated with python `cryptography`) is added with `peers add --label bnode --tor-key` and
   granted; the service is published and B fetches `http://<onion>:8080` with `curl --socks5-hostname`;
4. the client without the key cannot; after `revoke` the service is gone (`DEL_ONION`);
5. `disable` removes the service and keeps it off; `enable` publishes it again.

Exit code 2 (with a `SKIP` line) means Tor could not bootstrap from this Docker network; the control-port
logic is then only covered by the mock-server tests (`cargo test -p socketguard-daemon`).

# Managed Tor end-to-end test

`managed-tor-e2e.sh` checks the Tor that SocketGuard ships and runs itself (ADR 0052), with real Tor in
Docker (image from `Dockerfile.tor`; needs internet access to the Tor network and to dist.torproject.org;
about ten minutes with a warm build cache, longer for the first Rust build):

1. builds the daemon, then lays out the pinned Tor Expert Bundle next to it with
   `deploy/bundle/fetch.sh --skip-yggdrasil linux-x86_64` (the checksum is checked, the signature is not: the
   image has no gpg);
2. creates the system account `socketguard-net` with the command `service install` runs (a container has no
   service manager, so the install itself is not run);
3. checks that Tor ends when the process named by `__OwningControllerProcess` dies;
4. starts the daemon with `{"type": "tor", "managed": true}`: tor runs as `socketguard-net`, its data directory
   `<state>/tor` is private to it, the network goes up after the bootstrap, and a granted app gets an onion
   service that a second client with the generated key can fetch (one without the key cannot);
5. `kill -9` of the daemon ends Tor; a restart starts a new Tor and publishes the same name again;
6. `disable` stops Tor and keeps `<state>/tor`; `enable` starts it again; a normal stop and
   `socketguard-daemon --disable` leave no Tor behind.

It removes its containers, network and image on exit. The build volumes (`sg-target`, `sg-cargo-registry`) are
caches shared with the other scripts; `CLEAN_VOLUMES=1` removes them. Exit code 2 (a `SKIP` line) means Tor
could not bootstrap from this Docker network. It runs nightly and on request in `.github/workflows/e2e.yml` (not on push). The fetch of the page over Tor waits up to 600 s (`PUBLISH_SECS`) and restarts B's Tor client once after 300 s (`RESTART_AFTER_SECS`) to get new circuits.

# Managed Yggdrasil end-to-end test

`managed-ygg-e2e.sh` checks the Yggdrasil that SocketGuard ships and runs itself (ADR 0052), with real
Yggdrasil nodes in Docker (image from `Dockerfile`; no internet needed once the source and the Go modules
are in the build cache volume):

1. builds the daemon, then builds the pinned Yggdrasil from source next to it with
   `deploy/bundle/fetch.sh --build-yggdrasil --skip-tor linux-x86_64` in a `golang` image (`GO_IMAGE`);
2. creates the system account `socketguard-net` (as in the Tor test) and starts node B, a plain Yggdrasil
   node that listens on TCP;
3. starts the daemon with `{"type": "yggdrasil", "managed": true, "peers": ["tcp://<B>:9001"]}`: yggdrasil
   runs as `socketguard-net` after creating its tun as root, `<state>/yggdrasil/yggdrasil.conf` is private
   to root, the network goes up, and the status shows the node's address and `peers_connected >= 1`;
4. before any grant neither the node's address nor its /64 answers B; after granting one port to B's key, only
   that port answers on SocketGuard's address, the node's own address stays closed;
5. `disable` ends yggdrasil and the adapter and keeps the key; `enable` brings the same node back;
6. a killed daemon (`kill -9`) leaves yggdrasil running behind the unchanged firewall rules (it drops the
   parent-death signal when it changes its user id), and the next daemon ends the leftover and starts its own;
7. with another Yggdrasil node running on A, the managed one is held back with the reason; when the other is
   gone it starts; removing the network ends it and deletes its configuration.

It runs nightly and on request in `.github/workflows/e2e.yml` (not on push).

# Managed Tor bridges end-to-end test

`managed-tor-bridges-e2e.sh` checks bridges for the managed Tor (ADR 0052), with real Tor in Docker (image from
`Dockerfile.tor`; same build and `fetch.sh` steps as the managed Tor test, no onion service and no second client):

1. the daemon runs from `/opt/sg dir` and keeps its state in `/var/lib/sg state` (paths with a space, as on macOS and
   Windows), with `third_party/` laid out by `fetch.sh`, including the obfs4 helper (`lyrebird`) and its licence;
2. hostile bridge lines (a second option after a newline or `\r`, trailing options, another transport) are refused by
   `socketguard networks bridges` and change nothing;
3. two documentation-range bridges (`192.0.2.10:443`, `[2001:db8::5]:9001`, a made-up fingerprint and cert) are set:
   the status lists them in canonical form, the generated `torrc` ends with exactly `UseBridges 1`,
   `ClientTransportPlugin obfs4 exec ./pluggable_transports/lyrebird` and the two `Bridge` lines, Tor restarts,
   starts the helper as `socketguard-net` from the installed directory, and the network says it is connecting
   through bridges and does not come up (the bridges do not exist);
4. `networks bridges tor --clear` removes the lines, restarts Tor without the helper, and Tor bootstraps directly
   again (exit code 2 with a `SKIP` line if Tor cannot bootstrap from this Docker network; the checks before it
   still ran);
5. a normal stop leaves neither Tor nor the helper behind.

It removes its containers, network and image on exit. It runs nightly and on request in `.github/workflows/e2e.yml`.
