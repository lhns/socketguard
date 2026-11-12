# End-to-end tests

- `tor-e2e.sh`: the Tor network, with the Tor SocketGuard ships (below).
- `ygg-e2e.sh`: the Yggdrasil network, with the Yggdrasil SocketGuard ships (below).
- `tor-bridges-e2e.sh`: bridges for that Tor (section at the end of this file).

The nodes in the containers (the Yggdrasil peer, the client Tors) are plain programs from the image; the
network under test is always SocketGuard's own (ADR 0056).

# Tor end-to-end test

`tor-e2e.sh` checks the Tor that SocketGuard ships and runs itself (ADR 0052), with real Tor in
Docker (image from `Dockerfile.tor`; needs internet access to the Tor network and to dist.torproject.org;
about ten minutes with a warm build cache, longer for the first Rust build):

1. builds the daemon, then lays out the pinned Tor Expert Bundle next to it with
   `deploy/bundle/fetch.sh --skip-yggdrasil linux-x86_64` (the checksum is checked, the signature is not: the
   image has no gpg);
2. creates the system account `socketguard-net` with the command `service install` runs (a container has no
   service manager, so the install itself is not run);
3. checks that Tor ends when the process named by `__OwningControllerProcess` dies;
4. starts the daemon with `{"type": "tor"}`: tor runs as `socketguard-net`, its data directory
   `<state>/tor` is private to it, the network goes up after the bootstrap, and a granted app gets an onion
   service that a second client with the generated key can fetch (one without the key cannot);
5. `kill -9` of the daemon ends Tor; a restart starts a new Tor and publishes the same name again;
6. `disable` stops Tor and keeps `<state>/tor`; `enable` starts it again; a normal stop and
   `socketguard-daemon --disable` leave no Tor behind.

It removes its containers, network and image on exit. The build volumes (`sg-target`, `sg-cargo-registry`) are
caches shared with the other scripts; `CLEAN_VOLUMES=1` removes them. Exit code 2 (a `SKIP` line) means Tor
could not bootstrap from this Docker network. It runs nightly and on request in `.github/workflows/e2e.yml` (not on push). The fetch of the page over Tor waits up to 600 s (`PUBLISH_SECS`) and restarts B's Tor client once after 300 s (`RESTART_AFTER_SECS`) to get new circuits.

# Yggdrasil end-to-end test

`ygg-e2e.sh` checks the Yggdrasil that SocketGuard ships and runs itself (ADR 0052), with real
Yggdrasil nodes in Docker (image from `Dockerfile`; no internet needed once the source and the Go modules
are in the build cache volume):

1. builds the daemon, then builds the pinned Yggdrasil from source next to it with
   `deploy/bundle/fetch.sh --build-yggdrasil --skip-tor linux-x86_64` in a `golang` image (`GO_IMAGE`);
2. creates the system account `socketguard-net` (as in the Tor test) and starts node B, a plain Yggdrasil
   node that listens on TCP;
3. starts the daemon with `{"type": "yggdrasil", "peers": ["tcp://<B>:9001"]}`: yggdrasil
   runs as `socketguard-net` after creating its tun as root, `<state>/yggdrasil/yggdrasil.conf` is private
   to root, the network goes up, and the status shows the node's address and `peers_connected >= 1`;
4. before any grant neither the node's address nor its /64 answers B; after granting one port to B's key, only
   that port answers on SocketGuard's address, the node's own address stays closed;
5. `disable` ends yggdrasil and the adapter and keeps the key; `enable` brings the same node back;
6. yggdrasil is started through `socketguard-daemon child-guard` (it drops the parent-death signal when it changes
   its user id, so a root guard ends it when the daemon is gone): a killed daemon (`kill -9`) leaves no yggdrasil
   and no guard behind, the firewall table and the closed node address stay, and the next daemon starts a new one;
7. with another Yggdrasil node running on A, SocketGuard's is held back with the reason; when the other is
   gone it starts; removing the network ends it and deletes its configuration.

It runs nightly and on request in `.github/workflows/e2e.yml` (not on push).

# Tor bridges end-to-end test

`tor-bridges-e2e.sh` checks bridges for SocketGuard's Tor (ADR 0052), with real Tor in Docker (image from
`Dockerfile.tor`; same build and `fetch.sh` steps as the Tor test, no onion service and no second client):

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
