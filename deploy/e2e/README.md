# End-to-end tests

- `ygg-e2e.sh`: Yggdrasil (below).
- `tor-e2e.sh`: the Tor network (end of this file).

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
3. B's x25519 key (generated with python `cryptography`) is added with `peers add bnode --tor-key` and
   granted; the service is published and B fetches `http://<onion>:8080` with `curl --socks5-hostname`;
4. the client without the key cannot; after `revoke` the service is gone (`DEL_ONION`);
5. `disable` removes the service and keeps it off; `enable` publishes it again.

Exit code 2 (with a `SKIP` line) means Tor could not bootstrap from this Docker network; the control-port
logic is then only covered by the mock-server tests (`cargo test -p socketguard-daemon`).
