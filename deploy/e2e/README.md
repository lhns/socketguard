# Yggdrasil end-to-end test

`ygg-e2e.sh` checks the Yggdrasil backend against two real Yggdrasil nodes in Docker
(Linux containers; run from Git Bash on Windows or from Linux):

1. builds the daemon and CLI in `rust:1-bookworm` (cache volumes `sg-cargo-registry`, `sg-target`);
2. starts node A (Yggdrasil, the daemon, a test HTTP listener) and node B (Yggdrasil, peered to A);
3. asserts the daemon gave the listener a `300::/64` address on `ygg0` and installed its nftables table;
4. enforcement (ADR 0026/0029):
   - closed: B cannot fetch the allocated address; open (via the CLI): it can;
   - the wildcard listener is not reachable via A's own `200:` node address (overlay scope);
   - restarting Yggdrasil on A (same key, new tun) brings the address back and the scope still applies;
5. frozen state: after stopping the daemon, open stays open and closed stays closed (the table and
   address stay), and a restart does not interrupt access;
6. `socketguard-daemon --disable` removes the table and the address.

It prints PASS/FAIL per step, removes its containers and network, and exits non-zero on failure.
