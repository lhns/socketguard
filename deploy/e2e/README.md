# Yggdrasil end-to-end test

`ygg-e2e.sh` checks the Yggdrasil backend against two real Yggdrasil nodes in Docker
(Linux containers; run from Git Bash on Windows or from Linux):

1. builds the daemon and CLI in `rust:1-bookworm` (cache volumes `sg-cargo-registry`, `sg-target`);
2. starts node A (Yggdrasil, the daemon, a test HTTP listener) and node B (Yggdrasil, peered to A);
3. asserts the daemon gave the listener a `300::/64` address on `ygg0`, opens it via the CLI,
   and asserts B can fetch it;
4. restarts Yggdrasil on A (same key, new tun) and asserts the address comes back and B can fetch again.

It prints PASS/FAIL per step, removes its containers and network, and exits non-zero on failure.
