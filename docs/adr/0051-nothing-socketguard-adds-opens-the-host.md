# ADR 0051: Nothing SocketGuard Adds Opens the Host

## Status

Accepted. Extends ADR 0026 (protection scope) and ADR 0048 (network setup).

## Date

2026-11-11

## Context

ADR 0026 closes the whole Yggdrasil interface once the network is managed. Network setup (ADR 0048) can now install and start Yggdrasil, and the interface is found at runtime. That leaves windows in which the host is reachable over a network SocketGuard brought in or manages, outside its rules:

- between the installer starting the Yggdrasil service and the network being added;
- when setup stops halfway;
- whenever the adapter does not exist while the rules are written (node stopped, adapter recreated on restart): the interface rule cannot be made, and the adapter is open from the moment it appears until the next pass;
- after "turn off", after removing the network, and after uninstall, while the node keeps running;
- on Linux and macOS between boot and the daemon's first ruleset, where the rules are not persistent.

## Decision

**Invariant.** A network that SocketGuard adds, installs or manages never makes the host reachable outside SocketGuard's rules, at any moment, including before the network is usable and after a failure.

- **Close first.** The block for a network is in place before anything that could open it runs. Setup adds the block as its first step and installs or starts software only after the ruleset with that block has been applied and verified. If any later step fails, the block stays.
- **Block by address range, not only by interface.** The Yggdrasil block also matches the overlay's address space (`200::/7`) as destination on any interface, so it holds while the adapter does not exist, is renamed or is recreated. The interface rule stays in addition.
- **Pending networks.** A network can exist in SocketGuard before its software runs. It is Down and already closed.
- **Leaving is explicit about exposure.** Turning SocketGuard off, removing such a network or uninstalling says which networks stay reachable without it and offers to stop the services SocketGuard started (from the setup log). Removing a network keeps its block until the user confirms.
- **Boot.** Where rules do not survive a reboot, the service starts before the network comes up (systemd `Before=network-pre.target`; the launchd daemon loads the anchor at load). Where that cannot be guaranteed, it is listed in `docs/footprint.md` as an open gap, not hidden.
- **Every new kind of network states how it meets this** in its ADR, with a test that the block exists before the network is up and while its interface is missing.

## Consequences

- Installing Yggdrasil through SocketGuard never exposes the host, even if setup is interrupted.
- Software installed by hand before it is added in SocketGuard is outside this guarantee until it is added; the network cards say so.
- The address-range block also closes Yggdrasil traffic on a host where the user runs a node SocketGuard does not manage, once any Yggdrasil network is added. That is intended.
- Tor needs no block: it exposes nothing inbound until SocketGuard publishes a service.
