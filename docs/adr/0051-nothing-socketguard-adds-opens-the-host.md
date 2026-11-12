# ADR 0051: Nothing SocketGuard Adds Opens the Host

## Status

Accepted. Extends ADR 0026 (protection scope) and ADR 0048 (network setup).

Amended below. Superseded in part by ADR 0052: SocketGuard no longer installs or starts third-party software through setup; close-first applies to the networks it runs itself.

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
- **Block by address, not only by interface.** The block for a Yggdrasil network also matches that node's own address and routed subnet as destination on any interface, so it holds while the adapter does not exist, is renamed or is recreated. The addresses are remembered once known. The interface rule stays in addition. Only the managed node's addresses are blocked: a node the user runs outside SocketGuard is not touched.
- **Pending networks.** A network can exist in SocketGuard before its software runs. It is Down and already closed.
- **Leaving is explicit about exposure.** Turning SocketGuard off, removing such a network or uninstalling says which networks stay reachable without it and offers to stop the services SocketGuard started (from the setup log). Removing a network keeps its block until the user confirms.
- **Boot.** Where rules do not survive a reboot, the service starts before the network comes up (systemd `Before=network-pre.target`; the launchd daemon loads the anchor at load). Where that cannot be guaranteed, it is listed in `docs/footprint.md` as an open gap, not hidden.
- **Every new kind of network states how it meets this** in its ADR, with a test that the block exists before the network is up and while its interface is missing.

## Consequences

- Installing Yggdrasil through SocketGuard never exposes the host, even if setup is interrupted.
- Software installed by hand before it is added in SocketGuard is outside this guarantee until it is added; the network cards say so.
- A node SocketGuard has never seen has no address to block yet; it is closed by its interface rule, or SocketGuard refuses to start it. A node SocketGuard creates itself has its address known before it starts.
- Tor needs no block: it exposes nothing inbound until SocketGuard publishes a service.

## Amendment (2026-11-12): the whole range for an existing node; ready means the rules are applied

- **An existing Yggdrasil node is blocked by range.** For a network on a node the user runs themselves, the block matches the whole Yggdrasil address range (`200::/7`) as destination on any interface, not only the node's known address. No address has to be seen first, and a node that changes its key stays closed. This rests on one node per host (ADR 0052): the node handed to SocketGuard is the only one. SocketGuard's own node keeps the narrow block of its own address and subnet, so that it never touches a node it does not manage.
- **An existing node is added only while it answers.** A node that is not running cannot be added; SocketGuard does not start software it did not ship.
- **Ready means the rules are applied.** On Linux the service reports ready to the service manager only after its first ruleset is in force. The unit is ordered before the network, so the network waits for it. The first ruleset does not wait for Tor or Yggdrasil, and a start that takes too long fails visibly instead of holding the boot.
- **Not kept across a reboot.** The last ruleset is not saved and loaded before the daemon (the owner's choice): if the daemon cannot start, nothing is filtered and the machine stays reachable for repair. On macOS, where the service manager has no ordering, the gap at boot stays and is listed in `docs/footprint.md`.
