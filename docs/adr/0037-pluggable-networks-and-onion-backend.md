# ADR 0037: Pluggable Networks and the Onion Backend

## Status

Accepted

## Date

2026-11-09

## Context

The model (ADR 0027) gives each app an address per network and grants access to peers by credential (ADR 0028). Until now every network was an IPv6 network enforced by the host firewall. An onion (Tor) network is planned as a phase after the core redesign: it reaches hosts behind NAT without any open port, and its identities are keys. Its locators are `.onion` names, not IPv6 addresses, and its connections arrive over loopback, so the firewall cannot enforce it.

## Decision

- **A `Network` trait, in-tree, with capability flags.** Each network kind supplies:
  - create or remove a locator for (app, port set);
  - enforcement of grants for the credential types it understands;
  - the set of credential types it verifies by key.
- **Locators are network-specific**: IPv6 on IP networks (Local, LAN, Yggdrasil, WireGuard), `.onion` on Tor. The noun stays "Address".
- **IP networks enforce through the shared `DesiredRuleset` seam** (ADR 0029); each contributes scopes and rules for its interface.
- **Tor enforces through the Tor control port**: `ADD_ONION` with a stored `ED25519-V3` service key per address, and `ClientAuthV3` for each granted peer's `tor_client_key` (x25519). Connections reach the app over loopback, where the firewall cannot tell peers apart, so Tor client authorization is the enforcement.
- **Per-address keys work on Tor** because Tor publishes every service key; this is the contrast with ADR 0003's per-socket Yggdrasil keypairs, which no node announced (ADR 0031).
- **Service keys live in the SocketGuard DB**, which therefore needs protection at rest: restrictive file permissions at minimum.
- **Pluggability means a stable in-tree trait now.** An out-of-process plugin protocol (for example JSON over stdio, CNI-style) is a future option and is not designed here.

## Consequences

- Adding a network is implementing one trait; the model, API and frontends need no new nouns.
- Badges ("verified by key", "IP only", "not reachable here") come from each network's declared capabilities, not hard-coded backend checks.
- The DB now holds private keys, so its permissions become a security property and are part of the install.
- Tor enforcement depends on a reachable control port; if Tor is down, onion addresses are unreachable rather than open.
- Third-party networks need a SocketGuard build until a plugin protocol exists.
