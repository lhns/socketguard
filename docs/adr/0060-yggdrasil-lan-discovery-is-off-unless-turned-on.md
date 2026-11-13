# ADR 0060: Yggdrasil LAN Discovery Is Off Unless Turned On

## Status

Accepted. Amends ADR 0052, which kept Yggdrasil's defaults for everything SocketGuard does not decide.

## Date

2026-11-13

## Context

The configuration of SocketGuard's Yggdrasil node left `MulticastInterfaces` out on purpose, so Yggdrasil's default applied: it beacons on every interface and opens a peering listener on the link-local address of each adapter, which any host on the LAN can connect to. That is a port open outside SocketGuard's rules. The requirement is that nothing SocketGuard adds opens the machine outside its rules (ADR 0051).

## Decision

- The Yggdrasil backend has a setting `lan_discovery` (default false, left out of the JSON when false): `{ "type": "yggdrasil", "peers": [...], "lan_discovery": true }`.
- Off: the node's configuration has `"MulticastInterfaces": []` (with the existing `"Listen": []`), so the node neither beacons nor listens on the LAN. On: the key is left out and Yggdrasil's default applies. A change restarts the child, like a change of peers.
- `PUT /api/networks/{id}/lan-discovery` sets it (`socketguard networks lan-discovery <id> on|off`, a switch on the network in the UI). Turning it on opens the machine to the LAN's Yggdrasil nodes, so it needs `confirm_open` and the UI's confirmation dialog; turning it off needs none. Adding a network always adds it off. The network's status shows the setting.
- With no peers and LAN discovery off the node has nobody to talk to; the status says so.
- Portable mode follows the same rules.

## Consequences

- A new Yggdrasil node reaches nobody until peers are added or LAN discovery is turned on: the first-run hint says so.
- Other computers on the LAN can connect to the node only while the setting is on. They still reach no app without a grant.
- `docs/footprint.md` names what is open while the setting is on.
