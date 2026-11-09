# ADR 0027: Domain Model: Apps, Networks, Addresses, Peers and Grants

## Status

Accepted. Supersedes ADRs 0009 and 0016-0024, the schema and migration parts of ADR 0005, and the stale-socket deletion of ADR 0007.

## Date

2026-11-09

## Context

ADRs 0016-0024 layered per-backend policy, a Disabled mode (later removed), ACL groups, socket groups and group inheritance. ACL subjects were raw IP strings, and policy resolution was copy-pasted four times in `engine.rs`. ADR 0009's socket ID used `DefaultHasher`, which is not stable across Rust versions, and keyed on process name, so two Python scripts were one service. The UI ADRs (0019-0024) describe components for concepts that no longer exist.

## Decision

Six nouns replace the old model:

| Noun | Meaning | Replaces |
|---|---|---|
| **App** | A program. Key: SHA-256 of `exe_path`; for known interpreters and hosts (python, node, java, dotnet, ruby, svchost, ...) also the normalized script or service argument. Falls back to `process_name`. Cmdline is captured on all platforms. | `socket_id`, grouping by process name |
| **Network** | User-facing name for an instance of a pluggable network (ADR 0037): Local (ULA), LAN (SLAAC/DHCPv6), Yggdrasil, Tor (onion), later WireGuard | Backend instance as shown to users |
| **Address** | (app, network, port set, locator). The locator is network-specific: an IPv6 address (stored as interface ID) on IP networks, a `.onion` name on Tor | `SocketAddress`, `SocketGroupAddress`, socket groups |
| **Peer** | A label plus credentials (ADR 0028) | Raw `allowed_ip` strings |
| **Peer group** | A named set of peers | ACL groups |
| **Grant** | (app [+port] [+network], subject = peer, peer group or Anyone) | The `Policy` enum |

- **Grants, not policies.** No grants means closed; a grant to Anyone means open and needs confirmation in both frontends. There is no inactive or disabled state.
- **D1, one address mechanism.** An address belongs to one app on one network and serves a set of that app's ports. A global setting picks the default for new apps: one address per app, or one per port. In either mode the user can split a port onto its own address or merge ports onto one. There is no separate group concept.
- **Local means "this machine only".** The ULA prefix is a random `fd00::/8` /48 private to this host and never advertised, and `iif lo` is always allowed (ADR 0026), so grants on Local would have no effect. The API rejects them with 400 and a message saying Local is this machine only, and frontends show Local addresses without a grant list. ULA sits on loopback by default; if a user puts the ULA network on a LAN interface, it behaves like any IP network and grants apply.
- **Networks are pluggable, the model is not IPv6-only.** Each network kind implements the `Network` trait (ADR 0037): it creates and removes locators and enforces grants for the credential types it understands. IP networks enforce through the shared firewall seam (ADR 0029); Tor through its control port.
- **Address stability.** On IP networks the interface ID is stored. When a prefix changes, the address is rebuilt from the new prefix and the same interface ID. Grants reference apps, not addresses, so they are unaffected. On Tor the stored service key keeps the `.onion` name stable.
- **Apps are persistent records.** ADR 0007's stale-socket deletion no longer deletes apps, since that would drop their grants. An app's addresses persist while its App record exists, whether or not it is listening; they stay inside the protected scope, so nothing is reachable without a grant. They are removed only by an explicit `apps rm` or by `disable`. There is no automatic expiry.
- **D2, clean break.** Schema v1: apps, addresses (+ ports), peers, peer_credentials, peer_groups (+ members), grants, settings, plus the activity table (ADR 0034). Versioned with `PRAGMA user_version`. An old database is renamed to `socketguard.db.pre-v1`; there is no migration code.
- **One producer** turns this model into the desired firewall state (ADR 0029).

## Consequences

- Fewer concepts: groups of sockets become address port sets, groups of sources become peer groups.
- App identity survives restarts, toolchain upgrades and PID changes, and separates interpreter-hosted services.
- Upgrading drops existing sockets, ACLs and groups; the old DB is kept for reference only.
- Interpreter detection needs a maintained list of known hosts and per-host argument normalization.
