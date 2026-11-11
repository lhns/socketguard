# ADR 0028: Credentials and Verification

## Status

Accepted

## Date

2026-11-09

## Context

Access was granted to IP strings and rules matched only the source address, so a LAN host could forge a `200:` source. The UI exposed a backend taxonomy instead of telling users whether a grant is trustworthy. Two facts shape the design:

- Yggdrasil routes a node's `300::/64` (reachability) and, in `ipv6rwc.go`, drops any inbound packet whose source is not the sending key's address or /64 (identity).
- The key-to-address derivation is one-way, and a packet carries no proof that its sender holds the key. Only Yggdrasil's handshake proves possession, so SocketGuard cannot verify identity itself.

## Decision

- **A peer's identity is its key**; addresses are derived from it. Credential types: `ygg_key`, `ygg_addr` (a `200:` address or a `300:` /64), `ip` (address or CIDR, v4 or v6; LAN credentials may be prefix-relative so they survive prefix changes), `tor_client_key` (x25519, ADR 0037). Reserved for later: `wg_key`, `tls_spki` (ADR 0036).
- **Each network declares which credential types it verifies by key** (a capability of its `Network` implementation, ADR 0037): Yggdrasil verifies `ygg_key`/`ygg_addr`, Tor verifies `tor_client_key` through client authorization, LAN verifies none.
- **Verification is a property of the credential on a network**, not of the network. For each (address, credential) pair:
  - key-verified on this network: allow it; on IP networks by source matched with the `iifname` of that network's interface, on Tor by the client's authorization key;
  - IP/CIDR: allow the source; shown as "IP only";
  - not applicable to this network: nothing is allowed; shown as "not reachable here".
- **Yggdrasil sources are trusted only on the Yggdrasil interface.** A `200::/7` source arriving on any other interface never matches a Yggdrasil credential.
- **A bare Yggdrasil address is accepted** because the overlay enforces it just as well, but it is lossy: the key cannot be recovered from it, so it cannot carry over to WireGuard or TLS.
- **A `ygg_key` credential covers only that key's `200:` address.** Trusting its `300:` /64 needs an explicit subnet credential, which means "that node and everything it routes"; the frontends label it "whole subnet".
- **Frontends show badges, not backends:** "verified by key", "IP only", "not reachable here".

## Consequences

- Forged overlay sources from the LAN are dropped.
- Key-verified access works on Yggdrasil without WireGuard, and on Tor once the onion network lands. LAN stays IP-only and is flagged as such.
- A key peer with no Yggdrasil network shows "not reachable here" instead of silently granting nothing.
- Trusting everything a node routes is always a deliberate, visibly labelled choice.

## Amendment (ADRs 0044, 0045)

`ip` credentials accept IPv4, for whole-host scopes (ADR 0044). All credential input goes through one core parser (ADR 0045).

## Amendment (2026-11-11): peer names are optional

Unnamed peers are named after their first credential. A peer's `label` is optional in `POST /api/peers` and in the batch's `create_peer`: when missing or blank, the daemon uses the first credential's normalized value (a /32 or /128 dropped, a key shortened to 12 characters and `…`), with ` (2)`, ` (3)`… if the name is taken. No label and no credential is refused. An explicit label that clashes is still a 409. The batch gained `create_group` (members may be refs), so a frontend can create peers and put them in a group in one transaction. The CLI takes the name as `peers add --label`.
