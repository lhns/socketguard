# ADR 0045: Batch Changes, One Credential Parser, Stored Tor Client Keys

## Status

Accepted. Refines ADR 0028 and ADR 0040.

Superseded in part by ADR 0053: the `Review` batch operation is removed.

## Date

2026-11-10

## Context

- **Bulk changes:** bulk administration (ADR 0042) means many grants, tag memberships and new peers at once. With one request each, that is N reconciles and possible partial failure.
- **Credential parsing:** credential input was parsed three different ways (UI, CLI, daemon). That let a placeholder suggest values the daemon rejects, and stored `200::` as a peer address.
- **Tor client keys:** Tor client authorization needed the peer to bring its own x25519 key, with no way to create one.

## Decision

- **`POST /api/changes {ops, dry_run}`:**
  - **Ops:** `CreatePeer | CreateTag | AddGrant | RemoveGrant | AddTagMember | RemoveTagMember | Review`, applied in one transaction through the engine's commit path and unique-grant checks, with one reconcile.
  - **References:** a create op carries a client-chosen `ref` that later ops use in place of an id. The response maps refs to ids.
  - **Anyone:** an `AddGrant` to Anyone carries `confirm_open`; otherwise the whole batch is refused (409).
  - **Dry run:** returns the diff and the reach changes without writing.
  - Single-resource routes stay, and `/api/apply` stays the whole-config replace.
- **One parser:** `credential::parse_input` in core splits pasted text on newlines, commas and whitespace.
  - For each value it returns the kind, the normalized value and where it works per network kind, or an error.
  - It rejects the bare bases `200::` and `300::`, never guesses `wg_key` or `tls_spki`, and rejects IPv4 for `ip_suffix`.
  - The daemon exposes it as `POST /api/credentials/parse`; the CLI calls it directly.
  - Placeholder and help examples are a core constant exported to TypeScript, and a test parses each one.
- **Tor client keys:** `POST /api/peers/{id}/tor-key` generates an x25519 pair.
  - The public key becomes the peer's `tor_client_key` credential. The private key is stored, protected at rest like onion service keys.
  - `share` prints, for each granted peer with a stored key, the `<onion>:descriptor:x25519:<private>` line for the client's `ClientOnionAuthDir`.
  - Regenerating replaces the key.

## Consequences

- Bulk edits are atomic and cheap, and the matrix and the grant editor preview exactly what will change.
- Frontends cannot disagree about what a credential is.
- The daemon now holds Tor client private keys. Whoever can read its state can impersonate those peers to its own services, which is no more than the admin can already do.
