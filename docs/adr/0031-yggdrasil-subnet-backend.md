# ADR 0031: Yggdrasil Backend from the Node Subnet

## Status

Accepted. Supersedes ADR 0003.

## Date

2026-11-09

## Context

ADR 0003 minted an Ed25519 keypair per socket and derived a `200:` address from it. No Yggdrasil node announces those keys, so the addresses were unreachable. The derivation was also wrong: upstream has no SHA-512 step. The private keys were stored in plaintext and never used. The ULA part of ADR 0003 works but randomized its global ID per daemon instance, so addresses changed across restarts.

## Decision

- **Allocate from the node's own subnet.** Read the node's key, address and subnet with `yggdrasilctl -json getSelf`. Allocate /128s in the node's `300::/64` and add them to the tun interface with `nodad`. Yggdrasil already routes that /64 to the node.
- **Detect Yggdrasil restarts** (tun recreated, interface name or subnet changed) and re-add the addresses.
- **Remove** keypair generation, the `keypairs` table and `KeyPair`.
- **Derivation matches upstream `AddrForKey`/`SubnetForKey`**, used to turn peer keys into addresses (ADR 0028): invert the key's bits, count leading ones, and pack the count and the remaining bits after the first zero into the address. No hashing. Tested against an upstream test vector.
- **ULA continues** as in ADR 0003 (`fd` + 40-bit global ID + 16-bit subnet ID + 64-bit interface ID), with the **global ID now persisted**. Interface IDs are persisted for all backends (ADR 0027).
- A short spike confirms the premise before building: add `<subnet>::1/128 dev <tun> nodad` on one node and ping it from another.

## Consequences

- Per-app Yggdrasil addresses are reachable, and their identity is the node's key.
- All of an app's Yggdrasil addresses share the node's identity; a remote peer cannot tell apps apart by key, only by address.
- The backend depends on `yggdrasilctl` and its admin socket being available.
- Per-socket key storage, and its unencrypted private keys, are gone.
