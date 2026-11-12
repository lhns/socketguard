# ADR-0003: IPv6 Backend Strategy

## Status

Superseded by ADR 0031

## Date

2026-03-12

## Context

Each listening socket needs a unique IPv6 address. We need a way to generate these addresses. Two approaches were considered:

1. **ULA (Unique Local Addresses)**: Random addresses in the `fd00::/8` range. Simple, no external dependencies, works on any system with IPv6 enabled. However, these addresses are not routable on the public internet or across overlay networks.

2. **Yggdrasil-derived addresses**: Generate Ed25519 keypairs, derive addresses in the `200::/7` range using Yggdrasil's algorithm (SHA-512 hash of public key, count leading ones, encode into address). These addresses are cryptographically bound to a keypair and routable on the Yggdrasil overlay network.

## Decision

Support **both backends** behind the `Ipv6Backend` trait, selectable via configuration:

### ULA Backend (`fd00::/8`)
- Generates random addresses: `fd` + 40-bit Global ID + 16-bit Subnet ID + 64-bit Interface ID
- Global ID is randomized once per daemon instance for consistency
- No keypair management needed
- Default backend — works out of the box

### Yggdrasil Backend (`200::/7`)
- Generates Ed25519 keypairs using `ed25519-dalek`
- Derives IPv6 via SHA-512 hash of the public key
- Loops until an address in the `200::/7` range is produced (first byte `0x02` or `0x03`)
- Keypairs are stored in SQLite for persistence
- Enables identity-based access control (allow by Yggdrasil address = allow by public key)

### Address Derivation Algorithm (Yggdrasil)
1. SHA-512 hash the 32-byte public key
2. Count leading 1-bits in the hash (`ones`)
3. Skip `ones + 1` bits (the leading ones plus first zero)
4. Build address: `[0x02, ones, next_112_bits_from_hash...]`

## Consequences

- ULA is the safe default for local/testing use — no external dependencies.
- Yggdrasil backend enables the primary use case: identity-based per-socket ACLs on overlay networks.
- The `Ipv6Backend` trait makes adding future backends (e.g., WireGuard-derived addresses) straightforward.
- Keypair storage adds complexity but is necessary for persistent identity across daemon restarts.
- The Yggdrasil address generation loop is fast in practice — most keypairs produce valid addresses.
