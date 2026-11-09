# ADR 0039: Onion Service Lifecycle

## Status

Accepted. Refines ADR 0037.

## Date

2026-11-09

## Context

ADR 0037 puts Tor enforcement on the control port: an address with no grant is closed, grants become client authorization keys. Several details were open: how an address gets its `.onion` name before anything is published, how a service survives restarts, and what a per-service authorization means for per-port grants.

## Decision

- **Name before publication.** A new Tor address is created with `ADD_ONION NEW:ED25519-V3` carrying a client key nobody holds, and removed again at once. The private key is stored with the address (`onion_keys`, schema v2); the name is known and never serves anyone. Every later publication re-adds the stored key.
- **Detached services.** Services use `Flags=Detach`, so they survive control-connection drops and a daemon exit (frozen state, ADR 0026). The daemon connects per operation. It re-adds a desired service whose spec changed or that `GETINFO onions/detached` does not list (Tor restarted), checking at most every 10 s, and on start re-adds every desired service. `disable` removes all of ours; enforcement is suspended while the latch is set.
- **Per-service authorization.** Tor cannot gate ports separately. The published ports are the TCP ports covered by grants (UDP is not served). A client key whose grants cover fewer ports than that is left out, so a service is never wider than a grant; giving a port its own address (`split`) grants it separately. A grant to Anyone publishes openly only if it covers all published ports.
- **Tor down is a status.** The network shows `down` with the reason; no address is created and nothing is changed until Tor is back.
- **Keys at rest.** The DB file (and -wal/-shm) is mode 0600 on Unix. On Windows it must live where only the service account and Administrators have access; the daemon does not change ACLs.

## Consequences

- The `.onion` name of an address is stable for as long as the address exists; deleting the address (or its app) deletes the key and the name.
- A Tor restart or daemon restart briefly re-adds services (descriptor republish takes time).
- Anyone with read access to the database can impersonate the onion services.
- No new crates: the control client is a few hundred lines over `std::net`.
