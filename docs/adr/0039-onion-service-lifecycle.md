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
- No new crates for the control client itself: a few hundred lines over `std::net`, plus `hmac` (with `sha2`) for SAFECOOKIE.

## Amendment: control-port trust and fail-closed revocation (security review)

The control address is where the daemon sends onion keys, and the default `127.0.0.1:9051` can be bound by any local user while Tor is down. A rogue listener could also name any file as the cookie file. Separately, a revocation could be lost while Tor was down.

- **A unix control socket is preferred** (`control: "unix:/run/tor/control"`, Tor's `ControlSocket`): only Tor's account can own that path. `auth: none` is accepted only there. Optional `expect_tor_uid` checks the peer uid of the socket (Linux).
- **SAFECOOKIE by default** (`auth: cookie`): the daemon sends an `AUTHCHALLENGE` and verifies the server's HMAC over the cookie and both nonces before it sends its own hash. A server that does not know the cookie gets nothing further, and the cookie never goes over the wire. Plain COOKIE is refused unless `auth: cookie_insecure` is configured. Password auth is unverifiable and only as safe as the address.
- **The cookie file is checked before it is read**: not a symlink, a regular file of exactly 32 bytes, not writable by others, and on Unix owned by root, by `expect_tor_uid` or by the owner of `cookie_dir` (default: the directory of `cookie_path`). The optional `cookie_path` must equal the path PROTOCOLINFO reports.
- A `Control` value only exists after one of these succeeded, so `ADD_ONION` with a stored key cannot be sent to an unauthenticated server. The e2e Tor config uses `CookieAuthentication 1`, which offers SAFECOOKIE.
- **Revocation fails closed.** The engine persists, in the settings table (no schema change), `tor_owned_services` (every service id we created or that has an address) and `tor_tombstones` (ids whose address was deleted and that must be removed). Every enforcement pass retries both until Tor confirms (DEL_ONION, or `onions/detached` no longer lists the id), and sweeps any detached service in the owned set that no address wants. Services we did not create are never touched. A service leaves the in-memory `applied` set only after a confirmed removal.
- **Failures are visible.** Mutations still commit, but answer HTTP 202 with `enforcement: {status: "pending", message}` while a network cannot enforce them (docs/api.md).
