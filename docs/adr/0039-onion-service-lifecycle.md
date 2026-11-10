# ADR 0039: Onion Service Lifecycle

## Status

Accepted. Refines ADR 0037.

## Date

2026-11-09

## Context

ADR 0037 puts Tor enforcement on the control port: an address with no grant is closed, grants become client authorization keys. Several details were open: how an address gets its `.onion` name before anything is published, how a service survives restarts, and what a per-service authorization means for per-port grants.

## Decision

- **Name before publication** (superseded by the second amendment: keys are generated locally). A new Tor address is created with `ADD_ONION NEW:ED25519-V3` carrying a client key nobody holds, and removed again at once. The private key is stored with the address (`onion_keys`, schema v2); the name is known and never serves anyone. Every later publication re-adds the stored key.
- **Detached services.** Services use `Flags=Detach`, so they survive control-connection drops and a daemon exit (frozen state, ADR 0026). The daemon connects per operation. It re-adds a desired service whose spec changed or that `GETINFO onions/detached` does not list (Tor restarted), checking at most every 10 s, and on start re-adds every desired service. `disable` removes all of ours; enforcement is suspended while the latch is set.
- **Per-service authorization.** Tor cannot gate ports separately. The published ports are the TCP ports covered by grants (UDP is not served). A client key whose grants cover fewer ports than that is left out, so a service is never wider than a grant; giving a port its own address (`split`) grants it separately. A grant to Anyone publishes openly only if it covers all published ports.
- **Tor down is a status.** The network shows `down` with the reason; no address is created and nothing is changed until Tor is back.
- **Keys at rest.** The DB file (and -wal/-shm) is mode 0600 on Unix. On Windows see the amendment below (the daemon sets a protected ACL).

- **Tor down is a status.** (Address creation no longer needs Tor, see the second amendment.) The network shows `down` with the reason; no address is created and nothing is changed until Tor is back.
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

## Amendment: Windows database ACL

The daemon now protects the database on Windows itself instead of relying on where it lives. `Database::new` creates the file with a protected DACL (SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)`: SYSTEM and Administrators full control, nobody else, inheritance blocked) before SQLite opens it, so it is never readable by others. The same DACL is applied to the -wal/-shm files when they exist and to a `.pre-v1` backup. If it cannot be set on an existing file (not owned by us), the daemon logs a warning and runs on. A process that is neither SYSTEM nor an elevated administrator (a hand-started daemon, the tests) also gets an ACE for its own account, or it would lock itself out.

## Amendment: local key generation, per-network pending, adoption

- **Keys are generated in the daemon.** A new Tor address no longer does `ADD_ONION NEW` plus `DEL_ONION` (which briefly published a descriptor). The daemon draws a random 32-byte seed and expands it like Ed25519 (SHA-512, scalar clamped: `h[0] &= 248; h[31] &= 63; h[31] |= 64`). The 64 bytes, base64, are the `ED25519-V3:` blob Tor accepts and are stored exactly as before. The name is `base32(pubkey || checksum[0..2] || 0x03)` with `checksum = SHA3-256(".onion checksum" || pubkey || 0x03)`, the public key being the scalar times the base point (`curve25519-dalek`, `sha3`). No network call happens before the first grant, so addresses are also created while Tor is down. The e2e asserts that the ServiceID Tor returns on the first `ADD_ONION` equals the local name; a unit test pins an RFC 8032 vector.
- **202 means a change is waiting, not that a network is down.** `Network::pending()` (default false) is asked after each enforcement attempt. Tor is pending only while its desired services differ from what it has confirmed applied, or services it must remove (tombstones, owned services without an address) are still running. A mutation answers 202 only if some network is pending, so a LAN grant while Tor is down with no Tor work outstanding is 200/201. Known gap: after a daemon restart with Tor still down, a service of ours that should be closed is not counted until Tor was reached once.
- **Pre-ledger services are adopted.** At startup the service id of every stored onion key (derived from the key) is added to the owned set (idempotent), so services created before the ledger existed are swept when their address is gone.

Consequences: one more pair of crates (`curve25519-dalek`, `sha3`; `base64`), and the key format is now our responsibility, with Tor as the check (a mismatch is refused by enforcement, which compares Tor's ServiceID with the expected one).

## Amendment (second security review): Windows cookie, API-made Tor networks, removal, database

- **Windows cookie file.** The Unix owner check had no Windows counterpart, so a local user who bound the TCP control port while Tor was down could name any 32-byte file they controlled as COOKIEFILE and pass the SAFECOOKIE proof. On Windows cookie auth now requires a configured `cookie_path` (nothing is sent without it), and the open file is vetted through its handle (`GetSecurityInfo`): its owner must be SYSTEM, Administrators or the configured `cookie_owner` (a SID, for Tor's service account), and its DACL may grant write access (write data, append, EA, attributes, delete, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE/ALL) to no one else. A missing DACL is refused. An unsupported platform refuses cookie auth.
- **Control address.** A TCP control address must be loopback. Anything else needs `allow_remote_control: true` and then accepts only cookie auth: `none` and password are refused over any non-loopback address (checked from the text when the network is made, and from the resolved addresses on connect, so a name pointing elsewhere does not slip through).
- **API-made Tor networks.** Every `socketguard` group member may call `POST /api/networks`, and the control endpoint receives the keys, so the API accepts a Tor network only with the default settings or settings identical to a Tor entry already in the config file (read from disk, not from the live config, which also holds what the API added). Anything else (`unix:` path, `auth: none`, `cookie_insecure`, `cookie_path`, `cookie_dir`, `expect_tor_uid`, `allow_remote_control`, another control address) is a 400 `invalid` and belongs in the file, which only an administrator can edit. Consequence: on Windows, where the default has no `cookie_path`, Tor is configured in the file.
- **Removing the network.** `DELETE /api/networks/{id}` on a Tor network first runs a final removal of every owned service and tombstone (an enforcement pass with no addresses). If Tor cannot confirm it, the network stays and the answer is 409 `conflict`; `?force=true` (`socketguard networks rm --force`) removes it anyway with a warning, and the unconfirmed services are then no longer retried. A config-file reload that drops the network does not block and does not sweep. With nothing owned and no tombstones no connection is needed.
- **Client keys.** Tor client public keys that are small-order x25519 points (the seven encodings in the libsodium blocklist with the unused top bit masked, so all-zero and the identity among them) are refused: authorization with such a key protects nothing.
- **Database on Windows.** The protected DACL is applied to an existing database file as well (a file left by an earlier run or planted before the daemon first ran), not only on creation. If it cannot be applied, startup fails, because the database holds the onion keys; `SOCKETGUARD_ALLOW_UNPROTECTED_DB=1` downgrades that to a warning, for tests and development only. This replaces "logs a warning and runs on" in the Windows database ACL amendment above.
