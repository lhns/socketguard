# ADR 0040: Onion Service Lifecycle (Consolidated)

## Status

Accepted. Supersedes ADR 0039 (which stays as history); refines ADR 0037.

Amended in part by ADR 0047: one service per granted row, and a reservation's service takes only grants on the reservation (recorded as the last amendment of ADR 0039).

Superseded by ADR 0056: SocketGuard only runs its own Tor, so there are no control settings to trust.

## Date

2026-11-10

## Context

ADR 0039 grew four amendments, some of which replace parts of its Decision. This record states the decision set that is in force. Where it differs from a passage in 0039, this record wins.

## Decision

**Identity and publication**

- **Local key generation.** A new Tor address gets an Ed25519 key generated in the daemon (random 32-byte seed expanded as Ed25519, clamped). The 64 bytes, base64, are the `ED25519-V3:` blob Tor accepts; the `.onion` name is derived locally. No call to Tor happens before the first grant, so addresses can be created while Tor is down. Enforcement compares the ServiceID Tor returns with the expected name and refuses a mismatch. Tor client keys that are small-order x25519 points are refused.
- **Detached services, per-service client auth.** Services use `Flags=Detach`, so they survive control-connection drops and a daemon exit. The daemon connects per operation, re-adds desired services that changed or that `GETINFO onions/detached` no longer lists, and `disable` removes all of ours. Tor cannot gate ports separately: the published ports are the TCP ports covered by grants, and a client key whose grants cover fewer is left out, so a service is never wider than a grant. A grant to Anyone publishes openly only if it covers all published ports.
- **Unpublished without grants.** An address with no grant is not published. Tor being down is a network status (`down` with the reason), not an error.
- **Keys at rest.** The database holds the service keys. Unix: mode 0600 (also -wal/-shm). Windows: the daemon applies a protected DACL (`D:P(A;;FA;;;SY)(A;;FA;;;BA)`: SYSTEM and Administrators only) to the database, -wal/-shm and backups, on creation and on existing files; a process that is neither SYSTEM nor an elevated administrator also gets an ACE for its own account. If the ACL cannot be applied, startup fails. `SOCKETGUARD_ALLOW_UNPROTECTED_DB=1` downgrades that to a warning, for tests and development only.

**Control-port trust** (the control address receives the keys)

- A Unix control socket is preferred (`control: "unix:/run/tor/control"`); `auth: none` is accepted only there. `expect_tor_uid` additionally checks the uid serving the socket (Linux).
- A TCP control address must be loopback. Anything else needs `allow_remote_control: true` and then only cookie auth; `none` and password are refused for any non-loopback address, checked from the text and from the resolved addresses.
- `auth: cookie` (default) uses SAFECOOKIE: the daemon verifies the server's HMAC before it sends its own, and the cookie never goes over the wire. Plain COOKIE needs `auth: cookie_insecure`. Password auth is only as safe as the address.
- The cookie file is vetted through the open file. Unix: not a symlink, regular, exactly 32 bytes, not writable by others, owned by root, `expect_tor_uid` or the owner of `cookie_dir` (default: the directory of `cookie_path`). Windows: `cookie_path` is required; the owner must be SYSTEM, Administrators or `cookie_owner` (a SID), and the DACL may grant write access to no one else; a missing DACL is refused. `cookie_path` must equal the path PROTOCOLINFO reports.
- A `Control` value exists only after authentication succeeded, so keys cannot be sent to an unauthenticated server.

**Who may create Tor networks**

- `POST /api/networks` is open to every `socketguard` group member, so the API accepts a Tor network only with default settings or settings identical to a Tor entry already in the config file (read from disk). Any other control address, `unix:` path, auth mode, `cookie_*`, `expect_tor_uid` or `allow_remote_control` is a 400 `invalid` and belongs in the file, which only an administrator can edit. On Windows, where the default has no `cookie_path`, Tor is therefore configured in the file.

**Fail-closed revocation**

- The engine persists in the settings table the ledger `tor_owned_services` (every service id we created or whose key is stored) and `tor_tombstones` (ids whose address was deleted and that must be removed). Every enforcement pass retries both until Tor confirms (`DEL_ONION`, or the id is gone from `onions/detached`) and sweeps owned services no address wants. Services we did not create are never touched. A service leaves the in-memory applied set only after confirmed removal.
- **Adoption:** at startup the service id of every stored key is added to the owned set, so services from before the ledger are swept too.
- **Removal is refused while work is pending:** `DELETE /api/networks/{id}` on a Tor network first runs a final removal of all owned services and tombstones. If Tor cannot confirm, the network stays and the answer is 409 `conflict`. `?force=true` removes it anyway with a warning; the unconfirmed services are then no longer retried. A config-file reload that drops the network neither blocks nor sweeps.

**Visibility**

- `Network::pending()` is asked after each enforcement attempt. Tor is pending only while desired services differ from confirmed ones, or services it must remove are still running. A mutation answers HTTP 202 with `enforcement: {status: "pending", message}` only if some network is pending; a LAN grant while Tor is down with no Tor work outstanding is 200/201. Known gap: after a daemon restart with Tor still down, a service that should be closed is not counted as pending until Tor was reached once.

## Consequences

- The `.onion` name is stable for as long as the address exists; deleting the address or its app deletes the key and the name.
- Tor or daemon restarts briefly re-add services (descriptor republish takes time).
- Anyone who can read the database can impersonate the services; the file ACL is the protection.
- The key format is ours to get right, with Tor's ServiceID check as the safety net. Dependencies: `curve25519-dalek`, `sha3`, `base64`, `hmac`/`sha2`.
- Revocation is safe against Tor outages at the cost of persisted bookkeeping and an explicit 409 on network removal.
