# SocketGuard local API (v1)

REST with JSON bodies and server-sent events, served by the daemon on a local endpoint
(ADR 0032). There is no TCP listener, no token and no CORS: a browser cannot reach it, and
authorization is the operating system's identity check. Request and response types live in
`socketguard-core` (`api_types` for the bodies of the API, `model` for the domain types
they carry); the Rust client is the `socketguard-client` crate (ADR 0033); TypeScript
types are generated from the same Rust types (see below).

## Endpoint and access

| Platform | Endpoint | Config key | Default |
|---|---|---|---|
| Linux, macOS | Unix socket | `api_socket` | `/run/socketguard.sock` |
| Windows | named pipe | `api_pipe` | `\\.\pipe\socketguard` |

Clients (`socketguard`, the UI, `socketguard-client`) take the endpoint from the
`SOCKETGUARD_SOCKET` environment variable if set, else the default. For debugging on Unix:

    curl --unix-socket /run/socketguard.sock http://localhost/api/status

### Unix

The socket is created with mode `0660` and group `socketguard` if that group exists. If it
does not, the daemon logs a warning and falls back to mode `0600` (owner only). On every
connection it also checks the peer's credentials and accepts uid 0, the daemon's own uid,
and members of the group (primary group or supplementary groups from the user database).

Let a user in:

    sudo groupadd socketguard            # once, before the daemon starts
    sudo usermod -aG socketguard alice   # alice logs in again to pick it up
    sudo systemctl restart socketguard   # only needed if the group was created after the daemon started

### Windows

The pipe is created with this ACL: `SYSTEM` and `Administrators` full access, plus the local
group `SocketGuard Users` read/write if it exists at daemon start (otherwise the daemon logs
a warning and leaves it out). Remote clients are rejected, and a new server instance is always
waiting, so many clients can connect at once.

Let a user in:

    net localgroup "SocketGuard Users" /add
    net localgroup "SocketGuard Users" alice /add     (alice signs out and in again)

Restart the daemon after creating the group; it resolves the group once at startup.

A non-elevated process of an administrator is **not** an `Administrators` member for ACL
purposes (UAC strips the group from its token). A desktop user running the UI unelevated
therefore needs `SocketGuard Users`, even if they are an administrator.

## Routes

Bodies are JSON (`Content-Type: application/json`). Types are Rust names in
`socketguard_core::api_types` or `socketguard_core` (model). Statuses are 200 unless noted;
creates return 201 with the new object, deletes 204 with no body. Every error has the
[error body](#errors).

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| GET | `/api/status` | | `StatusResponse` | version, networks, protect-host interfaces, `disabled`, counts |
| GET | `/api/events` | | SSE stream | [events](#events) |
| GET | `/api/apps` | query `pending=true` (optional) | `App[]` | `pending=true`: only apps without a decision |
| GET | `/api/apps/{id}` | | `AppDetail` | app with addresses, ports, grants (with reach) and counters |
| DELETE | `/api/apps/{id}` | | 204 | forgets the app, its addresses and its grants; **it reappears as pending the next time it listens** |
| POST | `/api/apps/{id}/review` | `ReviewRequest` | `AppDetail` | mark reviewed (or pending again); it stays closed until granted |
| POST | `/api/apps/{id}/split` | `SplitRequest` | `Address` (201) | gives one port its own address on a network |
| POST | `/api/apps/{id}/merge` | `MergeRequest` | `Address` | merges addresses of one network into the first listed |
| GET | `/api/peers` | | `Peer[]` | |
| POST | `/api/peers` | `NewPeer` | `Peer` (201) | credentials are validated and normalized; unique across peers |
| GET | `/api/peers/{id}` | | `Peer` | |
| PATCH | `/api/peers/{id}` | `UpdateLabel` | `Peer` | rename |
| DELETE | `/api/peers/{id}` | | 204 | also deletes the grants naming the peer |
| POST | `/api/peers/{id}/credentials` | `NewCredential` | `Credential` (201) | |
| DELETE | `/api/peers/{id}/credentials/{cred_id}` | | 204 | |
| GET | `/api/peer-groups` | | `PeerGroup[]` | |
| POST | `/api/peer-groups` | `NewGroup` | `PeerGroup` (201) | |
| GET | `/api/peer-groups/{id}` | | `PeerGroup` | |
| PATCH | `/api/peer-groups/{id}` | `UpdateLabel` | `PeerGroup` | rename |
| DELETE | `/api/peer-groups/{id}` | | 204 | also deletes the grants naming the group |
| PUT | `/api/peer-groups/{id}/members` | `SetMembers` | `PeerGroup` | replaces the members |
| GET | `/api/grants` | query `app`, `peer`, `group` (all optional) | `GrantView[]` | `peer` matches grants to the peer or to a group it is in |
| POST | `/api/grants` | `NewGrant` | `GrantView` (201) | Anyone needs `"confirm_open": true` |
| DELETE | `/api/grants/{id}` | | 204 | |
| GET | `/api/networks` | | `Network[]` | |
| POST | `/api/networks` | `NewNetwork` | `Network` (201) | a backend instance: `{"id"?, "type": "slaac", "interface": "eth0", ...}`; also written to the `backends` key of the config file (`SOCKETGUARD_CONFIG` or the default; created if missing), so it survives a restart |
| DELETE | `/api/networks/{id}` | | 204 | its addresses leave the interfaces first; removed from the config file as well |
| GET | `/api/settings` | | `Settings` | |
| PUT | `/api/settings` | `UpdateSettings` | `Settings` | absent fields stay as they are |
| PUT | `/api/settings/protect-host` | `ProtectHostRequest` | `ProtectHostResponse` | an empty list turns it off; refused with 409 `protect_host_refused` unless `force` |
| GET | `/api/activity` | query `since`, `kind`, `app`, `peer`, `limit`, `before` | `ActivityRecord[]` | newest first; `since` is RFC 3339; `before` is a record id, for paging |
| GET | `/api/export` | | `ExportDocument` | [export and apply](#export-and-apply) |
| POST | `/api/apply` | `ApplyRequest` | `ApplyResponse` | |
| POST | `/api/disable` | `DisableRequest` | 204 | needs `"confirm": true`. Sets the persisted `disabled` latch, then removes all rules and addresses. While it is set the daemon (also after a restart) applies no rules and adds no addresses, but keeps tracking apps. `socketguard-daemon --disable` sets it too |
| POST | `/api/enable` | | 204 | clears the latch and re-applies rules and addresses |

## Errors

Every non-2xx response is JSON, `ApiError`:

    {"code": "not_found", "message": "peer 7c1f... not found", "details": null}

`details` is absent unless stated below.

| Status | `code` | When |
|---|---|---|
| 400 | `invalid` | malformed JSON or query, unknown field values, invalid credential, empty label, port the app does not have, invalid document |
| 400 | `local_network` | a grant on the Local network. Message: `Local is this machine only` |
| 404 | `not_found` | unknown app, peer, group, grant, network, credential, route |
| 409 | `conflict` | duplicate label, credential or grant; a second ULA or Yggdrasil network; a port that already has its own address |
| 409 | `confirmation_required` | a grant to Anyone without `confirm_open`; `disable` without `confirm` |
| 409 | `protect_host_refused` | whole-host protection would cut off remote administration. `details`: `LockoutRiskInfo[]` (process, port, protocol, bind address, message). Repeat with `"force": true` to override |
| 500 | `internal` | a bug or a failing system call; details are in the daemon log |

A Local network that sits on a non-loopback interface takes grants like any IP network
(ADR 0027); only Local on loopback answers `local_network`.

## Events

`GET /api/events` is a server-sent event stream (with keep-alive comments). The event name
carries the meaning; `data` is empty unless stated. Clients re-fetch what changed.

| Event | Meaning |
|---|---|
| `apps_changed` | apps, ports or addresses changed |
| `app_discovered` | a new, pending app; `data` is its id |
| `peers_changed` | peers, credentials or groups changed |
| `grants_changed` | grants (or what they resolve to) changed |
| `networks_changed` | a network was added, removed or changed state |
| `settings_changed` | address mode or whole-host protection changed |
| `activity` | new activity records |

The client crate parses them into `ApiEvent`.

## Export and apply

`GET /api/export` returns the portable state:

    {
      "version": 1,
      "settings": {"address_mode": "per_app", "protect_host_interfaces": []},
      "peers":  [{"label": "alice", "credentials": [{"kind": "ygg_key", "value": "ba83...", "label": null}]}],
      "groups": [{"label": "team", "members": ["alice"]}],
      "grants": [{"app": {"id": "5c0d...", "name": "nginx"},
                  "port": {"port": 80, "proto": "tcp"}, "network": "ygg",
                  "subject": {"peer": "alice"}}]
    }

`subject` is `{"peer": label}`, `{"group": label}` or `"anyone"`; `port` and `network` may be
absent (all ports, all networks). Apps are named by id, which is stable across restarts and
upgrades (the name is for humans).

`POST /api/apply {"document": ..., "dry_run": bool}` compares the document with the current
state and returns the diff, then applies it unless `dry_run`:

    {"dry_run": true, "changes": [
      {"kind": "create", "item": "peer", "name": "carol", "detail": "1 credentials"},
      {"kind": "delete", "item": "grant", "name": "nginx 80/tcp on ygg to Anyone", "opens_to_anyone": true}]}

- Peers and groups match by **label**; grants by (app id, port, network, subject). Settings are
  the two `settings` fields. Items are created, updated (peer credentials, group members,
  settings) or deleted; **whatever the document lacks is deleted**. Grants have no mutable
  fields, so they are only created or deleted.
- A grant to `"anyone"` in the document counts as confirmed (the file is explicit); the diff
  marks such changes with `opens_to_anyone`, so a dry run shows them.
- The document is validated first (version, duplicate labels, unknown peers, groups, apps,
  ports and networks, credential formats); an invalid one changes nothing. Applying is not
  transactional beyond that: if a later step fails (for instance the lockout guard refusing
  whole-host protection, which is applied last), the earlier steps stay applied. Run a dry run
  first. Applying an export of the same state is an empty diff.

## Tracing

The daemon opens a span per request (`tower-http` `TraceLayer`; name `METHOD /route`) and
takes the W3C `traceparent` header as its parent, so a CLI or UI action and the daemon's work
are one trace when OpenTelemetry export is configured (ADR 0034). The client crate adds the
header from the current OpenTelemetry context when built with its `otel` feature, or from any
hook set with `Client::with_header_hook`.

## Client

`socketguard-client` has one method per route (`Client::status`, `list_apps`, `create_grant`,
`events`, ...), returning the core types, and a typed `Error` (`Connect`, `Api { status, code,
message, details }`, `Protocol`). The daemon's test `tests/coverage.rs` compares the daemon's
`api::ROUTES` with the client's `CLIENT_ROUTES` and fails when they differ; the CLI's own table
(`CLI_ROUTES`, which lists the client method behind every command) is checked against
`ROUTES` too (ADR 0033).

## TypeScript types

The Rust types derive their TypeScript form with `ts-rs` behind the core crate's `ts`
feature. The generated files are committed in `ui/src/generated/`; regenerate them after
changing a type in `crates/core/src/{model,api_types,types,config}.rs`:

    cargo test -p socketguard-core --features ts export_bindings

(`.cargo/config.toml` points `TS_RS_EXPORT_DIR` at `ui/src/generated`.) The UI must not
declare these types by hand.
