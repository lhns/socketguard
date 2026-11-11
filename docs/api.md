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
group `SocketGuard Users` read and write-data (mask `0x12008B`, not create-instance) if it
exists at daemon start and is a group (otherwise the daemon logs a warning and leaves it
out). The first server instance is created exclusively, so the daemon does not start if
something else already owns the name, and clients open the pipe with identification-level
impersonation only. Remote clients are rejected, and a new server instance is always
waiting, so many clients can connect at once. The client in turn checks the server: after
opening the pipe it reads the pipe's owner and refuses unless that is `SYSTEM` or
`Administrators` ("pipe server is not the SocketGuard service"), so a process that took the
name while the daemon was down gets no requests. For tests and a daemon started by hand
from a normal account, set `SOCKETGUARD_TRUST_PIPE_SERVER=1` for the client.

The daemon also gives its database file (and -wal/-shm) a protected ACL, SYSTEM and Administrators only, because it holds the onion service keys, and refuses to start if it cannot. Set `SOCKETGUARD_ALLOW_UNPROTECTED_DB=1` for the daemon to continue with a warning; for tests and development only (ADR 0040).

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
creates return 201 with the new object, deletes 204 with no body. A change to apps, peers,
credentials, groups or grants is saved before it is enforced; if a network that is not
enforced by the firewall (Tor) still has a change waiting that it could not apply, the
response is **202** instead, with the same body (deletes: a body with only the notice) plus
[`enforcement`](#pending-enforcement). A network that is down but has nothing outstanding
does not cause a 202. Every error has the [error body](#errors).

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| GET | `/api/status` | | `StatusResponse` | version, networks, protect-host interfaces, `disabled`, `unadopted` (an existing ruleset was found with an empty database and is left alone until `enable` or `disable`), counts |
| GET | `/api/events` | | SSE stream | [events](#events) |
| GET | `/api/apps` | query `pending=true` (optional) | `App[]` | `pending=true`: only apps without a decision |
| GET | `/api/apps/{id}` | | `AppDetail` | app with addresses, ports, grants on it (with reach), `access` (every access with its origin: direct, tag or group, and what it covers on this app: `scope` and `ports`), its `tags`, the `socket_groups` attached to it and counters |
| GET | `/api/apps/{id}/share` | | `ShareResponse` | per onion service and granted peer with a Tor client key the daemon generated: the `<onion>:descriptor:x25519:<key>` line for the client's `ClientOnionAuthDir`. Holds private keys |
| DELETE | `/api/apps/{id}` | | 204 | forgets the app, its addresses and its grants; **it reappears as pending the next time it listens** |
| POST | `/api/apps/{id}/review` | `ReviewRequest` | `AppDetail` | mark reviewed (or pending again); it stays closed until granted |
| POST | `/api/apps/{id}/split` | `SplitRequest` | `Address` (201) | adds an address for one port (`port`, `proto`) or one attached socket group (`group`) on a network; the app's other addresses keep serving it too (addresses overlap, ADR 0047). 409 if it has one already |
| POST | `/api/apps/{id}/merge` | `MergeRequest` | `Address` | folds the listed addresses of one network into the app's address for all ports: it is created if missing, and the listed addresses with a narrower scope go. Returns the all-ports address |
| GET | `/api/peers` | | `Peer[]` | |
| POST | `/api/peers` | `NewPeer` | `Peer` (201) | credentials are validated and normalized; unique across peers. `label` is optional: an unnamed peer is named after its first credential (see below) |
| GET | `/api/peers/{id}` | | `Peer` | |
| PATCH | `/api/peers/{id}` | `UpdateLabel` | `Peer` | rename |
| DELETE | `/api/peers/{id}` | | 204 | also deletes the grants naming the peer |
| POST | `/api/credentials/parse` | `ParseCredentialsRequest` | `ParsedCredential[]` | classifies pasted values (newline, comma or space separated); changes nothing |
| POST | `/api/peers/{id}/credentials` | `NewCredential` | `Credential` (201) | |
| POST | `/api/peers/{id}/tor-key` | | `TorKeyResponse` (201) | generates an x25519 pair: the public key becomes a `tor_client_key` credential, the private key is stored in the database (like the onion service keys) and returned. Replaces the key generated before; a pasted key stays |
| DELETE | `/api/peers/{id}/credentials/{cred_id}` | | 204 | |
| GET | `/api/peer-groups` | | `PeerGroup[]` | |
| POST | `/api/peer-groups` | `NewGroup` | `PeerGroup` (201) | |
| GET | `/api/peer-groups/{id}` | | `PeerGroup` | |
| PATCH | `/api/peer-groups/{id}` | `UpdateLabel` | `PeerGroup` | rename |
| DELETE | `/api/peer-groups/{id}` | | 204 | also deletes the grants naming the group |
| PUT | `/api/peer-groups/{id}/members` | `SetMembers` | `PeerGroup` | replaces the members |
| GET | `/api/grants` | query `app`, `tag`, `peer`, `group` (all optional) | `GrantView[]` | `app`/`tag`: grants whose target is that app/tag; `peer` matches grants to the peer or to a group it is in |
| POST | `/api/grants` | `NewGrant` | `GrantView` (201) | `target` is `{"kind": "app" or "tag", "id"}`. Anyone needs `"confirm_open": true` |
| DELETE | `/api/grants/{id}` | | 204 | |
| POST | `/api/changes` | `ChangesRequest` | `ChangesResponse` | [batch changes](#batch-changes): many operations, one transaction, one firewall update |
| GET | `/api/tags` | | `Tag[]` | [tags](#tags) |
| POST | `/api/tags` | `NewTag` | `Tag` (201) | apps already matching the patterns join |
| GET | `/api/tags/{id}` | | `Tag` | |
| PATCH | `/api/tags/{id}` | `UpdateTag` | `Tag` | rename and/or replace the patterns; apps matching a new pattern join, none leaves. If any would join a tag that has a grant to Anyone, it needs `"confirm_open": true` (409 `confirmation_required` otherwise) |
| DELETE | `/api/tags/{id}` | | 204 | also deletes the grants on the tag |
| POST | `/api/tags/{id}/members` | `NewTagMember` | `Tag` | an app with a `scope` (all of it by default, one port, or a socket group attached to it); a manual addition clears an exclusion. On a tag that has a grant to Anyone it opens the app, so it needs `"confirm_open": true` |
| DELETE | `/api/tags/{id}/members/{app_id}` | query `port`, `proto` or `group` (optional) | `Tag` | without them the whole-app membership goes; with `port` (and `proto`) or `group` (a socket group id) the membership by that scope. Removing a whole app that a pattern matches records an exclusion (`excluded`) |
| GET | `/api/socket-groups` | | `SocketGroup[]` | [socket groups](#socket-groups) |
| POST | `/api/socket-groups` | `NewSocketGroup` | `SocketGroup` (201) | `label`, `ports` (`{start, end, proto}` ranges, normalized), optional `apps` to attach it to. Needs `"confirm_open": true` where attaching opens an app to Anyone |
| GET | `/api/socket-groups/{id}` | | `SocketGroup` | |
| PUT | `/api/socket-groups/{id}` | `UpdateSocketGroup` | `SocketGroup` | `label` and/or `ports`; new ports take effect everywhere the group is used (and need `confirm_open` where that opens an app to Anyone) |
| DELETE | `/api/socket-groups/{id}` | | 204 | 409 `conflict`, naming what uses it, while a grant (on an app or a tag) or a tag member has the group as its scope; addresses that served it go with it |
| PUT | `/api/socket-groups/{id}/apps/{app_id}` | `AttachSocketGroup` | `SocketGroup` | attach (idempotent). Widens what the app's whole-app grants and tag memberships cover; `confirm_open` is needed where a grant to Anyone covers the new ports |
| DELETE | `/api/socket-groups/{id}/apps/{app_id}` | | `SocketGroup` | detach; 409 `conflict`, naming the users, while a grant on the app or a tag member of it has the group as its scope; the app's addresses that served the group go |
| GET | `/api/networks` | | `Network[]` | |
| POST | `/api/networks` | `NewNetwork` | `Network` (201) | a backend instance: `{"id"?, "type": "slaac", "interface": "eth0", ...}`; also written to the `backends` key of the config file (`SOCKETGUARD_CONFIG` or the default; created if missing), so it survives a restart |
| DELETE | `/api/networks/{id}` | | 204 | its addresses leave the interfaces first; removed from the config file as well. Query `force=true`; a Tor network whose services cannot be removed is 409 `conflict` without it |
| GET | `/api/settings` | | `Settings` | |
| PUT | `/api/settings` | `UpdateSettings` | `Settings` | absent fields stay as they are |
| PUT | `/api/settings/protect-host` | `ProtectHostRequest` | `ProtectHostResponse` | an empty list turns it off; refused with 409 `protect_host_refused` unless `force` |
| GET | `/api/activity` | query `since`, `kind`, `app_id`, `peer_id`, `limit`, `before` | `ActivityRecord[]` | newest first; `since` is RFC 3339; `before` is a record id, for paging |
| GET | `/api/export` | | `ExportDocument` | [export and apply](#export-and-apply) |
| POST | `/api/apply` | `ApplyRequest` | `ApplyResponse` | |
| POST | `/api/disable` | `DisableRequest` | 204 | needs `"confirm": true`. Sets the persisted `disabled` latch, then removes all rules and addresses. While it is set the daemon (also after a restart) applies no rules and adds no addresses, but keeps tracking apps. `socketguard-daemon --disable` sets it too |
| POST | `/api/enable` | | 204 | clears the latch and re-applies rules and addresses |

## Credentials and networks

Credential `kind`s and the values they accept (the daemon normalizes them and rejects the rest):

| Kind | Value | Stored as |
|---|---|---|
| `ygg_key` | 64 hex characters | lowercase |
| `ygg_addr` | one address in `200::/7` | the address |
| `ygg_subnet` | a /64 in `300::/8` | `net/64` |
| `ip` | IPv6 address or CIDR (IPv4 is rejected); a value in `200::/7` becomes `ygg_addr` or `ygg_subnet` | `net/len` |
| `ip_suffix` | an interface ID such as `::a:b:c:d`, optionally `/64` | the address |
| `tor_client_key` | an x25519 public key in base32: 52 characters, case-insensitive, or the full `descriptor:x25519:<base32>` line of an `authorized_clients` file | the bare key, uppercase |
| `wg_key`, `tls_spki` | base64 | as given; not enforced yet |

A `tor_client_key` is `verified` on a Tor network and `not_reachable` on every other network; a
grant to Anyone is `open` everywhere.

A network is a backend instance (`POST /api/networks`, `{"id"?, "type": ..., ...}`):

| `type` | Fields | Notes |
|---|---|---|
| `ula` | `interface` (default loopback) | Local; singleton |
| `slaac`, `dhcpv6` | `interface`, `prefix?` | LAN |
| `yggdrasil` | `interface`, `admin_endpoint?` | singleton |
| `tor` | `control` (`host:port` or `unix:/path`, default `127.0.0.1:9051`), `auth` | singleton; no interface. `auth` is `"cookie"` (default; SAFECOOKIE with the cookie file named by PROTOCOLINFO), `"cookie_insecure"`, `"none"` (Unix socket only) or `{"password": "..."}`. Through the API only the defaults are accepted (below); other settings are edited in the config file |

On a Tor network each address is one onion service, and its locator is
`{"kind": "onion", "hostname": "<id>.onion"}`. The service key is created with the address and
kept (in the daemon's database), so the name never changes. An address is **not published** until
a grant applies: a grant to Anyone publishes it openly; grants to peers publish it for their
`tor_client_key`s only (Tor client authorization). Tor authorizes per service, not per port, so the
published ports are the TCP ports covered by grants that are listening now (a socket group's range
publishes only its listening ports), and a key granted fewer of them than that is
left out until the port gets its own address (`split`). UDP is not served over Tor. A Tor control
port that cannot be reached shows as the network's `status` `down`; nothing is published or
removed until it is back.

The control endpoint receives the onion keys, so `POST /api/networks` accepts a Tor network only with the default settings or settings identical to a Tor entry already in the config file; anything else is `400 invalid`. The remaining settings, for the config file only: `cookie_path` (the file PROTOCOLINFO must name), `cookie_dir`, `expect_tor_uid` (Linux, Unix socket), `cookie_owner` (Windows: the SID of Tor's account, besides SYSTEM and Administrators, that may own the cookie file), and `allow_remote_control` (accept a control address that is not loopback; cookie auth only). On Windows cookie auth requires `cookie_path`, and the file must be owned by SYSTEM, Administrators or `cookie_owner` and writable by no one else.

`DELETE /api/networks/{id}?force=true` (`networks rm --force`): removing a Tor network first removes every onion service the daemon owns on it. If Tor cannot confirm that, the answer is `409 conflict` ("Tor services are still being removed; retry when Tor is reachable, or use --force") and nothing changes; with `force` the network is removed anyway and the unconfirmed services are left running.

### Pending enforcement

    {"enforcement": {"status": "pending", "message": "saved, but not yet enforced; retrying (network 'tor': cannot reach the Tor control port ...)"}}

`Enforcement { status, message }` (`EnforcementNotice` for a body without other content). It
means the change is in the database but a network has not applied it yet (it is *pending*:
a service to publish, change or remove is unconfirmed), for example a
grant was revoked while Tor was down, so the onion service is still published. The daemon
keeps the removal on a persisted list and retries on every pass until Tor confirms it. The
CLI prints `warning: ...` to stderr, and the client's `Saved<T>` carries `enforcement`.

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
| 409 | `confirmation_required` | a grant to Anyone without `confirm_open`, or a new member of a tag that has a grant to Anyone without it; `disable` without `confirm` |
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
| `tags_changed` | tags, their patterns or members changed |
| `socket_groups_changed` | socket groups or their attachments changed |
| `networks_changed` | a network was added, removed or changed state |
| `settings_changed` | address mode or whole-host protection changed |
| `activity` | new activity records |

The client crate parses them into `ApiEvent`.

The desktop UI's Tauri backend re-emits these events to the frontend under the same names and adds two UI-local ones, `daemon_connected` and `daemon_disconnected`, for its own connection to the stream; the daemon never sends them.

## Scopes and socket groups

A **scope** (ADR 0047) says which sockets of an app a grant, a tag member or an address means. It is an object tagged by `kind`: `{"kind": "all"}` (the default when `scope` is absent), `{"kind": "port", "port": 80, "proto": "tcp"}`, or `{"kind": "group", "id": "<socket group id>"}`. The ports of a scope on an app:

- `all`: the app's detected ports and the ranges of every socket group attached to it,
- `port`: that port, detected or not,
- `group`: the group's ranges if it is attached to the app, else nothing. A grant or a tag member with a `group` scope on an app is refused (400) unless the group is attached to that app.

### Socket groups

A **socket group** is a label with ports and port ranges (`{"start": 50000, "end": 51000, "proto": "tcp"}`; a single port has `start == end`), standalone and attached to any number of apps (`apps`). Its ports need not be detected: a granted range is open before anything listens in it. A range leaves out ports that another app is listening on now (a wildcard listener answers on every local address), unless the app has the port itself; explicit `port` scopes and detected ports are not affected. Editing a group's ports takes effect everywhere. Detaching or deleting a group that a grant or tag member uses is a 409 whose message lists the users.

### Tags

A tag (ADR 0043) is a label with members (an app with a scope) and optional glob `patterns` on the process name or the executable path. A grant whose `target` is a tag covers, for each member, the member's ports narrowed to the grant's own scope (which needs no attachment: a group in the grant means its ranges). Apps matching the patterns join when they are first seen; removing a matched app by hand keeps it out. `AppDetail.access` lists every access an app has with its `origin`: `direct`, `tag` (with `tag_id`) or `group` (with `group_id`), its `scope` and the `ports` it covers there. Export and apply (below) leave grants on tags out.

## Batch changes

`POST /api/changes` (ADR 0045) takes `{"ops": [...], "dry_run": false}`. The operations are checked and applied in order, all or nothing, with one firewall update and (when something is pending) the usual 202. The first operation that fails refuses the batch and nothing is saved; the message names it (`operation 2: ...`).

| `op` | Fields |
|---|---|
| `create_peer` | `label?`, `credentials` (`NewCredential[]`), `ref?` |
| `create_group` | `label`, `members` (peer ids or refs of peers created earlier), `ref?` |
| `create_tag` | `label`, `patterns`, `ref?` |
| `create_socket_group` | `label`, `ports`, `apps?` (attach right away), `confirm_open`, `ref?` |
| `update_socket_group` | `group_id`, `label?`, `ports?`, `confirm_open` |
| `delete_socket_group` | `group_id` |
| `attach_socket_group` | `group_id`, `app_id`, `confirm_open` |
| `detach_socket_group` | `group_id`, `app_id` |
| `add_grant` | `target`, `scope?`, `network_id?`, `subject`, `confirm_open` |
| `remove_grant` | `grant_id` |
| `add_tag_member` | `tag_id`, `app_id`, `scope?`, `confirm_open` (needed when the tag has a grant to Anyone) |
| `remove_tag_member` | `tag_id`, `app_id`, `scope?` |
| `review` | `app_id`, `reviewed` |

Socket group operations are planned like the rest: attaching a group to an app (or widening its ports) lists, as `reach`, the grants that now cover more, sets `changes_reach` where one lets its subject in, and needs `confirm_open` where one of them is a grant to Anyone (409 `confirmation_required` otherwise; `opens_to_anyone` marks the change). Detach and delete are refused like their routes while something uses the group, unless the same batch removed the users first. A `scope` of `{"kind": "group", "id": "$g"}` may use the ref of a group created earlier.

A `ref` is a client-chosen name starting with `$` (`$new0`). Wherever an id goes in a later operation (a tag target, a subject, `tag_id`, `grant_id`), the ref stands for it; the response's `refs` maps each ref to the id it got. An `add_grant` to Anyone without `confirm_open` refuses the whole batch with 409 `confirmation_required`; so does an `add_tag_member` that adds a new member to a tag with a grant to Anyone (such a change has `opens_to_anyone`). The answer lists the `changes` (a diff: `kind`, `item`, `name`, `id`, and for grants the `reach` per network, for removed grants the reach that is lost). `changes_reach` is true when the batch gives someone access to something they could not reach before (a new grant, or a new member of a tag that has grants, with some network that lets the subject in); removals never set it. A new member's change lists the reach of the tag's grants and who they name. With `dry_run` nothing is saved or applied; the operations still run against the database's constraints, so a conflict shows.

A peer without a `label` (or with a blank one), in `POST /api/peers` and in `create_peer`, is named after its first credential: the normalized value without a `/32` or `/128`, a key (Yggdrasil, Tor, WireGuard, TLS) shortened to its first 12 characters and `…`. A name that is taken gets ` (2)`, ` (3)`… (in a batch, names created earlier count as taken). No label and no credential is `invalid` ("a peer needs a name or a credential"); an explicit label that is taken stays a 409.

## Export and apply

`GET /api/export` returns the portable state:

    {
      "version": 1,
      "settings": {"address_mode": "per_app", "protect_host_interfaces": []},
      "peers":  [{"label": "alice", "credentials": [{"kind": "ygg_key", "value": "ba83...", "label": null}]}],
      "groups": [{"label": "team", "members": ["alice"]}],
      "socket_groups": [{"label": "passive", "apps": [{"id": "5c0d...", "name": "nginx"}],
                         "ports": [{"start": 50000, "end": 51000, "proto": "tcp"}]}],
      "grants": [{"app": {"id": "5c0d...", "name": "nginx"},
                  "scope": {"kind": "port", "port": 80, "proto": "tcp"}, "network": "ygg",
                  "subject": {"peer": "alice"}}]
    }

`subject` is `{"peer": label}`, `{"group": label}` or `"anyone"`; `scope` and `network` may be
absent (all ports, all networks). A grant names a socket group by label:
`"scope": {"kind": "group", "label": "passive"}`, and the document must attach that group to
the grant's app. Socket groups match by label; applying creates, changes (ports, attached
apps) and deletes them, detaching only after the grants that used them are removed. Apps are named by id, which is stable across restarts and
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
`ROUTES` too (ADR 0033). The CLI test also reads `ui/src-tauri/src/main.rs` and fails when a route has no Tauri command, except for the CLI-only `completions` and `watch` (ADR 0042). A change that gets the 202 notice reaches the UI as `{value, enforcement}`.

## TypeScript types

The Rust types derive their TypeScript form with `ts-rs` behind the core crate's `ts`
feature. The generated files are committed in `ui/src/generated/`; regenerate them after
changing a type in `crates/core/src/{model,api_types,types,config}.rs`:

    cargo test -p socketguard-core --features ts export_bindings

(`.cargo/config.toml` points `TS_RS_EXPORT_DIR` at `ui/src/generated`.) The UI must not
declare these types by hand.
