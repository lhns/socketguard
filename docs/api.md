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
| Linux, macOS | Unix socket | `api_socket` | `/run/socketguard.sock` (macOS: `/var/run/socketguard.sock`) |
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

    sudo socketguard-daemon access allow alice   # creates the group if needed; alice logs in again to pick it up
    sudo systemctl restart socketguard           # only needed if the group was created after the daemon started

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
name while the daemon was down gets no requests. For the daemon's own tests, set
`SOCKETGUARD_TRUST_PIPE_SERVER=1` for the client; to try SocketGuard without installing it, use
the portable zip (below) instead.

The daemon also gives its database file (and -wal/-shm) a protected ACL, SYSTEM and Administrators only, because it holds the onion service keys, and refuses to start if it cannot. Set `SOCKETGUARD_ALLOW_UNPROTECTED_DB=1` for the daemon to continue with a warning; for tests and development only (ADR 0040).

**Portable mode** (ADR 0054) uses the pipe `\\.\pipe\socketguard-portable`, which the CLI and the
window use by default when a `portable` file sits next to them (or with `--portable`). Its ACL
admits `SYSTEM`, `Administrators` and the one account named by the daemon's `--allow-user <SID>`
(the same read and write-data mask as the group, `O:BA` as owner so the client's owner check
passes). There is no `SocketGuard Users` group in that mode. The database and `data\` are
protected as above unless the volume has no access control lists (FAT, exFAT): then the daemon
warns once and `GET /api/status` has `db_protected: false`.

The daemon's portable options: `--portable`, `--owner-pid <pid>` (end, through the teardown, when
that process ends), `--allow-user <SID>`. `POST /api/shutdown` ends it the same way.

Let a user in:

    socketguard-daemon access allow alice        (as Administrator; alice signs out and in again)

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
does not cause a 202. Creating or renaming a peer or a peer group, `PUT /api/networks/{id}/peers` and `/bridges`, `DELETE /api/networks/{id}`, `apply`, `disable` and `enable` never answer 202 (except `POST /api/networks`, below). Every error has the [error body](#errors).

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| GET | `/api/status` | | `StatusResponse` | version, networks, protect-host interfaces, `disabled`, `unadopted` (an existing ruleset was found with an empty database and is left alone until `enable` or `disable`), counts, `config_path`, `db_path`, `socket` (where the daemon keeps its state), `service_installed`, `portable` (ADR 0054), `db_protected` (false only in portable mode on a volume without ACLs), `drop_events` (false when blocked connections cannot be logged; portable mode does not change the system's net-event option), `bundled` `{dir?, versions: [{name, version}]}` (the third-party programs this build ships, from `third_party/VERSIONS`: looked up next to the daemon, then in the package location (`/usr/lib/socketguard/third_party`; `/usr/local/lib/socketguard/third_party` on macOS), then `$SOCKETGUARD_THIRD_PARTY`; empty without `dir` when Tor and Yggdrasil are not included, ADR 0052) |
| GET | `/api/events` | | SSE stream | [events](#events) |
| GET | `/api/apps` | | `App[]` | |
| GET | `/api/apps/{id}` | | `AppDetail` | app with addresses (the ones serving its rows, each with `up`; none until a grant names a row), ports, grants on it (with reach), `access` (every access with its origin: direct, tag, group or reservation, and what it covers on this app: `scope` and `ports`), its `tags`, the port groups attached to it (`port_groups`) and counters |
| GET | `/api/apps/{id}/share` | | `ShareResponse` | `{tor: [{network_id, hostname, peer_id, peer_label, auth_private}]}`, per onion service and granted peer with a Tor client key the daemon generated: `auth_private` is the `<onion>:descriptor:x25519:<key>` line for the client's `ClientOnionAuthDir`. Holds private keys |
| DELETE | `/api/apps/{id}` | | 204 | forgets the app, its addresses and its grants; **it reappears as a new, closed app the next time it listens** |
| POST | `/api/apps/{id}/move` | `MoveAppRequest` | `AppDetail` | `{"to": app id, "confirm_open"}`: moves the app's addresses, grants, tag memberships and reservation bindings to another app, for a program that came back under a new identity. Grants the target already has are skipped; a port group used by a moved item is attached to the target. Needs `"confirm_open": true` where an Anyone grant moves or the target gains access for Anyone (409 `confirmation_required` otherwise) |
| GET | `/api/peers` | | `Peer[]` | |
| POST | `/api/peers` | `NewPeer` | `Peer` (201) | credentials are validated and normalized; unique across peers. `label` is optional: an unnamed peer is named after its first credential (see below) |
| GET | `/api/peers/{id}` | | `Peer` | |
| PATCH | `/api/peers/{id}` | `UpdateLabel` | `Peer` | rename |
| DELETE | `/api/peers/{id}` | | 204 | also deletes the grants naming the peer |
| POST | `/api/credentials/parse` | `ParseCredentialsRequest` | `ParsedCredential[]` | `{"text"}`; classifies pasted values (newline, comma or space separated); changes nothing |
| POST | `/api/peers/{id}/credentials` | `NewCredential` | `Credential` (201) | |
| POST | `/api/peers/{id}/tor-key` | | `TorKeyResponse` (201) | `{credential, private_key}`; generates an x25519 pair: the public key becomes a `tor_client_key` credential, the private key is stored in the database (like the onion service keys) and returned. Replaces the key generated before; a pasted key stays |
| DELETE | `/api/peers/{id}/credentials/{cred_id}` | | 204 | |
| GET | `/api/peer-groups` | | `PeerGroup[]` | |
| POST | `/api/peer-groups` | `NewGroup` | `PeerGroup` (201) | |
| GET | `/api/peer-groups/{id}` | | `PeerGroup` | |
| PATCH | `/api/peer-groups/{id}` | `UpdateLabel` | `PeerGroup` | rename |
| DELETE | `/api/peer-groups/{id}` | | 204 | also deletes the grants naming the group |
| PUT | `/api/peer-groups/{id}/members` | `SetMembers` | `PeerGroup` | `{"peer_ids": [peer id]}` replaces the members |
| GET | `/api/grants` | query `app`, `tag`, `reservation`, `peer`, `group` (all optional) | `GrantView[]` | `app`/`tag`/`reservation`: grants whose target is that app/tag/reservation; `peer` matches grants to the peer or to a group it is in |
| POST | `/api/grants` | `NewGrant` | `GrantView` (201) | `target` is `{"kind": "app", "tag" or "reservation", "id"}`; `subject` is `{"kind": "peer" or "group", "id"}` or `{"kind": "anyone"}`; `scope` (default All) and `network_id` (default every network) are optional; a reservation takes scope All only. Anyone needs `"confirm_open": true`. The grant creates the addresses of the rows it names (see [addresses](#addresses-and-reservations)) |
| DELETE | `/api/grants/{id}` | | 204 | |
| POST | `/api/changes` | `ChangesRequest` | `ChangesResponse` | [batch changes](#batch-changes): many operations, one transaction, one firewall update |
| GET | `/api/tags` | | `Tag[]` | [tags](#tags) |
| POST | `/api/tags` | `NewTag` | `Tag` (201) | `label`, optional `patterns` and `members` (`TagMember[]`); apps already matching the patterns join |
| GET | `/api/tags/{id}` | | `Tag` | |
| PATCH | `/api/tags/{id}` | `UpdateTag` | `Tag` | rename and/or replace the patterns; apps matching a new pattern join, none leaves. Setting patterns (different from the current ones; clearing them needs nothing) on a tag that has a grant to Anyone, directly or through a reservation that binds it, needs `"confirm_open": true` (409 `confirmation_required` otherwise) whether or not an app matches today: apps that match later are opened without asking again (ADR 0059) |
| DELETE | `/api/tags/{id}` | | 204 | also deletes the grants on the tag |
| POST | `/api/tags/{id}/members` | `NewTagMember` | `Tag` | an app with a `scope` (all of it by default, one port, or a port group attached to it); a manual addition clears an exclusion. On a tag that has a grant to Anyone it opens the app, so it needs `"confirm_open": true` |
| DELETE | `/api/tags/{id}/members/{app_id}` | query `port`, `proto` or `group` (optional) | `Tag` | without them the All-ports membership goes; with `port` (and `proto`, default `tcp`) or `group` (a port group id) the membership by that scope; a port and a group together are 400. Removing an app's All-ports membership that a pattern gave records an exclusion (`excluded`). A tag bound to a reservation: taking a member out frees its row, which needs `?confirm_open=true` where a grant to Anyone on the row then becomes live on Tor |
| GET | `/api/port-groups` | | `PortGroup[]` | [port groups](#port-groups) |
| POST | `/api/port-groups` | `NewPortGroup` | `PortGroup` (201) | `ports` (`{start, end, proto}` ranges, normalized), optional `label` (a missing or blank one names the group after its ports, e.g. `80/tcp, 443/tcp`, with ` (2)` appended on a clash; an explicit label that is taken is a 409), optional `apps` to attach it to. Needs `"confirm_open": true` where attaching opens an app to Anyone |
| GET | `/api/port-groups/{id}` | | `PortGroup` | |
| PUT | `/api/port-groups/{id}` | `UpdatePortGroup` | `PortGroup` | `label` and/or `ports`; new ports take effect everywhere the group is used (and need `confirm_open` where that opens an app to Anyone) |
| DELETE | `/api/port-groups/{id}` | | 204 | 409 `conflict`, naming what uses it, while a grant (on an app or a tag), a tag member or a reservation binding has the group as its scope; addresses that served it go with it |
| PUT | `/api/port-groups/{id}/apps/{app_id}` | `AttachPortGroup` | `PortGroup` | attach (idempotent). Widens what the grants and tag memberships that cover the app's All ports cover; `confirm_open` is needed where a grant to Anyone covers the new ports |
| DELETE | `/api/port-groups/{id}/apps/{app_id}` | | `PortGroup` | detach; 409 `conflict`, naming the users, while a grant on the app, a tag member of it or a reservation binding has the group as its scope; the app's addresses that served the group go |
| GET | `/api/reservations` | | `ReservationView[]` | [reservations](#addresses-and-reservations) |
| POST | `/api/reservations` | `NewReservation` | `ReservationView` (201) | `label`, optional `bindings` (`{"kind": "app", "app_id", "scope"?}` or `{"kind": "tag", "tag_id"}`), `confirm_open` |
| GET | `/api/reservations/{id}` | | `ReservationView` | |
| PUT | `/api/reservations/{id}` | `{"label"}` | `ReservationView` | rename |
| DELETE | `/api/reservations/{id}` | query `confirm_open` (optional) | 204 | release: its addresses and the grants on it go; its rows are freed. Needs `?confirm_open=true` where a grant to Anyone that names a freed row becomes live on Tor (a bound row is inert there) |
| POST | `/api/reservations/{id}/bindings` | `NewBinding` | `ReservationView` (201) | `{"target", "confirm_open"}`; binding a row opens it where the reservation has a grant to Anyone, so that needs `confirm_open` |
| DELETE | `/api/reservations/{id}/bindings/{binding_id}` | query `confirm_open` (optional) | `ReservationView` | frees what the binding held; needs `?confirm_open=true` under the same condition as a release |
| GET | `/api/addresses` | | `Address[]` | every address, automatic and reserved, with `up` |
| POST | `/api/addresses/{id}/reserve` | `ReserveRequest` | `ReservationView` (201) | `{"label"}`: turns an automatic address into a reservation with that row bound, keeping the address |
| GET | `/api/networks` | | `Network[]` | a Tor or Yggdrasil network (ADR 0052, 0056) has `child` `ChildInfo` (the state of SocketGuard's own copy): `state` (`stopped`, `waiting`, `starting`, `bootstrapping`, `up`, `exited`, `unavailable`), `progress?` (Tor, percent), `detail?`, `runs_as?`, `version?`, `address?` (Yggdrasil: the node's own address, known from its key before the node runs), `peers` (configured), `peers_connected?` (Yggdrasil, from the node's admin socket; absent while it is not up or runs without one). A Yggdrasil network is `waiting` until the ruleset that closes its address is applied (`detail` "waiting for the firewall rules that close the node (…)") and while another Yggdrasil node runs on the host (`detail` "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it."); `starting` is shown as the network's `down` reason "Yggdrasil is starting" |
| GET | `/api/networks/setup` | | `NetworkSetup` | what can be added on this host, read only (ADR 0048, 0056). `lan`: usable interfaces (no loopback or tunnels), default route first, each with `description?`, `has_ipv6_prefix`, `is_default_route`, `vlan_id?`, `already_added`. `yggdrasil` and `tor`: a `KindSetup` `{available, reason?, version?, added}` for SocketGuard's own copy: `available` is false when the build cannot provide it and `reason` says why ("Not included in this build" or which file of the build is missing); `version` is the shipped one. For Yggdrasil `reason` is also set while `available` (adding is still possible, the network waits) when another Yggdrasil node runs on the host: "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it." `local` is a `SetupState` `{state, found}`: `ready` or `added`, `found` the loopback `interface`. `yggdrasil_block` is present once a Yggdrasil network is added: `{closed, address_blocked, interface_blocked, reason?}`, read from the ruleset last applied successfully. `address_blocked` (and `closed`, the same) means the scopes that close the node are in force: its own `/128` and `/64` as destination on any interface (`overlay:<id>:addr`, `:subnet`). `interface_blocked` means the ruleset denies everything arriving on the network's interface (on WFP only while the adapter exists). `reason` is set while `closed` is false (SocketGuard is off, the last apply failed, the rules are not applied yet). `config_path` is the absolute path of the config file the daemon saves its networks in. The daemon never installs or configures anything |
| POST | `/api/networks` | `NewNetwork` | `Network` (201) | a backend instance: `{"id"?, "type": "slaac", "interface": "eth0", ...}`; unknown keys are refused (400). `{"type": "tor"}` and `{"type": "yggdrasil", "peers": ["tls://host:port"]}` add SocketGuard's own Tor and Yggdrasil (ADR 0056) and are open to every API caller; they are refused with 400 `invalid` and the reason ("Not included in this build", or the missing file) when the build cannot provide the files. `peers` are URIs (`tcp`, `tls`, `quic`, `ws`, `wss`, `socks`, `sockstls`) without duplicates. A Yggdrasil network may be added while the node cannot start yet (another Yggdrasil node runs, the firewall rules are not in): it is `down` with the reason and already closed (ADR 0051); the ruleset is applied before the answer, and if that failed the answer is 202 with `enforcement` `{status: "failed", message}` and the network is not closed yet (the daemon retries). A network whose interface does not exist on the host is `down` with the reason `interface <name> does not exist`. The id `setup` is reserved; also written to the `backends` key of the config file (`SOCKETGUARD_CONFIG` or the fixed location; created if missing), so it survives a restart |
| PUT | `/api/networks/{id}/lan-discovery` | `SetLanDiscovery` | `Network` | `{"enabled": bool, "confirm_open"}` turns the Yggdrasil node's discovery of the local network (multicast beacons and a peering listener on the LAN) on or off and saves the config file; the node restarts. Turning it on needs `"confirm_open": true` (409 `confirmation_required` otherwise), off needs none; 404 for an unknown id, 400 when the network is not a Yggdrasil network. `POST /api/networks` refuses `lan_discovery: true` (it starts off). `Network.child.lan_discovery` shows the setting. Records a `network_changed` activity (ADR 0060) |
| PUT | `/api/networks/{id}/peers` | `SetPeers` | `Network` | `{"peers": [uri]}` replaces the peers of a Yggdrasil network and saves the config file; 404 for an unknown id, 400 `invalid` when the network is not a Yggdrasil network or a peer is invalid or listed twice. Records a `network_changed` activity |
| PUT | `/api/networks/{id}/bridges` | `SetBridges` | `Network` | `{"bridges": [line]}` replaces the obfs4 bridges of a Tor network (any API caller, like the peers) and saves the config file; Tor restarts. Each line must be, and only, `[Bridge ]obfs4 <IPv4:port or [IPv6]:port> <40 hex> cert=<70 base64> iat-mode=<0\|1\|2>` on a single line of printable ASCII, at most 300 characters (ADR 0040: a line never adds a Tor option); lines are stored in canonical form (no `Bridge `, upper-case fingerprint) and duplicates dropped, at most 32. 400 `invalid` for anything else (the message says what is expected and that only obfs4 is supported) or when the network is not a Tor network; 404 for an unknown id; 409 `conflict` when the build has no obfs4 helper (an empty list is always accepted). `ChildInfo.bridges` lists them, `bridges_unavailable` says why they cannot be set. Records a `network_changed` activity. While bridges are set, the network's `down` reason is "connecting through bridges" |
| DELETE | `/api/networks/{id}` | | 204 | its addresses leave the interfaces first; removed from the config file as well. Query `force=true`; a Tor network whose services cannot be removed is 409 `conflict` without it. |
| GET | `/api/settings` | | `Settings` | only `protect_host_interfaces`; there is no address mode (`PUT /api/settings` is gone) |
| PUT | `/api/settings/protect-host` | `ProtectHostRequest` | `ProtectHostResponse` | `{"interfaces": [name], "force"}`, answer `{settings, overridden}` (`overridden`: the lockout risks that `force` overrode); an empty list turns it off; refused with 409 `protect_host_refused` unless `force` |
| GET | `/api/activity` | query `since`, `kind`, `app_id`, `peer_id`, `limit`, `before` | `ActivityRecord[]` | newest first; `since` is RFC 3339; `before` is a record id, for paging |
| GET | `/api/export` | | `ExportDocument` | [export and apply](#export-and-apply) |
| POST | `/api/apply` | `ApplyRequest` | `ApplyResponse` | |
| POST | `/api/disable` | `DisableRequest` | 204 | needs `"confirm": true`. Sets the persisted `disabled` latch, then removes all rules and addresses. While it is set the daemon (also after a restart) applies no rules and adds no addresses, but keeps tracking apps. `socketguard-daemon --disable` sets it too |
| POST | `/api/enable` | | 204 | clears the latch and re-applies rules and addresses |
| POST | `/api/shutdown` | | 204 | portable mode only (404 otherwise, ADR 0054): ends the daemon through the same teardown as `disable`, which runs after the answer is sent. The result is in `data\last-exit.log` (`<unix seconds> clean...` or `LEFT: ...`) and the exit code. `socketguard shutdown` |

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
| `slaac` | `interface`, `prefix?` (default: discovered from the interface) | LAN |
| `dhcpv6` | `interface` | LAN |
| `yggdrasil` | `peers` | singleton; SocketGuard's own node (ADR 0056), its interface is found at runtime |
| `tor` | `bridges` (see `PUT /api/networks/{id}/bridges`) | singleton; no interface; SocketGuard's own Tor (ADR 0056), its control endpoint and cookie are chosen by the daemon |

On a Tor network each address is one onion service, and its locator is
`{"kind": "onion", "hostname": "<id>.onion"}`. The service key is created with the address and
kept (in the daemon's database), so the name never changes. An address is **not published** until
a grant applies: a grant to Anyone publishes it openly; grants to peers publish it for their
`tor_client_key`s only (Tor client authorization). Tor authorizes per service, not per port, so the
published ports are the TCP ports covered by grants that are listening now (a port group's range
publishes only its listening ports), and a key granted fewer of them than that is
left out (a port with its own grant gets its own onion service). A reservation is opened as a whole on Tor: only a grant on
the reservation itself admits a client to its onion address, and a grant on a single bound row
has no effect there (its `GrantReach.note` says why; the reach is `not_reachable`). UDP is not served over Tor. A Tor control
port that cannot be reached shows as the network's `status` `down`; nothing is published or
removed until it is back.

The control endpoint receives the onion keys, so the daemon builds it itself from paths of its own state directory and vets the cookie file (ADR 0040, 0056): nothing about it is configurable. An unknown key in a `backends` entry, or at the top level of the config file, makes the daemon refuse the file and name the key and the file.

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
| 409 | `conflict` | duplicate label, credential or grant; a second ULA or Yggdrasil network; an address that is already reserved |
| 409 | `confirmation_required` | a grant to Anyone without `confirm_open`, or a new member of a tag, a new binding of a reservation or a moved app that opens something to Anyone without it, or a removal that frees rows of a reservation so that an Anyone grant on them becomes live on Tor; `disable` without `confirm` |
| 409 | `protect_host_refused` | whole-host protection would cut off remote administration. `details`: `LockoutRiskInfo[]` (process, port, protocol, bind address, message). Repeat with `"force": true` to override |
| 500 | `internal` | a bug or a failing system call; details are in the daemon log |

A Local network that sits on a non-loopback interface takes grants like any IP network
(ADR 0027); only Local on loopback answers `local_network`.

## Events

`GET /api/events` is a server-sent event stream (with keep-alive comments). The event name
carries the meaning; `data` is empty unless stated. Clients re-fetch what changed.

| Event | Meaning |
|---|---|
| `apps_changed` | apps or ports changed |
| `addresses_changed` | addresses appeared, went up or down, or were reserved |
| `app_discovered` | a new app; `data` is its id |
| `peers_changed` | peers, credentials or groups changed |
| `grants_changed` | grants (or what they resolve to) changed |
| `tags_changed` | tags, their patterns or members changed |
| `port_groups_changed` | port groups or their attachments changed |
| `reservations_changed` | reservations or their bindings changed |
| `networks_changed` | a network was added, removed or changed state |
| `settings_changed` | whole-host protection changed |
| `activity` | new activity records |

The client crate parses them into `ApiEvent`.

The desktop UI's Tauri backend re-emits these events to the frontend under the same names and adds two UI-local ones, `daemon_connected` and `daemon_disconnected`, for its own connection to the stream; the daemon never sends them.

## Scopes and port groups

A **scope** (ADR 0047) says which ports of an app a grant, a tag member, a binding or an address means. It is an object tagged by `kind`: `{"kind": "all"}` (the default when `scope` is absent), `{"kind": "port", "port": 80, "proto": "tcp"}`, or `{"kind": "group", "id": "<port group id>"}`. The ports of a scope on an app:

- `all` ("All ports"): the app's detected ports and the ranges of every port group attached to it,
- `port`: that port, detected or not,
- `group`: the group's ranges if it is attached to the app, else nothing. A grant or a tag member with a `group` scope on an app is refused (400) unless the group is attached to that app.

### Port groups

A **port group** (`PortGroup`, route `/api/port-groups`) is a label with ports and port ranges (`{"start": 50000, "end": 51000, "proto": "tcp"}`; a single port has `start == end`), standalone and attached to any number of apps (`apps`). Its ports need not be detected: a granted range is open before anything listens in it. One exclusion rule holds for every scope: an address never serves a port that another app is listening on now and this app does not have itself (a wildcard listener answers on every local address); this applies to a named `port`, to a group and to ranges reached through `all`. The omitted ranges are reported as `Address.excluded`. A range is open to any listener inside it, not only to this app's processes. Adding ports to a group or attaching it to an app is a change of reach, like a new grant: dry runs list it and a grant to Anyone that covers the new ports needs `confirm_open`. An unidentified app (`unknown:<proto>/<port>`) takes no port groups (400). Editing a group's ports takes effect everywhere. Detaching or deleting a group that a grant, tag member or binding uses is a 409 whose message lists the users.

### Addresses and reservations

Addresses exist for what is open (ADR 0047). There is no address mode, and no split or merge.

- An app has an address **only once a grant names one of its rows** (a row is the app with a scope: All ports, one port, or one port group). Per network there is one automatic address for the app (scope All) and one for each port or port group a grant names. A tag grant names the row of each member; a reservation grant names none. An app without grants has none ("no address yet").
- An address overlaps the others: it serves every port of its app, and a grant decides who gets in. `Address.up` says whether it is on its interface (or published, on Tor) now. When the last grant naming it goes, it is taken down but remembered, so the row gets the same address back. Local on loopback takes no grants, so there every app keeps its address and it is always up. `GET /api/apps/{id}` lists the addresses serving the app's rows, each with `up`; `GET /api/addresses` lists all of them.
- `Address` fields: `id`, `network_id`, `locator`, `created_at`, `app_id` (automatic addresses), `scope`, `reservation_id` (reservation addresses), and computed `up`, `excluded` (port ranges left out because another app listens there) and `notes` (Tor).
- A **reservation** is a named object assembled from bindings: an app with a scope, or a tag. Grants can target it (`"kind": "reservation"`, scope All); the grant covers every bound row and follows the bindings as they change. It has one static address per network, created the first time a grant covers something it serves there and kept until the reservation is released; the daemon never deletes or changes it on its own. A row bound to a reservation gets no automatic address on IP networks. `POST /api/addresses/{id}/reserve` turns an automatic address into a reservation, keeping the address.
- `ReservationView` is the reservation (`id`, `label`, `bindings`, `created_at`) plus `addresses` (one per network), `conflicts` and `grants`. Two bindings that claim the same ports are never resolved silently: a conflict is `{ports, bindings, served_app}`, where `served_app` is the app they are served for, or null if the ports are closed.
- On Tor a reservation is opened as a whole: a grant on the reservation admits clients to its onion address; a grant on a single bound row has no effect there. `GrantReach.note` carries the reason.
- `POST /api/apps/{id}/move` moves an app's addresses, grants, tag memberships and bindings to another app.

### Tags

A tag (ADR 0043) is a label with members (an app with a scope) and optional glob `patterns` on the process name or the executable path. A grant whose `target` is a tag covers, for each member, the member's ports narrowed to the grant's own scope (which needs no attachment: a group in the grant means its ranges). Apps matching the patterns join when they are first seen; removing a matched app by hand keeps it out. `AppDetail.access` lists every access an app has with its `origin`: `direct`, `tag` (with `tag_id`), `group` (with `group_id`) or `reservation`, its `scope` and the `ports` it covers there. Export and apply (below) leave grants on tags out.

## Batch changes

`POST /api/changes` (ADR 0045) takes `{"ops": [...], "dry_run": false}`. The operations are checked and applied in order, all or nothing, with one firewall update and (when something is pending) the usual 202. The first operation that fails refuses the batch and nothing is saved; the message names it (`operation 2: ...`).

| `op` | Fields |
|---|---|
| `create_peer` | `label?`, `credentials` (`NewCredential[]`), `ref?` |
| `create_group` | `label`, `members` (peer ids or refs of peers created earlier), `ref?` |
| `create_tag` | `label`, `patterns`, `ref?` |
| `create_port_group` | `label?` (named after the ports when missing), `ports`, `apps?` (attach right away), `confirm_open`, `ref?` |
| `update_port_group` | `group_id`, `label?`, `ports?`, `confirm_open` |
| `delete_port_group` | `group_id` |
| `attach_port_group` | `group_id`, `app_id`, `confirm_open` |
| `detach_port_group` | `group_id`, `app_id` |
| `add_grant` | `target`, `scope?`, `network_id?`, `subject`, `confirm_open` |
| `remove_grant` | `grant_id` |
| `add_tag_member` | `tag_id`, `app_id`, `scope?`, `confirm_open` (needed when the tag has a grant to Anyone) |
| `remove_tag_member` | `tag_id`, `app_id`, `scope?`, `confirm_open` (needed when the row leaves a reservation's tag and an Anyone grant on it becomes live on Tor) |
| `create_reservation` | `label`, `bindings?`, `confirm_open`, `ref?` |
| `reserve_address` | `address_id`, `label`, `ref?` |
| `rename_reservation` | `reservation_id`, `label` |
| `add_binding` | `reservation_id`, `target`, `confirm_open` (needed when the reservation has a grant to Anyone) |
| `remove_binding` | `reservation_id`, `binding_id`, `confirm_open` (needed when a freed row has a grant to Anyone that becomes live on Tor) |
| `delete_tag` | `tag_id`, `confirm_open` (as for `remove_binding`: the bindings of the tag go with it and free their rows) |
| `release_reservation` | `reservation_id`, `confirm_open` (as for `remove_binding`) |
| `move_app` | `from`, `to`, `confirm_open` |

A grant `target` may be a reservation (or the ref of one created earlier). Port group operations are planned like the rest: attaching a group to an app (or widening its ports) lists, as `reach`, the grants that now cover more, sets `changes_reach` where one lets its subject in, and needs `confirm_open` where one of them is a grant to Anyone (409 `confirmation_required` otherwise; `opens_to_anyone` marks the change). Detach and delete are refused like their routes while something uses the group, unless the same batch removed the users first. A `scope` of `{"kind": "group", "id": "$g"}` may use the ref of a group created earlier.

A `ref` is a client-chosen name starting with `$` (`$new0`). Wherever an id goes in a later operation (a tag target, a subject, `tag_id`, `grant_id`), the ref stands for it; the response's `refs` maps each ref to the id it got. An `add_grant` to Anyone without `confirm_open` refuses the whole batch with 409 `confirmation_required`; so does an `add_tag_member` that adds a new member to a tag with a grant to Anyone (such a change has `opens_to_anyone`). The answer lists the `changes` (a diff: `kind`, `item`, `name`, `id`, and for grants the `reach` per network, for removed grants the reach that is lost). `changes_reach` is true when the batch gives someone access to something they could not reach before (a new grant, or a new member of a tag that has grants, with some network that lets the subject in); removals never set it, except one that frees rows of a reservation: the grants that name them and become live on Tor are listed as `reach` of that change, with who they name in `detail`, set `changes_reach`, and need `confirm_open` where one is a grant to Anyone (`remove_binding`, `release_reservation`, `remove_tag_member`, `delete_tag`; no other operation can confirm, so one that frees such a row is refused). `DELETE /api/tags/{id}` takes `?confirm_open=true` for the same case (the bindings of the tag go with it) and is the `delete_tag` operation; a dry run of that operation previews it. A new member's change lists the reach of the tag's grants and who they name. An `add_grant` to Anyone on a tag with patterns (or a reservation that binds one) carries "Apps that match these patterns later will be open to Anyone without asking again." as the `note` of its reach; discovery logs an app that joins such a tag by its pattern as opened to Anyone. With `dry_run` nothing is saved or applied; the operations still run against the database's constraints, so a conflict shows.

A peer without a `label` (or with a blank one), in `POST /api/peers` and in `create_peer`, is named after its first credential: the normalized value without a `/32` or `/128`, a key (Yggdrasil, Tor, WireGuard, TLS) shortened to its first 12 characters and `…`. A name that is taken gets ` (2)`, ` (3)`… (in a batch, names created earlier count as taken). No label and no credential is `invalid` ("a peer needs a name or a credential"); an explicit label that is taken stays a 409.

## Export and apply

`GET /api/export` returns the portable state:

    {
      "version": 1,
      "settings": {"protect_host_interfaces": []},
      "peers":  [{"label": "alice", "credentials": [{"kind": "ygg_key", "value": "ba83...", "label": null}]}],
      "groups": [{"label": "team", "members": ["alice"]}],
      "port_groups": [{"label": "passive", "apps": [{"id": "5c0d...", "name": "nginx"}],
                         "ports": [{"start": 50000, "end": 51000, "proto": "tcp"}]}],
      "grants": [{"app": {"id": "5c0d...", "name": "nginx"},
                  "scope": {"kind": "port", "port": 80, "proto": "tcp"}, "network": "ygg",
                  "subject": {"peer": "alice"}}],
      "reservations": [{"label": "public-web",
                        "bindings": [{"kind": "app", "app": {"id": "5c0d...", "name": "nginx"},
                                      "scope": {"kind": "port", "port": 80, "proto": "tcp"}},
                                     {"kind": "tag", "label": "dev"}],
                        "grants": [{"network": "ygg", "subject": {"peer": "alice"}}]}]
    }

`subject` is `{"peer": label}`, `{"group": label}` or `"anyone"`; `scope` and `network` may be
absent (All ports, all networks). A grant names a port group by label:
`"scope": {"kind": "group", "label": "passive"}`, and the document must attach that group to
the grant's app. Port groups (`port_groups`) match by label; applying creates, changes (ports, attached
apps) and deletes them, detaching only after the grants that used them are removed. Apps are named by id, which is stable across restarts and
upgrades (the name is for humans).

`reservations` match by label. Each lists its bindings (an app with a `scope`, or a tag by label)
and its grants (`network?` and `subject`; a grant on a reservation always covers all its rows).
The addresses of reservations are not part of the document, so applying it elsewhere creates
new ones.

`POST /api/apply {"document": ..., "dry_run": bool, "confirm_open": bool}` compares the document with the current
state and returns the diff, then applies it unless `dry_run`:

    {"dry_run": true, "changes": [
      {"kind": "create", "item": "peer", "name": "carol", "detail": "1 credentials"},
      {"kind": "delete", "item": "grant", "name": "nginx 80/tcp on ygg to Anyone", "opens_to_anyone": true}]}

- Peers, groups and reservations match by **label**; grants by (app id, port, network, subject).
  The only setting is `protect_host_interfaces`. Items are created, updated (peer credentials, group members,
  settings) or deleted; **whatever the document lacks is deleted**. Grants have no mutable
  fields, so they are only created or deleted.
- The diff marks grants to Anyone with `opens_to_anyone`. `ApplyRequest.confirm_open` (default
  false) confirms changes that affect what Anyone can reach (ADR 0061). `confirm_open_required`
  in the response says the import needs it: a grant to Anyone exists now or in the document, and
  the import creates grants, bindings or reservations, removes bindings, releases reservations, or
  adds ports or apps to port groups. The test is coarse, so it can ask when nothing ends up opening.
  Without `confirm_open`, such an import is refused with `confirmation_required` before it applies
  anything; a dry run always returns the preview.
- The document is validated first (version, duplicate labels, unknown peers, groups, apps,
  ports and networks, credential formats); an invalid one changes nothing. Applying is not
  transactional beyond that: if a later step fails (for instance the lockout guard refusing
  whole-host protection, which is applied last), the earlier steps stay applied. Run a dry run
  first. Applying an export of the same state is an empty diff.

## Tracing

The daemon opens a span per request (`tower-http` `TraceLayer`; name `METHOD /route`) and
takes the W3C `traceparent` header as its parent, so a CLI or UI action and the daemon's work
are one trace when OpenTelemetry export is configured (ADR 0034). The client crate sends no trace
context (ADR 0034, amendment): a CLI or UI action is one trace starting at the daemon's API layer.

## Client

`socketguard-client` has one method per route (`Client::status`, `list_apps`, `create_grant`,
`events`, ...), returning the core types, and a typed `Error` (`Connect`, `Api { status, code,
message, details }`, `Protocol`). The daemon's test `tests/coverage.rs` compares the daemon's
`api::ROUTES` with the client's `CLIENT_ROUTES` and fails when they differ; the CLI's own table
(`CLI_ROUTES` in `crates/cli/src/routes.rs`, which lists the client method behind every command) is checked against
`ROUTES` too (ADR 0033). The CLI test also reads `ui/src-tauri/src/main.rs` and fails when a route has no Tauri command, except for the CLI-only `completions` and `watch` (ADR 0042). A change that gets the 202 notice reaches the UI as `{value, enforcement}`.

## TypeScript types

The Rust types derive their TypeScript form with `ts-rs` behind the core crate's `ts`
feature. The generated files are committed in `ui/src/generated/`; regenerate them after
changing a type in `crates/core/src/{model,api_types,types,config}.rs`:

    cargo test -p socketguard-core --features ts export_bindings

(`.cargo/config.toml` points `TS_RS_EXPORT_DIR` at `ui/src/generated`.) The UI must not
declare these types by hand.
