# ADR 0047: Addresses on Demand, Reservations and Socket Groups

## Status

Accepted. Supersedes the address-mode and split/merge decision of ADR 0027 (D1) and its rule that every app has an address on every network. Extends ADR 0041 (the unique grant) and ADR 0043 (tag members and tag grants).

## Date

2026-11-11

## Context

ADR 0027 gave every app an address on every network, open or not, and let a port sit either on the app's address or on its own, chosen by a global setting and changed per app with split and merge. In use this was unclear and costly:

- A host has dozens of system services; each held an address, a DHCPv6 lease and an onion key although nothing was granted.
- "Per app or per port" is a per-app question, and the either/or meant that giving a port its own address changed what the app's address served.
- An address could not be named, kept or moved. An app whose binary moves becomes a new app and loses its addresses.
- The socket groups of ADR 0018 (ports that belong together, such as FTP's control port and passive range) had no successor. Grants and addresses took single detected ports only.

## Decision

### Rows and scope
- Inside an app there are rows: the built-in "All sockets", each detected socket, each attached socket group. A row is (app, scope), `Scope = All | Port | Group`.
- A socket group is standalone: a name plus ports and ranges, attached to any number of apps. Unidentified apps take none.
- "All sockets" is the detected sockets plus the attached groups.
- Tags, grants and addresses sit on rows. A tag member is a row.

### Grants
- A grant targets an app row, a tag, or a reservation.
- A direct grant names its row. A tag grant names each member's row; a port or socket group on it only limits ports. A reservation grant has scope All and covers every bound row.
- Subjects are unchanged: Anyone, a peer, a peer group. A group stands for its members' credentials wherever a peer does.
- Attaching a socket group, adding ports to one, adding a tag member or adding a binding counts as opening when an existing grant then covers more: it is shown as a change of reach and needs confirmation when Anyone gains.

### Exclusion
- An address never serves a port that another app is listening on and its own app is not. A stale port record is not listening. Excluded ports are reported per address.
- A granted range is open before anything listens; any listener inside it is reachable through that address until the port is attributed.

### Automatic addresses (apps)
- A row has an address on a network while a grant names it there. The address follows the grant, not who the grant lets in: an empty peer group or a peer without a usable credential still names the row.
- When no grant names the row the address is taken down and remembered; the row gets the same one back.
- `up` means really on the interface or published. On Tor a service with nobody to admit is not published.
- A Local network on loopback takes no grants; every app keeps an "All sockets" address there.
- A remembered DHCPv6 lease is kept. Prefix changes keep the interface ID.
- A row bound to a reservation has no automatic address on any network.
- No address mode, split or merge.

### Reservations
- A named object with bindings; it behaves like an app assembled from rows of several apps, with its own "All sockets". A binding is its own record and targets an app row or a tag (its members' rows).
- One static address per network, created the first time a grant covers something it serves there, never deleted or changed by the daemon, removed on release. It survives its apps.
- On firewall-enforced networks the address serves every bound row, and each (address, port) admits whoever a grant covers for that app and port.
- A port is served for the app listening on it; an unlistened port claimed by one binding follows it; claimed by several it stays closed. Such conflicts are reported with the reservation.
- **Tor: opened as a whole.** Only grants that target the reservation count for its onion address: they create it, and their clients are its client list. A grant on a bound row, direct or through a tag, has no effect on Tor while the row is bound, even for a client who holds every bound row that way; its reach is "not reachable" with the reason, shown per member for tag grants.
- Reserving an automatic address makes a reservation with that row bound and that address as its address on that network.
- Port remapping is left open, for reservations only.

### Moving an app
- `move_app` moves direct grants, tag memberships, automatic addresses and bindings to another app. Grants the target has are skipped; needed socket groups are attached; Anyone grants need confirmation.

### Migration
- v6 to v7: an all-ports address becomes an "All sockets" address, a one-port address a socket address, a several-port address a socket group attached to that app.
- v7 to v8: an address whose row a grant names stays automatic. One a grant covers without naming it becomes a reservation with that row bound. One no grant covers is remembered and taken down. The address mode is dropped.

## Consequences

- A host with nothing granted holds no addresses, leases or onion services beyond loopback.
- "Per app or per socket" is no setting any more; it follows from what is granted.
- Every granted row has its own onion address with its own client list, so different people per socket work on Tor without a manual step. Inside a reservation Tor access is all or nothing.
- A granted range is the one place where something the monitor has not seen is open.
- A reservation puts several apps behind one address and is a third grant target next to apps and tags; frontends show where access comes from.
- "Same address" still means the interface ID; a prefix change moves the upper half.
- The CLI loses `apps split`, `apps merge` and `settings address-mode`; the export format loses the address mode and gains socket groups and reservations.
- Port remapping and per-client access on one onion address (which needs authentication inside the connection) are not built.
