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

### Scope

One type says which sockets of an app are meant: `Scope = All | Port(port, proto) | Group(socket group)`. Grants, tag members and addresses all use it.

- **Socket group:** a standalone definition, a name plus ports and port ranges (`passive = 50000-51000/tcp`). It is attached to any number of apps and then usable in each like a socket. Its ports need not be detected.
- `Group` is valid on an app only while the group is attached to it. Detaching or deleting a group is refused while a grant, tag member or reservation uses it there.
- **Tag member:** an app with a scope.
- **Tag grant:** may carry a port or a socket group. Per member it covers the intersection of the member's scope and the grant's scope.
- The unique grant index covers the scope.

### Addresses exist for what is open

- An address is on an interface, or published on Tor, only while a grant covers something it serves. Nothing closed has an address.
- **Automatic addresses,** per network, once a grant covers the app there: one for the app (scope `All`), and one for each port or socket group that a grant names.
- Addresses overlap: the app's address serves every socket, including those with their own address. A grant decides who gets in; an address is only where.
- An automatic address is remembered while its app record exists, so closing and reopening gives the same one. A remembered DHCPv6 lease is kept while closed; the address is held and denied.
- A Local network on loopback takes no grants, so there every app keeps its address at all times.
- The address mode setting, split and merge are removed.

### Reservations

- A reservation is an address with a name. The daemon never deletes or changes it on its own, and it survives its app.
- It is bound to an app with a scope, to a tag, or to nothing (held, closed). Bound to a tag it serves the scoped sockets of every member.
- A reservation is created new or from an automatic address, can be rebound and released.
- `move_app` moves an app's addresses, grants and tag memberships to another app, for a program that reappeared under a new identity.

### Rules

- A source is let in on (address, port) when a grant covers that app and port. Grant logic is unchanged.
- A range rule leaves out ports that another app is listening on, because a wildcard listener answers on every local address.
- On Tor a range publishes only the ports currently listening.

## Consequences

- A host with nothing granted holds no addresses, leases or onion services beyond loopback.
- Port-only grants work on Tor without a manual step: the port's own service admits the client that the app's service leaves out (ADR 0039).
- **A granted range is open before anything listens in it.** A process of that app that binds inside it is reachable at once, before the monitor has seen the port. This is the purpose of ranges and the one exception to "nothing unseen is open".
- "Same address" still means the interface ID; a prefix change moves the upper half, as before.
- An app has more addresses than before once it is opened by port, and a tag reservation puts several apps behind one address.
- Schema v7 migrates: an all-ports address stays the app's address, a one-port address becomes a port address, a several-port address becomes a socket group attached to that app. No existing address goes dark, because a grant that covers a port opens every address serving it.
- The CLI loses `apps split`, `apps merge` and `settings address-mode`; the export format loses the address mode and gains socket groups and reservations.

## Amendment (2026-11-11): one exclusion rule; a range is open to any listener; "All sockets"

- **One exclusion rule.** An address never serves a port that is detected on another app and not on its own, whatever the scope: a named port, a socket group, or a range reached through `All`. The earlier text applied this to ranges only, which would have let the grantees of a port that app A stopped using reach app B once B listens there.
- **Correction to the consequence on ranges.** The firewall cannot tell whose process binds a port. Any wildcard listener inside a granted range is reachable through that address until the monitor attributes the port, not only a process of that app.
- **Changing a socket group changes reach.** Adding ports to a group, or attaching it to an app, is treated like a new grant for everyone whose grant covers it: it is shown as a change of reach and needs confirmation when Anyone is among them.
- **Unidentified apps** (ADR 0046) take no socket groups: their identity is one port.
- **Wording.** Frontends call scope `All` the built-in socket group "All sockets". A detected socket and a socket group are the same kind of row inside an app, and a tag always sits on one of these rows; tagging an app means tagging its "All sockets".
- **An address belongs to a row, and a row gets one when a grant names it.** This replaces "one for the app once a grant covers the app". "All sockets" gets its address when a grant names "All sockets" (directly, or through a tag member with that scope); a socket or socket group gets its own when a grant names it. A socket that is only covered by an "All sockets" grant has no address of its own and is reached on that one.
- **A reservation takes several bindings.** Each binding is a row of an app or a tag, so one reserved address can front sockets of several apps, like one IPv4 address in front of several services. Ports are not remapped. A port is served for the app that is detected on it; an undetected port that only one binding claims follows that binding, and one that several bindings claim stays closed until an app is detected on it.

## Amendment (2026-11-11): when an address is up, in one place

This settles the rules where the text above and the first amendment disagree. Where they differ, this section holds.

- **Automatic address:** exists for a row that a grant names, on each network where that grant applies, and is up only while named. When the last naming grant goes, it is taken down but remembered, so the row gets the same address back.
- **Reservation:** up while a grant covers anything it serves, named or not. A row bound to a reservation gets no automatic address on that network.
- **What a tag grant names:** the row of each member (the member's scope). A port or socket group on the tag grant only limits which ports are let in; it names no other row.
- **A reservation is one address on one network,** chosen when it is created.
- **Shared reservations on Tor:** a service admits a client only if its grants cover every published port (ADR 0039). A reserved onion address that fronts several apps therefore admits only clients granted on all of them. Frontends show the existing note; use one reservation per app on Tor.
- **Migration:** an existing address that a grant names stays as the automatic address of its row. One that a grant covers without naming it (a port grant on an app address) becomes a reservation on its row, so no address in use changes. One that no grant covers is remembered and taken down.
- **`move_app`:** grants the target already has are skipped (ADR 0041); a socket group used by a moved grant, tag member or address is attached to the target; port scopes move as they are.
- **Port conflicts are reported, never resolved silently.** When two bindings of a reservation claim the same port, the reservation lists the conflict (the port, the bindings, and which app is served or that the port is closed). The API returns it with the reservation and frontends show it on the reservation and on the affected rows. The same applies wherever the exclusion rule leaves a port out of an address.
- **Port remapping is left open, for reservations only.** A binding may later carry an outside port that differs from the socket's port. Automatic addresses will always show sockets on their real ports. Nothing is built for it now; the binding is its own record so the field can be added.

## Amendment (2026-11-11): a reservation is a grant target with an address per network

A reservation behaves like an app assembled from sockets of several apps. This replaces "one address on one network".

- **Rows.** A reservation has its bound rows and a built-in "All sockets" row that stands for all of them.
- **Grant target.** A grant can target a reservation (`Target::Reservation`). It covers every bound row, follows the bindings as they change, and can be limited to a network like any grant. A grant on a single bound row is the ordinary grant on that app row, the same one shown under the app.
- **Addresses.** A reservation has one static address per network, created the first time a grant covers something it serves there and kept until the reservation is released. It is up while such a grant exists.
- **Tor.** A grant on the reservation covers every published port, so those clients are admitted to its onion address. Clients granted only single rows are left out there, as before.
- Reserving an automatic address creates a reservation with that row bound and that address as its address on that network.
- **Bound rows on Tor keep their own address.** On a network that authorises per address (Tor), a bound row that a grant names still gets its automatic address, so a client granted only that row is admitted there. On IP networks a bound row has no automatic address; the firewall separates ports on the reservation's address.
