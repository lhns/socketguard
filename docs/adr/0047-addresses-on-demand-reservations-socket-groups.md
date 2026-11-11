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
