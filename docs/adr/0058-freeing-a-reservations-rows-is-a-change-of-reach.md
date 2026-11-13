# ADR 0058: Freeing a Reservation's Rows Is a Change of Reach

## Status

Accepted. Extends ADR 0047 (adding a binding counts as opening; so does removing one). Supersedes in part the last consequence of ADR 0057: the networks' data trees are removed from the purge list, not only by the install record.

## Date

2026-11-13

## Context

ADR 0047: on Tor a reservation is opened as a whole, and a grant on a bound row (direct or through a tag) has no effect there while the row is bound; a bound row has no automatic address. Freeing the row (removing the binding, releasing the reservation, taking the row out of a tag the reservation binds, deleting that tag) gives it its own onion address, published to whoever the grant names. For a grant to Anyone that is an opening, yet the plans returned no reach and needed no confirmation, and the port-based comparison of covered ports could not see it.

The purge of ADR 0057 had the same list twice: the daemon deleted the networks' data trees only when the install record listed them, the Debian postrm by the printed list.

## Decision

- After every operation of a batch the planner compares the rows bound to a reservation before and after. A grant that names a freed row (its own row, or a member of its tag) and lets its subject in on a Tor network afterwards is a change of reach: it is listed in that operation's `reach` and `detail`, sets `changes_reach`, and when it is a grant to Anyone the operation needs `confirm_open`. The comparison is per row, so a tag grant that was already live through its other members counts when a further member is freed.
- `remove_binding`, `release_reservation` and `remove_tag_member` carry `confirm_open` (also as `?confirm_open=true` on their DELETE routes, as for `DELETE /api/tags/{id}`, which gets the same check for the bindings that go with the tag, and in the CLI as `-y`). An operation without the flag that frees such a row is refused. Imports (`apply`) count as confirmed: the document states its Anyone grants.
- Other operations cannot free a row that a grant still names: renaming and reserving bind or keep rows; detaching or deleting a port group is refused while a binding, grant or tag member uses it; `move_app` moves bindings, grants and tag memberships together; `remove_grant` does not touch bindings.
- `uninstall --purge` deletes the `Tree` items of the purge list that lie strictly inside the state directory whether or not the install record lists them, in addition to the recorded owned directories. A symlink is unlinked, not followed.

## Consequences

- A release or an unbind that publishes a service to Anyone is previewed and confirmed like adding a grant.
- A batch is judged operation by operation: freeing a row and removing its grant in the same batch needs the confirmation unless the grant goes first.
- The daemon and the postrm purge the same trees; the record no longer decides it.
