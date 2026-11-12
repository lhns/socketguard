# ADR 0049: The Reconcile Pass Runs Under the Engine's Read Lock

## Status

Accepted.

## Date

2026-11-11

## Context

The reconcile pass held the engine's write lock from the socket scan to the last address it put on an interface. API handlers need the read lock, and the lock is fair, so every request waited behind a pass. On Windows adding one address to an interface takes 0.3 to 1 s; the first pass after granting access, or after a start, adds one address per app, so the UI could not load app details for tens of seconds.

The pass also wrote to SQLite once per app and per port on every poll, although nothing had changed, and built the full address model several times.

## Decision

- `Engine::reconcile` takes `&self` and runs under the read lock. Only adding or removing a network (which changes the set of backends) keeps the write lock.
- A `poll_lock` serialises passes and is also taken by `disable` and `enable`, so a pass never puts addresses back while they are being taken away (the exclusion the write lock gave).
- An `apps_lock` covers the pass's read-modify-write of apps and ports and the deletion of an app, so a pass never writes ports for an app that was just forgotten.
- Mutations already ran under the read lock and side by side; their ordering rests on `alloc_lock` and `firewall_lock` as before.
- Interface calls run on the blocking pool, up to four at a time. An address is still recorded as owned, and the ruleset that denies it applied, before it is added.
- A poll writes only what changed: one transaction for the apps and ports that differ from the stored state, and a refresh of `last_seen` at most every five minutes for an unchanged app. Settings (the onion ledger saves on every pass) are written only when the value changes. The database file is opened in WAL mode (sqlx opens it in the rollback-journal mode, where a commit locks readers out) with a pool of five connections, so reads do not wait for a commit.

## Consequences

- Queries are no longer held up by a pass; a request sees the state as of its own reads.
- `last_seen` of an app or port can be up to five minutes old.
- A pass and a mutation can interleave their steps. Each step stays safe on its own (an address that is on an interface is owned and denied), and the next pass settles the rest.
