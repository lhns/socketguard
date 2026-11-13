# ADR 0062: Changes Are Planned and Written One at a Time, Against One Snapshot

## Status

Accepted. Refines ADR 0045 (batch changes) and the lock order on `AppState`.

## Date

2026-11-13

## Context

A change reads the stored state, decides (exists, reaches Anyone, needs confirmation, would lock the host out) and writes. Two things let it decide on a state that is not the one it writes to:

- `Catalog::load` made eight independent reads on the pool and `gather_snapshot` two more; a commit landing between them gave a catalog that never existed.
- Nothing serialized changes: the API handlers take the engine's read lock, which is shared. Two concurrent changes could each plan against the same state, for instance a grant to Anyone on a tag while another request adds an app to the tag.

## Decision

- The catalog (`Catalog::load`) and the snapshot (`gather_snapshot`: catalog, whole-host protection, owned addresses) are read in one transaction on one connection (`Database::read_catalog`, `read_snapshot`). SQLite's WAL gives the transaction the state of its first read. The `list_*`/`load_*` queries are shared with the single-resource reads through a connection parameter.
- `Engine::change_lock` (a `tokio::sync::Mutex`) is taken by every change from loading the state it decides on until its database write has committed, and released before the ruleset is applied (`apply_and_ensure`, `commit`). It sits after the engine RwLock and before `poll_lock` in the lock order; nothing holding `poll_lock` or a later lock takes it. It is not held across firewall or interface changes or network calls.
- It is taken by: `apply_changes` (so every operation that goes through `run_one`: tag members, reservations, bindings, `move_app`), `create_peer`, `update_peer_label`, `delete_peer`, `add_credential`, `remove_credential`, `create_group`, `rename_group`, `delete_group`, `set_group_members`, `create_grant`, `delete_grant`, `create_tag`, `update_tag`, `delete_tag`, `create/update/delete/attach/detach_port_group`, `generate_tor_key`, `set_protect_host`. The import calls these one at a time, each taking the lock itself; no locked method calls another.
- Not taken: the reconcile pass and discovery (they hold `poll_lock` and `apps_lock`; a pattern that adds members later is the accepted case of ADR 0059); `delete_app` (it decides nothing about reach and its network calls run before the write); the network add, remove and settings changes (`add_network`, `remove_network`, `set_peers`, `set_bridges`, `set_lan_discovery`), which take the engine's write lock and so exclude every other change.
- `set_protect_host` holds the lock across its lockout check, which lists sockets and interface addresses (read only), so the grants it checked are the ones that stand when it writes.

## Consequences

- A change sees one consistent state and no other change commits between its read and its write. Changes run one after the other, in the order they get the lock.
- Reads are now serial within a snapshot (about 10 to 25 percent slower in a debug build on the perf harness, noise included).
- The outcome of two racing changes was already a serial one (a join that raced a grant ended as "joined first" or "refused"); the lock makes the decision and the commit one step, which is what the confirmation relies on.

## Amendment (2026-11-13)

`delete_app` now takes the lock. It was left out because it decides nothing about reach and its network calls ran before the write. Both reasons are gone: it now retires its addresses in the transaction that deletes the app (as a batch does) and removes the locators after the commit, so nothing it holds the lock across is a network call. It takes the lock before `apps_lock`, which keeps the order. The two other places that retired an address before a separate write now do both in one transaction too, without the lock: the removal of a network (it holds the engine's write lock) and the re-homing of addresses after a prefix change (it runs under `poll_lock`).
