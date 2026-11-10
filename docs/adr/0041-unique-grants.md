# ADR 0041: Grants Are Unique in the Database

## Status

Accepted. Refines ADR 0027.

## Date

2026-11-10

## Context

`create_grant` checked for an identical grant and then inserted, with only a read lock held. Two identical requests racing past the check stored the grant twice, and every rule it produces twice. Peers, groups and credentials were already safe: their labels and `(kind, value)` pairs are `UNIQUE`, and the engine maps that violation to a conflict.

## Decision

Schema v4 adds a unique index on `grants` over `(app_id, port, proto, network_id, subject_kind, subject_id)`, with `COALESCE` folding the nullable columns, because SQLite treats NULLs as distinct in a plain unique index. The migration deletes existing duplicates first and keeps the oldest of each. The engine maps the violation to `EngineError::Conflict` (HTTP 409), the same answer the pre-check gives; the pre-check stays for its clearer error path.

## Consequences

- A grant exists once, whatever the timing of the requests. The constraint, not the engine, is the guarantee.
- Upgrading drops duplicate grants. They produced identical rules, so no access changes.
- A database written by this version cannot be opened by a daemon that knows only schema v3 (it refuses a newer schema, as before).
