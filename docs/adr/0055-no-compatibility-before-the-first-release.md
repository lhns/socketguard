# ADR 0055: No Compatibility With States From Before the First Release

## Status

Accepted. Removes the migration and compatibility parts of earlier ADRs (0005, 0027, 0043, 0047, 0050, 0053); their decisions about the current model stand.

## Date

2026-11-12

## Context

SocketGuard has never been released and has no users. Its code nevertheless carries ten database migrations with their tests, a classification pass for addresses from older schemas, a one-time move of state out of the working directory, serde aliases and ignored fields for old export and config documents, legacy entries in the install record, and cleanup of a firewall table from an early layout. All of it serves databases and documents that only existed on development machines.

## Decision

- The database has one schema, created fresh, at version 1. There are no migrations and no migration tests until a release exists. A database written by an earlier development build is refused at start with a message that names the file and says to remove it.
- Removed: the pre-v1 archive, the classification of legacy addresses, the one-time move of state from the working directory, aliases and ignored fields for old documents (`socket_groups`, `address_mode`, `reviewed`, the single `backend` key), legacy entries of the install record, and cleanup of the old `ip6` nftables table.
- From the first release on, a change to the schema or to a document format comes with a migration or a compatibility rule, and this ADR no longer applies to it.

## Consequences

- A development machine with an old database or config starts over.
- Less code and fewer tests to carry; the schema is readable in one place.
- The first release fixes the formats that then have to be kept compatible.
