# ADR 0063: Onion Services from Before the Ledger Are Not Adopted

## Status

Accepted. Refines ADR 0055 (no compatibility before the first release); removes the adoption that the amendment of ADR 0039 introduced and ADR 0040 repeated.

## Date

2026-11-13

## Context

ADR 0039 and ADR 0040 had the daemon add the service id of every stored onion key to the owned set at each start, so that services created before the ledger existed were swept once their address was gone. ADR 0055 says there is no compatibility with states from before the first release, and no release has had a database without the ledger.

## Decision

`ledger::adopt_stored_keys` and its call at startup are removed, with the test that covered it. A service is owned when it is recorded in the ledger before it is published (`add_owned`), as ADR 0040 describes for every service the daemon creates.

## Consequences

- One less write and one less thing to explain at start. A database from before the ledger would keep any onion service it left running in Tor until Tor restarts; no such database exists.
- The retiring of addresses that predate the owned-address table (`disable`, ADR 0026) is a different adoption and stays.
