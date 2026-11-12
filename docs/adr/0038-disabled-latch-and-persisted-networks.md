# ADR 0038: Disabled Latch and Persisted Networks

## Status

Accepted. Refines ADR 0026 and ADR 0032.

## Date

2026-11-09

## Context

`disable` removed the rules and addresses, but the running daemon put them back on its next reconcile pass, and a restarted daemon re-applied them. The only safe way to stay disabled was to stop the daemon first. Networks added through the API lived only in the running daemon's memory and were gone after a restart, so the CLI could not set up a host that survives a reboot.

## Decision

- **Latch:** `disable` (API, or `socketguard-daemon --disable`) first stores the setting `disabled=true` in the database, then removes rules and addresses. While it is set, no code path applies a ruleset or adds an address (reconcile, startup, API mutations). Apps are still tracked. `POST /api/enable` clears it and re-applies. `GET /api/status` reports it as `disabled`.
- **Networks:** `POST /api/networks` and `DELETE /api/networks/{id}` write the `backends` list to the config file the daemon loaded (`SOCKETGUARD_CONFIG`, else `socketguard.json`), creating it if missing. The write is a temp file plus rename and keeps the file's other keys. A file that is not a JSON object is left alone; the change stays live and a warning is logged.

## Consequences

- Disabling is one command and stays in force across passes and restarts; the user must run `enable` to be protected again. `status` shows it prominently.
- The database is the source of truth for the latch, not the config file, so `--disable` works with the daemon stopped.
- The config file is rewritten with JSON formatting, so comments and key order are not kept (the file is JSON; it has no comments).
- A failed config write does not fail the API call: the network works until the next restart, and the log says why.

## Amendment: second security review

- **Fresh database next to an existing ruleset.** A database created by this start (schema v0 on migrate; the `fresh_db` setting, cleared by the startup check or the first successful apply) used to apply an empty ruleset on startup, deleting the kernel table while old addresses stayed on their interfaces. Now `startup_reconcile` asks `Firewall::verify`; if a SocketGuard table or filters exist, it sets the persisted `unadopted` setting and logs an error. While set, nothing is applied or added (same gates as `disabled`). `enable` clears it and applies the new state, replacing the old ruleset; `disable` removes the old ruleset and clears it. `GET /api/status` reports `unadopted`; the CLI `status` and the UI banner show it. No schema change.
- **`disable` keeps the rules while an address remains.** `disable_all` removes the firewall rules only after every owned address is confirmed removed. Otherwise it returns an error listing the addresses, keeps the rules (the addresses stay denied) and leaves the latch set; the disabled daemon's sweep retries and removes the rules once the last address is gone.
