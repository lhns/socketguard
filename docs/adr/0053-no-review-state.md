# ADR 0053: New Apps Are Just Closed; There Is No Review State

## Status

Accepted. Removes the reviewed flag of ADR 0027's app record and the review actions that ADR 0042 brought into the UI.

## Date

2026-11-12

## Context

A newly detected app was "pending" until the user marked it reviewed, with a badge, a counter in the navigation, a "pending only" filter and a "keep closed" action. The state changed nothing about enforcement: an app is closed until something is granted, pending or not. In use it was one more thing to click away for every program a host happens to run, and it suggested a decision was needed when the safe default already applied.

## Decision

- An app has no review state. A new app appears in the list, closed, like every other app without grants.
- The reviewed flag, the review route and batch operation, the CLI's review command and `--pending` filter, the pending badge, counter, filter and the "keep closed" and "mark reviewed" actions are removed.
- That a new app was detected is still recorded in the activity log.
- The list shows what matters instead: whether an app is closed or who can reach it.
- The database column stays unused until the next schema change removes it; exports ignore a `reviewed` field in old documents.

## Consequences

- Nothing asks for attention when a program starts listening. Someone who wants to know about new apps reads the activity log.
- The hint for an app that looks like a moved one (ADR 0050) no longer hangs on "pending": it shows on any app that has no grants and matches the rule.
