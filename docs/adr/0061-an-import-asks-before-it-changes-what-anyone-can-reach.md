# ADR 0061: An Import Asks Before It Changes What Anyone Can Reach

## Status

Accepted. Supersedes in part ADR 0058 (the sentence "Imports (`apply`) count as confirmed"). Refines ADR 0047.

## Date

2026-11-13

## Context

`POST /api/apply` passed `confirm_open: true` to every engine call: the document states its Anyone grants, so it counted as confirmed. That held for a grant the document names. It does not hold for what an import does to grants it does not name: a port group that grows or is attached widens an existing Anyone grant, a binding that joins a reservation, or one that goes (ADR 0058), changes what that grant reaches. The import also applies one change at a time and is not atomic, so a refusal midway would leave the first half applied.

## Decision

- `ApplyRequest` has `confirm_open` (default false). Every engine call of the import passes it; the engine stays the authority on what needs it.
- Before anything is applied, `apply` decides `confirm_open_required` from the plan with a coarse rule: a grant to Anyone exists now (on any target: app, tag, reserved address) or in the document, AND the plan has a change that the import carries out through a call that takes the flag (new or changed port groups with new ports or apps, grants, reservations, bindings added or removed, reservations released). Without `confirm_open` an import that requires it is refused with `confirmation_required`, nothing applied. The rule is a superset of the engine's refusals: the engine asks only when a grant to Anyone exists, and during the import the grants are a subset of the current ones plus the document's.
- A dry run never refuses; it returns the preview with `confirm_open_required`. The per-change `opens_to_anyone` marks stay as they were.
- The CLI asks "Some of these changes affect what Anyone can reach. Apply them?" (`-y` confirms, as elsewhere); the UI asks the same in the import review.

## Consequences

- An import can no longer open anything to Anyone unasked, including through grants it does not mention.
- The rule is coarse: on a host with an Anyone grant, any import that creates a grant, binding or port group asks, even when nothing ends up opening. An import that only touches peers, groups, credentials, settings and deletions of grants and port groups asks for nothing.
- `has_confirming_calls` in `apply.rs` destructures the plan exhaustively, so a new kind of change has to be classified next to the calls.
