# ADR 0059: Patterns on a Tag That Anyone Can Reach Are Confirmed

## Status

Accepted. Refines ADR 0043 (tags and their patterns) and ADR 0047 (confirmation of changes of reach).

## Date

2026-11-13

## Context

A tag's patterns put every app whose name or path matches into the tag, now and whenever one is discovered later. When Anyone has a grant on the tag (or on a reservation that binds it), a matching app is opened to Anyone. Setting patterns asked for confirmation only when an app matched today; a pattern that matched nothing yet needed none, and an app found later was opened without a word.

Opening future apps to Anyone by a pattern is a valid use. It must be said when it is set up.

## Decision

- Setting or changing the patterns of a tag whose grants (on the tag, or on a reservation that binds it) include one to Anyone needs `confirm_open` whether or not an app matches today. Clearing the patterns, or saving the same ones, needs none.
- Adding a grant to Anyone on a tag, or on a reservation that binds a tag, that has patterns lists in its preview (the `note` of its reach) that apps matching the patterns later will be open to Anyone without asking again. The UI dialog and the CLI prompt for both directions say the same sentence.
- When discovery puts a new app into such a tag, the activity log records that the app was opened to Anyone through the tag's pattern.

## Consequences

- A tag with patterns that Anyone can reach is a standing opening, and every way into that state asks first.
- A pattern edit on an open tag asks even when it changes nothing today.
