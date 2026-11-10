# ADR 0043: App Tags as Grant Targets

## Status

Accepted. Refines ADR 0027 and ADR 0041.

## Date

2026-11-10

## Context

Peers can be grouped, apps cannot. The old ACL and socket groups (ADRs 0018–0020) gave one rule set to many services, including ones started later. The redesign dropped that, so a standing policy such as "the team can reach every dev service" needed one grant per app, repeated for every new app.

## Decision

- **Tags:** a tag has a unique label and members. A member is an app or one port of an app (`tag_members(tag_id, app_id, port NULL, proto NULL)`), the same shape as a grant target.
- **Grant target:** `App(app_id)` or `Tag(tag_id)`. `port` and `network_id` stay optional.
- **What a tag grant covers:** each member, narrowed to the member's port if it has one, and to the grant's port if it has one. When both are set and differ, it covers nothing on that member.
- **Match patterns:** a tag may have process name or exe path globs, using the process filter's matcher.
  - Discovery adds matching new apps, so the tag's grants cover them from the first reconcile.
  - Manual membership is kept as is. Removing a matched app from a tag is remembered as an exclusion.
- **Reach and the ruleset** expand tag grants per address. Each effective access carries its origin (direct, tag or group) for display.
- **Schema v5** adds `tags`, `tag_members`, `tag_exclusions` and the grant target columns. The unique index of ADR 0041 covers the target kind and id.

## Consequences

- Bulk policies are data, not repetition, and they survive new apps.
- Effective access is no longer one lookup, so frontends must show where it comes from.
- Revoking a tag grant can remove access from many apps. The dry-run preview of ADR 0045 shows that before it happens.
