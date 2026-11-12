# ADR 0043: App Tags as Grant Targets

## Status

Accepted. Refines ADR 0027 and ADR 0041.

Amended below; read the amendments in order.

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

## Amendment (2026-11-10): schema v6, patterns apply to existing apps

- The tables arrived with schema **v6**, not v5: v5 was taken by the address family of ports (ADR 0044). The migration rebuilds `grants` with `target_kind`/`target_id` (no foreign key, so deleting an app or a tag deletes its grants explicitly).
- A pattern adds matching apps that already exist as well as new ones, when the tag is created and when its patterns change. Otherwise a pattern would do nothing visible until the next app starts. Apps removed by hand stay out; nobody leaves a tag because a pattern went away.
- Export and apply (`/api/export`, `/api/apply`) do not carry tags or grants on tags yet; they leave them as they are.

## Amendment (2026-11-10): joining a tag that is open to anyone needs confirmation

Putting an app into a tag that has a grant to Anyone opens the app, but only granting to Anyone asked for confirmation. Adding a member by hand to such a tag, and creating or changing a tag so that its patterns add existing apps, now need `confirm_open` like that grant does (409 otherwise). Apps that join through a pattern when they are first seen are not confirmed: that is the tag's standing policy.

## Amendment (2026-11-11): members are rows; a tag grant can be limited to a port group

Follows ADR 0047. A tag member is a row of an app: "All ports", one port, or an attached port group. Tagging an app means tagging its "All ports", and patterns add that row. A tag grant may be limited to a port or to a port group; it covers, per member, what the member's row and that limit have in common. Attaching a port group to an app whose "All ports" is a member of a granted tag counts as opening and needs confirmation when the tag is open to Anyone.
