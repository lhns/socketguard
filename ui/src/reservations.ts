// Pure helpers over reservations: the rows they serve, how they read in a list, their conflicts.
import type { App, GrantView, PortConflict, ReservationView, Scope, PortGroup, Tag } from "./api";
import { rangeLabel, sameScope, scopeKey, scopeLabel } from "./lib";

/** One row a reservation serves: an app with a scope, which a binding names itself or through a tag. */
export interface BoundRow {
  /** Unique in the reservation. */
  key: string;
  bindingId: string;
  appId: string;
  scope: Scope;
  /** The app's name and the row ("nginx · 443/tcp"). */
  label: string;
  /** Present when the row is there because a tag is bound. */
  viaTag?: Tag;
}

/** The rows a reservation serves: each app binding's row, each member row of a tag binding. A tag
 * without members is one entry with no app, so it can still be removed. */
export function boundRows(r: ReservationView, apps: App[], tags: Tag[], groups: PortGroup[]): BoundRow[] {
  const name = (id: string) => apps.find((a) => a.id === id)?.name ?? `app ${id.slice(0, 8)}`;
  return r.bindings.flatMap<BoundRow>((b) => {
    if (b.target.kind === "app") {
      const { app_id, scope } = b.target;
      return [{ key: `${b.id}`, bindingId: b.id, appId: app_id, scope, label: `${name(app_id)} · ${scopeLabel(scope, groups)}` }];
    }
    const tag = tags.find((t) => t.id === (b.target as { tag_id: string }).tag_id);
    if (!tag) return [];
    if (tag.members.length === 0) {
      return [{ key: b.id, bindingId: b.id, appId: "", scope: { kind: "all" }, label: `tag ${tag.label}`, viaTag: tag }];
    }
    return tag.members.map((m) => ({
      key: `${b.id}|${m.app_id}|${scopeKey(m.scope)}`,
      bindingId: b.id,
      appId: m.app_id,
      scope: m.scope,
      label: `${name(m.app_id)} · ${scopeLabel(m.scope, groups)}`,
      viaTag: tag,
    }));
  });
}

/** What a reservation serves, in a few words: `sshd 22/tcp, nginx 443/tcp` or `tag web`. */
export function servesText(r: ReservationView, apps: App[], tags: Tag[], groups: PortGroup[]): string {
  const name = (id: string) => apps.find((a) => a.id === id)?.name ?? id.slice(0, 8);
  const parts = r.bindings.flatMap((b) => {
    if (b.target.kind === "app") return [`${name(b.target.app_id)} ${scopeLabel(b.target.scope, groups)}`];
    const tag = tags.find((t) => t.id === (b.target as { tag_id: string }).tag_id);
    return [`tag ${tag?.label ?? (b.target as { tag_id: string }).tag_id.slice(0, 8)}`];
  });
  return parts.join(", ");
}

/** The grants on bound rows themselves (the app-row grants), not those on the reservation. */
export function rowGrants(rows: BoundRow[], grants: GrantView[]): GrantView[] {
  return grants.filter((g) => g.target.kind === "app" && rows.some((row) => row.appId === g.target.id && sameScope(row.scope, g.scope)));
}

/** The names of the apps whose bindings claim a conflict's ports. */
export function conflictApps(c: PortConflict, r: ReservationView, apps: App[], tags: Tag[]): string[] {
  const name = (id: string) => apps.find((a) => a.id === id)?.name ?? id.slice(0, 8);
  const ids = c.bindings.flatMap((bid) => {
    const b = r.bindings.find((x) => x.id === bid);
    if (!b) return [];
    if (b.target.kind === "app") return [b.target.app_id];
    return tags.find((t) => t.id === (b.target as { tag_id: string }).tag_id)?.members.map((m) => m.app_id) ?? [];
  });
  return [...new Set(ids.map(name))];
}

/** `443/tcp: nginx and caddy — served: nginx` or `— closed until one of them listens`. */
export function conflictText(c: PortConflict, r: ReservationView, apps: App[], tags: Tag[]): string {
  const who = conflictApps(c, r, apps, tags);
  const served = c.served_app ? apps.find((a) => a.id === c.served_app)?.name ?? c.served_app.slice(0, 8) : null;
  return `${rangeLabel(c.ports)}: ${who.join(" and ")} — ${served ? `served: ${served}` : "closed until one of them listens"}`;
}
