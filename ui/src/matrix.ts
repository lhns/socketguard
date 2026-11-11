// The logic of the access overview, free of React: what each cell shows. Rows are tags, apps
// and the rows of an app (a port or an attached port group); columns are groups, peers, Anyone and "Everyone on <network>". Nothing is
// edited here; edits are made in the inspector.
import type {
  App, GrantView, Network, Peer, PeerGroup, PortRef, ReservationView, Scope, SocketGroup, Subject, Tag, Target,
} from "./api";
import { coversScope, sameSubject } from "./access";
import { ALL_SCOPE, portLabel, sameScope, scopeKey, scopeOfPort } from "./lib";

export interface Row {
  key: string;
  /** "port" is a row inside an app: one port or one attached port group. */
  kind: "tag" | "app" | "port";
  target: Target;
  /** Which rows of the app this row is; All ports for tag and app rows. */
  scope: Scope;
  /** The port of a port row; null for All ports and for a port group. */
  port: PortRef | null;
  label: string;
  /** The app this row belongs to (app and port rows). */
  app?: App;
}

export interface Col {
  key: string;
  kind: "group" | "peer" | "anyone" | "segment";
  subject: Subject;
  /** For a segment column: the network it is about. */
  networkId: string | null;
  label: string;
}

export type CellState = "none" | "granted" | "partial" | "inherited";

export interface Cell {
  state: CellState;
  /** The direct grants behind a granted or partial cell. */
  grants: GrantView[];
  /** Networks a partial cell is granted on. */
  networkIds: string[];
  /** Granted only through a grant that spans all networks while a network is selected. */
  allNetworks: boolean;
  /** Where an inherited cell gets its access from. */
  origin?: { kind: "tag" | "group" | "app" | "reservation"; id: string; label: string };
}

export interface Ctx {
  grants: GrantView[];
  tags: Tag[];
  peers: Peer[];
  groups: PeerGroup[];
  networks: Network[];
  /** Selected network id, or null for all networks. */
  scope: string | null;
  /** Their bindings make a grant on a reservation reach the bound rows. */
  reservations?: Pick<ReservationView, "id" | "label" | "bindings">[];
}

export const rowKey = (target: Target, port: PortRef | null) =>
  `${target.kind}:${target.id}${port ? `:${portLabel(port)}` : ""}`;

const subRowKey = (target: Target, scope: Scope) => `${target.kind}:${target.id}${scope.kind === "all" ? "" : `:${scopeKey(scope)}`}`;

/** Segment columns: one per LAN network (VLANs are LAN networks) that takes grants. */
export const segmentNetworks = (networks: Network[]) =>
  networks.filter((n) => n.grants_apply && n.kind === "lan");

export function buildColumns(ctx: Pick<Ctx, "peers" | "groups" | "networks" | "scope">): Col[] {
  const cols: Col[] = [];
  for (const g of ctx.groups) {
    cols.push({ key: `group:${g.id}`, kind: "group", subject: { kind: "group", id: g.id }, networkId: null, label: `group ${g.label}` });
  }
  for (const p of ctx.peers) {
    cols.push({ key: `peer:${p.id}`, kind: "peer", subject: { kind: "peer", id: p.id }, networkId: null, label: p.label });
  }
  cols.push({ key: "anyone", kind: "anyone", subject: { kind: "anyone" }, networkId: null, label: "Anyone" });
  if (ctx.scope === null) {
    for (const n of segmentNetworks(ctx.networks)) {
      cols.push({ key: `segment:${n.id}`, kind: "segment", subject: { kind: "anyone" }, networkId: n.id, label: `Everyone on ${n.name}` });
    }
  }
  return cols;
}

/** The port groups attached to an app. */
export const groupsOf = (appId: string, socketGroups: SocketGroup[]) => socketGroups.filter((g) => g.apps.includes(appId));

export function buildRows(apps: App[], tags: Tag[], expanded: Set<string>, socketGroups: SocketGroup[] = []): Row[] {
  const rows: Row[] = tags.map((t) => ({
    key: rowKey({ kind: "tag", id: t.id }, null),
    kind: "tag",
    target: { kind: "tag", id: t.id },
    scope: ALL_SCOPE,
    port: null,
    label: `tag ${t.label}`,
  }));
  for (const a of apps) {
    const target: Target = { kind: "app", id: a.id };
    rows.push({ key: rowKey(target, null), kind: "app", target, scope: ALL_SCOPE, port: null, label: a.name, app: a });
    if (expanded.has(a.id)) {
      for (const p of a.ports) {
        const port = { port: p.port, proto: p.proto };
        rows.push({ key: rowKey(target, port), kind: "port", target, scope: scopeOfPort(port), port, label: portLabel(p), app: a });
      }
      for (const g of groupsOf(a.id, socketGroups)) {
        const scope: Scope = { kind: "group", id: g.id };
        rows.push({ key: subRowKey(target, scope), kind: "port", target, scope, port: null, label: g.label, app: a });
      }
    }
  }
  return rows;
}

/** Does one of the bindings serve this row of the app? A binding of All ports serves every row. */
export function bindsRow(bindings: ReservationView["bindings"], tags: Tag[], appId: string, row: Scope): boolean {
  return bindings.some((b) =>
    b.target.kind === "app"
      ? b.target.app_id === appId && coversScope(b.target.scope, row)
      : (tags.find((t) => t.id === (b.target as { tag_id: string }).tag_id)?.members ?? []).some((m) => m.app_id === appId && coversScope(m.scope, row)),
  );
}

const sameTarget = (a: Target, b: Target) => a.kind === b.kind && a.id === b.id;

/** Does grant network `n` count for this column in the selected scope? */
function networkCounts(g: GrantView, col: Col, ctx: Ctx): boolean {
  if (col.kind === "segment") return g.network_id === col.networkId;
  if (ctx.scope !== null) return g.network_id === null || g.network_id === ctx.scope;
  // The Anyone column leaves the grants a segment column shows to that column.
  if (col.kind === "anyone" && g.network_id !== null) {
    return !segmentNetworks(ctx.networks).some((n) => n.id === g.network_id);
  }
  return true;
}

export function cellOf(row: Row, col: Col, ctx: Ctx): Cell {
  const direct = ctx.grants.filter(
    (g) => sameTarget(g.target, row.target) && sameScope(g.scope, row.scope) && sameSubject(g.subject, col.subject) && networkCounts(g, col, ctx),
  );
  if (direct.length > 0) {
    const everywhere = direct.some((g) => g.network_id === null);
    if (ctx.scope !== null || col.kind === "segment" || everywhere) {
      return {
        state: "granted",
        grants: direct,
        networkIds: [],
        allNetworks: ctx.scope !== null && !direct.some((g) => g.network_id === ctx.scope),
      };
    }
    return { state: "partial", grants: direct, networkIds: direct.map((g) => g.network_id as string), allNetworks: false };
  }
  const origin = inheritedFrom(row, col, ctx);
  if (origin) return { state: "inherited", grants: [], networkIds: [], allNetworks: false, origin };
  return { state: "none", grants: [], networkIds: [], allNetworks: false };
}

function inheritedFrom(row: Row, col: Col, ctx: Ctx): Cell["origin"] | undefined {
  const peer = col.kind === "peer" ? ctx.peers.find((p) => col.subject.kind === "peer" && p.id === col.subject.id) : undefined;
  const subjectMatches = (s: Subject) => sameSubject(s, col.subject);
  const viaGroup = (s: Subject) => s.kind === "group" && peer !== undefined && peer.groups.includes(s.id);
  const groupLabel = (id: string) => ctx.groups.find((g) => g.id === id)?.label ?? id.slice(0, 8);
  const tagLabel = (id: string) => ctx.tags.find((t) => t.id === id)?.label ?? id.slice(0, 8);

  for (const g of ctx.grants) {
    if (!networkCounts(g, col, ctx)) continue;
    const bySubject = subjectMatches(g.subject);
    const byGroup = viaGroup(g.subject);
    if (!bySubject && !byGroup) continue;
    const groupOrigin = byGroup && g.subject.kind === "group" ? { kind: "group" as const, id: g.subject.id, label: groupLabel(g.subject.id) } : undefined;

    // The same row, reached through a group.
    if (sameTarget(g.target, row.target) && sameScope(g.scope, row.scope) && groupOrigin) return groupOrigin;
    if (row.kind === "tag") continue;
    const appId = row.target.id;
    // A grant on All ports covers its ports and port groups.
    if (row.kind === "port" && g.target.kind === "app" && g.target.id === appId && g.scope.kind === "all") {
      return groupOrigin ?? { kind: "app", id: appId, label: "All ports" };
    }
    // A grant on a reservation that has this row bound (directly or through a tag).
    if (g.target.kind === "reservation") {
      const res = ctx.reservations?.find((r) => r.id === (g.target as { id: string }).id);
      if (res && bindsRow(res.bindings, ctx.tags, appId, row.scope)) {
        return groupOrigin ? { ...groupOrigin, label: `${groupOrigin.label} on reservation ${res.label}` } : { kind: "reservation", id: res.id, label: res.label };
      }
    }
    // A grant on a tag the app (or this port of it) belongs to.
    if (g.target.kind === "tag") {
      const tag = ctx.tags.find((t) => t.id === (g.target as { id: string }).id);
      const member = tag?.members.find(
        (m) => m.app_id === appId && (row.scope.kind === "all" ? m.scope.kind === "all" : coversScope(m.scope, row.scope)),
      );
      if (tag && member && (row.scope.kind === "all" ? g.scope.kind === "all" : coversScope(g.scope, row.scope))) {
        return groupOrigin ? { ...groupOrigin, label: `${groupOrigin.label} on tag ${tagLabel(tag.id)}` } : { kind: "tag", id: tag.id, label: tag.label };
      }
    }
  }
  return undefined;
}
