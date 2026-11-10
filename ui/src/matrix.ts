// The logic of the access overview, free of React: what each cell shows. Rows are tags, apps
// and app ports; columns are groups, peers, Anyone and "Everyone on <network>". Nothing is
// edited here; edits are made in the inspector.
import type {
  App, GrantView, Network, Peer, PeerGroup, PortRef, Subject, Tag, Target,
} from "./api";
import { covers, sameSubject } from "./access";
import { portLabel, samePort } from "./lib";

export interface Row {
  key: string;
  kind: "tag" | "app" | "port";
  target: Target;
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
  origin?: { kind: "tag" | "group" | "app"; id: string; label: string };
}

export interface Ctx {
  grants: GrantView[];
  tags: Tag[];
  peers: Peer[];
  groups: PeerGroup[];
  networks: Network[];
  /** Selected network id, or null for all networks. */
  scope: string | null;
}

export const rowKey = (target: Target, port: PortRef | null) =>
  `${target.kind}:${target.id}${port ? `:${portLabel(port)}` : ""}`;

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

export function buildRows(apps: App[], tags: Tag[], expanded: Set<string>): Row[] {
  const rows: Row[] = tags.map((t) => ({
    key: rowKey({ kind: "tag", id: t.id }, null),
    kind: "tag",
    target: { kind: "tag", id: t.id },
    port: null,
    label: `tag ${t.label}`,
  }));
  for (const a of apps) {
    const target: Target = { kind: "app", id: a.id };
    rows.push({ key: rowKey(target, null), kind: "app", target, port: null, label: a.name, app: a });
    if (expanded.has(a.id)) {
      for (const p of a.ports) {
        const port = { port: p.port, proto: p.proto };
        rows.push({ key: rowKey(target, port), kind: "port", target, port, label: portLabel(p), app: a });
      }
    }
  }
  return rows;
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
    (g) => sameTarget(g.target, row.target) && samePort(g.port, row.port) && sameSubject(g.subject, col.subject) && networkCounts(g, col, ctx),
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
    if (sameTarget(g.target, row.target) && samePort(g.port, row.port) && groupOrigin) return groupOrigin;
    if (row.kind === "tag") continue;
    const appId = row.target.id;
    // A grant on the whole app covers its ports.
    if (row.kind === "port" && g.target.kind === "app" && g.target.id === appId && g.port === null) {
      return groupOrigin ?? { kind: "app", id: appId, label: "the whole app" };
    }
    // A grant on a tag the app (or this port of it) belongs to.
    if (g.target.kind === "tag") {
      const tag = ctx.tags.find((t) => t.id === (g.target as { id: string }).id);
      const member = tag?.members.find(
        (m) => m.app_id === appId && (row.port === null ? m.port === null : m.port === null || samePort(m.port, row.port)),
      );
      if (tag && member && (row.port === null ? g.port === null : covers(g.port, row.port))) {
        return groupOrigin ? { ...groupOrigin, label: `${groupOrigin.label} on tag ${tagLabel(tag.id)}` } : { kind: "tag", id: tag.id, label: tag.label };
      }
    }
  }
  return undefined;
}
