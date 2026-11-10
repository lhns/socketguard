// Pure helpers over grants, tags and groups shared by the pages, the lists and the overview.
import type {
  App, EffectiveAccess, GrantReach, GrantView, Network, Peer, PeerGroup, PortRef, Subject, Tag, Target,
} from "./api";
import { portLabel, samePort, subjectLabel, targetLabel } from "./lib";
import type { Focus } from "./nav";

/** The tags an app belongs to, with the port when the membership is for one port only. */
export function membershipsOf(appId: string, tags: Tag[]): { tag: Tag; port: PortRef | null }[] {
  return tags.flatMap((tag) =>
    tag.members.filter((m) => m.app_id === appId).map((m) => ({ tag, port: m.port })),
  );
}

export const sameSubject = (a: Subject, b: Subject) =>
  a.kind === b.kind && (a.kind === "anyone" || (b.kind !== "anyone" && a.id === b.id));

/** How an app is reachable, for the list: grants on the app, grants on its tags, and whether any
 * of them opens it to Anyone. */
export function accessSummary(appId: string, grants: GrantView[], tags: Tag[]) {
  const tagIds = new Set(membershipsOf(appId, tags).map((m) => m.tag.id));
  const mine = grants.filter(
    (g) => (g.target.kind === "app" && g.target.id === appId) || (g.target.kind === "tag" && tagIds.has(g.target.id)),
  );
  return {
    direct: mine.filter((g) => g.target.kind === "app").length,
    viaTag: mine.filter((g) => g.target.kind === "tag").length,
    open: mine.some((g) => g.subject.kind === "anyone" && g.network_id === null),
    segment: mine.some((g) => g.subject.kind === "anyone" && g.network_id !== null),
  };
}

/** Does a grant on `grantPort` cover `port` (null = the whole app)? A port-specific grant does
 * not cover the whole app. */
export const covers = (grantPort: PortRef | null, port: PortRef | null) =>
  grantPort === null || (port !== null && samePort(grantPort, port));

// ─── Access, as the lists show it ───────────────────────────────────────────

/** What names things in an access list. */
export interface NameCtx {
  apps: App[];
  tags: Tag[];
  peers: Peer[];
  groups: PeerGroup[];
  networks: Network[];
}

export type EntryOrigin =
  | { kind: "direct" }
  | { kind: "tag"; id: string; label: string }
  | { kind: "group"; id: string; label: string };

/** One access: who or what, on which port and network, how well identified, and where it comes
 * from. The same shape serves "who can reach this" and "what can this reach". */
export interface AccessEntry {
  key: string;
  /** Groups the same access across several selected things. */
  ident: string;
  name: string;
  /** Where the name leads. */
  link?: { page: "apps" | "peers"; focus: Focus };
  subject?: Subject;
  port: PortRef | null;
  networkId: string | null;
  reach: GrantReach[];
  origin: EntryOrigin;
  /** The grants that a Revoke removes (none for access that comes through a tag or a group). */
  grants: GrantView[];
  /** With several selected things: how many of them have this access. */
  have?: number;
  of?: number;
}

/** "Anyone", "Everyone on LAN", a peer, or "group x". */
export function subjectName(s: Subject, networkId: string | null, ctx: Pick<NameCtx, "peers" | "groups" | "networks">): string {
  if (s.kind === "anyone" && networkId) {
    return `Everyone on ${ctx.networks.find((n) => n.id === networkId)?.name ?? networkId}`;
  }
  return subjectLabel(s, ctx.peers, ctx.groups);
}

const subjectKey = (s: Subject) => (s.kind === "anyone" ? "anyone" : `${s.kind}:${s.id}`);
const portKey = (p: PortRef | null) => (p ? portLabel(p) : "*");

const subjectLink = (s: Subject): AccessEntry["link"] =>
  s.kind === "peer" ? { page: "peers", focus: { peerId: s.id } } : s.kind === "group" ? { page: "peers", focus: { groupId: s.id } } : undefined;

const targetLink = (t: Target): NonNullable<AccessEntry["link"]> =>
  t.kind === "app" ? { page: "apps", focus: { appId: t.id } } : { page: "apps", focus: { tagId: t.id } };

/** Whole-app access first, then what only some ports have, each by name. */
export const sortEntries = (entries: AccessEntry[]) =>
  [...entries].sort(
    (a, b) => Number(a.port !== null) - Number(b.port !== null) || a.name.localeCompare(b.name) || portKey(a.port).localeCompare(portKey(b.port)),
  );

/** Direct grants as entries: `side` is what the entry names (the subject, for "who can reach this"). */
export function grantEntries(grants: GrantView[], side: "subject" | "target", ctx: NameCtx): AccessEntry[] {
  return grants.map((g) => {
    const name = side === "subject" ? subjectName(g.subject, g.network_id, ctx) : targetLabel(g.target, ctx.apps, ctx.tags);
    const who = side === "subject" ? subjectKey(g.subject) : `${g.target.kind}:${g.target.id}`;
    return {
      key: g.id,
      ident: `${who}|${portKey(g.port)}|${g.network_id ?? "*"}|direct`,
      name,
      link: side === "subject" ? subjectLink(g.subject) : targetLink(g.target),
      subject: g.subject,
      port: g.port,
      networkId: g.network_id,
      reach: g.reach,
      origin: { kind: "direct" },
      grants: [g],
    };
  });
}

/** Everything that lets someone reach one app: its own grants and the grants on its tags, each
 * once, whole-app access first. A grant on the app is revocable here, whoever it names. */
export function appEntries(access: EffectiveAccess[], grants: GrantView[], ctx: NameCtx): AccessEntry[] {
  const seen = new Set<string>();
  const out: AccessEntry[] = [];
  for (const a of access) {
    const key = `${a.grant_id}|${portKey(a.port)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const grant = grants.find((g) => g.id === a.grant_id);
    const origin: EntryOrigin =
      a.origin.kind === "tag"
        ? { kind: "tag", id: a.origin.tag_id, label: ctx.tags.find((t) => t.id === (a.origin as { tag_id: string }).tag_id)?.label ?? a.origin.tag_id.slice(0, 8) }
        : { kind: "direct" };
    out.push({
      key,
      ident: `${subjectKey(a.subject)}|${portKey(a.port)}|${a.network_id ?? "*"}|${origin.kind === "tag" ? origin.id : "direct"}`,
      name: subjectName(a.subject, a.network_id, ctx),
      link: subjectLink(a.subject),
      subject: a.subject,
      port: a.port,
      networkId: a.network_id,
      reach: grant?.reach ?? [],
      origin,
      grants: origin.kind === "direct" && grant ? [grant] : [],
    });
  }
  return sortEntries(out);
}

/** What a subject can reach: the grants that name it, and for a peer the grants of its groups. */
export function subjectEntries(
  subject: Subject, networkId: string | null, grants: GrantView[], ctx: NameCtx,
): AccessEntry[] {
  const own = grants.filter((g) => sameSubject(g.subject, subject) && (subject.kind !== "anyone" || g.network_id === networkId));
  const entries = grantEntries(own, "target", ctx);
  if (subject.kind === "peer") {
    const peer = ctx.peers.find((p) => p.id === subject.id);
    for (const gid of peer?.groups ?? []) {
      const group = ctx.groups.find((g) => g.id === gid);
      const via = grantEntries(grants.filter((g) => g.subject.kind === "group" && g.subject.id === gid), "target", ctx);
      for (const e of via) {
        entries.push({
          ...e,
          key: `${e.key}|via`,
          ident: e.ident.replace(/\|direct$/, `|group:${gid}`),
          origin: { kind: "group", id: gid, label: group?.label ?? gid.slice(0, 8) },
          grants: [],
        });
      }
    }
  }
  return sortEntries(entries);
}

/** The accesses several selected things have in common or in part. */
export function mergeEntries(lists: AccessEntry[][]): AccessEntry[] {
  const by = new Map<string, AccessEntry>();
  for (const list of lists) {
    const counted = new Set<string>();
    for (const e of list) {
      const have = by.get(e.ident);
      if (!have) by.set(e.ident, { ...e, have: 1, of: lists.length, grants: [...e.grants] });
      else {
        have.grants.push(...e.grants);
        if (!counted.has(e.ident)) have.have = (have.have ?? 0) + 1;
      }
      counted.add(e.ident);
    }
  }
  return sortEntries([...by.values()]);
}

/** The same as `appEntries`, worked out from the lists instead of one app's detail: the grants on
 * the app, and the grants on the tags it belongs to (narrowed to the member's port). */
export function appEntriesFromGrants(appId: string, grants: GrantView[], ctx: NameCtx): AccessEntry[] {
  const direct = grantEntries(grants.filter((g) => g.target.kind === "app" && g.target.id === appId), "subject", ctx);
  const viaTags = membershipsOf(appId, ctx.tags).flatMap(({ tag, port }) =>
    grantEntries(grants.filter((g) => g.target.kind === "tag" && g.target.id === tag.id), "subject", ctx).map<AccessEntry>((e) => ({
      ...e,
      key: `${e.key}|${port ? portLabel(port) : "*"}`,
      ident: e.ident.replace(/\|direct$/, `|${tag.id}`),
      port: port ?? e.port,
      origin: { kind: "tag", id: tag.id, label: tag.label },
      grants: [],
    })),
  );
  return sortEntries([...direct, ...viaTags]);
}
