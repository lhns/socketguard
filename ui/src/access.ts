// Pure helpers over grants, tags and groups shared by the Apps page and the matrix.
import type { AccessOrigin, GrantView, PeerGroup, PortRef, Subject, Tag } from "./api";
import { samePort } from "./lib";

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

/** "direct", "via tag web" or "via group team". */
export function originLabel(origin: AccessOrigin, tags: Tag[], groups: PeerGroup[]): string {
  switch (origin.kind) {
    case "direct":
      return "direct";
    case "tag":
      return `via tag ${tags.find((t) => t.id === origin.tag_id)?.label ?? origin.tag_id.slice(0, 8)}`;
    case "group":
      return `via group ${groups.find((g) => g.id === origin.group_id)?.label ?? origin.group_id.slice(0, 8)}`;
  }
}

/** Does a grant on `grantPort` cover `port` (null = the whole app)? A port-specific grant does
 * not cover the whole app. */
export const covers = (grantPort: PortRef | null, port: PortRef | null) =>
  grantPort === null || (port !== null && samePort(grantPort, port));
