import { useEffect, useRef } from "react";
import type { AccessEntry } from "../access";
import { sameSubject } from "../access";
import type { Network, Subject } from "../api";
import { useNav } from "../nav";
import { ReachBadge } from "../reach";

export interface AccessHighlight {
  subject: Subject;
  networkId: string | null;
}

interface Props {
  entries: AccessEntry[];
  /** "who": the subjects that can reach something; "what": the things a subject can reach. */
  direction: "who" | "what";
  networks: Network[];
  /** Without it the list is read-only. */
  onRevoke?: (entry: AccessEntry) => void;
  /** The entry for this subject is marked and scrolled to (a click on a cell of the overview). */
  highlight?: AccessHighlight | null;
  empty?: string;
  /** What the "of N" counts, with several things selected. */
  unit?: string;
}

const nameOf = (e: AccessEntry) => `${e.name}${e.scope.kind !== "all" ? ` ${e.scopeText}` : ""}`;

/** Access in either direction: the name, port, network, how well the subject is identified and
 * where it comes from. A direct entry can be revoked; one that comes through a tag or a group
 * links to it. */
export default function AccessList({ entries, direction, networks, onRevoke, highlight = null, empty, unit = "selected" }: Props) {
  const nav = useNav();
  const marked = useRef<HTMLLIElement>(null);
  const netName = (id: string) => networks.find((n) => n.id === id)?.name ?? id;

  const isMarked = (e: AccessEntry) =>
    highlight !== null && e.subject !== undefined && sameSubject(e.subject, highlight.subject) &&
    (highlight.subject.kind !== "anyone" || e.networkId === highlight.networkId || (highlight.networkId !== null && e.networkId === null));
  const firstMarked = entries.findIndex(isMarked);

  useEffect(() => {
    marked.current?.scrollIntoView?.({ block: "nearest" });
  }, [highlight, firstMarked]);

  if (entries.length === 0) {
    return <p className="muted">{empty ?? (direction === "who" ? "Nobody can reach it." : "It can reach nothing.")}</p>;
  }
  return (
    <ul className="access-list plain-list">
      {entries.map((e, i) => {
        const hit = isMarked(e);
        return (
          <li key={e.key} ref={i === firstMarked ? marked : undefined} className={`access-item${hit ? " access-highlight" : ""}`}>
            <div className="access-main">
              {e.link ? (
                <button className="link-btn access-name" onClick={() => nav.go(e.link!.page, e.link!.focus)}>{e.name}</button>
              ) : (
                <span className="access-name">{e.name}</span>
              )}
              {e.scope.kind !== "all" && <span className="badge access-port mono" title="Only these ports">{e.scopeText}</span>}
              {e.networkId && e.subject?.kind !== "anyone" && <span className="muted">on {netName(e.networkId)}</span>}
              {e.of !== undefined && e.of > 1 && (
                <span className={`badge ${e.have === e.of ? "reach reach-ok" : "reach reach-warn"}`}>
                  {e.have === e.of ? `all ${e.of} ${unit}` : `${e.have} of ${e.of} ${unit}`}
                </span>
              )}
            </div>
            <div className="access-meta">
              {e.reach.map((r, j) => <ReachBadge key={`${r.network_id}-${j}`} reach={r.reach} network={netName(r.network_id)} />)}
              {e.origin.kind === "tag" && (
                <button className="link-btn" aria-label={`Go to tag ${e.origin.label}`} onClick={() => nav.go("apps", { tagId: (e.origin as { id: string }).id })}>
                  via tag {e.origin.label}
                </button>
              )}
              {e.origin.kind === "group" && (
                <button className="link-btn" aria-label={`Go to group ${e.origin.label}`} onClick={() => nav.go("peers", { groupId: (e.origin as { id: string }).id })}>
                  via group {e.origin.label}
                </button>
              )}
              {e.origin.kind === "reservation" && <span className="muted">via reservation {e.origin.label}</span>}
              {e.origin.kind === "direct" && e.grants.length > 0 && onRevoke && (
                <button className="btn btn-danger btn-sm access-revoke" aria-label={`Revoke ${nameOf(e)}`} onClick={() => onRevoke(e)}>
                  Revoke
                </button>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
