import type { ReactNode, RefObject } from "react";
import type { AccessEntry } from "../access";
import type { Scope } from "../api";
import { reachNotes } from "../batch";
import { useRevoke } from "../commit";
import AccessList, { type AccessHighlight } from "./AccessList";
import CommitPreview from "./CommitPreview";
import { useNameCtx } from "./Inspector";

interface CardProps {
  rowKey: string;
  itemRef?: RefObject<HTMLLIElement>;
  /** Name and badges. */
  head: ReactNode;
  /** The tags part; the cards of a reservation have none. */
  tags?: ReactNode;
  /** Who can reach it (a RowAccess), absent where grants do not apply. */
  access?: ReactNode;
  /** The Add access part. */
  add?: ReactNode;
  /** The Address part, always last; the cards of a reservation have none. */
  address?: ReactNode;
}

/** One row of the Ports section, in an app and in a reservation. The parts are always in this
 * order: name, tags, who can reach it, Add access, address. */
export default function RowCard({ rowKey, itemRef, head, tags, access, add, address }: CardProps) {
  return (
    <li className="port-row" ref={itemRef} data-row={rowKey}>
      <div className="port-head">{head}</div>
      {tags && <div className="port-tags">{tags}</div>}
      {access}
      {add && <div className="port-add">{add}</div>}
      {address}
    </li>
  );
}

interface AccessProps {
  entries: AccessEntry[];
  /** The row the list is of, so the badge shows only what limits an entry beyond it. */
  rowScope: Scope;
  empty: string;
  highlight?: AccessHighlight | null;
  /** A line under the list (a link to the grants that also cover the row). */
  extra?: ReactNode;
}

/** Who can reach a row. Revoke acts on the grants listed; a Tor note of the daemon (a bound row
 * is not reachable there) is spelled out under the list. */
export function RowAccess({ entries, rowScope, empty, highlight = null, extra }: AccessProps) {
  const names = useNameCtx();
  const { revoke, commit } = useRevoke();
  const netName = (id: string) => names.networks.find((n) => n.id === id)?.name ?? id;
  const notes = reachNotes(entries.flatMap((e) => e.reach), netName);
  return (
    <div className="port-access">
      <AccessList entries={entries} direction="who" networks={names.networks} onRevoke={revoke} highlight={highlight} empty={empty} rowScope={rowScope} />
      {extra}
      {notes.map((n) => (
        <p key={n} className="muted access-note">{n}</p>
      ))}
      <CommitPreview commit={commit} />
    </div>
  );
}
