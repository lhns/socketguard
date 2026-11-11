// Shared by every place that sends a batch (ADR 0045): the confirmation flag and the list of
// changes a dry run returns.
import type { BatchChange, ChangeOp, GrantView, Network } from "./api";
import { ReachBadge } from "./reach";

/** The same operations with the Anyone confirmation set. A dry run is sent this way (it saves
 * nothing, and the answer says which changes need the question); an apply only after the user
 * agreed. */
export const confirmAll = (ops: ChangeOp[]): ChangeOp[] =>
  ops.map((o) => (o.op === "add_grant" || o.op === "add_tag_member" ? { ...o, confirm_open: true } : o));

/** The operation that puts a removed grant back. */
export const grantInverse = (g: GrantView): ChangeOp => ({
  op: "add_grant",
  target: g.target,
  scope: g.scope,
  ...(g.network_id ? { network_id: g.network_id } : {}),
  subject: g.subject,
  confirm_open: false,
});

const KIND_SIGN = { create: "+", update: "~", delete: "−" } as const;

/** The diff of a batch: what is created or removed and how well each new grant identifies
 * its subject on every network. */
export function ChangeList({ changes, networks }: { changes: BatchChange[]; networks: Network[] }) {
  if (changes.length === 0) return <p className="muted">Nothing would change.</p>;
  const netName = (id: string) => networks.find((n) => n.id === id)?.name ?? id;
  return (
    <ul className="plain-list change-list">
      {changes.map((c, i) => (
        <li key={i} className={`change change-${c.kind}`}>
          <span className="change-sign" aria-hidden="true">{KIND_SIGN[c.kind]}</span>
          <span className="change-item">{c.kind} {c.item.replace("_", " ")}</span>
          <span className="change-name">{c.name}</span>
          {c.detail && <span className="muted">{c.detail}</span>}
          {c.opens_to_anyone && <span className="badge reach reach-bad">opens to anyone</span>}
          {(c.reach ?? []).map((r, j) => (
            <ReachBadge key={`${r.network_id}-${j}`} reach={r.reach} network={netName(r.network_id)} />
          ))}
        </li>
      ))}
    </ul>
  );
}
