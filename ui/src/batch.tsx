// Shared by every place that sends a batch (ADR 0045): the dry-run preview and the list of
// changes it returns.
import { useEffect, useState } from "react";
import { api, toDaemonError, type BatchChange, type ChangeOp, type ChangesResponse, type Network } from "./api";
import { ReachBadge } from "./reach";

export type DryRun =
  | { state: "idle" }
  | { state: "loading" }
  | { state: "ok"; result: ChangesResponse }
  | { state: "error"; message: string; code: string };

/** Ask the daemon what a batch would do, whenever the operations change. Nothing is saved. */
export function useDryRun(ops: ChangeOp[], enabled = true): DryRun {
  const key = JSON.stringify(ops);
  const [run, setRun] = useState<{ key: string; value: DryRun } | null>(null);

  useEffect(() => {
    if (!enabled || ops.length === 0) return;
    let stale = false;
    api
      .changes({ ops, dry_run: true })
      .then((result) => !stale && setRun({ key, value: { state: "ok", result } }))
      .catch((e) => {
        if (stale) return;
        const err = toDaemonError(e);
        setRun({ key, value: { state: "error", message: err.message, code: err.code } });
      });
    return () => {
      stale = true;
    };
    // `key` stands for `ops`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, enabled]);

  if (!enabled || ops.length === 0) return { state: "idle" };
  return run && run.key === key ? run.value : { state: "loading" };
}

/** Does any operation open an app to Anyone? */
export const opensToAnyone = (ops: ChangeOp[]) =>
  ops.some((o) => o.op === "add_grant" && o.subject.kind === "anyone");

/** The same operations with the Anyone confirmation set on every grant. */
export const confirmAll = (ops: ChangeOp[]): ChangeOp[] =>
  ops.map((o) => (o.op === "add_grant" ? { ...o, confirm_open: true } : o));

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
          {(c.reach ?? []).map((r) => (
            <ReachBadge key={r.network_id} reach={r.reach} network={netName(r.network_id)} />
          ))}
        </li>
      ))}
    </ul>
  );
}
