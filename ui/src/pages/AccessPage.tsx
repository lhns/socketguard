import { useEffect, useId, useMemo, useState } from "react";
import { toDaemonError, type ChangeOp } from "../api";
import { ChangeList, confirmAll, opensToAnyone, useDryRun } from "../batch";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/Toast";
import { errorText, splitOperationError } from "../lib";
import {
  buildColumns, buildRows, cellKey, cellOf, isOn, opsFromStaged, type Cell, type Col, type Ctx, type Row, type Staged,
} from "../matrix";
import { useNav } from "../nav";
import { useApps, useChanges, useGrants, useGroups, useNetworks, usePeers, useTags } from "../queries";

const STATE_TEXT = {
  none: "no access",
  granted: "granted",
  partial: "granted on some networks",
  inherited: "inherited",
} as const;

export default function AccessPage() {
  const nav = useNav();
  const apps = useApps();
  const tags = useTags();
  const grants = useGrants();
  const peers = usePeers();
  const groups = useGroups();
  const networks = useNetworks();

  const [scope, setScope] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [staged, setStaged] = useState<Staged>(new Map());
  const [anchor, setAnchor] = useState<{ r: number; c: number } | null>(null);
  const [inherited, setInherited] = useState<{ row: Row; col: Col; cell: Cell } | null>(null);
  const [previewing, setPreviewing] = useState(false);

  const ctx: Ctx = useMemo(
    () => ({
      grants: grants.data ?? [],
      tags: tags.data ?? [],
      peers: peers.data ?? [],
      groups: groups.data ?? [],
      networks: networks.data ?? [],
      scope,
    }),
    [grants.data, tags.data, peers.data, groups.data, networks.data, scope],
  );
  const cols = useMemo(() => buildColumns(ctx), [ctx]);
  const shownApps = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (apps.data ?? [])
      .filter((a) => !q || a.name.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [apps.data, filter]);
  const rows = useMemo(() => buildRows(shownApps, ctx.tags, expanded), [shownApps, ctx.tags, expanded]);
  const allRows = useMemo(() => buildRows(apps.data ?? [], ctx.tags, new Set((apps.data ?? []).map((a) => a.id))), [apps.data, ctx.tags]);

  // Staged edits belong to a scope; switching it drops them rather than reinterpret them.
  const changeScope = (s: string | null) => {
    setScope(s);
    setStaged(new Map());
    setAnchor(null);
  };

  const cells = useMemo(() => {
    const m = new Map<string, Cell>();
    for (const r of rows) for (const c of cols) m.set(cellKey(r, c), cellOf(r, c, ctx));
    return m;
  }, [rows, cols, ctx]);
  const on = (r: Row, c: Col) => isOn(cells.get(cellKey(r, c))!, staged.get(cellKey(r, c)));

  const flip = (map: Staged, r: Row, c: Col) => {
    const key = cellKey(r, c);
    if (map.has(key)) map.delete(key);
    else map.set(key, on(r, c) ? "remove" : "add");
  };
  /** Make every cell in `targets` on (or off), flipping only those that are not already. */
  const setAll = (targets: [Row, Col][], desired: boolean) => {
    const next: Staged = new Map(staged);
    for (const [r, c] of targets) if (on(r, c) !== desired) flip(next, r, c);
    setStaged(next);
  };

  const clickCell = (ri: number, ci: number, shift: boolean) => {
    const r = rows[ri];
    const c = cols[ci];
    const cell = cells.get(cellKey(r, c))!;
    if (shift && anchor) {
      // Extend what the first click did to the whole rectangle.
      const desired = on(rows[anchor.r], cols[anchor.c]);
      const targets: [Row, Col][] = [];
      for (let i = Math.min(anchor.r, ri); i <= Math.max(anchor.r, ri); i++) {
        for (let j = Math.min(anchor.c, ci); j <= Math.max(anchor.c, ci); j++) targets.push([rows[i], cols[j]]);
      }
      setAll(targets, desired);
      return;
    }
    setAnchor({ r: ri, c: ci });
    if (cell.state === "inherited" && !staged.has(cellKey(r, c))) {
      setInherited({ row: r, col: c, cell });
      return;
    }
    const next: Staged = new Map(staged);
    flip(next, r, c);
    setStaged(next);
  };

  // Every row counts, also those the filter hides now.
  const ops = useMemo(() => opsFromStaged(allRows, cols, staged, ctx), [allRows, cols, staged, ctx]);

  const rowHeadClick = (r: Row) => setAll(cols.map((c) => [r, c]), !cols.every((c) => on(r, c)));
  const colHeadClick = (c: Col) => setAll(rows.map((r) => [r, c]), !rows.every((r) => on(r, c)));
  const toggleExpand = (id: string) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  const stagedCount = staged.size;
  const grantNetworks = (networks.data ?? []).filter((n) => n.grants_apply);

  return (
    <div>
      <div className="toolbar">
        <label htmlFor="matrix-net">Network</label>
        <select id="matrix-net" className="input" value={scope ?? ""} onChange={(e) => changeScope(e.target.value || null)}>
          <option value="">All networks</option>
          {grantNetworks.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </select>
        <input className="input grow" type="search" aria-label="Filter apps" placeholder="Filter apps" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted legend">✓ granted · ◐ some networks · ↳ inherited (dimmed)</span>
      </div>
      {scope !== null && (
        <p className="hint">
          Showing and changing grants on {grantNetworks.find((n) => n.id === scope)?.name} only. A grant that spans all networks is
          shown as granted; removing it here keeps it on the other networks.
        </p>
      )}

      {(apps.isLoading || grants.isLoading) && <p className="muted">Loading…</p>}
      {(apps.error || grants.error) && <div className="error-banner">{errorText(apps.error ?? grants.error)}</div>}
      {apps.data?.length === 0 && <div className="card empty"><p>No apps detected yet.</p></div>}

      {rows.length > 0 && (
        <div className="matrix-wrap">
          <table className="matrix" aria-label="Access matrix">
            <thead>
              <tr>
                <th className="matrix-corner" />
                {cols.map((c) => (
                  <th key={c.key} className="matrix-colhead">
                    <button className="link-btn" title={`Select the ${c.label} column`} onClick={() => colHeadClick(c)}>{c.label}</button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={r.key} className={`matrix-row matrix-row-${r.kind}`}>
                  <th scope="row" className="matrix-rowhead">
                    {r.kind === "app" && (r.app?.ports.length ?? 0) > 0 && (
                      <button
                        className="link-btn"
                        aria-label={`${expanded.has(r.app!.id) ? "Collapse" : "Expand"} ports of ${r.label}`}
                        aria-expanded={expanded.has(r.app!.id)}
                        onClick={() => toggleExpand(r.app!.id)}
                      >
                        {expanded.has(r.app!.id) ? "▾" : "▸"}
                      </button>
                    )}{" "}
                    <button className="link-btn" title="Select the whole row" onClick={() => rowHeadClick(r)}>{r.label}</button>
                    {r.kind === "app" && r.app && !r.app.reviewed && <span className="badge badge-pending">pending</span>}
                  </th>
                  {cols.map((c, ci) => {
                    const cell = cells.get(cellKey(r, c))!;
                    const st = staged.get(cellKey(r, c));
                    const shown = st === "add" ? "granted" : st === "remove" ? "none" : cell.state;
                    return (
                      <td key={c.key} className={`matrix-cell cell-${shown}${st ? " cell-staged" : ""}`}>
                        <button
                          className="cell-btn"
                          aria-label={`${r.label} – ${c.label}: ${STATE_TEXT[cell.state]}${st ? `, staged ${st}` : ""}`}
                          title={cellTitle(cell, ctx)}
                          onClick={(e) => clickCell(ri, ci, e.shiftKey)}
                        >
                          {shown === "granted" ? (cell.allNetworks && !st ? "✓*" : "✓") : shown === "partial" ? "◐" : shown === "inherited" ? "↳" : ""}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {inherited && (
        <div className="card inherited-pop" role="dialog" aria-label="Inherited access">
          <p>
            <strong>{inherited.row.label}</strong> reaches <strong>{inherited.col.label}</strong> through{" "}
            {inherited.cell.origin?.kind === "group" ? "group " : inherited.cell.origin?.kind === "tag" ? "tag " : ""}
            <strong>{inherited.cell.origin?.label}</strong>. That cannot be removed here.
          </p>
          <div className="actions">
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                const next: Staged = new Map(staged);
                next.set(cellKey(inherited.row, inherited.col), "add");
                setStaged(next);
                setInherited(null);
              }}
            >
              Add a direct grant
            </button>
            {inherited.cell.origin?.kind === "tag" && (
              <button className="btn btn-sm" onClick={() => nav.go("apps", { tagId: inherited.cell.origin!.id })}>Go to the tag grant</button>
            )}
            {inherited.cell.origin?.kind === "group" && (
              <button className="btn btn-sm" onClick={() => nav.go("peers", { groupId: inherited.cell.origin!.id })}>Go to the group</button>
            )}
            <button className="btn btn-sm" onClick={() => setInherited(null)}>Close</button>
          </div>
        </div>
      )}

      {stagedCount > 0 && (
        <div className="staged-bar" role="region" aria-label="Staged changes">
          <span>{stagedCount} staged</span>
          <button className="btn btn-sm" onClick={() => setStaged(new Map())}>Discard</button>
          <button className="btn btn-primary" onClick={() => setPreviewing(true)}>Apply {stagedCount} changes</button>
        </div>
      )}

      {previewing && (
        <StagedPreview
          ops={ops}
          onClose={() => setPreviewing(false)}
          onDone={() => {
            setPreviewing(false);
            setStaged(new Map());
          }}
        />
      )}
    </div>
  );
}

function cellTitle(cell: Cell, ctx: Ctx): string {
  switch (cell.state) {
    case "inherited":
      return `Inherited through ${cell.origin?.kind} ${cell.origin?.label}. Click for options.`;
    case "partial":
      return `Granted on ${cell.networkIds.map((id) => ctx.networks.find((n) => n.id === id)?.name ?? id).join(", ")} only`;
    case "granted":
      return cell.allNetworks ? "Granted on all networks" : "Granted";
    default:
      return "No access. Click to grant.";
  }
}

/** The staged edits as one batch: a dry run shows what it would do, Apply sends it. */
function StagedPreview({ ops, onClose, onDone }: { ops: ChangeOp[]; onClose: () => void; onDone: () => void }) {
  const id = useId();
  const toast = useToast();
  const networks = useNetworks().data ?? [];
  const changes = useChanges();
  const dry = useDryRun(ops);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !asking && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [asking, onClose]);

  const apply = async (confirmed: boolean) => {
    setError(null);
    try {
      await changes.mutateAsync({ ops: confirmed ? confirmAll(ops) : ops, dryRun: false });
      toast.success("Changes applied");
      onDone();
    } catch (e) {
      if (toDaemonError(e).code === "confirmation_required") setAsking(true);
      else setError(errorText(e));
    }
  };
  const failure = error ?? (dry.state === "error" ? dry.message : null);
  const failed = failure ? splitOperationError(failure) : null;

  return (
    <>
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby={`${id}-t`} onClick={(e) => e.stopPropagation()}>
          <h2 id={`${id}-t`} className="modal-title">Apply {ops.length} changes?</h2>
          {dry.state === "loading" && <p className="muted">Checking…</p>}
          {dry.state === "ok" && <ChangeList changes={dry.result.changes} networks={networks} />}
          {failed && (
            <div className="error-banner" role="alert">
              {failed.index !== null ? `Change ${failed.index + 1}: ` : ""}{failed.text}
            </div>
          )}
          <div className="modal-actions">
            <button className="btn" onClick={onClose}>Back</button>
            <button
              className="btn btn-primary"
              disabled={dry.state !== "ok" || changes.isPending}
              onClick={() => (opensToAnyone(ops) ? setAsking(true) : void apply(false))}
            >
              Apply
            </button>
          </div>
        </div>
      </div>
      {asking && (
        <ConfirmDialog
          title="Open to anyone?"
          confirmLabel="Open to anyone"
          onCancel={() => setAsking(false)}
          onConfirm={() => {
            setAsking(false);
            void apply(true);
          }}
        >
          <p>
            Some of these changes let anyone connect: every host on the network, or on the whole network for segment columns,
            with nothing verified. This is not limited to your peers.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
