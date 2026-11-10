import { useMemo, useRef, useState } from "react";
import type { App } from "../api";
import { accessSummary, membershipsOf } from "../access";
import AppDetailView from "../components/AppDetailCard";
import GrantEditor from "../components/GrantEditor";
import RevokeDialog from "../components/RevokeDialog";
import TagDialog from "../components/TagDialog";
import TagsPanel from "../components/TagsPanel";
import { useToast } from "../components/Toast";
import { errorText, portLabel } from "../lib";
import { useApps, useChanges, useGrants, useNetworks, useTags } from "../queries";
import type { Focus } from "../nav";

type Dialog = "grant" | "revoke" | "tag" | null;

export default function AppsPage({ focus = {} }: { focus?: Focus }) {
  const toast = useToast();
  const apps = useApps();
  const tags = useTags();
  const grants = useGrants();
  const networks = useNetworks();
  const changes = useChanges();

  const [detail, setDetail] = useState<string | null>(focus.appId ?? null);
  const [pendingOnly, setPendingOnly] = useState(focus.pendingOnly ?? false);
  const [search, setSearch] = useState(focus.search ?? "");
  const [tagFilter, setTagFilter] = useState<string | null>(focus.tagId ?? null);
  const [netFilter, setNetFilter] = useState("");
  const [showSystem, setShowSystem] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<Dialog>(null);
  const anchor = useRef<string | null>(null);

  const tagList = useMemo(() => tags.data ?? [], [tags.data]);
  const grantList = grants.data ?? [];
  const tagMembers = useMemo(
    () => new Set(tagList.find((t) => t.id === tagFilter)?.members.map((m) => m.app_id) ?? []),
    [tagList, tagFilter],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (apps.data ?? [])
      .filter((a) => !pendingOnly || !a.reviewed)
      .filter((a) => !tagFilter || tagMembers.has(a.id))
      .filter((a) => !netFilter || a.addresses.some((ad) => ad.network_id === netFilter))
      .filter((a) => !q || a.name.toLowerCase().includes(q) || a.process_name.toLowerCase().includes(q))
      .sort((a, b) => Number(a.reviewed) - Number(b.reviewed) || a.name.localeCompare(b.name));
  }, [apps.data, pendingOnly, search, tagFilter, tagMembers, netFilter]);
  const own = filtered.filter((a) => !a.system);
  const system = filtered.filter((a) => a.system);
  // A search or a filter that matches system services should not hide them.
  const systemOpen = showSystem || search.trim() !== "" || tagFilter !== null;
  const visible = systemOpen ? [...own, ...system] : own;
  const pendingCount = (apps.data ?? []).filter((a) => !a.reviewed).length;

  const clickBox = (app: App, shift: boolean) => {
    const next = new Set(selected);
    if (shift && anchor.current) {
      const a = visible.findIndex((x) => x.id === anchor.current);
      const b = visible.findIndex((x) => x.id === app.id);
      if (a >= 0 && b >= 0) {
        const on = !selected.has(app.id);
        for (const x of visible.slice(Math.min(a, b), Math.max(a, b) + 1)) {
          if (on) next.add(x.id);
          else next.delete(x.id);
        }
        setSelected(next);
        anchor.current = app.id;
        return;
      }
    }
    if (next.has(app.id)) next.delete(app.id);
    else next.add(app.id);
    anchor.current = app.id;
    setSelected(next);
  };
  const allChecked = visible.length > 0 && visible.every((a) => selected.has(a.id));
  const selectedIds = [...selected];

  const markReviewed = () =>
    changes.mutate(
      { ops: selectedIds.map((app_id) => ({ op: "review" as const, app_id, reviewed: true })), dryRun: false },
      {
        onSuccess: () => toast.success(`Marked ${selectedIds.length} reviewed`),
        onError: (e) => toast.error(errorText(e)),
      },
    );

  const renderRow = (a: App) => {
    const sum = accessSummary(a.id, grantList, tagList);
    const listening = a.ports.filter((p) => p.listening);
    const myTags = membershipsOf(a.id, tagList);
    return (
      <tr key={a.id} className={a.id === detail ? "row-selected" : undefined}>
        <td>
          <input
            type="checkbox"
            aria-label={`Select ${a.name}`}
            checked={selected.has(a.id)}
            onChange={() => {}}
            onClick={(e) => clickBox(a, e.shiftKey)}
          />
        </td>
        <td>
          <button className="link-btn" onClick={() => setDetail(a.id)} aria-pressed={a.id === detail}>{a.name}</button>{" "}
          {!a.reviewed && <span className="badge badge-pending">pending</span>}
          {a.identity_note === "unidentified" && <span className="badge reach reach-warn" title="Owner of the socket unknown">unidentified</span>}
        </td>
        <td>
          {myTags.map((m) => (
            <span key={`${m.tag.id}-${m.port ? portLabel(m.port) : "*"}`} className="tag-pill tag-pill-static">
              {m.tag.label}{m.port ? ` ${portLabel(m.port)}` : ""}
            </span>
          ))}
        </td>
        <td className="mono ports-cell">{listening.length ? listening.map(portLabel).join(", ") : <span className="muted">not listening</span>}</td>
        <td>
          {sum.open && <span className="badge reach reach-bad">open to anyone</span>}
          {sum.segment && <span className="badge reach reach-warn">segment</span>}
          {sum.direct + sum.viaTag === 0 ? (
            <span className="muted">closed</span>
          ) : (
            <span className="muted">
              {sum.direct > 0 && `${sum.direct} direct`}
              {sum.direct > 0 && sum.viaTag > 0 && ", "}
              {sum.viaTag > 0 && `${sum.viaTag} via tag`}
            </span>
          )}
        </td>
      </tr>
    );
  };

  return (
    <div>
      <TagsPanel active={tagFilter} onFilter={setTagFilter} />
      <div className="apps-layout">
        <section aria-label="Apps">
          <div className="toolbar">
            <input
              className="input grow"
              type="search"
              aria-label="Filter apps"
              placeholder="Filter apps"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <label className="check">
              <input type="checkbox" checked={pendingOnly} onChange={(e) => setPendingOnly(e.target.checked)} />
              Pending only ({pendingCount})
            </label>
            <label className="visually-hidden" htmlFor="net-filter">Network</label>
            <select id="net-filter" className="input" value={netFilter} onChange={(e) => setNetFilter(e.target.value)}>
              <option value="">Any network</option>
              {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
            </select>
          </div>

          {selected.size > 0 && (
            <div className="bulk-bar" role="toolbar" aria-label="Bulk actions">
              <strong>{selected.size} selected</strong>
              <button className="btn btn-sm btn-primary" onClick={() => setDialog("grant")}>Grant…</button>
              <button className="btn btn-sm" onClick={() => setDialog("revoke")}>Revoke…</button>
              <button className="btn btn-sm" onClick={() => setDialog("tag")}>Tag…</button>
              <button className="btn btn-sm" onClick={markReviewed} disabled={changes.isPending}>Mark reviewed</button>
              <button className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
            </div>
          )}

          {apps.isLoading && <p className="muted">Loading…</p>}
          {apps.error && <div className="error-banner">{errorText(apps.error)}</div>}
          {apps.data && filtered.length === 0 && (
            <div className="card empty">
              <p>{apps.data.length === 0 ? "No apps detected yet." : "No apps match."}</p>
              {apps.data.length === 0 && <p className="hint">The daemon discovers listening programs automatically.</p>}
            </div>
          )}
          {filtered.length > 0 && (
            <div className="table-wrap">
              <table className="apps-table">
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        aria-label="Select all shown apps"
                        checked={allChecked}
                        onChange={(e) => setSelected(e.target.checked ? new Set(visible.map((a) => a.id)) : new Set())}
                      />
                    </th>
                    <th>App</th><th>Tags</th><th>Ports</th><th>Access</th>
                  </tr>
                </thead>
                <tbody>
                  {own.map(renderRow)}
                  {system.length > 0 && (
                    <tr className="group-row">
                      <td colSpan={5}>
                        <button
                          className="link-btn"
                          aria-expanded={systemOpen}
                          onClick={() => setShowSystem(!showSystem)}
                          disabled={search.trim() !== "" || tagFilter !== null}
                        >
                          {systemOpen ? "▾" : "▸"} System services ({system.length})
                        </button>
                        <span className="muted"> Windows services and system processes</span>
                      </td>
                    </tr>
                  )}
                  {systemOpen && system.map(renderRow)}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section aria-label="App details">
          {detail ? (
            <AppDetailView key={detail} id={detail} onForgotten={() => setDetail(null)} />
          ) : (
            <div className="card empty"><p>Select an app to see its ports and who can reach them.</p></div>
          )}
        </section>
      </div>

      {dialog === "grant" && (
        <GrantEditor targets={selectedIds.map((id) => ({ kind: "app" as const, id }))} onClose={() => setDialog(null)} />
      )}
      {dialog === "revoke" && <RevokeDialog appIds={selectedIds} onClose={() => setDialog(null)} />}
      {dialog === "tag" && <TagDialog members={selectedIds.map((app_id) => ({ app_id, port: null }))} onClose={() => setDialog(null)} />}
    </div>
  );
}
