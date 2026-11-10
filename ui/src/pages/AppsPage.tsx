import { useEffect, useMemo, useState } from "react";
import { accessSummary, membershipsOf } from "../access";
import type { App, Tag } from "../api";
import type { AccessHighlight } from "../components/AccessList";
import { AppInspector, AppsInspector } from "../components/AppInspector";
import EntityList, { type ListColumn, type ListRow, type ListSection } from "../components/EntityList";
import Inspector, { InspectorEmpty } from "../components/Inspector";
import Picker, { type PickerItem } from "../components/Picker";
import { NewTagForm, TagInspector, TagsInspector } from "../components/TagInspector";
import { useColumns } from "../columns";
import { errorText, portLabel } from "../lib";
import { buildColumns, buildRows, cellOf, type Cell, type Col, type Ctx, type Row as MatrixRow } from "../matrix";
import type { FocusMessage } from "../nav";
import { useApps, useGrants, useGroups, useNetworks, usePeers, useTags } from "../queries";

interface AppRow extends ListRow {
  m: MatrixRow;
}

const CELL_GLYPH = { granted: "✓", partial: "◐", inherited: "↳", none: "" } as const;
const CELL_TEXT = { granted: "granted", partial: "granted on some networks", inherited: "inherited", none: "no access" } as const;
const ALL = "__all__";

const toRow = (m: MatrixRow): AppRow => ({ key: m.key, kind: m.kind, selectable: m.kind !== "port", indent: m.kind === "port", m });

export default function AppsPage({ focus = { seq: 0 } }: { focus?: FocusMessage }) {
  const apps = useApps();
  const tags = useTags();
  const grants = useGrants();
  const peers = usePeers();
  const groups = useGroups();
  const networks = useNetworks();
  const columns = useColumns();

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [pendingOnly, setPendingOnly] = useState(false);
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [showSystem, setShowSystem] = useState(false);
  const [scope, setScope] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [stripOpen, setStripOpen] = useState(false);
  const [highlight, setHighlight] = useState<AccessHighlight | null>(null);
  const [selectLabel, setSelectLabel] = useState<string | null>(null);

  const tagList = useMemo(() => tags.data ?? [], [tags.data]);
  const appList = useMemo(() => apps.data ?? [], [apps.data]);
  const ctx: Ctx = useMemo(
    () => ({
      grants: grants.data ?? [], tags: tagList, peers: peers.data ?? [], groups: groups.data ?? [], networks: networks.data ?? [], scope,
    }),
    [grants.data, tagList, peers.data, groups.data, networks.data, scope],
  );

  // A link from elsewhere: show what it points at. The page stays mounted, so the rest of its
  // state (filters, columns, selection) is kept.
  useEffect(() => {
    if (focus.seq === 0) return;
    if (focus.search !== undefined) setSearch(focus.search);
    if (focus.pendingOnly) setPendingOnly(true);
    const key = focus.appId ? `app:${focus.appId}` : focus.tagId ? `tag:${focus.tagId}` : null;
    if (key) {
      setSelected(new Set([key]));
      setCreating(false);
      setStripOpen(true);
      setHighlight(null);
    }
    // Only a new link counts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus.seq]);

  // A tag that was just created is selected as soon as it is in the list.
  useEffect(() => {
    if (!selectLabel) return;
    const t = tagList.find((x) => x.label === selectLabel);
    if (t) {
      setSelected(new Set([`tag:${t.id}`]));
      setSelectLabel(null);
    }
  }, [tagList, selectLabel]);

  // ─── The rows ──────────────────────────────────────────────────────────────
  const q = search.trim().toLowerCase();
  const tagMembers = useMemo(
    () => new Set(tagList.find((t) => t.id === tagFilter)?.members.map((m) => m.app_id) ?? []),
    [tagList, tagFilter],
  );
  const shownApps = useMemo(
    () =>
      appList
        .filter((a) => !pendingOnly || !a.reviewed)
        .filter((a) => !tagFilter || tagMembers.has(a.id))
        .filter((a) => !q || a.name.toLowerCase().includes(q) || a.process_name.toLowerCase().includes(q))
        .sort((a, b) => Number(a.reviewed) - Number(b.reviewed) || a.name.localeCompare(b.name)),
    [appList, pendingOnly, tagFilter, tagMembers, q],
  );
  const shownTags = useMemo(() => tagList.filter((t) => !q || t.label.toLowerCase().includes(q)), [tagList, q]);
  const own = shownApps.filter((a) => !a.system);
  const system = shownApps.filter((a) => a.system);
  const selectedSystem = appList.some((a) => a.system && selected.has(`app:${a.id}`));
  // A search, a filter or a selection that reaches a system service should not hide it.
  const systemOpen = showSystem || q !== "" || tagFilter !== null || selectedSystem;

  const allCols = useMemo(() => buildColumns({ ...ctx, scope: null }), [ctx]);
  const shownCols: Col[] = useMemo(
    () => allCols.filter((c) => columns.keys.includes(c.key)).filter((c) => scope === null || c.kind !== "segment"),
    [allCols, columns.keys, scope],
  );
  const withCols = shownCols.length > 0;

  const appRows = (list: App[]) => buildRows(list, [], withCols ? expanded : new Set()).map(toRow);
  const sections: ListSection<AppRow>[] = [
    {
      key: "tags",
      title: "Tags",
      count: shownTags.length,
      rows: buildRows([], shownTags, new Set()).map(toRow),
      action: <button className="btn btn-sm" onClick={() => { setCreating(true); setSelected(new Set()); setStripOpen(true); }}>New tag</button>,
      emptyText: tagList.length === 0 ? "No tags yet. A tag groups apps so one grant covers all of them, also programs that start later." : "No tag matches.",
    },
    { key: "apps", title: "Apps", count: own.length, rows: appRows(own), emptyText: appList.length === 0 ? "No apps detected yet. The daemon discovers listening programs automatically." : "No app matches." },
    ...(system.length > 0
      ? [{ key: "system", title: "System services", count: system.length, hint: "Windows services and system processes", rows: appRows(system), collapsed: !systemOpen, onToggle: () => setShowSystem(!showSystem) }]
      : []),
  ];

  // ─── The columns of the list ───────────────────────────────────────────────
  const sumColumns: ListColumn<AppRow>[] = [
    {
      key: "tags",
      header: "Tags",
      className: "col-tags",
      cell: (r) => {
        if (r.m.kind === "tag") {
          const t = tagList.find((x) => x.id === r.m.target.id);
          return <span className="muted">{t && t.patterns.length > 0 ? `matches ${t.patterns.join(", ")}` : ""}</span>;
        }
        const mine = membershipsOf(r.m.target.id, tagList).filter((m) => (r.m.kind === "app" ? true : m.port !== null && r.m.port !== null && portLabel(m.port) === portLabel(r.m.port)));
        return (
          <>
            {mine.map((m) => (
              <button key={`${m.tag.id}-${m.port ? portLabel(m.port) : "*"}`} className="tag-pill" title="Show only this tag" onClick={() => setTagFilter(m.tag.id)}>
                {m.tag.label}{m.port && r.m.kind === "app" ? ` ${portLabel(m.port)}` : ""}
              </button>
            ))}
          </>
        );
      },
    },
    {
      key: "ports",
      header: "Ports",
      className: "ports-cell mono",
      cell: (r) => {
        if (r.m.kind === "tag") {
          const n = tagList.find((t) => t.id === r.m.target.id)?.members.length ?? 0;
          return <span className="muted">{n} {n === 1 ? "member" : "members"}</span>;
        }
        if (r.m.kind === "port") return null;
        const listening = r.m.app?.ports.filter((p) => p.listening) ?? [];
        return listening.length ? listening.map(portLabel).join(", ") : <span className="muted">not listening</span>;
      },
    },
    {
      key: "access",
      header: "Access",
      className: "col-access",
      cell: (r) => {
        if (r.m.kind === "port") return null;
        if (r.m.kind === "tag") {
          const n = (grants.data ?? []).filter((g) => g.target.kind === "tag" && g.target.id === r.m.target.id).length;
          return <span className="muted">{n === 0 ? "no grants" : `${n} grant${n === 1 ? "" : "s"}`}</span>;
        }
        const sum = accessSummary(r.m.target.id, grants.data ?? [], tagList);
        return (
          <>
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
          </>
        );
      },
    },
  ];

  const cellFor = (r: AppRow, c: Col): Cell => cellOf(r.m, c, ctx);
  const cellTitle = (cell: Cell): string => {
    switch (cell.state) {
      case "inherited":
        return `Inherited through ${cell.origin?.kind} ${cell.origin?.label}`;
      case "partial":
        return `Granted on ${cell.networkIds.map((id) => ctx.networks.find((n) => n.id === id)?.name ?? id).join(", ")} only`;
      case "granted":
        return cell.allNetworks ? "Granted on all networks" : "Granted";
      default:
        return "No access";
    }
  };
  const openCell = (r: AppRow, c: Col) => {
    setSelected(new Set([r.m.kind === "tag" ? r.key : `app:${r.m.target.id}`]));
    setHighlight({ subject: c.subject, networkId: c.networkId });
    setCreating(false);
    setStripOpen(true);
  };
  const subjectColumns: ListColumn<AppRow>[] = shownCols.map((c) => ({
    key: c.key,
    header: c.label,
    title: c.label,
    vertical: true,
    className: "matrix-cell",
    cell: (r) => <span aria-hidden="true">{CELL_GLYPH[cellFor(r, c).state]}</span>,
    cellClass: (r) => `cell-${cellFor(r, c).state}`,
    cellLabel: (r) => `${r.m.label} – ${c.label}: ${CELL_TEXT[cellFor(r, c).state]}`,
    cellTitle: (r) => cellTitle(cellFor(r, c)),
    onCell: (r) => openCell(r, c),
  }));

  // ─── Selection and the inspector ───────────────────────────────────────────
  const selectedApps = appList.filter((a) => selected.has(`app:${a.id}`));
  const selectedTags = tagList.filter((t) => selected.has(`tag:${t.id}`));
  const clear = () => {
    setSelected(new Set());
    setCreating(false);
    setHighlight(null);
  };
  const open = (r: AppRow) => {
    setSelected(new Set([r.m.kind === "tag" ? r.key : `app:${r.m.target.id}`]));
    setCreating(false);
    setHighlight(null);
    setStripOpen(true);
  };
  const collapsed = withCols && !stripOpen;
  const onCollapse = withCols ? () => setStripOpen(false) : undefined;

  const inspector = (() => {
    if (collapsed) return <Inspector label="Details" title="" collapsed onExpand={() => setStripOpen(true)} />;
    if (creating) return <NewTagForm onCreated={(label) => { setCreating(false); setSelectLabel(label); }} onClose={() => setCreating(false)} />;
    if (selectedApps.length === 1 && selectedTags.length === 0) {
      return <AppInspector key={selectedApps[0].id} id={selectedApps[0].id} highlight={highlight} onCollapse={onCollapse} onClose={clear} />;
    }
    if (selectedApps.length > 1) return <AppsInspector ids={selectedApps.map((a) => a.id)} onCollapse={onCollapse} onClose={clear} />;
    if (selectedTags.length === 1) {
      return <TagInspector key={selectedTags[0].id} tag={selectedTags[0]} highlight={highlight} onCollapse={onCollapse} onClose={clear} />;
    }
    if (selectedTags.length > 1) return <TagsInspector tags={selectedTags} onCollapse={onCollapse} onClose={clear} />;
    return <InspectorEmpty>Select an app or a tag to see who can reach it. Tick several to change them together.</InspectorEmpty>;
  })();

  // ─── The columns picker ────────────────────────────────────────────────────
  const section = (c: Col) => (c.kind === "group" ? "Groups" : c.kind === "peer" ? "Peers" : "Built-in");
  const order = { "Built-in": 0, Groups: 1, Peers: 2 } as const;
  const pickable = [...allCols].sort((a, b) => order[section(a)] - order[section(b)]);
  const chosen = pickable.filter((c) => columns.keys.includes(c.key)).length;
  const columnItems: PickerItem[] = [
    { id: ALL, label: "All", hint: `${pickable.length} columns`, state: chosen === 0 ? "off" : chosen === pickable.length ? "on" : "mixed" },
    ...pickable.map<PickerItem>((c) => ({ id: c.key, label: c.label, section: section(c), state: columns.keys.includes(c.key) ? "on" : "off" })),
  ];
  const toggleColumn = (item: PickerItem) => {
    if (item.id === ALL) {
      columns.set(item.state === "on" ? [] : pickable.map((c) => c.key));
      if (item.state !== "on") setStripOpen(false);
      return;
    }
    const next = columns.keys.includes(item.id) ? columns.keys.filter((k) => k !== item.id) : [...columns.keys, item.id];
    if (columns.keys.length === 0 && next.length > 0) setStripOpen(false);
    columns.set(next);
  };

  const pendingCount = appList.filter((a) => !a.reviewed).length;
  const filterTag: Tag | undefined = tagList.find((t) => t.id === tagFilter);
  const grantNetworks = (networks.data ?? []).filter((n) => n.grants_apply);

  return (
    <div>
      <div className="toolbar">
        <input
          className="input grow"
          type="search"
          aria-label="Filter apps"
          placeholder="Filter apps and tags"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <label className="check">
          <input type="checkbox" checked={pendingOnly} onChange={(e) => setPendingOnly(e.target.checked)} />
          Pending only ({pendingCount})
        </label>
        {filterTag && (
          <button className="tag-pill tag-pill-active" onClick={() => setTagFilter(null)} aria-label={`Stop filtering by tag ${filterTag.label}`}>
            tag: {filterTag.label} ×
          </button>
        )}
        {withCols && (
          <>
            <label htmlFor="overview-net" className="muted">Network</label>
            <select id="overview-net" className="input" value={scope ?? ""} onChange={(e) => setScope(e.target.value || null)}>
              <option value="">All networks</option>
              {grantNetworks.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
            </select>
          </>
        )}
        <Picker
          label="Columns"
          trigger={`Columns${shownCols.length > 0 ? ` (${shownCols.length})` : ""}`}
          items={columnItems}
          onToggle={toggleColumn}
          placeholder="Show who has access"
          align="right"
        />
      </div>
      {withCols && (
        <p className="hint">
          Columns show who can reach each app: ✓ granted, ◐ some networks, ↳ through a tag or group. Click a cell to change it in the details.
        </p>
      )}

      {apps.isLoading && <p className="muted">Loading…</p>}
      {apps.error && <div className="error-banner">{errorText(apps.error)}</div>}

      <div className={`split-layout${collapsed ? " split-collapsed" : ""}`}>
        <section aria-label="Apps and tags" className="split-list">
          <EntityList<AppRow>
            label="Apps and tags"
            sections={sections}
            columns={[...sumColumns, ...subjectColumns]}
            name={(r) => <RowName r={r} />}
            nameLabel={(r) => r.m.label.replace(/^tag /, "")}
            selected={selected}
            onSelect={(keys) => { setSelected(keys); setCreating(false); setHighlight(null); }}
            onOpen={open}
            selectAllKind="app"
            selectAllLabel="Select all shown apps"
            expand={(r) =>
              withCols && r.m.kind === "app" && (r.m.app?.ports.length ?? 0) > 0
                ? {
                    open: expanded.has(r.m.target.id),
                    label: `${expanded.has(r.m.target.id) ? "Collapse" : "Expand"} ports of ${r.m.label}`,
                    toggle: () => {
                      const next = new Set(expanded);
                      if (next.has(r.m.target.id)) next.delete(r.m.target.id);
                      else next.add(r.m.target.id);
                      setExpanded(next);
                    },
                  }
                : null
            }
          />
        </section>
        <section aria-label="Details" className="split-inspector">{inspector}</section>
      </div>
    </div>
  );
}

function RowName({ r }: { r: AppRow }) {
  if (r.m.kind === "tag") return <span className="row-tag"><span className="tag-glyph" aria-hidden="true">#</span>{r.m.label.replace(/^tag /, "")}</span>;
  if (r.m.kind === "port") return <span className="mono">{r.m.label}</span>;
  const a = r.m.app!;
  return (
    <>
      {a.name}{" "}
      {!a.reviewed && <span className="badge badge-pending">pending</span>}
      {a.identity_note === "unidentified" && <span className="badge reach reach-warn" title="Owner of the socket unknown">unidentified</span>}
    </>
  );
}
