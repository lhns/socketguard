import { useEffect, useMemo, useState } from "react";
import type { ReservationView } from "../api";
import { locatorText } from "../components/AddressLines";
import EntityList, { type ListColumn, type ListRow, type ListSection } from "../components/EntityList";
import { InspectorEmpty } from "../components/Inspector";
import { NewReservationForm, ReservationInspector, ReservationsInspector } from "../components/ReservationInspector";
import { errorText } from "../lib";
import type { FocusMessage } from "../nav";
import { rowGrants, boundRows, servesText } from "../reservations";
import { useApps, useGrants, useList, useNetworks, useReservations, useSocketGroups, useTags } from "../queries";

interface ResRow extends ListRow {
  r: ReservationView;
}

const toRow = (r: ReservationView): ResRow => ({ key: `res:${r.id}`, kind: "res", selectable: true, r });

/** Reserved addresses: one entry per reservation, with the inspector beside it, like Apps. */
export default function ReservedPage({ focus = { seq: 0 } }: { focus?: FocusMessage }) {
  const reservations = useReservations();
  const list = useList(reservations);
  const apps = useList(useApps());
  const tags = useList(useTags());
  const groups = useList(useSocketGroups());
  const grants = useList(useGrants());
  const networks = useList(useNetworks());

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [closed, setClosed] = useState(false);
  const [selectLabel, setSelectLabel] = useState<string | null>(null);

  useEffect(() => {
    if (focus.seq === 0 || !focus.reservationId) return;
    setSelected(new Set([`res:${focus.reservationId}`]));
    setCreating(false);
    setClosed(false);
    // Only a new link counts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus.seq]);

  // A reservation that was just created is selected as soon as it is in the list.
  useEffect(() => {
    if (!selectLabel) return;
    const r = list.find((x) => x.label === selectLabel);
    if (r) {
      setSelected(new Set([`res:${r.id}`]));
      setSelectLabel(null);
    }
  }, [list, selectLabel]);

  const q = search.trim().toLowerCase();
  const shown = useMemo(
    () =>
      list
        .filter((r) => !q || r.label.toLowerCase().includes(q) || servesText(r, apps, tags, groups).toLowerCase().includes(q))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [list, apps, tags, groups, q],
  );

  const sections: ListSection<ResRow>[] = [
    {
      key: "reserved",
      title: "Reserved addresses",
      count: shown.length,
      rows: shown.map(toRow),
      action: (
        <button className="btn btn-sm" onClick={() => { setCreating(true); setSelected(new Set()); setClosed(false); }}>
          New reservation
        </button>
      ),
      emptyText: list.length === 0 ? "A named address that stays the same and can front ports of several apps." : "No reservation matches.",
    },
  ];

  const columns: ListColumn<ResRow>[] = [
    {
      key: "serves",
      header: "Serves",
      className: "col-serves",
      cell: (row) => {
        const text = servesText(row.r, apps, tags, groups);
        return text ? <span>{text}</span> : <span className="muted">nothing bound yet</span>;
      },
    },
    {
      key: "addresses",
      header: "Addresses",
      className: "col-addresses",
      cell: (row) =>
        row.r.addresses.length === 0 ? (
          <span className="muted">none yet</span>
        ) : (
          <ul className="plain-list address-brief">
            {row.r.addresses.map((a) => (
              <li key={a.id}>
                {networks.find((n) => n.id === a.network_id)?.name ?? a.network_id}: <span className="mono">{locatorText(a)}</span>{" "}
                <span className={`badge reach ${a.up ? "reach-ok" : "reach-muted"}`}>{a.up ? "up" : "closed"}</span>
              </li>
            ))}
          </ul>
        ),
    },
    {
      key: "access",
      header: "Access",
      className: "col-access",
      cell: (row) => {
        const own = row.r.grants.length;
        const single = rowGrants(boundRows(row.r, apps, tags, groups), grants).length;
        return (
          <>
            {row.r.grants.some((g) => g.subject.kind === "anyone" && g.network_id === null) && <span className="badge reach reach-bad">open to anyone</span>}
            <span className="muted">
              {own === 0 ? "no grants" : `${own} ${own === 1 ? "grant" : "grants"}`}
              {single > 0 && `, ${single} on single ports`}
            </span>
          </>
        );
      },
    },
  ];

  const selectedRes = list.filter((r) => selected.has(`res:${r.id}`));
  const close = () => setClosed(true);
  const hidden = closed && !creating;

  const inspector = (() => {
    if (creating) return <NewReservationForm onCreated={(label) => { setCreating(false); setSelectLabel(label); }} onClose={() => setCreating(false)} />;
    if (selectedRes.length === 1) return <ReservationInspector key={selectedRes[0].id} reservation={selectedRes[0]} highlight={null} onClose={close} />;
    if (selectedRes.length > 1) return <ReservationsInspector reservations={selectedRes} onClose={close} />;
    return <InspectorEmpty>Select a reserved address to see what it serves and who can reach it. Tick several to release them together.</InspectorEmpty>;
  })();

  return (
    <div>
      <div className="toolbar">
        <input
          className="input grow"
          type="search"
          aria-label="Filter reservations"
          placeholder="Filter reserved addresses"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {reservations.isLoading && <p className="muted">Loading…</p>}
      {reservations.error && <div className="error-banner">{errorText(reservations.error)}</div>}

      <div className={`split-layout${hidden ? " split-closed" : ""}`}>
        <section aria-label="Reservations" className="split-list">
          <EntityList<ResRow>
            label="Reservations"
            sections={sections}
            columns={columns}
            name={(row) => <ResName r={row.r} />}
            nameLabel={(row) => row.r.label}
            selected={selected}
            onSelect={(keys) => { setSelected(keys); setCreating(false); setClosed(false); }}
            onOpen={(row) => { setSelected(new Set([row.key])); setCreating(false); setClosed(false); }}
            selectAllKind="res"
            selectAllLabel="Select all shown reservations"
          />
        </section>
        {!hidden && <section aria-label="Details" className="split-inspector">{inspector}</section>}
      </div>
    </div>
  );
}

function ResName({ r }: { r: ReservationView }) {
  return (
    <>
      <span className="row-tag"><span className="tag-glyph" aria-hidden="true">◈</span>{r.label}</span>{" "}
      {r.conflicts.length > 0 && <span className="badge reach reach-warn" title="Several apps claim the same ports">port conflict</span>}
    </>
  );
}
