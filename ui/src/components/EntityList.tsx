import { useEffect, useRef, type ReactNode } from "react";

export interface ListRow {
  key: string;
  /** Only rows of one kind are selected together. */
  kind: string;
  /** Has a checkbox. */
  selectable: boolean;
  /** A row that belongs to the one above it (a port of an app). */
  indent?: boolean;
}

export interface ListColumn<R> {
  key: string;
  header: ReactNode;
  title?: string;
  className?: string;
  /** A narrow column with the header written upright (a subject of the overview). */
  vertical?: boolean;
  cell: (row: R) => ReactNode;
  /** The cell is a button (the overview): a click opens the row at this column. */
  onCell?: (row: R) => void;
  cellClass?: (row: R) => string | undefined;
  cellLabel?: (row: R) => string;
  cellTitle?: (row: R) => string | undefined;
}

export interface ListSection<R> {
  key: string;
  title: ReactNode;
  count?: number;
  hint?: ReactNode;
  rows: R[];
  /** With `onToggle` the section can be folded. */
  collapsed?: boolean;
  onToggle?: () => void;
  action?: ReactNode;
  emptyText?: string;
}

interface Props<R extends ListRow> {
  label: string;
  sections: ListSection<R>[];
  columns: ListColumn<R>[];
  name: (row: R) => ReactNode;
  nameLabel: (row: R) => string;
  selected: Set<string>;
  onSelect: (keys: Set<string>) => void;
  /** Name or row clicked: show this row alone. */
  onOpen: (row: R) => void;
  /** The kind the header checkbox selects. */
  selectAllKind: string;
  selectAllLabel: string;
  rowClass?: (row: R) => string | undefined;
  /** A fold-out for the row (the ports of an app). */
  expand?: (row: R) => { open: boolean; toggle: () => void; label: string } | null;
  empty?: ReactNode;
}

/** The table of Apps and of Peers: sections of rows with checkboxes (shift extends a range), a
 * name that opens the row in the inspector, and optional extra columns. */
export default function EntityList<R extends ListRow>({
  label, sections, columns, name, nameLabel, selected, onSelect, onOpen, selectAllKind, selectAllLabel, rowClass, expand, empty,
}: Props<R>) {
  const anchor = useRef<string | null>(null);
  const all = useRef<HTMLInputElement>(null);

  const visible = sections.filter((s) => !s.collapsed).flatMap((s) => s.rows).filter((r) => r.selectable);
  const everyKind = visible.filter((r) => r.kind === selectAllKind);
  const chosen = everyKind.filter((r) => selected.has(r.key)).length;

  useEffect(() => {
    if (all.current) all.current.indeterminate = chosen > 0 && chosen < everyKind.length;
  }, [chosen, everyKind.length]);

  const kindOfKey = (key: string) => visible.find((r) => r.key === key)?.kind;

  const clickBox = (row: R, shift: boolean) => {
    // A selection holds one kind; picking another kind starts over.
    const next = new Set([...selected].filter((k) => kindOfKey(k) === row.kind));
    const from = anchor.current === null ? -1 : visible.findIndex((r) => r.key === anchor.current);
    const to = visible.findIndex((r) => r.key === row.key);
    if (shift && from >= 0 && visible[from].kind === row.kind) {
      const on = !next.has(row.key);
      for (const r of visible.slice(Math.min(from, to), Math.max(from, to) + 1)) {
        if (r.kind !== row.kind) continue;
        if (on) next.add(r.key);
        else next.delete(r.key);
      }
    } else if (next.has(row.key)) next.delete(row.key);
    else next.add(row.key);
    anchor.current = row.key;
    onSelect(next);
  };

  const span = 2 + columns.length;
  const total = sections.reduce((n, s) => n + s.rows.length, 0);

  return (
    <div className="table-wrap entity-wrap">
      <table className="entity-table" aria-label={label}>
        <thead>
          <tr>
            <th className="check-col">
              <input
                ref={all}
                type="checkbox"
                aria-label={selectAllLabel}
                checked={everyKind.length > 0 && chosen === everyKind.length}
                onChange={(e) => onSelect(e.target.checked ? new Set(everyKind.map((r) => r.key)) : new Set())}
              />
            </th>
            <th className="name-col">Name</th>
            {columns.map((c) => (
              <th key={c.key} className={`${c.vertical ? "col-vertical" : ""} ${c.className ?? ""}`} title={c.title} scope="col">
                {c.vertical ? <span className="col-vertical-text">{c.header}</span> : c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {total === 0 && sections.every((s) => !s.onToggle && !s.action) && (
            <tr><td colSpan={span} className="muted empty-cell">{empty ?? "Nothing to show."}</td></tr>
          )}
          {sections.map((s) => (
            <SectionRows
              key={s.key}
              section={s}
              span={span}
              columns={columns}
              name={name}
              nameLabel={nameLabel}
              selected={selected}
              clickBox={clickBox}
              onOpen={onOpen}
              rowClass={rowClass}
              expand={expand}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SectionRows<R extends ListRow>({
  section: s, span, columns, name, nameLabel, selected, clickBox, onOpen, rowClass, expand,
}: {
  section: ListSection<R>; span: number; columns: ListColumn<R>[]; name: (row: R) => ReactNode; nameLabel: (row: R) => string;
  selected: Set<string>; clickBox: (row: R, shift: boolean) => void; onOpen: (row: R) => void;
  rowClass?: (row: R) => string | undefined; expand?: Props<R>["expand"];
}) {
  const header = s.onToggle ? (
    <button className="link-btn section-toggle" aria-expanded={!s.collapsed} onClick={s.onToggle}>
      {s.collapsed ? "▸" : "▾"} {s.title}{s.count !== undefined ? ` (${s.count})` : ""}
    </button>
  ) : (
    <span className="section-label">{s.title}{s.count !== undefined ? ` (${s.count})` : ""}</span>
  );
  return (
    <>
      <tr className={s.onToggle ? "group-row" : "section-row"}>
        <td colSpan={span}>
          <div className="section-head">
            {header}
            {s.hint && <span className="muted section-hint">{s.hint}</span>}
            {s.action && <span className="section-action">{s.action}</span>}
          </div>
        </td>
      </tr>
      {!s.collapsed && s.rows.length === 0 && s.emptyText && (
        <tr><td colSpan={span} className="muted empty-cell">{s.emptyText}</td></tr>
      )}
      {!s.collapsed &&
        s.rows.map((row) => {
          const fold = expand?.(row) ?? null;
          const on = selected.has(row.key);
          return (
            <tr
              key={row.key}
              className={`entity-row${on ? " row-selected" : ""}${row.indent ? " row-indent" : ""} ${rowClass?.(row) ?? ""}`}
              onClick={(e) => {
                if ((e.target as HTMLElement).closest("button, input, a, select, label")) return;
                onOpen(row);
              }}
            >
              <td className="check-col">
                {row.selectable && (
                  <input
                    type="checkbox"
                    aria-label={`Select ${nameLabel(row)}`}
                    checked={on}
                    onChange={() => {}}
                    onClick={(e) => clickBox(row, e.shiftKey)}
                  />
                )}
              </td>
              <td className="name-cell">
                <div className="name-line">
                  {fold && (
                    <button className="link-btn fold-btn" aria-expanded={fold.open} aria-label={fold.label} onClick={fold.toggle}>
                      {fold.open ? "▾" : "▸"}
                    </button>
                  )}
                  <button className="link-btn row-name" aria-pressed={on} onClick={() => onOpen(row)}>{name(row)}</button>
                </div>
              </td>
              {columns.map((c) => {
                const cls = `${c.className ?? ""} ${c.cellClass?.(row) ?? ""}`;
                return (
                  <td key={c.key} className={cls}>
                    {c.onCell ? (
                      <button className="cell-btn" aria-label={c.cellLabel?.(row)} title={c.cellTitle?.(row)} onClick={() => c.onCell?.(row)}>
                        {c.cell(row)}
                      </button>
                    ) : (
                      c.cell(row)
                    )}
                  </td>
                );
              })}
            </tr>
          );
        })}
    </>
  );
}
