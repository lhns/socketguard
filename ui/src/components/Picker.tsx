import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";

export interface PickerItem {
  id: string;
  label: string;
  /** Small text after the label. */
  hint?: string;
  /** All have it, some have it (mixed) or none. */
  state: "on" | "off" | "mixed";
  /** Items with the same section are listed under its heading. */
  section?: string;
}

/** An extra row at the end for something the typed text could create. */
export interface PickerCreate {
  label: ReactNode;
  pick: () => void;
}

interface Props {
  /** The button that opens the list. */
  trigger: ReactNode;
  /** Name of the list for assistive technology. */
  label: string;
  items: PickerItem[];
  onToggle: (item: PickerItem) => void;
  /** `Create "<typed>"`: given the typed text, the row to offer (null: none). */
  create?: (typed: string) => PickerCreate | null;
  /** Mirrors the typed text, for callers that parse it. */
  onQuery?: (typed: string) => void;
  placeholder?: string;
  /** Controlled open state; without it the picker opens and closes itself. */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** The text for an empty list. */
  empty?: string;
  triggerClass?: string;
  /** Which edge of the button the list lines up with; "right" for a button at the far right. */
  align?: "left" | "right";
  /** Names a button whose text is only a symbol. */
  compactLabel?: string;
}

/** A search popover with checkbox rows: tags on apps, groups on peers, members of tags and
 * groups, the other side of "add access" and the columns of the overview. Enter picks the
 * highlighted row, the arrow keys move, Escape and a click outside close it. */
export default function Picker({
  trigger, label, items, onToggle, create, onQuery, placeholder = "Search", open: controlled, onOpenChange,
  empty = "Nothing to pick.", triggerClass = "btn btn-sm", align = "left", compactLabel,
}: Props) {
  const id = useId();
  const [inner, setInner] = useState(false);
  const open = controlled ?? inner;
  const setOpen = (o: boolean) => {
    if (controlled === undefined) setInner(o);
    onOpenChange?.(o);
  };
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const q = query.trim().toLowerCase();
  const shown = useMemo(
    () => items.filter((i) => !q || i.label.toLowerCase().includes(q) || (i.hint ?? "").toLowerCase().includes(q)),
    [items, q],
  );
  const typed = query.trim();
  const createRow = typed !== "" && create && !items.some((i) => i.label.toLowerCase() === q) ? create(typed) : null;
  const rows = shown.length + (createRow ? 1 : 0);
  const at = Math.min(active, Math.max(rows - 1, 0));

  useEffect(() => {
    if (open) search.current?.focus();
    else {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  // The list floats at the button's position, so a scrolling panel around it does not clip it.
  const [pos, setPos] = useState<{ top: number; left: number; width: number; max: number } | null>(null);
  useLayoutEffect(() => {
    if (!open || !button.current) return;
    const r = button.current.getBoundingClientRect();
    const width = Math.min(300, window.innerWidth - 16);
    const left = align === "right" ? Math.max(8, r.right - width) : Math.min(Math.max(8, r.left), window.innerWidth - width - 8);
    const top = r.bottom + 4;
    setPos({ top, left, width, max: Math.max(140, Math.min(320, window.innerHeight - top - 76)) });
  }, [open, align]);

  useEffect(() => {
    if (!open) return;
    const outside = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    // Scrolling the page moves the button away from the list.
    const scrolled = (e: Event) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", outside);
    window.addEventListener("scroll", scrolled, true);
    window.addEventListener("resize", scrolled);
    return () => {
      document.removeEventListener("mousedown", outside);
      window.removeEventListener("scroll", scrolled, true);
      window.removeEventListener("resize", scrolled);
    };
    // `setOpen` only closes over the controlled flag and the callback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, controlled, onOpenChange]);

  const change = (v: string) => {
    setQuery(v);
    setActive(0);
    onQuery?.(v.trim());
  };
  const pickRow = (i: number) => {
    if (i < shown.length) onToggle(shown[i]);
    else if (createRow) {
      createRow.pick();
      change("");
    }
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive(Math.min(at + 1, rows - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive(Math.max(at - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (rows > 0) pickRow(at);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      button.current?.focus();
    }
  };

  let lastSection: string | undefined;
  return (
    <div className="picker" ref={root}>
      <button
        type="button"
        ref={button}
        className={triggerClass}
        aria-haspopup="listbox"
        aria-label={compactLabel}
        title={compactLabel}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen(!open)}
      >
        {trigger}
      </button>
      {open && (
        <div
          className="picker-pop"
          id={id}
          role="dialog"
          aria-label={label}
          onKeyDown={onKey}
          style={pos ? { top: pos.top, left: pos.left, width: pos.width } : { visibility: "hidden" }}
        >
          <input
            ref={search}
            className="input picker-search"
            type="search"
            role="combobox"
            aria-expanded="true"
            aria-controls={`${id}-list`}
            aria-activedescendant={rows > 0 ? `${id}-r${at}` : undefined}
            aria-label={`Search ${label}`}
            placeholder={placeholder}
            autoComplete="off"
            value={query}
            onChange={(e) => change(e.target.value)}
          />
          <ul className="picker-list" id={`${id}-list`} role="listbox" aria-label={label} aria-multiselectable="true" style={{ maxHeight: pos?.max }}>
            {shown.map((item, i) => {
              const heading = item.section !== undefined && item.section !== lastSection ? item.section : null;
              lastSection = item.section;
              return (
                <li key={item.id} role="presentation">
                  {heading && <div className="picker-heading">{heading}</div>}
                  <PickerRow id={`${id}-r${i}`} item={item} active={i === at} onPick={() => onToggle(item)} onHover={() => setActive(i)} />
                </li>
              );
            })}
            {createRow && (
              <li role="presentation">
                <button
                  type="button"
                  id={`${id}-r${shown.length}`}
                  role="option"
                  aria-selected={shown.length === at}
                  className={`picker-row picker-create${shown.length === at ? " picker-active" : ""}`}
                  onMouseEnter={() => setActive(shown.length)}
                  onClick={() => pickRow(shown.length)}
                >
                  {createRow.label}
                </button>
              </li>
            )}
            {rows === 0 && <li className="picker-empty muted" role="presentation">{typed ? "No match." : empty}</li>}
          </ul>
        </div>
      )}
    </div>
  );
}

function PickerRow({
  id, item, active, onPick, onHover,
}: { id: string; item: PickerItem; active: boolean; onPick: () => void; onHover: () => void }) {
  const box = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (box.current) box.current.indeterminate = item.state === "mixed";
  }, [item.state]);
  return (
    <label
      id={id}
      role="option"
      aria-selected={item.state !== "off"}
      className={`picker-row${active ? " picker-active" : ""}`}
      onMouseEnter={onHover}
    >
      <input
        ref={box}
        type="checkbox"
        tabIndex={-1}
        checked={item.state === "on"}
        aria-checked={item.state === "mixed" ? "mixed" : item.state === "on"}
        onChange={onPick}
      />
      <span className="picker-label">{item.label}</span>
      {item.hint && <span className="muted picker-hint">{item.hint}</span>}
    </label>
  );
}
