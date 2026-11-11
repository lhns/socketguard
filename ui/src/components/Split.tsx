import { Children, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

const MIN_INSPECTOR = 300;
const MIN_LIST = 360;
const HANDLE = 16;
const STEP = 24;

const keyOf = (id: string) => `socketguard.split.${id}`;

function load(id: string): number | null {
  try {
    const raw = window.localStorage.getItem(keyOf(id));
    const n = raw === null ? NaN : Number(raw);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}
function save(id: string, width: number | null) {
  try {
    if (width === null) window.localStorage.removeItem(keyOf(id));
    else window.localStorage.setItem(keyOf(id), String(Math.round(width)));
  } catch {
    // The width is only a convenience.
  }
}

interface Props {
  /** Names the page; the width is remembered per page. */
  id: string;
  /** The list and, unless `closed`, the inspector. */
  children: ReactNode;
  /** No inspector: the list takes the whole width. */
  closed?: boolean;
  /** The inspector is a narrow strip (overview columns need the width): no handle, no remembered width. */
  collapsed?: boolean;
}

/** The list and the inspector beside it, with a drag handle between them: mouse, arrow keys
 * (Home and End for the limits), double-click to reset. The width is clamped to the window and
 * remembered in localStorage. */
export default function Split({ id, children, closed = false, collapsed = false }: Props) {
  const [list, inspector] = Children.toArray(children);
  const box = useRef<HTMLDivElement>(null);
  const [saved, setSaved] = useState<number | null>(() => load(id));
  const [viewport, setViewport] = useState(() => window.innerWidth);

  // The container's own width is known after the first layout.
  const [, measured] = useState(0);
  useLayoutEffect(() => measured(box.current?.clientWidth ?? 0), []);
  useEffect(() => {
    const onResize = () => setViewport(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const total = (box.current?.clientWidth || viewport);
  const max = Math.max(MIN_INSPECTOR, total - MIN_LIST - HANDLE);
  const clamp = (w: number) => Math.min(Math.max(w, MIN_INSPECTOR), max);
  // Without a remembered width: about a third of the window, as before the handle existed.
  const width = clamp(saved ?? Math.min(Math.max(viewport * 0.34, 340), 460));

  const set = useCallback((w: number | null) => {
    setSaved(w);
    save(id, w);
  }, [id]);

  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    const rect = box.current?.getBoundingClientRect();
    const right = rect && rect.width > 0 ? rect.right : window.innerWidth;
    const move = (ev: MouseEvent) => set(clamp(right - ev.clientX - HANDLE / 2));
    const up = () => {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      document.body.classList.remove("split-dragging");
    };
    document.body.classList.add("split-dragging");
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  };

  const onKey = (e: React.KeyboardEvent) => {
    // The handle moves left to widen the inspector.
    const next =
      e.key === "ArrowLeft" ? width + STEP
      : e.key === "ArrowRight" ? width - STEP
      : e.key === "Home" ? MIN_INSPECTOR
      : e.key === "End" ? max
      : null;
    if (next === null) return;
    e.preventDefault();
    set(clamp(next));
  };

  const resizable = !closed && !collapsed;
  return (
    <div
      ref={box}
      className={`split-layout${collapsed ? " split-collapsed" : ""}${closed ? " split-closed" : ""}${resizable ? " split-resizable" : ""}`}
      style={resizable ? ({ "--insp-w": `${width}px` } as React.CSSProperties) : undefined}
    >
      {list}
      {resizable && (
        <div
          className="split-handle"
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize details"
          aria-valuenow={Math.round(width)}
          aria-valuemin={MIN_INSPECTOR}
          aria-valuemax={Math.round(max)}
          tabIndex={0}
          title="Drag to resize, double-click to reset"
          onMouseDown={startDrag}
          onDoubleClick={() => set(null)}
          onKeyDown={onKey}
        />
      )}
      {inspector}
    </div>
  );
}
