import type { ReactNode } from "react";
import type { NameCtx } from "../access";
import { useApps, useGroups, useNetworks, usePeers, useReservations, usePortGroups, useTags } from "../queries";

/** What names apps, tags, peers, groups and networks in access lists. */
export function useNameCtx(): NameCtx {
  return {
    apps: useApps().data ?? [],
    tags: useTags().data ?? [],
    peers: usePeers().data ?? [],
    groups: useGroups().data ?? [],
    networks: useNetworks().data ?? [],
    portGroups: usePortGroups().data ?? [],
    reservations: useReservations().data ?? [],
  };
}

interface Props {
  /** Names the panel for assistive technology. */
  label: string;
  title: ReactNode;
  subtitle?: ReactNode;
  badges?: ReactNode;
  /** Narrow strip: the details are hidden until a row or cell is clicked. */
  collapsed?: boolean;
  onExpand?: () => void;
  /** Offered with the overview columns, which need the width: the panel shrinks to a strip. */
  onCollapse?: () => void;
  /** Hides the panel; the selection stays. Without the overview columns (with them `onCollapse`
   * does the same, so only that button shows). */
  onClose?: () => void;
  children?: ReactNode;
}

/** The panel beside a list: it shows whatever is selected (one row, several rows, or a form).
 * Apps and Peers use the same panel. */
export default function Inspector({ label, title, subtitle, badges, collapsed, onExpand, onCollapse, onClose, children }: Props) {
  if (collapsed) {
    return (
      <aside className="inspector inspector-strip" aria-label={label}>
        <button className="btn-icon" onClick={onExpand} aria-label="Show details" title="Show details">‹</button>
        <span className="strip-text">Details</span>
      </aside>
    );
  }
  return (
    <aside className="inspector card" aria-label={label}>
      <header className="inspector-head">
        <div className="inspector-titles">
          <h2 className="card-title">{title}</h2>
          {subtitle && <div className="muted inspector-sub">{subtitle}</div>}
        </div>
        <div className="inspector-tools">
          {badges && <div className="badges">{badges}</div>}
          {onCollapse && <button className="btn-icon" onClick={onCollapse} aria-label="Hide details" title="Hide details">›</button>}
          {onClose && !onCollapse && <button className="btn-icon" onClick={onClose} aria-label="Close details" title="Close details">×</button>}
        </div>
      </header>
      {children}
    </aside>
  );
}

/** A titled part of the inspector. */
export function Section({ title, aside, children }: { title: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="insp-section">
      <div className="insp-section-head">
        <h3 className="section-title">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

/** Nothing selected. */
export function InspectorEmpty({ children }: { children: ReactNode }) {
  return <aside className="inspector card empty-inspector"><p className="muted">{children}</p></aside>;
}
