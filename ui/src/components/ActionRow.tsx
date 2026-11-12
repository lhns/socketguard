import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const Ctx = createContext<{ setFormOpen: (open: boolean) => void; formOpen: boolean } | null>(null);

/** The one layout of constructive actions: small secondary buttons in a left-aligned row (8px gap,
 * wrapping as whole buttons). A form that an action opens takes the full width of the row and
 * the other buttons step aside while it is open (see `useFormOpen`). */
export function ActionRow({ children }: { children: ReactNode }) {
  const [formOpen, setFormOpen] = useState(false);
  return (
    <Ctx.Provider value={{ formOpen, setFormOpen }}>
      <div className="action-row" role="group" aria-label="Actions">{children}</div>
    </Ctx.Provider>
  );
}

/** For an action that opens an inline form: reports `open` to the row. Returns whether another
 * action's form is open, in which case this action hides. */
export function useFormOpen(open: boolean): boolean {
  const ctx = useContext(Ctx);
  const set = ctx?.setFormOpen;
  useEffect(() => {
    if (!set || !open) return;
    set(true);
    return () => set(false);
  }, [set, open]);
  return !open && (ctx?.formOpen ?? false);
}

/** A plain action button of the row; it steps aside while a form is open. */
export function RowButton({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const aside = useFormOpen(false);
  if (aside) return null;
  return <button type="button" className="btn btn-sm" {...props}>{children}</button>;
}

/** The destructive action of an inspector, alone at its end behind a divider. */
export function DangerZone({ children }: { children: ReactNode }) {
  return <div className="danger-zone">{children}</div>;
}
