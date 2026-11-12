import { useEffect, useId, useRef, type ReactNode } from "react";

interface Props {
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  /** Style the confirm button as destructive. */
  danger?: boolean;
  /** A block above the body that says what is risky (a different look from the body). */
  warning?: ReactNode;
  /** The last attempt failed: shown inside the dialog, which stays open. */
  error?: string | null;
  /** The confirmed action is running. */
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({ title, children, confirmLabel = "Confirm", danger = true, warning, error, busy = false, onConfirm, onCancel }: Props) {
  const titleId = useId();
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel, busy]);

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} onClick={(e) => e.stopPropagation()}>
        <h2 id={titleId} className="modal-title">{title}</h2>
        {warning && <div className="modal-warning" role="note">{warning}</div>}
        <div className="modal-body">{children}</div>
        {error && <div className="error-banner" role="alert">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="btn" ref={cancelRef} disabled={busy} onClick={onCancel}>Cancel</button>
          <button type="button" className={danger ? "btn btn-danger" : "btn btn-primary"} disabled={busy} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
