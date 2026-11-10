import { useState, useCallback, createContext, useContext } from "react";

export interface ToastAction {
  label: string;
  onClick: () => void;
}

interface ToastMessage {
  id: number;
  text: string;
  type: "success" | "error";
  action?: ToastAction;
}

interface ToastContextType {
  /** `action` adds a button (Undo) and keeps the toast longer. */
  success: (text: string, action?: ToastAction) => void;
  error: (text: string) => void;
}

const ToastContext = createContext<ToastContextType>({
  success: () => {},
  error: () => {},
});

export function useToast() {
  return useContext(ToastContext);
}

let nextId = 0;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const dismiss = useCallback((id: number) => setToasts((prev) => prev.filter((t) => t.id !== id)), []);

  const addToast = useCallback(
    (text: string, type: "success" | "error", action?: ToastAction) => {
      const id = nextId++;
      setToasts((prev) => [...prev, { id, text, type, action }]);
      setTimeout(() => dismiss(id), action ? 9000 : 3000);
    },
    [dismiss],
  );

  const success = useCallback((text: string, action?: ToastAction) => addToast(text, "success", action), [addToast]);
  const error = useCallback((text: string) => addToast(text, "error"), [addToast]);

  return (
    <ToastContext.Provider value={{ success, error }}>
      {children}
      <div className="toast-container" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            <span>{t.text}</span>
            {t.action && (
              <button
                className="toast-action"
                onClick={() => {
                  dismiss(t.id);
                  t.action?.onClick();
                }}
              >
                {t.action.label}
              </button>
            )}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
