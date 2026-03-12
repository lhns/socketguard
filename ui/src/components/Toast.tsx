import { useState, useEffect, useCallback, createContext, useContext } from "react";

interface ToastMessage {
  id: number;
  text: string;
  type: "success" | "error";
}

interface ToastContextType {
  success: (text: string) => void;
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

  const addToast = useCallback((text: string, type: "success" | "error") => {
    const id = nextId++;
    setToasts((prev) => [...prev, { id, text, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const success = useCallback((text: string) => addToast(text, "success"), [addToast]);
  const error = useCallback((text: string) => addToast(text, "error"), [addToast]);

  return (
    <ToastContext.Provider value={{ success, error }}>
      {children}
      <div style={{
        position: "fixed",
        bottom: 16,
        right: 16,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        zIndex: 1000,
      }}>
        {toasts.map((t) => (
          <div
            key={t.id}
            style={{
              padding: "0.6rem 1.2rem",
              borderRadius: 6,
              background: t.type === "success" ? "#2e7d32" : "#c62828",
              color: "#fff",
              fontSize: "0.9rem",
              boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
              animation: "fadeIn 0.2s ease-in",
            }}
          >
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
