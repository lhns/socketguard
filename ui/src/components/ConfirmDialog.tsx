interface Props {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({ message, onConfirm, onCancel }: Props) {
  return (
    <div style={{
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,0.4)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 999,
    }}>
      <div style={{
        background: "#fff",
        padding: "1.5rem",
        borderRadius: 8,
        maxWidth: 400,
        boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
      }}>
        <p style={{ margin: "0 0 1.2rem", lineHeight: 1.5 }}>{message}</p>
        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end" }}>
          <button
            onClick={onCancel}
            style={{
              padding: "0.4rem 1rem",
              border: "1px solid #999",
              borderRadius: 4,
              background: "#fff",
              cursor: "pointer",
            }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            style={{
              padding: "0.4rem 1rem",
              border: "1px solid #c62828",
              borderRadius: 4,
              background: "#c62828",
              color: "#fff",
              cursor: "pointer",
            }}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}
