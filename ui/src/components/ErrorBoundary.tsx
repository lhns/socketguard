import React from "react";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  State
> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div
        style={{
          padding: "40px 24px",
          maxWidth: 600,
          margin: "0 auto",
          fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif",
          color: "#e1e4ed",
        }}
      >
        <h2 style={{ color: "#e05252", marginBottom: 16, fontSize: 18 }}>
          UI Error
        </h2>
        <pre
          style={{
            background: "#1a1d27",
            border: "1px solid #2e3140",
            borderRadius: 8,
            padding: 16,
            fontSize: 13,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            marginBottom: 20,
          }}
        >
          {error.message}
          {error.stack && "\n\n" + error.stack}
        </pre>
        <button
          onClick={() => window.location.reload()}
          style={{
            padding: "8px 20px",
            background: "#5b8def",
            border: "none",
            borderRadius: 6,
            color: "#fff",
            fontSize: 13,
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          Reload
        </button>
      </div>
    );
  }
}
