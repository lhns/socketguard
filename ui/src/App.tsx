import { useState } from "react";
import SocketList from "./components/SocketList";
import SocketDetail from "./components/SocketDetail";
import Settings from "./components/Settings";

type View = "list" | "detail" | "settings";

function App() {
  const [view, setView] = useState<View>("list");
  const [selectedSocket, setSelectedSocket] = useState<string | null>(null);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: "1rem", maxWidth: 900, margin: "0 auto" }}>
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem", borderBottom: "2px solid #333", paddingBottom: "0.5rem" }}>
        <h1 style={{ margin: 0, fontSize: "1.5rem" }}>SocketGuard</h1>
        <nav style={{ display: "flex", gap: "1rem" }}>
          <button onClick={() => { setView("list"); setSelectedSocket(null); }}
            style={navStyle(view === "list")}>
            Sockets
          </button>
          <button onClick={() => setView("settings")}
            style={navStyle(view === "settings")}>
            Settings
          </button>
        </nav>
      </header>

      {view === "list" && (
        <SocketList onSelect={(id) => { setSelectedSocket(id); setView("detail"); }} />
      )}
      {view === "detail" && selectedSocket && (
        <SocketDetail
          socketId={selectedSocket}
          onBack={() => { setView("list"); setSelectedSocket(null); }}
        />
      )}
      {view === "settings" && <Settings />}
    </div>
  );
}

function navStyle(active: boolean): React.CSSProperties {
  return {
    background: active ? "#333" : "transparent",
    color: active ? "#fff" : "#333",
    border: "1px solid #333",
    padding: "0.4rem 1rem",
    borderRadius: 4,
    cursor: "pointer",
    fontSize: "0.9rem",
  };
}

export default App;
