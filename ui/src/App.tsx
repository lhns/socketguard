import { useState } from "react";
import SocketList from "./components/SocketList";
import SocketDetail from "./components/SocketDetail";
import Settings from "./components/Settings";

type View = "list" | "detail" | "settings";

function App() {
  const [view, setView] = useState<View>("list");
  const [selectedSocket, setSelectedSocket] = useState<string | null>(null);

  return (
    <>
      <header className="header">
        <div className="header-inner">
          <h1>
            <span className="logo">S</span>
            SocketGuard
          </h1>
          <nav className="nav">
            <button
              className={`nav-btn ${view !== "settings" ? "active" : ""}`}
              onClick={() => { setView("list"); setSelectedSocket(null); }}
            >
              Sockets
            </button>
            <button
              className={`nav-btn ${view === "settings" ? "active" : ""}`}
              onClick={() => setView("settings")}
            >
              Settings
            </button>
          </nav>
        </div>
      </header>

      <main className="content">
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
      </main>
    </>
  );
}

export default App;
