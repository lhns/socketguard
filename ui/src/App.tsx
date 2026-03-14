import { useState, useEffect, useCallback, useRef } from "react";
import {
  listSockets, onSocketsChanged, onDaemonConnected, startDaemon, initSSE,
  ManagedSocket, AclGroupResponse, SocketGroupResponse,
} from "./api";
import AppTree from "./components/AppTree";
import SocketDetail from "./components/SocketDetail";
import Settings from "./components/Settings";

function App() {
  const [sockets, setSockets] = useState<ManagedSocket[]>([]);
  const [aclGroups, setAclGroups] = useState<AclGroupResponse[]>([]);
  const [socketGroups, setSocketGroups] = useState<SocketGroupResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [selectedSocket, setSelectedSocket] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const lastJson = useRef("");
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const resp = await listSockets();
      setError(null);
      const json = JSON.stringify(resp);
      if (json !== lastJson.current) {
        lastJson.current = json;
        setSockets(resp.sockets);
        setAclGroups(resp.acl_groups);
        setSocketGroups(resp.socket_groups);
      }
      setStarting(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (error) {
      retryTimer.current = setTimeout(() => refresh(), 5000);
      return () => {
        if (retryTimer.current) clearTimeout(retryTimer.current);
      };
    }
  }, [error, refresh]);

  useEffect(() => {
    initSSE().catch(console.error);
    refresh();
    const unlistens: (() => void)[] = [];
    onSocketsChanged(() => refresh()).then((fn) => unlistens.push(fn));
    onDaemonConnected(() => refresh()).then((fn) => unlistens.push(fn));
    return () => unlistens.forEach((fn) => fn());
  }, [refresh]);

  const handleStartDaemon = async () => {
    setStarting(true);
    try {
      await startDaemon();
    } catch (e) {
      setStarting(false);
      setError(String(e));
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <>
      <header className="header">
        <div className="header-inner">
          <h1>
            <span className="logo">S</span>
            SocketGuard
          </h1>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {selectedSocket && (
              <button
                className="btn btn-sm btn-ghost"
                onClick={() => setSelectedSocket(null)}
              >
                &larr; Back
              </button>
            )}
            <button
              className="btn btn-sm btn-ghost"
              onClick={() => { setShowSettings(!showSettings); setSelectedSocket(null); }}
              title="Settings"
              style={{ fontSize: 16, padding: "4px 8px" }}
            >
              {showSettings ? "x" : "\u2699"}
            </button>
          </div>
        </div>
      </header>

      <main className="content">
        {error && (
          <div className="error-banner" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
            <span>Cannot connect to daemon: {error}</span>
            <button className="btn btn-primary btn-sm" onClick={handleStartDaemon} disabled={starting}>
              {starting ? "Starting..." : "Start Daemon"}
            </button>
          </div>
        )}

        {showSettings ? (
          <Settings />
        ) : selectedSocket ? (
          <SocketDetail
            socketId={selectedSocket}
            aclGroups={aclGroups}
            onBack={() => setSelectedSocket(null)}
          />
        ) : sockets.length === 0 && !error ? (
          <div className="card">
            <div className="empty">
              <div className="empty-icon">~</div>
              <p>No sockets detected yet.</p>
              <p style={{ fontSize: 12, marginTop: 4 }}>The daemon will discover listening sockets automatically.</p>
            </div>
          </div>
        ) : (
          <AppTree
            sockets={sockets}
            aclGroups={aclGroups}
            socketGroups={socketGroups}
            onRefresh={refresh}
            onSelectSocket={(id) => setSelectedSocket(id)}
          />
        )}
      </main>
    </>
  );
}

export default App;
