import { useEffect, useState, useRef, useCallback } from "react";
import { listSockets, onSocketsChanged, onDaemonConnected, startDaemon, ManagedSocket } from "../api";

interface Props {
  onSelect: (id: string) => void;
}

export default function SocketList({ onSelect }: Props) {
  const [sockets, setSockets] = useState<ManagedSocket[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const lastJson = useRef("");
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const resp = await listSockets();
      // Only update state if data actually changed
      const json = JSON.stringify(resp.sockets);
      if (json !== lastJson.current) {
        lastJson.current = json;
        setSockets(resp.sockets);
      }
      setStarting(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Fallback retry when in error state
  useEffect(() => {
    if (error) {
      retryTimer.current = setTimeout(() => refresh(), 5000);
      return () => {
        if (retryTimer.current) clearTimeout(retryTimer.current);
      };
    }
  }, [error, refresh]);

  useEffect(() => {
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

  if (loading) return <div className="loading">Loading sockets...</div>;
  if (error) return (
    <div className="error-banner" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
      <span>Cannot connect to daemon: {error}</span>
      <button className="btn btn-primary btn-sm" onClick={handleStartDaemon} disabled={starting}>
        {starting ? "Starting..." : "Start Daemon"}
      </button>
    </div>
  );

  if (sockets.length === 0) {
    return (
      <div className="card">
        <div className="empty">
          <div className="empty-icon">~</div>
          <p>No sockets detected yet.</p>
          <p style={{ fontSize: 12, marginTop: 4 }}>The daemon will discover listening sockets automatically.</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="card-header">
        <span className="card-title">
          Detected Sockets
          <span style={{ color: "var(--text-muted)", fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
            ({sockets.length})
          </span>
        </span>
        <button className="btn btn-sm" onClick={refresh}>Refresh</button>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Process</th>
                <th>Port</th>
                <th>Assigned IPv6</th>
                <th>Policy</th>
              </tr>
            </thead>
            <tbody>
              {sockets.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => onSelect(s.id)}>
                  <td>
                    <span style={{ fontWeight: 500 }}>{s.process_name}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: 12, marginLeft: 6 }}>PID {s.pid}</span>
                  </td>
                  <td>
                    <span className="mono">{s.port}</span>
                    <span style={{ color: "var(--text-muted)", marginLeft: 2 }}>/{s.protocol}</span>
                  </td>
                  <td className="mono">{s.assigned_ipv6}</td>
                  <td>
                    <span className={`badge badge-${s.policy}`}>
                      <span className="badge-dot" />
                      {s.policy}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
