import { useEffect, useState, useRef, useCallback, useMemo } from "react";
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
  const [hiddenBackends, setHiddenBackends] = useState<Set<string>>(new Set());
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const resp = await listSockets();
      setError(null);
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

  // Collect all unique backend IDs across all sockets
  const allBackendIds = useMemo(() => {
    const ids = new Set<string>();
    for (const s of sockets) {
      for (const a of s.addresses) ids.add(a.backend_id);
    }
    return Array.from(ids).sort();
  }, [sockets]);

  const toggleBackend = (id: string) => {
    setHiddenBackends((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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

      {allBackendIds.length > 1 && (
        <div className="backend-filters">
          {allBackendIds.map((id) => {
            const checked = !hiddenBackends.has(id);
            return (
              <label
                key={id}
                className={`backend-filter${checked ? " checked" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleBackend(id)}
                />
                {id}
              </label>
            );
          })}
        </div>
      )}

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
              {sockets.map((s) => {
                const visible = s.addresses.filter((a) => !hiddenBackends.has(a.backend_id));
                const multiBackend = allBackendIds.length > 1;
                return (
                  <tr key={s.id} className="clickable" onClick={() => onSelect(s.id)}>
                    <td>
                      <span style={{ fontWeight: 500 }}>{s.process_name}</span>
                      <span style={{ color: "var(--text-muted)", fontSize: 12, marginLeft: 6 }}>PID {s.pid}</span>
                    </td>
                    <td>
                      <span className="mono">{s.port}</span>
                      <span style={{ color: "var(--text-muted)", marginLeft: 2 }}>/{s.protocol}</span>
                    </td>
                    <td className="mono">
                      {visible.length === 0 ? (
                        <span style={{ color: "var(--text-muted)" }}>(none)</span>
                      ) : (
                        visible.map((a) => (
                          <div key={a.backend_id} style={{ lineHeight: 1.4 }}>
                            {a.address}
                            {multiBackend && (
                              <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 4 }}>
                                [{a.backend_id}]
                              </span>
                            )}
                          </div>
                        ))
                      )}
                    </td>
                    <td>
                      {(() => {
                        const policies = visible.map((a) => a.policy);
                        const unique = [...new Set(policies)];
                        if (unique.length === 0) {
                          return <span className="badge badge-closed"><span className="badge-dot" />{s.policy}</span>;
                        }
                        if (unique.length === 1) {
                          return <span className={`badge badge-${unique[0]}`}><span className="badge-dot" />{unique[0]}</span>;
                        }
                        return <span className="badge badge-mixed"><span className="badge-dot" />mixed</span>;
                      })()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
