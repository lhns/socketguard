import { useEffect, useState } from "react";
import { listSockets, ManagedSocket } from "../api";

interface Props {
  onSelect: (id: string) => void;
}

export default function SocketList({ onSelect }: Props) {
  const [sockets, setSockets] = useState<ManagedSocket[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      setError(null);
      const resp = await listSockets();
      setSockets(resp.sockets);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="loading">Loading sockets...</div>;
  if (error) return <div className="error-banner">Cannot connect to daemon: {error}</div>;

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
