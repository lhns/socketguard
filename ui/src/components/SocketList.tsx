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

  if (loading) return <p>Loading...</p>;
  if (error) return <p style={{ color: "red" }}>Error: {error}</p>;

  if (sockets.length === 0) {
    return <p>No sockets detected. The daemon will discover them automatically.</p>;
  }

  const policyColor = (policy: string) => {
    switch (policy) {
      case "closed": return "#d32f2f";
      case "open": return "#388e3c";
      case "managed": return "#1976d2";
      default: return "#666";
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h2 style={{ margin: 0 }}>Detected Sockets</h2>
        <button onClick={refresh} style={{ padding: "0.3rem 0.8rem", cursor: "pointer" }}>Refresh</button>
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #ccc", textAlign: "left" }}>
            <th style={thStyle}>Process</th>
            <th style={thStyle}>Port</th>
            <th style={thStyle}>IPv6</th>
            <th style={thStyle}>Policy</th>
            <th style={thStyle}>Backend</th>
          </tr>
        </thead>
        <tbody>
          {sockets.map((s) => (
            <tr
              key={s.id}
              onClick={() => onSelect(s.id)}
              style={{ cursor: "pointer", borderBottom: "1px solid #eee" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "#f5f5f5")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "")}
            >
              <td style={tdStyle}>{s.process_name} <span style={{ color: "#999", fontSize: "0.8em" }}>({s.pid})</span></td>
              <td style={tdStyle}>{s.port}/{s.protocol}</td>
              <td style={{ ...tdStyle, fontFamily: "monospace", fontSize: "0.85em" }}>{s.assigned_ipv6}</td>
              <td style={tdStyle}>
                <span style={{ color: policyColor(s.policy), fontWeight: "bold" }}>{s.policy}</span>
              </td>
              <td style={tdStyle}>{s.backend}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const thStyle: React.CSSProperties = { padding: "0.5rem", fontSize: "0.85rem" };
const tdStyle: React.CSSProperties = { padding: "0.5rem" };
