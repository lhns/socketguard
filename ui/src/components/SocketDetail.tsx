import { useEffect, useState } from "react";
import { getSocket, allowIp, removeAclEntry, setPolicy, onSocketsChanged, onDaemonConnected, ManagedSocket, AclEntry } from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  socketId: string;
  onBack: () => void;
}

export default function SocketDetail({ socketId, onBack }: Props) {
  const [socket, setSocket] = useState<ManagedSocket | null>(null);
  const [acl, setAcl] = useState<AclEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const refresh = async () => {
    try {
      const resp = await getSocket(socketId);
      setSocket(resp.socket);
      setAcl(resp.acl);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => { refresh(); }, [socketId]);

  useEffect(() => {
    const unlistens: (() => void)[] = [];
    onSocketsChanged(() => refresh()).then((fn) => unlistens.push(fn));
    onDaemonConnected(() => refresh()).then((fn) => unlistens.push(fn));
    return () => unlistens.forEach((fn) => fn());
  }, [socketId]);

  const handleAllow = async () => {
    if (!newIp.trim()) return;
    try {
      await allowIp(socketId, newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success(`Allowed ${newIp.trim()}`);
      refresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemove = (entry: AclEntry) => {
    setConfirm({
      message: `Remove access for ${entry.allowed_ip}${entry.label ? ` (${entry.label})` : ""}?`,
      action: async () => {
        try {
          await removeAclEntry(socketId, entry.id);
          toast.success(`Removed ${entry.allowed_ip}`);
          refresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const handlePolicy = (p: string) => {
    if (p === "open") {
      setConfirm({
        message: "Setting policy to open will allow ALL incoming connections to this socket. Are you sure?",
        action: () => doSetPolicy(p),
      });
    } else {
      doSetPolicy(p);
    }
  };

  const doSetPolicy = async (p: string) => {
    try {
      await setPolicy(socketId, p);
      toast.success(`Policy set to ${p}`);
      refresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  if (!socket) return <div className="loading">Loading...</div>;

  return (
    <div>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <button className="back-link" onClick={onBack}>
        &larr; Back to sockets
      </button>

      {error && <div className="error-banner">{error}</div>}

      {/* Header */}
      <div className="detail-header">
        <div>
          <div className="detail-title">{socket.process_name}</div>
          <div className="detail-subtitle">
            Port {socket.port}/{socket.protocol}
            <span style={{ margin: "0 6px", opacity: 0.3 }}>|</span>
            PID {socket.pid}
          </div>
        </div>
        <span className={`badge badge-${socket.policy}`}>
          <span className="badge-dot" />
          {socket.policy}
        </span>
      </div>

      {/* Addresses */}
      <div className="card">
        <div className="section-title">
          Addresses
          {socket.addresses.length > 0 && (
            <span style={{ textTransform: "none", letterSpacing: 0, fontWeight: 400, marginLeft: 6 }}>
              ({socket.addresses.length})
            </span>
          )}
        </div>
        {socket.addresses.length === 0 ? (
          <div style={{ padding: "8px 0", color: "var(--text-muted)", fontSize: 13 }}>
            No addresses assigned.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IPv6 Address</th>
                  <th>Backend</th>
                  <th>Interface</th>
                  <th>Prefix</th>
                </tr>
              </thead>
              <tbody>
                {socket.addresses.map((addr, i) => (
                  <tr key={`${addr.backend_id}-${i}`}>
                    <td className="mono">{addr.address}</td>
                    <td>
                      <span className="badge" style={{ fontSize: 11, padding: "1px 6px" }}>
                        {addr.backend_id}
                      </span>
                    </td>
                    <td>{addr.interface}</td>
                    <td className="mono">/{addr.prefix_len}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details */}
      <div className="card">
        <div className="section-title">Details</div>
        <div className="info-grid">
          {socket.exe_path && (
            <>
              <span className="info-label">Executable</span>
              <span className="info-value mono" style={{ wordBreak: "break-all" }}>{socket.exe_path}</span>
            </>
          )}
          <span className="info-label">First seen</span>
          <span className="info-value">{new Date(socket.first_seen).toLocaleString()}</span>
          <span className="info-label">Last seen</span>
          <span className="info-value">{new Date(socket.last_seen).toLocaleString()}</span>
        </div>
      </div>

      {/* Policy */}
      <div className="card">
        <div className="section-title">Policy</div>
        <div className="policy-toggle">
          <button
            className={`policy-btn ${socket.policy === "closed" ? "active-closed" : ""}`}
            onClick={() => handlePolicy("closed")}
          >
            Closed
          </button>
          <button
            className={`policy-btn ${socket.policy === "open" ? "active-open" : ""}`}
            onClick={() => handlePolicy("open")}
          >
            Open
          </button>
        </div>
        <p style={{ marginTop: 10, fontSize: 12, color: "var(--text-muted)" }}>
          {socket.policy === "closed"
            ? "Only allowed IPs can connect. Add entries below to grant access."
            : "All incoming connections are allowed without restriction."}
        </p>
      </div>

      {/* ACL */}
      <div className="card">
        <div className="section-title">
          Access Control List
          {acl.length > 0 && (
            <span style={{ textTransform: "none", letterSpacing: 0, fontWeight: 400, marginLeft: 6 }}>
              ({acl.length} {acl.length === 1 ? "entry" : "entries"})
            </span>
          )}
        </div>

        {socket.policy === "closed" && (
          <div className="acl-form">
            <input
              className="input"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              placeholder="IPv6 address to allow"
              onKeyDown={(e) => e.key === "Enter" && handleAllow()}
              style={{ flex: 2 }}
            />
            <input
              className="input"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (optional)"
              onKeyDown={(e) => e.key === "Enter" && handleAllow()}
              style={{ flex: 1 }}
            />
            <button className="btn btn-primary" onClick={handleAllow}>Allow</button>
          </div>
        )}

        {acl.length === 0 ? (
          <div style={{ padding: "16px 0", color: "var(--text-muted)", fontSize: 13 }}>
            {socket.policy === "closed"
              ? "No allowed IPs. All incoming traffic to this socket is blocked."
              : "ACL is not active when policy is open."}
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Allowed IP</th>
                  <th>Label</th>
                  <th>Added</th>
                  <th style={{ width: 60 }}></th>
                </tr>
              </thead>
              <tbody>
                {acl.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono">{entry.allowed_ip}</td>
                    <td>{entry.label || <span style={{ color: "var(--text-muted)" }}>&mdash;</span>}</td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                    <td>
                      <button className="btn-danger btn-sm" onClick={() => handleRemove(entry)}>
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
