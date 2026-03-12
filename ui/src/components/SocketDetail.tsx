import { useEffect, useState } from "react";
import { getSocket, allowIp, removeAclEntry, setPolicy, ManagedSocket, AclEntry } from "../api";
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
        message: "Setting policy to \"open\" will allow all incoming connections to this socket. Continue?",
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

  if (!socket) return <p>Loading...</p>;

  return (
    <div>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <button onClick={onBack} style={{ marginBottom: "1rem", cursor: "pointer" }}>Back</button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      <h2>{socket.process_name} :{socket.port}/{socket.protocol}</h2>

      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0.3rem 1rem", marginBottom: "1.5rem" }}>
        <strong>PID:</strong> <span>{socket.pid}</span>
        <strong>IPv6:</strong> <span style={{ fontFamily: "monospace" }}>{socket.assigned_ipv6}</span>
        <strong>Backend:</strong> <span>{socket.backend}</span>
        <strong>First seen:</strong> <span>{new Date(socket.first_seen).toLocaleString()}</span>
        <strong>Last seen:</strong> <span>{new Date(socket.last_seen).toLocaleString()}</span>
      </div>

      <div style={{ marginBottom: "1.5rem" }}>
        <h3>Policy</h3>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {(["closed", "managed", "open"] as const).map((p) => (
            <button
              key={p}
              onClick={() => handlePolicy(p)}
              style={{
                padding: "0.4rem 1rem",
                background: socket.policy === p ? "#333" : "#eee",
                color: socket.policy === p ? "#fff" : "#333",
                border: "1px solid #333",
                borderRadius: 4,
                cursor: "pointer",
              }}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <div>
        <h3>Access Control List</h3>

        {socket.policy === "managed" && (
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
            <input
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              placeholder="IPv6 address"
              style={{ flex: 2, padding: "0.4rem" }}
            />
            <input
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (optional)"
              style={{ flex: 1, padding: "0.4rem" }}
            />
            <button onClick={handleAllow} style={{ padding: "0.4rem 1rem", cursor: "pointer" }}>
              Allow
            </button>
          </div>
        )}

        {acl.length === 0 ? (
          <p style={{ color: "#999" }}>No ACL entries. {socket.policy === "managed" ? "Add IPs above to grant access." : ""}</p>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "2px solid #ccc", textAlign: "left" }}>
                <th style={{ padding: "0.4rem" }}>Allowed IP</th>
                <th style={{ padding: "0.4rem" }}>Label</th>
                <th style={{ padding: "0.4rem" }}>Added</th>
                <th style={{ padding: "0.4rem" }}></th>
              </tr>
            </thead>
            <tbody>
              {acl.map((entry) => (
                <tr key={entry.id} style={{ borderBottom: "1px solid #eee" }}>
                  <td style={{ padding: "0.4rem", fontFamily: "monospace" }}>{entry.allowed_ip}</td>
                  <td style={{ padding: "0.4rem" }}>{entry.label || "-"}</td>
                  <td style={{ padding: "0.4rem", fontSize: "0.85em" }}>{new Date(entry.created_at).toLocaleString()}</td>
                  <td style={{ padding: "0.4rem" }}>
                    <button onClick={() => handleRemove(entry)} style={{ cursor: "pointer", color: "red", background: "none", border: "none" }}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
