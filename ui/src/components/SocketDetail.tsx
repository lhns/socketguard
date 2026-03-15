import { useEffect, useState } from "react";
import {
  getSocket, setBackendPolicy, allowBackendIp, removeAclEntry,
  onSocketsChanged, onDaemonConnected, addToAclGroup,
  ManagedSocket, AclEntry, SocketAddress, AclGroupResponse,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  socketId: string;
  aclGroups: AclGroupResponse[];
  onBack: () => void;
}

function AddressCard({
  socketId,
  addr,
  acl,
  aclGroupId,
  aclGroups,
  onRefresh,
}: {
  socketId: string;
  addr: SocketAddress;
  acl: AclEntry[];
  aclGroupId: string | null;
  aclGroups: AclGroupResponse[];
  onRefresh: () => void;
}) {
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const handlePolicy = (p: string) => {
    if (p === "open") {
      setConfirm({
        message: `Setting ${addr.backend_id} to open will allow ALL incoming connections on this address. Are you sure?`,
        action: () => doSetPolicy(p),
      });
    } else if (p === "group") {
      if (aclGroups.length === 0) {
        toast.error("No ACL groups exist");
        return;
      }
      if (!aclGroupId) {
        // Auto-select first group
        addToAclGroup(aclGroups[0].group.id, [socketId])
          .then(() => doSetPolicy("group"))
          .catch((e) => toast.error(String(e)));
      } else {
        doSetPolicy(p);
      }
    } else {
      doSetPolicy(p);
    }
  };

  const handleGroupChange = async (newGroupId: string) => {
    try {
      await addToAclGroup(newGroupId, [socketId]);
      toast.success("Moved to group");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const doSetPolicy = async (p: string) => {
    try {
      await setBackendPolicy(socketId, addr.backend_id, p);
      toast.success(`${addr.backend_id} policy set to ${p}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleAllow = async () => {
    if (!newIp.trim()) return;
    try {
      await allowBackendIp(socketId, addr.backend_id, newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success(`Allowed ${newIp.trim()} on ${addr.backend_id}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemove = (entry: AclEntry) => {
    setConfirm({
      message: `Remove access for ${entry.allowed_ip}${entry.label ? ` (${entry.label})` : ""} on ${addr.backend_id}?`,
      action: async () => {
        try {
          await removeAclEntry(socketId, entry.id);
          toast.success(`Removed ${entry.allowed_ip}`);
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const isInactive = addr.policy === "closed" && acl.length === 0;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Address header */}
      <div className={isInactive ? "address-inactive-label" : ""} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div>
          <span className="badge" style={{ fontSize: 11, padding: "1px 6px", marginRight: 8 }}>
            {addr.backend_id}
          </span>
          <span className="mono" style={{ fontSize: 13 }}>{addr.address}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 12, marginLeft: 6 }}>
            /{addr.prefix_len} on {addr.interface}
          </span>
        </div>
        <span className={`badge badge-${addr.policy}`}>
          <span className="badge-dot" />
          {addr.policy}
        </span>
      </div>

      {/* Policy toggle */}
      <div className="policy-toggle" style={{ marginBottom: 8 }}>
        <button
          className={`policy-btn ${addr.policy === "closed" ? "active-closed" : ""}`}
          onClick={() => handlePolicy("closed")}
        >
          Closed
        </button>
        <button
          className={`policy-btn ${addr.policy === "open" ? "active-open" : ""}`}
          onClick={() => handlePolicy("open")}
        >
          Open
        </button>
        <button
          className={`policy-btn ${addr.policy === "group" ? "active-group" : ""}`}
          onClick={() => handlePolicy("group")}
          title={aclGroupId ? "Inherit from ACL group" : "Join an ACL group first"}
        >
          Group
        </button>
      </div>

      {/* ACL Group dropdown — shown when policy is "group" */}
      {addr.policy === "group" && aclGroups.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <select
            className="input"
            value={aclGroupId || ""}
            onChange={(e) => handleGroupChange(e.target.value)}
            style={{ width: "100%" }}
          >
            {aclGroups.map((g) => (
              <option key={g.group.id} value={g.group.id}>{g.group.label}</option>
            ))}
          </select>
        </div>
      )}

      <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
        {addr.policy === "group"
          ? aclGroupId
            ? "Policy and ACL inherited from ACL group."
            : "Not in any group — treated as inactive (closed, no ACL)."
          : addr.policy === "closed"
          ? isInactive
            ? "Inactive — closed with no ACL entries. Address not active on interface."
            : "Only allowed IPs can connect via this address."
          : "All incoming connections are allowed on this address."}
      </p>

      {/* ACL section — only shown when closed (not group) */}
      {addr.policy === "closed" && (
        <>
          <div className="acl-form" style={{ marginBottom: 8 }}>
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
            <button className="btn btn-primary btn-sm" onClick={handleAllow}>Allow</button>
          </div>

          {acl.length === 0 ? (
            <div style={{ padding: "8px 0", color: "var(--text-muted)", fontSize: 12 }}>
              No allowed IPs — address is inactive (not added to interface).
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
        </>
      )}
    </div>
  );
}

export default function SocketDetail({ socketId, aclGroups, onBack }: Props) {
  const [socket, setSocket] = useState<ManagedSocket | null>(null);
  const [acl, setAcl] = useState<AclEntry[]>([]);
  const [aclGroupId, setAclGroupId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const resp = await getSocket(socketId);
      setSocket(resp.socket);
      setAcl(resp.acl);
      setAclGroupId(resp.acl_group_id);
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

  if (!socket) return <div className="loading">Loading...</div>;

  // Group ACL entries by backend_id
  const aclByBackend: Record<string, AclEntry[]> = {};
  for (const entry of acl) {
    if (!aclByBackend[entry.backend_id]) aclByBackend[entry.backend_id] = [];
    aclByBackend[entry.backend_id].push(entry);
  }

  return (
    <div>
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
            {aclGroupId && (
              <>
                <span style={{ margin: "0 6px", opacity: 0.3 }}>|</span>
                <span style={{ color: "var(--accent)" }}>In ACL group</span>
              </>
            )}
          </div>
        </div>
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

      {/* Per-backend address cards */}
      <div className="card-header">
        <span className="card-title">
          Backend Addresses
          {socket.addresses.length > 0 && (
            <span style={{ color: "var(--text-muted)", fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
              ({socket.addresses.length})
            </span>
          )}
        </span>
      </div>

      {socket.addresses.length === 0 ? (
        <div className="card">
          <div style={{ padding: "8px 0", color: "var(--text-muted)", fontSize: 13 }}>
            No addresses assigned.
          </div>
        </div>
      ) : (
        socket.addresses.map((addr) => (
          <AddressCard
            key={addr.backend_id}
            socketId={socketId}
            addr={addr}
            acl={aclByBackend[addr.backend_id] || []}
            aclGroupId={aclGroupId}
            aclGroups={aclGroups}
            onRefresh={refresh}
          />
        ))
      )}
    </div>
  );
}
