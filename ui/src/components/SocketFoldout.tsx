import { useEffect, useState } from "react";
import {
  getSocket, setBackendPolicy, allowBackendIp, removeAclEntry,
  addToAclGroup, onSocketsChanged, onDaemonConnected,
  ManagedSocket, AclEntry, AclGroupResponse,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  socket: ManagedSocket;
  aclGroups: AclGroupResponse[];
  onRefresh: () => void;
  onOpenDetail: (id: string) => void;
}

export default function SocketFoldout({ socket, aclGroups, onRefresh, onOpenDetail }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [acl, setAcl] = useState<AclEntry[]>([]);
  const [aclGroupId, setAclGroupId] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const loadDetail = async () => {
    try {
      const resp = await getSocket(socket.id);
      setAcl(resp.acl);
      setAclGroupId(resp.acl_group_id);
    } catch (e) {
      toast.error(String(e));
    }
  };

  useEffect(() => {
    if (expanded) loadDetail();
  }, [expanded, socket.id]);

  useEffect(() => {
    if (!expanded) return;
    const unlistens: (() => void)[] = [];
    onSocketsChanged(() => loadDetail()).then((fn) => unlistens.push(fn));
    onDaemonConnected(() => loadDetail()).then((fn) => unlistens.push(fn));
    return () => unlistens.forEach((fn) => fn());
  }, [expanded, socket.id]);

  const aclGroup = aclGroups.find((g) => g.members.includes(socket.id));

  // Group ACL entries by backend_id
  const aclByBackend: Record<string, AclEntry[]> = {};
  for (const entry of acl) {
    if (!aclByBackend[entry.backend_id]) aclByBackend[entry.backend_id] = [];
    aclByBackend[entry.backend_id].push(entry);
  }

  return (
    <div className="tree-l2" style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Collapsed header */}
      <div
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ opacity: 0.5, fontSize: 12 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span className="mono" style={{ fontSize: 13 }}>{socket.port}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 12 }}>/{socket.protocol}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 4 }}>
            PID {socket.pid}
          </span>
          {socket.socket_group_id && (
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>(in socket group)</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          {socket.addresses.map((addr) => (
            <span key={addr.backend_id} className={`badge badge-${addr.policy}`} style={{ fontSize: 10, padding: "1px 6px" }}>
              <span className="badge-dot" />
              {addr.backend_id}: {addr.policy}
            </span>
          ))}
          {aclGroup && (
            <span className="group-ref" style={{ fontSize: 11 }}>
              group: {aclGroup.group.label}
            </span>
          )}
        </div>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div style={{ marginTop: 8, paddingLeft: 20 }}>
          {/* Details */}
          {socket.exe_path && (
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              <span style={{ fontWeight: 500 }}>Exe:</span> <span className="mono" style={{ wordBreak: "break-all" }}>{socket.exe_path}</span>
            </div>
          )}
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
            First seen: {new Date(socket.first_seen).toLocaleString()} | Last seen: {new Date(socket.last_seen).toLocaleString()}
          </div>

          {/* Per-backend sections */}
          {socket.addresses.map((addr) => (
            <FoldoutAddressSection
              key={addr.backend_id}
              socketId={socket.id}
              addr={addr}
              acl={aclByBackend[addr.backend_id] || []}
              aclGroupId={aclGroupId}
              aclGroups={aclGroups}
              onRefresh={() => { loadDetail(); onRefresh(); }}
            />
          ))}

          <div style={{ marginTop: 8 }}>
            <button
              className="btn btn-sm btn-ghost"
              onClick={(e) => { e.stopPropagation(); onOpenDetail(socket.id); }}
            >
              Open full details &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function FoldoutAddressSection({
  socketId, addr, acl, aclGroupId, aclGroups, onRefresh,
}: {
  socketId: string;
  addr: { backend_id: string; address: string; policy: string; interface: string; prefix_len: number };
  acl: AclEntry[];
  aclGroupId: string | null;
  aclGroups: AclGroupResponse[];
  onRefresh: () => void;
}) {
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const doSetPolicy = async (p: string) => {
    try {
      await setBackendPolicy(socketId, addr.backend_id, p);
      toast.success(`${addr.backend_id} policy set to ${p}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handlePolicy = (p: string) => {
    if (p === "open") {
      setConfirm({
        message: `Setting ${addr.backend_id} to open will allow ALL incoming connections. Are you sure?`,
        action: () => doSetPolicy(p),
      });
    } else if (p === "group") {
      if (aclGroups.length === 0) {
        toast.error("No ACL groups exist");
        return;
      }
      if (!aclGroupId) {
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

  const handleAllow = async () => {
    if (!newIp.trim()) return;
    try {
      await allowBackendIp(socketId, addr.backend_id, newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success(`Allowed ${newIp.trim()}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemove = (entry: AclEntry) => {
    setConfirm({
      message: `Remove ${entry.allowed_ip}?`,
      action: async () => {
        try {
          await removeAclEntry(socketId, entry.id);
          toast.success("Removed");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  return (
    <div className="card" style={{ marginBottom: 8, padding: 8 }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <div>
          <span className="badge" style={{ fontSize: 11, padding: "1px 6px", marginRight: 6 }}>{addr.backend_id}</span>
          <span className="mono" style={{ fontSize: 12 }}>{addr.address}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 4 }}>/{addr.prefix_len} on {addr.interface}</span>
        </div>
        <span className={`badge badge-${addr.policy}`}>
          <span className="badge-dot" />
          {addr.policy}
        </span>
      </div>

      {/* Policy toggle */}
      <div className="policy-toggle" style={{ marginBottom: 6 }}>
        <button className={`policy-btn ${addr.policy === "closed" ? "active-closed" : ""}`} onClick={() => handlePolicy("closed")}>Closed</button>
        <button className={`policy-btn ${addr.policy === "open" ? "active-open" : ""}`} onClick={() => handlePolicy("open")}>Open</button>
        <button className={`policy-btn ${addr.policy === "group" ? "active-group" : ""}`} onClick={() => handlePolicy("group")}>Group</button>
      </div>

      {/* Group dropdown */}
      {addr.policy === "group" && aclGroups.length > 0 && (
        <div style={{ marginBottom: 6 }}>
          <select className="input" value={aclGroupId || ""} onChange={(e) => handleGroupChange(e.target.value)} style={{ width: "100%" }}>
            {aclGroups.map((g) => (
              <option key={g.group.id} value={g.group.id}>{g.group.label}</option>
            ))}
          </select>
        </div>
      )}

      {/* ACL section — only when closed */}
      {addr.policy === "closed" && (
        <>
          <div className="acl-form" style={{ marginBottom: 4 }}>
            <input className="input" value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder="IPv6 to allow" onKeyDown={(e) => e.key === "Enter" && handleAllow()} style={{ flex: 2 }} />
            <input className="input" value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Label" onKeyDown={(e) => e.key === "Enter" && handleAllow()} style={{ flex: 1 }} />
            <button className="btn btn-primary btn-sm" onClick={handleAllow}>Allow</button>
          </div>
          {acl.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Allowed IP</th><th>Label</th><th style={{ width: 60 }}></th></tr></thead>
                <tbody>
                  {acl.map((entry) => (
                    <tr key={entry.id}>
                      <td className="mono">{entry.allowed_ip}</td>
                      <td>{entry.label || <span style={{ color: "var(--text-muted)" }}>&mdash;</span>}</td>
                      <td><button className="btn-danger btn-sm" onClick={() => handleRemove(entry)}>Remove</button></td>
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
