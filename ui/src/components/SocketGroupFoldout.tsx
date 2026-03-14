import { useState } from "react";
import {
  SocketGroupResponse, ManagedSocket, AclGroupResponse, SocketGroupAclEntry,
  deleteSocketGroup, addSocketToSocketGroup, removeSocketFromSocketGroup,
  setSocketGroupAddressPolicy, addSocketGroupAclEntry, removeSocketGroupAclEntry,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  sg: SocketGroupResponse;
  allSockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  backendFilter: string | null;
  onRefresh: () => void;
}

export default function SocketGroupFoldout({ sg, allSockets, backendFilter, onRefresh }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [managing, setManaging] = useState(false);
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const groupSockets = allSockets.filter((s) => s.socket_group_id === sg.group.id);
  const ungroupedSockets = allSockets.filter((s) => !s.socket_group_id);
  const filteredAddresses = sg.addresses.filter((a) => !backendFilter || a.backend_id === backendFilter);

  const handleDelete = () => {
    setConfirm({
      message: `Delete socket group "${sg.group.label}"? Member sockets will become ungrouped.`,
      action: async () => {
        try {
          await deleteSocketGroup(sg.group.id);
          toast.success("Socket group deleted");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const handleAddSocket = async (socketId: string) => {
    try {
      await addSocketToSocketGroup(sg.group.id, [socketId]);
      toast.success("Socket added to group");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemoveSocket = (socketId: string) => {
    setConfirm({
      message: `Remove socket from "${sg.group.label}"?`,
      action: async () => {
        try {
          await removeSocketFromSocketGroup(sg.group.id, socketId);
          toast.success("Socket removed");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  return (
    <div className="tree-l2" style={{ marginBottom: 4, padding: "4px 0" }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Header */}
      <div
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ opacity: 0.5, fontSize: 12 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span style={{ fontWeight: 500, fontSize: 13, color: "var(--text-muted)" }}>
            Socket Group: &ldquo;{sg.group.label}&rdquo;
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
            ({groupSockets.length} member{groupSockets.length !== 1 ? "s" : ""}, {sg.addresses.length} addr{sg.addresses.length !== 1 ? "s" : ""})
          </span>
        </div>
      </div>

      {expanded && (
        <div style={{ paddingLeft: 20, marginTop: 8 }}>
          {/* Shared addresses with policy/ACL */}
          {filteredAddresses.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div className="section-title">Shared Addresses</div>
              {filteredAddresses.map((a) => (
                <SocketGroupAddressSection
                  key={a.backend_id}
                  groupId={sg.group.id}
                  address={a}
                  aclEntries={sg.acl_entries.filter((e) => e.backend_id === a.backend_id)}
                  onRefresh={onRefresh}
                />
              ))}
            </div>
          )}

          {/* Members */}
          <div style={{ marginBottom: 8 }}>
            <div className="section-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Members</span>
              <button
                className={`btn btn-sm ${managing ? "btn-primary" : "btn-ghost"}`}
                onClick={(e) => { e.stopPropagation(); setManaging(!managing); }}
              >
                {managing ? "Done" : "Manage"}
              </button>
            </div>
            {groupSockets.length === 0 ? (
              <div style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>
                No sockets in this group
              </div>
            ) : (
              groupSockets.map((s) => (
                <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 0", fontSize: 12 }}>
                  <span>{s.port}/{s.protocol} (PID {s.pid})</span>
                  {managing && (
                    <button className="btn-danger btn-sm" style={{ fontSize: 10, padding: "0 4px" }} onClick={() => handleRemoveSocket(s.id)}>
                      Remove
                    </button>
                  )}
                </div>
              ))
            )}
            {managing && ungroupedSockets.length > 0 && (
              <div style={{ marginTop: 4, borderTop: "1px dashed var(--border)", paddingTop: 4 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>Add sockets:</div>
                {ungroupedSockets.map((s) => (
                  <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 6, padding: "1px 0", fontSize: 12 }}>
                    <span>{s.port}/{s.protocol} (PID {s.pid})</span>
                    <button className="btn btn-sm btn-ghost" style={{ fontSize: 10, padding: "0 4px" }} onClick={() => handleAddSocket(s.id)}>
                      + Add
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 8 }}>
            <button className="btn-danger btn-sm" onClick={handleDelete}>Delete Group</button>
          </div>
        </div>
      )}
    </div>
  );
}

function SocketGroupAddressSection({
  groupId, address, aclEntries, onRefresh,
}: {
  groupId: string;
  address: { backend_id: string; address: string; policy: string; interface: string; prefix_len: number };
  aclEntries: SocketGroupAclEntry[];
  onRefresh: () => void;
}) {
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const handlePolicy = async (p: string) => {
    if (p === "open" && address.policy !== "open") {
      setConfirm({
        message: `Setting ${address.backend_id} to open will allow ALL connections. Are you sure?`,
        action: async () => {
          try {
            await setSocketGroupAddressPolicy(groupId, address.backend_id, p);
            toast.success(`Policy set to ${p}`);
            onRefresh();
          } catch (e) {
            toast.error(String(e));
          }
        },
      });
      return;
    }
    try {
      await setSocketGroupAddressPolicy(groupId, address.backend_id, p);
      toast.success(`Policy set to ${p}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleAllow = async () => {
    if (!newIp.trim()) return;
    try {
      await addSocketGroupAclEntry(groupId, address.backend_id, newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success("ACL entry added");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemoveEntry = (entry: SocketGroupAclEntry) => {
    setConfirm({
      message: `Remove ${entry.allowed_ip}?`,
      action: async () => {
        try {
          await removeSocketGroupAclEntry(groupId, entry.id);
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
          <span className="badge" style={{ fontSize: 11, padding: "1px 6px", marginRight: 6 }}>{address.backend_id}</span>
          <span className="mono" style={{ fontSize: 12 }}>{address.address}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 4 }}>/{address.prefix_len} on {address.interface}</span>
          <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 4 }}>(shared)</span>
        </div>
        <span className={`badge badge-${address.policy}`}>
          <span className="badge-dot" />
          {address.policy}
        </span>
      </div>

      {/* Policy toggle */}
      <div className="policy-toggle" style={{ marginBottom: 6 }}>
        <button className={`policy-btn ${address.policy === "closed" ? "active-closed" : ""}`} onClick={() => handlePolicy("closed")}>Closed</button>
        <button className={`policy-btn ${address.policy === "open" ? "active-open" : ""}`} onClick={() => handlePolicy("open")}>Open</button>
      </div>

      {/* ACL section — only when closed */}
      {address.policy === "closed" && (
        <>
          <div className="acl-form" style={{ marginBottom: 4 }}>
            <input className="input" value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder="IPv6 to allow" onKeyDown={(e) => e.key === "Enter" && handleAllow()} style={{ flex: 2 }} />
            <input className="input" value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Label" onKeyDown={(e) => e.key === "Enter" && handleAllow()} style={{ flex: 1 }} />
            <button className="btn btn-primary btn-sm" onClick={handleAllow}>Allow</button>
          </div>
          {aclEntries.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Allowed IP</th><th>Label</th><th style={{ width: 60 }}></th></tr></thead>
                <tbody>
                  {aclEntries.map((entry) => (
                    <tr key={entry.id}>
                      <td className="mono">{entry.allowed_ip}</td>
                      <td>{entry.label || <span style={{ color: "var(--text-muted)" }}>&mdash;</span>}</td>
                      <td><button className="btn-danger btn-sm" onClick={() => handleRemoveEntry(entry)}>Remove</button></td>
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
