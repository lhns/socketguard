import { useState } from "react";
import {
  AclGroupResponse, AclEntry, ManagedSocket,
  updateAclGroup, deleteAclGroup, addToAclGroup, removeFromAclGroup,
  addAclGroupEntry, removeAclGroupEntry,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  group: AclGroupResponse;
  allSockets: ManagedSocket[];
  onRefresh: () => void;
}

export default function AclGroupNode({ group, allSockets, onRefresh }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [newBackend, setNewBackend] = useState("");
  const [adding, setAdding] = useState(false);
  const toast = useToast();

  const memberSockets = allSockets.filter((s) => group.members.includes(s.id));
  const nonMembers = allSockets.filter((s) => !group.members.includes(s.id));

  const handlePolicyToggle = async (p: string) => {
    try {
      await updateAclGroup(group.group.id, undefined, p);
      toast.success(`Group policy set to ${p}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleDelete = () => {
    setConfirm({
      message: `Delete ACL group "${group.group.label}"? Member sockets will revert to their own ACL.`,
      action: async () => {
        try {
          await deleteAclGroup(group.group.id);
          toast.success("Group deleted");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const handleAddSocket = async (socketId: string) => {
    try {
      await addToAclGroup(group.group.id, [socketId]);
      toast.success("Socket added to group");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemoveSocket = (socketId: string, name: string) => {
    setConfirm({
      message: `Remove ${name} from "${group.group.label}"?`,
      action: async () => {
        try {
          await removeFromAclGroup(group.group.id, socketId);
          toast.success("Socket removed from group");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const handleAddEntry = async () => {
    if (!newIp.trim() || !newBackend.trim()) return;
    try {
      await addAclGroupEntry(group.group.id, newBackend.trim(), newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success("ACL entry added to group");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemoveEntry = (entry: AclEntry) => {
    setConfirm({
      message: `Remove ${entry.allowed_ip} from group ACL?`,
      action: async () => {
        try {
          await removeAclGroupEntry(group.group.id, entry.id);
          toast.success("Entry removed");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  // Get unique backend IDs from member sockets
  const backendIds = [...new Set(memberSockets.flatMap((s) => s.addresses.map((a) => a.backend_id)))].sort();
  if (!newBackend && backendIds.length > 0) {
    // Set default backend for new entry form
    setTimeout(() => setNewBackend(backendIds[0]), 0);
  }

  return (
    <div className="card tree-l1" style={{ marginBottom: 8 }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      <div
        className="tree-node-header"
        onClick={() => setExpanded(!expanded)}
        style={{ cursor: "pointer" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
          <span style={{ opacity: 0.5, fontSize: 12 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span style={{ fontWeight: 500, color: "var(--accent)" }}>ACL Group:</span>
          <span style={{ fontWeight: 600 }}>{group.group.label}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 12 }}>
            ({group.members.length} socket{group.members.length !== 1 ? "s" : ""})
          </span>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className={`badge badge-${group.group.policy}`}>
            <span className="badge-dot" />
            {group.group.policy}
          </span>
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: 12, paddingLeft: 20 }}>
          {/* Policy toggle */}
          <div style={{ marginBottom: 12 }}>
            <div className="section-title">Group Policy</div>
            <div className="policy-toggle" style={{ marginBottom: 8 }}>
              <button
                className={`policy-btn ${group.group.policy === "closed" ? "active-closed" : ""}`}
                onClick={() => handlePolicyToggle("closed")}
              >
                Closed
              </button>
              <button
                className={`policy-btn ${group.group.policy === "open" ? "active-open" : ""}`}
                onClick={() => handlePolicyToggle("open")}
              >
                Open
              </button>
            </div>
          </div>

          {/* Group ACL entries */}
          {group.group.policy === "closed" && (
            <div style={{ marginBottom: 12 }}>
              <div className="section-title">Group ACL</div>
              <div className="acl-form" style={{ marginBottom: 8 }}>
                {backendIds.length > 1 && (
                  <select
                    className="input"
                    value={newBackend}
                    onChange={(e) => setNewBackend(e.target.value)}
                    style={{ width: 120 }}
                  >
                    {backendIds.map((id) => (
                      <option key={id} value={id}>{id}</option>
                    ))}
                  </select>
                )}
                <input
                  className="input"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="IPv6 to allow"
                  onKeyDown={(e) => e.key === "Enter" && handleAddEntry()}
                  style={{ flex: 2 }}
                />
                <input
                  className="input"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  placeholder="Label"
                  onKeyDown={(e) => e.key === "Enter" && handleAddEntry()}
                  style={{ flex: 1 }}
                />
                <button className="btn btn-primary btn-sm" onClick={handleAddEntry}>Allow</button>
              </div>
              {group.entries.length === 0 ? (
                <div style={{ fontSize: 12, color: "var(--text-muted)", padding: "4px 0" }}>
                  No ACL entries — members with "group" policy will be inactive.
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Backend</th>
                        <th>Allowed IP</th>
                        <th>Label</th>
                        <th style={{ width: 60 }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.entries.map((entry) => (
                        <tr key={entry.id}>
                          <td style={{ fontSize: 12 }}>{entry.backend_id}</td>
                          <td className="mono">{entry.allowed_ip}</td>
                          <td>{entry.label || <span style={{ color: "var(--text-muted)" }}>&mdash;</span>}</td>
                          <td>
                            <button className="btn-danger btn-sm" onClick={() => handleRemoveEntry(entry)}>
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
          )}

          {/* Members */}
          <div style={{ marginBottom: 12 }}>
            <div className="section-title">Members</div>
            {memberSockets.length === 0 ? (
              <div style={{ fontSize: 12, color: "var(--text-muted)", padding: "4px 0" }}>
                No sockets in this group.
              </div>
            ) : (
              memberSockets.map((s) => (
                <div key={s.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0" }}>
                  <span>
                    <span style={{ fontWeight: 500 }}>{s.process_name}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: 12, marginLeft: 6 }}>
                      :{s.port}/{s.protocol}
                    </span>
                  </span>
                  <button className="btn-danger btn-sm" onClick={() => handleRemoveSocket(s.id, s.process_name)}>
                    Remove
                  </button>
                </div>
              ))
            )}
            {!adding && nonMembers.length > 0 && (
              <button
                className="btn btn-sm btn-ghost"
                style={{ marginTop: 4 }}
                onClick={() => setAdding(true)}
              >
                + Add socket
              </button>
            )}
            {adding && (
              <div style={{ marginTop: 4, display: "flex", flexWrap: "wrap", gap: 4 }}>
                {nonMembers.map((s) => (
                  <button
                    key={s.id}
                    className="btn btn-sm"
                    onClick={() => { handleAddSocket(s.id); setAdding(false); }}
                  >
                    {s.process_name}:{s.port}
                  </button>
                ))}
                <button className="btn btn-sm btn-ghost" onClick={() => setAdding(false)}>Cancel</button>
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
