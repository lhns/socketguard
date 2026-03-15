import { useState } from "react";
import {
  SocketGroupResponse, ManagedSocket, AclGroupResponse,
  deleteSocketGroup, updateSocketGroup,
  setSocketGroupAddressPolicy, addSocketGroupAclEntry, removeSocketGroupAclEntry,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";
import BackendAddressNode from "./BackendAddressNode";

interface Props {
  sg: SocketGroupResponse;
  allSockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  backendFilter: string | null;
  allBackendIds: string[];
  isManaging: boolean;
  onToggleManage: () => void;
  onRefresh: () => void;
  managingAclGroup?: { groupId: string; memberSocketIds: string[] } | null;
  onToggleAclMember?: (socketId: string, backendId: string, add: boolean) => void;
}

export default function SocketGroupFoldout({ sg, allSockets, aclGroups, backendFilter, allBackendIds, isManaging, onToggleManage, onRefresh, managingAclGroup, onToggleAclMember }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const [editing, setEditing] = useState(false);
  const [editLabel, setEditLabel] = useState("");
  const toast = useToast();

  const groupSockets = allSockets.filter((s) => sg.members.includes(s.id));
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

  const handleRename = async () => {
    if (!editLabel.trim()) return;
    try {
      await updateSocketGroup(sg.group.id, editLabel.trim());
      setEditing(false);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  // Derive backend IDs from member sockets when no group addresses exist
  const derivedBackendIds = (() => {
    const ids = new Set<string>();
    for (const s of groupSockets) {
      for (const a of s.addresses) ids.add(a.backend_id);
    }
    if (ids.size > 0) return Array.from(ids);
    if (allBackendIds.length > 0) return allBackendIds;
    return ["default"];
  })();

  return (
    <div className={`tree-l2${isManaging ? " socket-group-managing" : ""}`} style={{ marginBottom: 4, padding: "4px 0" }}>
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
          <span style={{ fontWeight: 500, fontSize: 13, color: "var(--text-muted)" }}>Socket Group:</span>
          {editing ? (
            <div style={{ display: "flex", gap: 4, alignItems: "center" }} onClick={(e) => e.stopPropagation()}>
              <input
                className="input"
                value={editLabel}
                onChange={(e) => setEditLabel(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleRename(); if (e.key === "Escape") setEditing(false); }}
                autoFocus
                style={{ width: 160 }}
              />
              <button className="btn btn-primary btn-sm" onClick={handleRename}>Save</button>
              <button className="btn btn-sm" onClick={() => setEditing(false)}>Cancel</button>
            </div>
          ) : (
            <>
              <span style={{ fontWeight: 500, fontSize: 13, color: "var(--text-muted)" }}>
                &ldquo;{sg.group.label}&rdquo;
              </span>
              <button
                className="btn btn-sm btn-ghost"
                onClick={(e) => { e.stopPropagation(); setEditLabel(sg.group.label); setEditing(true); }}
                title="Rename"
                style={{ padding: "0 4px", fontSize: 11, lineHeight: 1 }}
              >
                &#9998;
              </button>
            </>
          )}
          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
            ({groupSockets.length} socket{groupSockets.length !== 1 ? "s" : ""}, {sg.addresses.length} addr{sg.addresses.length !== 1 ? "s" : ""})
          </span>
        </div>
      </div>

      {expanded && (
        <div style={{ paddingLeft: 20, marginTop: 8 }}>
          {/* Members summary + manage button */}
          <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
              Members ({groupSockets.length})
            </span>
            <button
              className={`btn btn-sm ${isManaging ? "btn-primary" : "btn-ghost"}`}
              onClick={(e) => { e.stopPropagation(); onToggleManage(); }}
            >
              {isManaging ? "Done" : "Manage Members"}
            </button>
          </div>
          {groupSockets.length === 0 && !isManaging && (
            <div style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic", marginBottom: 8 }}>
              Click &ldquo;Manage Members&rdquo; to add sockets to this group
            </div>
          )}

          {/* Backend addresses as tree-l3 nodes */}
          <div style={{ marginBottom: 8 }}>
            <div className="section-title">Shared Addresses &amp; Policy</div>
            {filteredAddresses.length > 0 ? (
              filteredAddresses.map((a) => (
                <BackendAddressNode
                  key={a.backend_id}
                  groupId={sg.group.id}
                  addr={a}
                  acl={sg.acl_entries.filter((e) => e.backend_id === a.backend_id)}
                  supportsGroupPolicy={true}
                  aclGroupId={sg.acl_group_id}
                  aclGroups={aclGroups}
                  managingAclGroup={managingAclGroup}
                  onToggleAclMember={onToggleAclMember}
                  onRefresh={onRefresh}
                />
              ))
            ) : (
              <InlinePolicyControls sg={sg} backendIds={derivedBackendIds} onRefresh={onRefresh} />
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

/** Inline policy/ACL controls shown when group has no allocated addresses yet. */
function InlinePolicyControls({
  sg,
  backendIds,
  onRefresh,
}: {
  sg: SocketGroupResponse;
  backendIds: string[];
  onRefresh: () => void;
}) {
  const toast = useToast();
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);

  const handleSetPolicy = async (backendId: string, policy: string) => {
    try {
      await setSocketGroupAddressPolicy(sg.group.id, backendId, policy);
      toast.success(`Policy set to ${policy}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleAllow = async (backendId: string) => {
    if (!newIp.trim()) return;
    try {
      await addSocketGroupAclEntry(sg.group.id, backendId, newIp.trim(), newLabel.trim() || undefined);
      setNewIp("");
      setNewLabel("");
      toast.success(`Allowed ${newIp.trim()}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemoveEntry = (entryId: number, ip: string) => {
    setConfirm({
      message: `Remove ${ip}?`,
      action: async () => {
        try {
          await removeSocketGroupAclEntry(sg.group.id, entryId);
          toast.success("Removed");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  return (
    <div>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}
      {backendIds.map((bid) => {
        const entries = sg.acl_entries.filter((e) => e.backend_id === bid);
        return (
          <div key={bid} className="card" style={{ marginBottom: 6, padding: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <span className="badge" style={{ fontSize: 10, padding: "1px 6px" }}>{bid}</span>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                (address pending)
              </span>
            </div>

            {/* Policy toggle */}
            <div className="policy-toggle" style={{ marginBottom: 6 }}>
              <button className="policy-btn active-closed" onClick={() => handleSetPolicy(bid, "closed")}>Closed</button>
              <button className="policy-btn" onClick={() => handleSetPolicy(bid, "open")}>Open</button>
            </div>

            {/* ACL form */}
            <div className="acl-form" style={{ marginBottom: 4 }}>
              <input className="input" value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder="IPv6 to allow" onKeyDown={(e) => e.key === "Enter" && handleAllow(bid)} style={{ flex: 2 }} />
              <input className="input" value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Label" onKeyDown={(e) => e.key === "Enter" && handleAllow(bid)} style={{ flex: 1 }} />
              <button className="btn btn-primary btn-sm" onClick={() => handleAllow(bid)}>Allow</button>
            </div>

            {/* ACL entries */}
            {entries.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Allowed IP</th><th>Label</th><th style={{ width: 60 }}></th></tr></thead>
                  <tbody>
                    {entries.map((entry) => (
                      <tr key={entry.id}>
                        <td className="mono">{entry.allowed_ip}</td>
                        <td>{entry.label || <span style={{ color: "var(--text-muted)" }}>&mdash;</span>}</td>
                        <td><button className="btn-danger btn-sm" onClick={() => handleRemoveEntry(entry.id, entry.allowed_ip)}>Remove</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
