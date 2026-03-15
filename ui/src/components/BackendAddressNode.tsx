import { useState } from "react";
import {
  AclGroupResponse,
  setBackendPolicy, allowBackendIp, removeAclEntry, addToAclGroup,
  setSocketGroupAddressPolicy, addSocketGroupAclEntry, removeSocketGroupAclEntry,
  setSocketGroupAclGroup,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

interface BackendAddressNodeProps {
  socketId?: string;
  groupId?: string;
  addr: {
    backend_id: string;
    address: string;
    interface: string;
    prefix_len: number;
    policy: string;
  };
  acl: Array<{ id: number; allowed_ip: string; label: string | null }>;
  supportsGroupPolicy: boolean;
  aclGroupId?: string | null;
  aclGroups?: AclGroupResponse[];
  managingAclGroup?: { groupId: string; memberSocketIds: string[] } | null;
  onToggleAclMember?: (socketId: string, backendId: string, add: boolean) => void;
  onRefresh: () => void;
}

export default function BackendAddressNode({
  socketId, groupId, addr, acl, supportsGroupPolicy, aclGroupId, aclGroups, managingAclGroup, onToggleAclMember, onRefresh,
}: BackendAddressNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const toast = useToast();

  const doSetPolicy = async (p: string) => {
    try {
      if (socketId) {
        await setBackendPolicy(socketId, addr.backend_id, p);
      } else if (groupId) {
        await setSocketGroupAddressPolicy(groupId, addr.backend_id, p);
      }
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
    } else if (p === "group" && supportsGroupPolicy) {
      if (!aclGroups || aclGroups.length === 0) {
        toast.error("No ACL groups exist");
        return;
      }
      if (!aclGroupId) {
        const assignGroup = socketId
          ? addToAclGroup(aclGroups[0].group.id, [socketId])
          : groupId
            ? setSocketGroupAclGroup(groupId, aclGroups[0].group.id)
            : Promise.resolve();
        assignGroup
          .then(() => doSetPolicy("group"))
          .catch((e) => toast.error(String(e)));
      } else {
        doSetPolicy(p);
      }
    } else {
      doSetPolicy(p);
    }
  };

  const handleGroupChange = async (newAclGroupId: string) => {
    try {
      if (socketId) {
        await addToAclGroup(newAclGroupId, [socketId]);
      } else if (groupId) {
        await setSocketGroupAclGroup(groupId, newAclGroupId);
      } else {
        return;
      }
      toast.success("Moved to group");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleAllow = async () => {
    if (!newIp.trim()) return;
    try {
      if (socketId) {
        await allowBackendIp(socketId, addr.backend_id, newIp.trim(), newLabel.trim() || undefined);
      } else if (groupId) {
        await addSocketGroupAclEntry(groupId, addr.backend_id, newIp.trim(), newLabel.trim() || undefined);
      }
      setNewIp("");
      setNewLabel("");
      toast.success(`Allowed ${newIp.trim()}`);
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleRemove = (entry: { id: number; allowed_ip: string }) => {
    setConfirm({
      message: `Remove ${entry.allowed_ip}?`,
      action: async () => {
        try {
          if (socketId) {
            await removeAclEntry(socketId, entry.id);
          } else if (groupId) {
            await removeSocketGroupAclEntry(groupId, entry.id);
          }
          toast.success("Removed");
          onRefresh();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  const isInactive = addr.policy === "closed" && acl.length === 0;

  return (
    <div className="tree-l3" style={{ padding: "2px 0" }}>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Collapsed header — tree line, not a card */}
      <div
        className={isInactive ? "address-inactive-label" : ""}
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", padding: "3px 0" }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {managingAclGroup && socketId && onToggleAclMember && (
            <input
              type="checkbox"
              className="member-checkbox"
              checked={addr.policy === "group" && managingAclGroup.memberSocketIds.includes(socketId)}
              onChange={(e) => { e.stopPropagation(); onToggleAclMember(socketId, addr.backend_id, e.target.checked); }}
              onClick={(e) => e.stopPropagation()}
            />
          )}
          <span style={{ opacity: 0.5, fontSize: 11 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span className="badge" style={{ fontSize: 10, padding: "1px 6px" }}>{addr.backend_id}</span>
          <span className="mono" style={{ fontSize: 12 }}>{addr.address}</span>
          {isInactive && (
            <span style={{ color: "var(--text-muted)", fontSize: 10 }}>(inactive)</span>
          )}
          {addr.policy === "closed" && acl.length > 0 && (
            <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
              {acl.length} rule{acl.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        <span className={`badge badge-${addr.policy}`} style={{ fontSize: 10, padding: "1px 6px" }}>
          <span className="badge-dot" />
          {addr.policy}
        </span>
      </div>

      {/* Expanded body — card-styled content */}
      {expanded && (
        <div className="card" style={{ marginTop: 4, marginBottom: 4, padding: 10, marginLeft: 16 }}>
          {/* Address details */}
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
            /{addr.prefix_len} on {addr.interface}
          </div>

          {/* Policy toggle */}
          <div className="policy-toggle" style={{ marginBottom: 6 }}>
            <button className={`policy-btn ${addr.policy === "closed" ? "active-closed" : ""}`} onClick={() => handlePolicy("closed")}>Closed</button>
            <button className={`policy-btn ${addr.policy === "open" ? "active-open" : ""}`} onClick={() => handlePolicy("open")}>Open</button>
            {supportsGroupPolicy && (
              <button className={`policy-btn ${addr.policy === "group" ? "active-group" : ""}`} onClick={() => handlePolicy("group")}>Group</button>
            )}
          </div>

          {/* Group dropdown */}
          {supportsGroupPolicy && addr.policy === "group" && aclGroups && aclGroups.length > 0 && (
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
      )}
    </div>
  );
}
