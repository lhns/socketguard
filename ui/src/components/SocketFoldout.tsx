import { useEffect, useState } from "react";
import {
  getSocket, onSocketsChanged, onDaemonConnected,
  ManagedSocket, AclEntry, AclGroupResponse,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";
import BackendAddressNode from "./BackendAddressNode";

interface Props {
  socket: ManagedSocket;
  aclGroups: AclGroupResponse[];
  backendFilter: string | null;
  onRefresh: () => void;
  onOpenDetail: (id: string) => void;
  managingGroup?: { groupId: string; members: string[] } | null;
  onToggleMember?: (socketId: string, add: boolean) => void;
  managingAclGroup?: { groupId: string; memberSocketIds: string[] } | null;
  onToggleAclMember?: (socketId: string, backendId: string, add: boolean) => void;
}

export default function SocketFoldout({ socket, aclGroups, backendFilter, onRefresh, onOpenDetail, managingGroup, onToggleMember, managingAclGroup, onToggleAclMember }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [acl, setAcl] = useState<AclEntry[]>([]);
  const [aclGroupId, setAclGroupId] = useState<string | null>(null);
  const [showInfo, setShowInfo] = useState(false);
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

  const filteredAddresses = socket.addresses.filter((a) => !backendFilter || a.backend_id === backendFilter);

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
          {managingGroup && onToggleMember && (
            <input
              type="checkbox"
              className="member-checkbox"
              checked={managingGroup.members.includes(socket.id)}
              onChange={(e) => { e.stopPropagation(); onToggleMember(socket.id, e.target.checked); }}
              onClick={(e) => e.stopPropagation()}
            />
          )}
          <span style={{ opacity: 0.5, fontSize: 12 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span className="mono" style={{ fontSize: 13 }}>{socket.port}/{socket.protocol}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>PID {socket.pid}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
            {socket.addresses.length} addr{socket.addresses.length !== 1 ? "s" : ""}
          </span>
          {(socket.socket_group_ids?.length ?? 0) > 0 && (
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
              (in {socket.socket_group_ids.length} socket group{socket.socket_group_ids.length !== 1 ? "s" : ""})
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          {socket.addresses.map((addr) => {
            const groupLabel = addr.policy === "group" && aclGroup ? aclGroup.group.label : null;
            const isUnassignedGroup = addr.policy === "group" && !aclGroup;
            return (
              <span
                key={addr.backend_id}
                className={`badge ${isUnassignedGroup ? "badge-warning" : `badge-${addr.policy}`}`}
                style={{ fontSize: 10, padding: "1px 6px" }}
              >
                <span className="badge-dot" />
                {addr.backend_id}: {isUnassignedGroup ? "group (unassigned)" : groupLabel ? `group: ${groupLabel}` : addr.policy}
              </span>
            );
          })}
        </div>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div style={{ marginTop: 8, paddingLeft: 20 }}>
          {/* Info toggle */}
          <div className="tree-info-toggle" onClick={() => setShowInfo(!showInfo)}>
            <span>{showInfo ? "\u25BE" : "\u25B8"}</span>
            <span>&#9432; Socket Details</span>
          </div>
          {showInfo && (
            <div className="tree-info-content">
              <div>First seen: {new Date(socket.first_seen).toLocaleString()}</div>
              <div>Last seen: {new Date(socket.last_seen).toLocaleString()}</div>
              <div style={{ marginTop: 4 }}>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={(e) => { e.stopPropagation(); onOpenDetail(socket.id); }}
                >
                  Open full details &rarr;
                </button>
              </div>
            </div>
          )}

          {/* Per-backend tree-l3 nodes */}
          {filteredAddresses.map((addr) => (
            <BackendAddressNode
              key={addr.backend_id}
              socketId={socket.id}
              addr={addr}
              acl={aclByBackend[addr.backend_id] || []}
              supportsGroupPolicy={true}
              aclGroupId={aclGroupId}
              aclGroups={aclGroups}
              managingAclGroup={managingAclGroup}
              onToggleAclMember={onToggleAclMember}
              onRefresh={() => { loadDetail(); onRefresh(); }}
            />
          ))}

        </div>
      )}
    </div>
  );
}
