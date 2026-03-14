import { useState, useMemo } from "react";
import {
  ManagedSocket, AclGroupResponse, SocketGroupResponse,
  SocketAddress,
  createAclGroup, createSocketGroup,
} from "../api";
import { useToast } from "./Toast";
import AclGroupNode from "./AclGroupNode";
import BackendFilterBar from "./BackendFilterBar";

interface Props {
  sockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  socketGroups: SocketGroupResponse[];
  onRefresh: () => void;
  onSelectSocket: (id: string) => void;
}

function AddressLine({
  addr,
  aclGroup,
}: {
  socketId: string;
  addr: SocketAddress;
  aclGroup?: AclGroupResponse;
  onRefresh: () => void;
}) {
  const isGroup = addr.policy === "group";
  const groupLabel = isGroup && aclGroup ? aclGroup.group.label : null;

  return (
    <div className="tree-l3" style={{ display: "flex", alignItems: "center", gap: 8, padding: "2px 0" }}>
      <span style={{ color: "var(--text-muted)", fontSize: 12, minWidth: 60 }}>
        {addr.backend_id}:
      </span>
      <span className="mono" style={{ fontSize: 12, flex: 1 }}>
        {addr.address}
      </span>
      {isGroup && groupLabel ? (
        <span className="badge policy-group" style={{ fontSize: 11, padding: "1px 8px" }}>
          group &rarr; {groupLabel}
        </span>
      ) : (
        <span className={`badge badge-${addr.policy}`} style={{ fontSize: 11, padding: "1px 8px" }}>
          <span className="badge-dot" />
          {addr.policy}
        </span>
      )}
    </div>
  );
}

function AppNode({
  appName,
  sockets,
  aclGroups,
  socketGroups,
  backendFilter,
  onRefresh,
  onSelectSocket,
}: {
  appName: string;
  sockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  socketGroups: SocketGroupResponse[];
  backendFilter: string | null;
  onRefresh: () => void;
  onSelectSocket: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const toast = useToast();

  const appSocketGroups = socketGroups.filter((sg) => sg.group.app_name === appName);

  const handleCreateSocketGroup = async () => {
    const label = prompt("Socket group label:");
    if (!label) return;
    try {
      await createSocketGroup(label, appName);
      toast.success("Socket group created");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  return (
    <div className="tree-l1" style={{ marginBottom: 4 }}>
      <div
        className="tree-node-header"
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", padding: "6px 0" }}
      >
        <div onClick={() => setExpanded(!expanded)} style={{ display: "flex", alignItems: "center", gap: 6, flex: 1 }}>
          <span style={{ opacity: 0.5, fontSize: 12 }}>{expanded ? "\u25BE" : "\u25B8"}</span>
          <span style={{ fontWeight: 600 }}>{appName}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 12 }}>
            ({sockets.length} socket{sockets.length !== 1 ? "s" : ""})
          </span>
        </div>
        <button className="btn btn-sm btn-ghost" onClick={handleCreateSocketGroup} title="Create socket group">
          + Socket Group
        </button>
      </div>

      {expanded && (
        <div style={{ paddingLeft: 16 }}>
          {/* Socket groups for this app */}
          {appSocketGroups.map((sg) => {
            const groupSockets = sockets.filter((s) => s.socket_group_id === sg.group.id);
            if (groupSockets.length === 0) return null;
            return (
              <div key={sg.group.id} className="tree-l2" style={{ marginBottom: 4, padding: "4px 0" }}>
                <div style={{ fontWeight: 500, fontSize: 13, color: "var(--text-muted)", marginBottom: 2 }}>
                  Socket Group: "{sg.group.label}"
                </div>
                <div style={{ paddingLeft: 12, fontSize: 12, color: "var(--text-muted)" }}>
                  {groupSockets.map((s) => `${s.port}/${s.protocol}`).join(", ")}
                </div>
                {sg.addresses.length > 0 && sg.addresses
                  .filter((a) => !backendFilter || a.backend_id === backendFilter)
                  .map((a) => (
                    <div key={a.backend_id} className="tree-l3" style={{ display: "flex", gap: 8, padding: "2px 0 2px 12px" }}>
                      <span style={{ color: "var(--text-muted)", fontSize: 12, minWidth: 60 }}>{a.backend_id}:</span>
                      <span className="mono" style={{ fontSize: 12 }}>{a.address}</span>
                      <span style={{ fontSize: 11, color: "var(--text-muted)" }}>(shared)</span>
                    </div>
                  ))
                }
              </div>
            );
          })}

          {/* Individual sockets */}
          {sockets.map((socket) => {
            const aclGroup = aclGroups.find((g) => g.members.includes(socket.id));
            const filtered = socket.addresses.filter((a) => !backendFilter || a.backend_id === backendFilter);

            return (
              <div
                key={socket.id}
                className="tree-l2 clickable"
                style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}
                onClick={() => onSelectSocket(socket.id)}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <span className="mono" style={{ fontSize: 13 }}>{socket.port}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: 12 }}>/{socket.protocol}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 8 }}>
                      PID {socket.pid}
                    </span>
                    {socket.socket_group_id && (
                      <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 8 }}>
                        (in socket group)
                      </span>
                    )}
                  </div>
                  {aclGroup && (
                    <span className="group-ref" style={{ fontSize: 11 }}>
                      group: {aclGroup.group.label}
                    </span>
                  )}
                </div>
                {filtered.map((addr) => (
                  <AddressLine
                    key={addr.backend_id}
                    socketId={socket.id}
                    addr={addr}
                    aclGroup={aclGroup}
                    onRefresh={onRefresh}
                  />
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function AppTree({ sockets, aclGroups, socketGroups, onRefresh, onSelectSocket }: Props) {
  const [backendFilter, setBackendFilter] = useState<string | null>(null);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [newGroupLabel, setNewGroupLabel] = useState("");
  const toast = useToast();

  // Collect all unique backend IDs
  const allBackendIds = useMemo(() => {
    const ids = new Set<string>();
    for (const s of sockets) {
      for (const a of s.addresses) ids.add(a.backend_id);
    }
    return Array.from(ids).sort();
  }, [sockets]);

  // Group sockets by process_name
  const appGroups = useMemo(() => {
    const map = new Map<string, ManagedSocket[]>();
    for (const s of sockets) {
      const group = map.get(s.process_name) || [];
      group.push(s);
      map.set(s.process_name, group);
    }
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [sockets]);

  const handleCreateAclGroup = async () => {
    if (!newGroupLabel.trim()) return;
    try {
      await createAclGroup(newGroupLabel.trim());
      setNewGroupLabel("");
      setCreatingGroup(false);
      toast.success("ACL group created");
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  return (
    <div>
      {/* Top bar: backend filters + actions */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <BackendFilterBar
          allBackendIds={allBackendIds}
          activeFilter={backendFilter}
          onToggle={setBackendFilter}
        />
        <div style={{ display: "flex", gap: 6 }}>
          {!creatingGroup ? (
            <button className="btn btn-sm" onClick={() => setCreatingGroup(true)}>
              + ACL Group
            </button>
          ) : (
            <div style={{ display: "flex", gap: 4 }}>
              <input
                className="input"
                value={newGroupLabel}
                onChange={(e) => setNewGroupLabel(e.target.value)}
                placeholder="Group name"
                onKeyDown={(e) => e.key === "Enter" && handleCreateAclGroup()}
                autoFocus
                style={{ width: 140 }}
              />
              <button className="btn btn-primary btn-sm" onClick={handleCreateAclGroup}>Create</button>
              <button className="btn btn-sm" onClick={() => setCreatingGroup(false)}>Cancel</button>
            </div>
          )}
        </div>
      </div>

      {/* ACL Groups at top */}
      {aclGroups.map((g) => (
        <AclGroupNode
          key={g.group.id}
          group={g}
          allSockets={sockets}
          onRefresh={onRefresh}
        />
      ))}

      {/* App tree */}
      {appGroups.map(([appName, appSockets]) => (
        <AppNode
          key={appName}
          appName={appName}
          sockets={appSockets}
          aclGroups={aclGroups}
          socketGroups={socketGroups}
          backendFilter={backendFilter}
          onRefresh={onRefresh}
          onSelectSocket={onSelectSocket}
        />
      ))}
    </div>
  );
}
