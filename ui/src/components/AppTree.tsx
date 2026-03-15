import { useState, useMemo } from "react";
import {
  ManagedSocket, AclGroupResponse, SocketGroupResponse,
  createAclGroup, createSocketGroup,
  addSocketToSocketGroup, removeSocketFromSocketGroup,
  addToAclGroup, setBackendPolicy,
} from "../api";
import { useToast } from "./Toast";
import AclGroupNode from "./AclGroupNode";
import BackendFilterBar from "./BackendFilterBar";
import SocketFoldout from "./SocketFoldout";
import SocketGroupFoldout from "./SocketGroupFoldout";

interface Props {
  sockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  socketGroups: SocketGroupResponse[];
  onRefresh: () => void;
  onSelectSocket: (id: string) => void;
}

function AppNode({
  appName,
  sockets,
  aclGroups,
  socketGroups,
  backendFilter,
  allBackendIds,
  managingAclGroup,
  onToggleAclMember,
  onRefresh,
  onSelectSocket,
}: {
  appName: string;
  sockets: ManagedSocket[];
  aclGroups: AclGroupResponse[];
  socketGroups: SocketGroupResponse[];
  backendFilter: string | null;
  allBackendIds: string[];
  managingAclGroup: { groupId: string; memberSocketIds: string[] } | null;
  onToggleAclMember: (socketId: string, backendId: string, add: boolean) => void;
  onRefresh: () => void;
  onSelectSocket: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [showInfo, setShowInfo] = useState(false);
  const [creatingSG, setCreatingSG] = useState(false);
  const [newSGLabel, setNewSGLabel] = useState("");
  const [managingGroupId, setManagingGroupId] = useState<string | null>(null);
  const toast = useToast();
  const exePath = sockets.find((s) => s.exe_path)?.exe_path ?? null;

  const appSocketGroups = socketGroups.filter((sg) => sg.group.app_name === appName);
  const managingGroup = managingGroupId
    ? appSocketGroups.find((sg) => sg.group.id === managingGroupId) ?? null
    : null;

  const handleToggleMember = async (socketId: string, add: boolean) => {
    if (!managingGroupId) return;
    try {
      if (add) {
        await addSocketToSocketGroup(managingGroupId, [socketId]);
      } else {
        await removeSocketFromSocketGroup(managingGroupId, socketId);
      }
      onRefresh();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleCreateSocketGroup = async () => {
    if (!newSGLabel.trim()) return;
    try {
      await createSocketGroup(newSGLabel.trim(), appName);
      setNewSGLabel("");
      setCreatingSG(false);
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
        {!creatingSG ? (
          <button className="btn btn-sm btn-ghost" onClick={() => setCreatingSG(true)} title="Create socket group">
            + Socket Group
          </button>
        ) : (
          <div style={{ display: "flex", gap: 4 }} onClick={(e) => e.stopPropagation()}>
            <input
              className="input"
              value={newSGLabel}
              onChange={(e) => setNewSGLabel(e.target.value)}
              placeholder="Group name"
              onKeyDown={(e) => e.key === "Enter" && handleCreateSocketGroup()}
              autoFocus
              style={{ width: 140 }}
            />
            <button className="btn btn-primary btn-sm" onClick={handleCreateSocketGroup}>Create</button>
            <button className="btn btn-sm" onClick={() => { setCreatingSG(false); setNewSGLabel(""); }}>Cancel</button>
          </div>
        )}
      </div>

      {expanded && (
        <div style={{ paddingLeft: 16 }}>
          {/* App-level info section */}
          <div className="tree-info-toggle" onClick={() => setShowInfo(!showInfo)}>
            <span>{showInfo ? "\u25BE" : "\u25B8"}</span>
            <span>&#9432; App Details</span>
          </div>
          {showInfo && (
            <div className="tree-info-content">
              {exePath && (
                <div><span style={{ fontWeight: 500 }}>Exe:</span> <span className="mono" style={{ wordBreak: "break-all" }}>{exePath}</span></div>
              )}
            </div>
          )}

          {/* Socket groups for this app */}
          {appSocketGroups.map((sg) => (
            <SocketGroupFoldout
              key={sg.group.id}
              sg={sg}
              allSockets={sockets}
              aclGroups={aclGroups}
              backendFilter={backendFilter}
              allBackendIds={allBackendIds}
              isManaging={managingGroupId === sg.group.id}
              onToggleManage={() => setManagingGroupId(managingGroupId === sg.group.id ? null : sg.group.id)}
              onRefresh={onRefresh}
              managingAclGroup={managingAclGroup}
              onToggleAclMember={onToggleAclMember}
            />
          ))}

          {/* Individual sockets */}
          {sockets.map((socket) => (
            <SocketFoldout
              key={socket.id}
              socket={socket}
              aclGroups={aclGroups}
              backendFilter={backendFilter}
              onRefresh={onRefresh}
              onOpenDetail={onSelectSocket}
              managingGroup={managingGroup ? { groupId: managingGroup.group.id, members: managingGroup.members } : null}
              onToggleMember={handleToggleMember}
              managingAclGroup={managingAclGroup}
              onToggleAclMember={onToggleAclMember}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function AppTree({ sockets, aclGroups, socketGroups, onRefresh, onSelectSocket }: Props) {
  const [backendFilter, setBackendFilter] = useState<string | null>(null);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [newGroupLabel, setNewGroupLabel] = useState("");
  const [managingAclGroupId, setManagingAclGroupId] = useState<string | null>(null);
  const toast = useToast();

  const managingAclGroup = managingAclGroupId
    ? aclGroups.find((g) => g.group.id === managingAclGroupId) ?? null
    : null;

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

  const handleToggleAclMember = async (socketId: string, backendId: string, add: boolean) => {
    if (!managingAclGroupId) return;
    try {
      if (add) {
        await addToAclGroup(managingAclGroupId, [socketId]);
        await setBackendPolicy(socketId, backendId, "group");
      } else {
        await setBackendPolicy(socketId, backendId, "closed");
      }
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
          isManaging={managingAclGroupId === g.group.id}
          onToggleManage={() => setManagingAclGroupId(managingAclGroupId === g.group.id ? null : g.group.id)}
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
          allBackendIds={allBackendIds}
          managingAclGroup={managingAclGroup ? { groupId: managingAclGroup.group.id, memberSocketIds: managingAclGroup.members } : null}
          onToggleAclMember={handleToggleAclMember}
          onRefresh={onRefresh}
          onSelectSocket={onSelectSocket}
        />
      ))}
    </div>
  );
}
