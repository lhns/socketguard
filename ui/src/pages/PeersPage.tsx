import { useEffect, useMemo, useState } from "react";
import { subjectEntries } from "../access";
import type { Network, Peer, PeerGroup } from "../api";
import EntityList, { type ListColumn, type ListRow, type ListSection } from "../components/EntityList";
import { BuiltinInspector, GroupInspector, GroupsInspector, NewGroupForm } from "../components/GroupInspector";
import { InspectorEmpty, useNameCtx } from "../components/Inspector";
import Split from "../components/Split";
import { AddPeersForm, PeerInspector, PeersInspector } from "../components/PeerInspector";
import { errorText } from "../lib";
import type { FocusMessage } from "../nav";
import { useGrants, useGroups, useNetworks, usePeers } from "../queries";
import { CREDENTIAL_INFO } from "../reach";
import { segmentNetworks } from "../matrix";

type PeerRow = ListRow & ({ type: "anyone" } | { type: "segment"; network: Network } | { type: "group"; group: PeerGroup } | { type: "peer"; peer: Peer });

const ANYONE = "builtin:anyone";

export default function PeersPage({ focus = { seq: 0 } }: { focus?: FocusMessage }) {
  const peers = usePeers();
  const groups = useGroups();
  const networks = useNetworks();
  const grants = useGrants().data ?? [];
  const names = useNameCtx();

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [adding, setAdding] = useState(false);
  const [newGroup, setNewGroup] = useState(false);
  const [search, setSearch] = useState("");
  const [groupFilter, setGroupFilter] = useState<string | null>(null);
  const [selectLabel, setSelectLabel] = useState<string | null>(null);
  const [closed, setClosed] = useState(false);

  const peerList = useMemo(() => peers.data ?? [], [peers.data]);
  const groupList = useMemo(() => groups.data ?? [], [groups.data]);

  useEffect(() => {
    if (focus.seq === 0) return;
    const key = focus.peerId ? `peer:${focus.peerId}` : focus.groupId ? `group:${focus.groupId}` : null;
    if (key) {
      setSelected(new Set([key]));
      setAdding(false);
      setNewGroup(false);
      setClosed(false);
    }
    // Only a new link counts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus.seq]);

  useEffect(() => {
    if (!selectLabel) return;
    const g = groupList.find((x) => x.label === selectLabel);
    if (g) {
      setSelected(new Set([`group:${g.id}`]));
      setSelectLabel(null);
    }
  }, [groupList, selectLabel]);

  const q = search.trim().toLowerCase();
  const shownPeers = peerList
    .filter((p) => !groupFilter || p.groups.includes(groupFilter))
    .filter((p) => !q || p.label.toLowerCase().includes(q))
    .sort((a, b) => a.label.localeCompare(b.label));
  const shownGroups = groupList.filter((g) => !q || g.label.toLowerCase().includes(q)).sort((a, b) => a.label.localeCompare(b.label));
  const segments = segmentNetworks(networks.data ?? []);

  const sections: ListSection<PeerRow>[] = [
    {
      key: "builtin",
      title: "Built-in",
      rows: [
        { key: ANYONE, kind: "builtin", selectable: false, type: "anyone" },
        ...segments.map<PeerRow>((n) => ({ key: `builtin:seg:${n.id}`, kind: "builtin", selectable: false, type: "segment", network: n })),
      ],
    },
    {
      key: "groups",
      title: "Groups",
      count: shownGroups.length,
      rows: shownGroups.map<PeerRow>((g) => ({ key: `group:${g.id}`, kind: "group", selectable: true, type: "group", group: g })),
      action: <button className="btn btn-sm" onClick={() => { setNewGroup(true); setAdding(false); setSelected(new Set()); setClosed(false); }}>New group</button>,
      emptyText: groupList.length === 0 ? "No groups yet. A grant to a group applies to every member, including peers added later." : "No group matches.",
    },
    {
      key: "peers",
      title: "Peers",
      count: shownPeers.length,
      rows: shownPeers.map<PeerRow>((p) => ({ key: `peer:${p.id}`, kind: "peer", selectable: true, type: "peer", peer: p })),
      action: <button className="btn btn-primary btn-sm" onClick={() => { setAdding(true); setNewGroup(false); setSelected(new Set()); setClosed(false); }}>Add peers</button>,
      emptyText: peerList.length === 0 ? "No peers yet. Use Add peers, or add one while giving access to an app." : "No peer matches.",
    },
  ];

  const count = (row: PeerRow) => {
    switch (row.type) {
      case "anyone":
        return subjectEntries({ kind: "anyone" }, null, grants, names).length;
      case "segment":
        return subjectEntries({ kind: "anyone" }, row.network.id, grants, names).length;
      case "group":
        return subjectEntries({ kind: "group", id: row.group.id }, null, grants, names).length;
      case "peer":
        return subjectEntries({ kind: "peer", id: row.peer.id }, null, grants, names).length;
    }
  };

  const columns: ListColumn<PeerRow>[] = [
    {
      key: "in",
      header: "Groups / members",
      cell: (r) => {
        if (r.type === "peer") {
          return (
            <>
              {r.peer.groups.map((gid) => {
                const g = groupList.find((x) => x.id === gid);
                return g ? <button key={gid} className="tag-pill" title="Show only this group" onClick={() => setGroupFilter(gid)}>{g.label}</button> : null;
              })}
            </>
          );
        }
        if (r.type === "group") return <span className="muted">{r.group.members.length} {r.group.members.length === 1 ? "peer" : "peers"}</span>;
        return <span className="muted">{r.type === "anyone" ? "every source" : "every host there"}</span>;
      },
    },
    {
      key: "creds",
      header: "Credentials",
      cell: (r) =>
        r.type === "peer" ? (
          r.peer.credentials.length === 0 ? (
            <span className="badge reach reach-warn" title="Not reachable on any network">none</span>
          ) : (
            <span className="muted">{[...new Set(r.peer.credentials.map((c) => CREDENTIAL_INFO[c.kind].name))].join(", ")}</span>
          )
        ) : null,
    },
    {
      key: "reach",
      header: "Can reach",
      cell: (r) => {
        const n = count(r);
        return <span className="muted">{n === 0 ? "nothing" : `${n} access${n === 1 ? "" : "es"}`}</span>;
      },
    },
  ];

  const selectedPeers = peerList.filter((p) => selected.has(`peer:${p.id}`));
  const selectedGroups = groupList.filter((g) => selected.has(`group:${g.id}`));
  // Closing hides the details but keeps the selection; the next click or tick shows them again.
  const close = () => setClosed(true);
  const open = (r: PeerRow) => {
    setSelected(new Set([r.key]));
    setAdding(false);
    setNewGroup(false);
    setClosed(false);
  };
  const hidden = closed && !adding && !newGroup;

  const inspector = (() => {
    if (adding) return <AddPeersForm onClose={() => setAdding(false)} />;
    if (newGroup) return <NewGroupForm onCreated={(label) => { setNewGroup(false); setSelectLabel(label); }} onClose={() => setNewGroup(false)} />;
    if (selected.has(ANYONE)) return <BuiltinInspector network={null} onClose={close} />;
    const seg = segments.find((n) => selected.has(`builtin:seg:${n.id}`));
    if (seg) return <BuiltinInspector network={seg} onClose={close} />;
    if (selectedPeers.length === 1) return <PeerInspector key={selectedPeers[0].id} peer={selectedPeers[0]} onClose={close} />;
    if (selectedPeers.length > 1) return <PeersInspector peers={selectedPeers} onClose={close} />;
    if (selectedGroups.length === 1) return <GroupInspector key={selectedGroups[0].id} group={selectedGroups[0]} onClose={close} />;
    if (selectedGroups.length > 1) return <GroupsInspector groups={selectedGroups} onClose={close} />;
    return <InspectorEmpty>Select a peer or a group to see what it can reach. Tick several to change them together.</InspectorEmpty>;
  })();

  const filterGroup = groupList.find((g) => g.id === groupFilter);

  return (
    <div>
      <div className="toolbar">
        <input className="input grow" type="search" aria-label="Filter peers" placeholder="Filter peers and groups" value={search} onChange={(e) => setSearch(e.target.value)} />
        {filterGroup && (
          <button className="tag-pill tag-pill-active" onClick={() => setGroupFilter(null)} aria-label={`Stop filtering by group ${filterGroup.label}`}>
            group: {filterGroup.label} <span className="pill-x" aria-hidden="true">×</span>
          </button>
        )}
      </div>
      {peers.isLoading && <p className="muted">Loading…</p>}
      {peers.error && <div className="error-banner">{errorText(peers.error)}</div>}
      <Split id="peers" closed={hidden}>
        <section aria-label="Peers and groups" className="split-list">
          <EntityList<PeerRow>
            label="Peers and groups"
            sections={sections}
            columns={columns}
            name={(r) => <PeerName r={r} />}
            nameLabel={(r) => (r.type === "peer" ? r.peer.label : r.type === "group" ? r.group.label : r.type === "segment" ? `Everyone on ${r.network.name}` : "Anyone")}
            selected={selected}
            onSelect={(keys) => { setSelected(keys); setAdding(false); setNewGroup(false); setClosed(false); }}
            onOpen={open}
            selectAllKind="peer"
            selectAllLabel="Select all shown peers"
          />
        </section>
        {!hidden && <section aria-label="Peer details" className="split-inspector">{inspector}</section>}
      </Split>
    </div>
  );
}

function PeerName({ r }: { r: PeerRow }) {
  switch (r.type) {
    case "anyone":
      return <span className="row-builtin">Anyone</span>;
    case "segment":
      return <span className="row-builtin">Everyone on {r.network.name}</span>;
    case "group":
      return <span className="row-tag"><span className="tag-glyph" aria-hidden="true">@</span>{r.group.label}</span>;
    case "peer":
      return <>{r.peer.label}</>;
  }
}
