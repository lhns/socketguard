import { useId, useState } from "react";
import { mergeEntries, subjectEntries } from "../access";
import type { Network, PeerGroup } from "../api";
import { useCommit, useRevoke } from "../commit";
import { errorText } from "../lib";
import { useNav } from "../nav";
import { useCreateGroup, useDeleteGroup, useGrants, usePeers, useRenameGroup } from "../queries";
import AccessList from "./AccessList";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import { ShowAsColumn } from "./PeerInspector";
import { useToast } from "./Toast";

interface Common {
  onCollapse?: () => void;
  onClose: () => void;
}

/** One group: its name, its members, and what it can reach. */
export function GroupInspector({ group, onCollapse, onClose }: { group: PeerGroup } & Common) {
  const id = useId();
  const toast = useToast();
  const nav = useNav();
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const rename = useRenameGroup();
  const del = useDeleteGroup();
  const { revoke, commit: revokeCommit } = useRevoke();
  const members = useCommit();
  const [label, setLabel] = useState(group.label);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const own = grants.filter((g) => g.subject.kind === "group" && g.subject.id === group.id);
  const peerName = (pid: string) => names.peers.find((p) => p.id === pid)?.label ?? pid.slice(0, 8);

  const items: PickerItem[] = names.peers.map((p) => ({ id: p.id, label: p.label, state: group.members.includes(p.id) ? "on" : "off" }));
  const toggle = (item: PickerItem) => {
    const next = item.state === "on" ? group.members.filter((m) => m !== item.id) : [...group.members, item.id];
    void members.runGroupMembers(group, next, item.state === "on" ? `Removed ${item.label} from ${group.label}` : `Added ${item.label} to ${group.label}`);
    setOpen(false);
  };

  const memberPicker = (
    <Picker
      label={`Members of ${group.label}`}
      trigger="+"
      triggerClass="tag-pill tag-pill-add"
      compactLabel="Add or remove members"
      items={items}
      onToggle={toggle}
      open={open}
      onOpenChange={setOpen}
      placeholder="Find a peer"
      empty="No peers yet."
    />
  );

  return (
    <Inspector label="Group details" title={group.label} subtitle={`group · ${group.members.length} ${group.members.length === 1 ? "peer" : "peers"}`} onCollapse={onCollapse} onClose={onClose}>
      <Section title="Name">
        <form
          className="form-inline"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            rename.mutate({ id: group.id, label: label.trim() }, {
              onSuccess: () => toast.success("Group renamed"),
              onError: (err) => setError(errorText(err)),
            });
          }}
        >
          <div className="form-row grow">
            <label htmlFor={`${id}-l`}>Name of group {group.label}</label>
            <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            {error && <span className="field-error" role="alert">{error}</span>}
          </div>
          <button type="submit" className="btn btn-sm" disabled={label.trim() === group.label || rename.isPending}>Save</button>
        </form>
      </Section>

      <Section title={`Members (${group.members.length})`}>
        <div className="tag-row">
          {group.members.length === 0 && <span className="muted">No members yet.</span>}
          {group.members.map((m) => (
            <button key={m} className="tag-pill" onClick={() => nav.go("peers", { peerId: m })}>{peerName(m)}</button>
          ))}
          {memberPicker}
        </div>
        <CommitPreview commit={members} title="Joining this group lets more in" />
      </Section>

      <Section title="What it can reach">
        <AccessList entries={subjectEntries({ kind: "group", id: group.id }, null, grants, names)} direction="what" networks={names.networks} onRevoke={revoke} empty="No grants name this group." />
        <CommitPreview commit={revokeCommit} />
        <AddAccess fixed={{ side: "subjects", subjects: [{ kind: "group", id: group.id }] }} />
      </Section>

      <div className="actions">
        <ShowAsColumn columnKey={`group:${group.id}`} />
        <button className="btn btn-danger btn-sm" aria-label={`Delete group ${group.label}`} onClick={() => setDeleting(true)}>Delete group</button>
      </div>

      {deleting && (
        <ConfirmDialog
          title={`Delete group ${group.label}?`}
          confirmLabel="Delete group"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            del.mutate(group.id, {
              onSuccess: () => { toast.success(`Deleted ${group.label}`); onClose(); },
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>{own.length > 0 ? `The ${own.length} grant(s) naming this group are removed with it. ` : ""}The peers stay.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** Several groups: what they can reach, and the same edits for all of them. */
export function GroupsInspector({ groups, onCollapse, onClose }: { groups: PeerGroup[] } & Common) {
  const names = useNameCtx();
  const toast = useToast();
  const grants = useGrants().data ?? [];
  const del = useDeleteGroup();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [deleting, setDeleting] = useState(false);
  const entries = mergeEntries(groups.map((g) => subjectEntries({ kind: "group", id: g.id }, null, grants, names)));
  const deleteAll = async () => {
    setDeleting(false);
    try {
      for (const g of groups) await del.mutateAsync(g.id);
      toast.success(`Deleted ${groups.length} groups`);
      onClose();
    } catch (e) {
      toast.error(errorText(e));
    }
  };
  return (
    <Inspector label="Groups details" title={`${groups.length} groups selected`} subtitle={groups.map((g) => g.label).join(", ")} onCollapse={onCollapse} onClose={onClose}>
      <Section title="What they can reach">
        <AccessList entries={entries} direction="what" networks={names.networks} onRevoke={revoke} unit="groups" empty="No grants name these groups." />
        <CommitPreview commit={revokeCommit} />
        <AddAccess fixed={{ side: "subjects", subjects: groups.map((g) => ({ kind: "group" as const, id: g.id })) }} />
      </Section>
      <div className="actions">
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete {groups.length} groups</button>
      </div>
      {deleting && (
        <ConfirmDialog title={`Delete ${groups.length} groups?`} confirmLabel="Delete groups" onCancel={() => setDeleting(false)} onConfirm={() => void deleteAll()}>
          <p>The grants naming these groups are removed with them. The peers stay.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** Anyone, or everyone on one network: not editable; it answers what is open to everyone. */
export function BuiltinInspector({ network, onCollapse, onClose }: { network: Network | null } & Common) {
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const title = network ? `Everyone on ${network.name}` : "Anyone";
  const entries = subjectEntries({ kind: "anyone" }, network?.id ?? null, grants, names);
  return (
    <Inspector label="Built-in details" title={title} subtitle="built-in · not editable" onCollapse={onCollapse} onClose={onClose}>
      <p className="hint">
        {network
          ? `Any host on ${network.name} can connect to what is listed here; nothing is verified.`
          : "Any source that can reach this machine can connect to what is listed here; nothing is verified."}{" "}
        Close an app in its own details.
      </p>
      <Section title="What is open to them">
        <AccessList entries={entries} direction="what" networks={names.networks} empty="Nothing is open to them." />
      </Section>
      <div className="actions">
        <ShowAsColumn columnKey={network ? `segment:${network.id}` : "anyone"} />
      </div>
    </Inspector>
  );
}

/** A group to fill later. */
export function NewGroupForm({ onCreated, onClose }: { onCreated: (label: string) => void; onClose: () => void }) {
  const id = useId();
  const toast = useToast();
  const create = useCreateGroup();
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const peers = usePeers().data ?? [];
  return (
    <Inspector label="New group" title="New group">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          create.mutate({ label: label.trim(), members: [] }, {
            onSuccess: (g) => {
              toast.success(`Created group ${g.label}`);
              onCreated(g.label);
            },
            onError: (err) => setError(errorText(err)),
          });
        }}
      >
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Group name</label>
          <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
          {error && <span className="field-error" role="alert">{error}</span>}
        </div>
        <p className="hint">
          A grant to a group applies to every member, including peers added later.{" "}
          {peers.length > 0 ? "Add the members afterwards, or select peers and use + next to Groups in their details." : ""}
        </p>
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={create.isPending}>Create group</button>
          <button type="button" className="btn btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Inspector>
  );
}
