import { useId, useState } from "react";
import type { Peer, PeerGroup } from "../api";
import { errorField, errorText } from "../lib";
import {
  useCreateGroup, useDeleteGroup, useGrants, usePeers, useRenameGroup, useSetGroupMembers, useGroups,
} from "../queries";
import ConfirmDialog from "./ConfirmDialog";
import { useToast } from "./Toast";

/** Groups: create, rename, change members, delete. */
export default function GroupsSection({ highlight }: { highlight?: string }) {
  const groups = useGroups();
  const peers = usePeers();
  return (
    <section aria-label="Groups">
      <h2 className="section-title">Groups</h2>
      <p className="hint">A grant to a group applies to every member, including peers added later.</p>
      <NewGroupForm peers={peers.data ?? []} />
      {groups.data?.length === 0 && <p className="muted">No groups.</p>}
      {groups.data?.map((g) => (
        <GroupCard key={g.id} group={g} peers={peers.data ?? []} highlighted={g.id === highlight} />
      ))}
    </section>
  );
}

function MemberChecks({ peers, chosen, onChange, legend }: { peers: Peer[]; chosen: Set<string>; onChange: (s: Set<string>) => void; legend: string }) {
  if (peers.length === 0) return <p className="muted">No peers yet.</p>;
  return (
    <fieldset className="checks">
      <legend className="visually-hidden">{legend}</legend>
      {peers.map((p) => (
        <label key={p.id} className="check">
          <input
            type="checkbox"
            checked={chosen.has(p.id)}
            onChange={(e) => {
              const next = new Set(chosen);
              if (e.target.checked) next.add(p.id);
              else next.delete(p.id);
              onChange(next);
            }}
          />
          {p.label}
        </label>
      ))}
    </fieldset>
  );
}

function NewGroupForm({ peers }: { peers: Peer[] }) {
  const id = useId();
  const toast = useToast();
  const create = useCreateGroup();
  const [label, setLabel] = useState("");
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    create.mutate({ label: label.trim(), members: [...members] }, {
      onSuccess: (g) => {
        toast.success(`Created group ${g.label}`);
        setLabel("");
        setMembers(new Set());
      },
      onError: (err) => setError(errorText(err)),
    });
  };

  return (
    <form className="card" onSubmit={submit}>
      <h3 className="card-title">New group</h3>
      <div className="form-row">
        <label htmlFor={`${id}-l`}>Group name</label>
        <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
        {error && <span className="field-error" role="alert">{error}</span>}
      </div>
      <MemberChecks peers={peers} chosen={members} onChange={setMembers} legend="Members of the new group" />
      <button type="submit" className="btn btn-primary" disabled={create.isPending}>Create group</button>
    </form>
  );
}

function GroupCard({ group, peers, highlighted }: { group: PeerGroup; peers: Peer[]; highlighted: boolean }) {
  const id = useId();
  const toast = useToast();
  const rename = useRenameGroup();
  const setMembers = useSetGroupMembers();
  const del = useDeleteGroup();
  const grants = (useGrants().data ?? []).filter((g) => g.subject.kind === "group" && g.subject.id === group.id);
  const [label, setLabel] = useState(group.label);
  const [members, setLocal] = useState<Set<string>>(new Set(group.members));
  const [error, setError] = useState<{ field: string; text: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const dirtyMembers = [...members].sort().join() !== [...group.members].sort().join();

  const save = () => {
    setError(null);
    const done = () => toast.success("Group saved");
    const failed = (err: unknown) => setError({ field: errorField(err), text: errorText(err) });
    const members_ = () => dirtyMembers && setMembers.mutate({ id: group.id, peerIds: [...members] }, { onSuccess: done, onError: failed });
    if (label.trim() !== group.label) {
      rename.mutate({ id: group.id, label: label.trim() }, { onSuccess: () => (dirtyMembers ? members_() : done()), onError: failed });
    } else members_();
  };

  return (
    <div className={`card${highlighted ? " card-highlight" : ""}`} role="group" aria-label={`Group ${group.label}`}>
      <div className="form-inline">
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Name of group {group.label}</label>
          <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} />
          {error?.field === "label" && <span className="field-error">{error.text}</span>}
        </div>
        <button className="btn" onClick={save} disabled={(label.trim() === group.label && !dirtyMembers) || rename.isPending || setMembers.isPending}>
          Save group
        </button>
        <button className="btn btn-danger btn-sm" aria-label={`Delete group ${group.label}`} onClick={() => setDeleting(true)}>Delete group</button>
      </div>
      <MemberChecks peers={peers} chosen={members} onChange={setLocal} legend={`Members of ${group.label}`} />
      {error && error.field !== "label" && <div className="error-banner" role="alert">{error.text}</div>}
      <p className="hint">{grants.length === 0 ? "No grants name this group." : `${grants.length} grant${grants.length === 1 ? "" : "s"} name this group.`}</p>
      {deleting && (
        <ConfirmDialog
          title={`Delete group ${group.label}?`}
          confirmLabel="Delete group"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            del.mutate(group.id, {
              onSuccess: () => toast.success(`Deleted ${group.label}`),
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>{grants.length > 0 ? `The ${grants.length} grant(s) naming this group are removed with it. ` : ""}The peers stay.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
