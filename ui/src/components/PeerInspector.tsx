import { useId, useState } from "react";
import { mergeEntries, subjectEntries } from "../access";
import { api, type ChangeOp, type Peer, type TorKeyResponse } from "../api";
import { useColumns } from "../columns";
import { useCommit, useRevoke } from "../commit";
import {
  CREDENTIAL_PLACEHOLDER, credentialsFromParsed, errorField, errorText, splitOperationError,
} from "../lib";
import { useNav } from "../nav";
import {
  useAddCredential, useCreateGroup, useDeletePeer, useGenerateTorKey, useGrants, useGroups, useParsedCredentials,
  useRemoveCredential, useRenamePeer,
} from "../queries";
import { CREDENTIAL_INFO, CredentialBadge, ParsedChips } from "../reach";
import AccessList from "./AccessList";
import { ActionRow, DangerZone } from "./ActionRow";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import { useToast } from "./Toast";

interface Common {
  onCollapse?: () => void;
  onClose: () => void;
}

/** The groups of the selected peers: a group some of them are in shows as mixed. */
export function GroupPicker({ peerIds }: { peerIds: string[] }) {
  const nav = useNav();
  const toast = useToast();
  const groups = useGroups().data ?? [];
  const create = useCreateGroup();
  const commit = useCommit();
  const [open, setOpen] = useState(false);
  const count = (members: string[]) => peerIds.filter((p) => members.includes(p)).length;
  const items: PickerItem[] = groups.map((g) => {
    const n = count(g.members);
    return { id: g.id, label: g.label, hint: `${g.members.length} peers`, state: n === 0 ? "off" : n === peerIds.length ? "on" : "mixed" };
  });
  const toggle = (item: PickerItem) => {
    const g = groups.find((x) => x.id === item.id);
    if (!g) return;
    const next = item.state === "on" ? g.members.filter((m) => !peerIds.includes(m)) : [...new Set([...g.members, ...peerIds])];
    void commit.runGroupMembers(g, next, item.state === "on" ? `Removed from ${g.label}` : `Added to ${g.label}`);
    setOpen(false);
  };
  const mine = groups.filter((g) => count(g.members) > 0);
  return (
    <div className="tag-picker">
      <div className="tag-row">
        {mine.map((g) => (
          <button key={g.id} className={`tag-pill${count(g.members) < peerIds.length ? " tag-pill-partial" : ""}`} title="Show the group" onClick={() => nav.go("peers", { groupId: g.id })}>
            {g.label}{count(g.members) < peerIds.length ? ` ${count(g.members)}/${peerIds.length}` : ""}
          </button>
        ))}
        {mine.length === 0 && <span className="muted">no groups</span>}
        <Picker
          label="Groups"
          trigger="+"
          triggerClass="tag-pill tag-pill-add"
          compactLabel="Add or remove groups"
          items={items}
          onToggle={toggle}
          open={open}
          onOpenChange={setOpen}
          placeholder="Find or create a group"
          empty="No groups yet. Type a name to create one."
          create={(typed) => ({
            label: <>Create &ldquo;{typed}&rdquo;</>,
            pick: () => {
              create.mutate({ label: typed, members: peerIds }, {
                onSuccess: (g) => toast.success(`Created group ${g.label}`),
                onError: (e) => toast.error(errorText(e)),
              });
              setOpen(false);
            },
          })}
        />
      </div>
      <CommitPreview commit={commit} title="Add to this group?" confirmLabel="Add to group" />
    </div>
  );
}

/** "Show as column in Apps": add the subject to the overview and go there. */
export function ShowAsColumn({ columnKey }: { columnKey: string }) {
  const nav = useNav();
  const columns = useColumns();
  return (
    <button
      className="btn btn-sm"
      onClick={() => {
        columns.add(columnKey);
        nav.go("apps");
      }}
    >
      Show as column in Apps
    </button>
  );
}

/** One peer: its groups, its credentials, and what it can reach. */
export function PeerInspector({ peer, onCollapse, onClose }: { peer: Peer } & Common) {
  const id = useId();
  const toast = useToast();
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const del = useDeletePeer();
  const add = useAddCredential();
  const remove = useRemoveCredential();
  const rename = useRenamePeer();
  const genKey = useGenerateTorKey();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [torKey, setTorKey] = useState<TorKeyResponse | null>(null);
  const hasTorKey = peer.credentials.some((c) => c.kind === "tor_client_key");

  const addCred = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    let result;
    try {
      result = credentialsFromParsed(await api.parseCredentials(value));
    } catch (err) {
      return setError(errorText(err));
    }
    if ("error" in result) return setError(result.error);
    for (const req of result.credentials) {
      try {
        await add.mutateAsync({ peerId: peer.id, req });
      } catch (err) {
        return setError(errorText(err));
      }
    }
    setValue("");
  };
  const generate = () =>
    genKey.mutate(peer.id, { onSuccess: (r) => setTorKey(r), onError: (err) => toast.error(errorText(err)) });

  return (
    <Inspector label="Peer details" title={peer.label} subtitle={`peer · ${peer.credentials.length} ${peer.credentials.length === 1 ? "credential" : "credentials"}`} onCollapse={onCollapse} onClose={onClose}>
      <Section
        title="Name"
        aside={renaming === null && <button className="btn btn-sm" aria-label={`Rename peer ${peer.label}`} onClick={() => setRenaming(peer.label)}>Rename</button>}
      >
        {renaming !== null && (
          <form
            className="form-inline"
            onSubmit={(e) => {
              e.preventDefault();
              setRenameError(null);
              rename.mutate({ id: peer.id, label: renaming.trim() }, {
                onSuccess: () => setRenaming(null),
                onError: (err) => setRenameError(errorText(err)),
              });
            }}
          >
            <div className="form-row grow">
              <label htmlFor={`${id}-r`}>New label for {peer.label}</label>
              <input id={`${id}-r`} className="input" value={renaming} onChange={(e) => setRenaming(e.target.value)} required />
              {renameError && <span className="field-error" role="alert">{renameError}</span>}
            </div>
            <button type="submit" className="btn btn-sm">Save</button>
            <button type="button" className="btn btn-sm" onClick={() => setRenaming(null)}>Cancel</button>
          </form>
        )}
      </Section>

      <Section title="Groups">
        <GroupPicker peerIds={[peer.id]} />
      </Section>

      <Section title="Credentials">
        {peer.credentials.length === 0 && <p className="muted">No credentials: this peer is not reachable on any network.</p>}
        <ul className="plain-list">
          {peer.credentials.map((c) => (
            <li key={c.id} className="cred-item">
              <div className="cred-row">
                <strong>{CREDENTIAL_INFO[c.kind].name}</strong>
                <CredentialBadge kind={c.kind} />
                <button
                  className="btn btn-danger btn-sm access-revoke"
                  aria-label={`Remove ${c.value} from ${peer.label}`}
                  onClick={() => remove.mutate({ peerId: peer.id, credentialId: c.id }, { onError: (err) => toast.error(errorText(err)) })}
                >
                  Remove
                </button>
              </div>
              <span className="mono cred-value">{c.value}</span>
            </li>
          ))}
        </ul>
        <form className="form-inline" onSubmit={addCred}>
          <div className="form-row grow">
            <label htmlFor={`${id}-c`}>Add credentials to {peer.label}</label>
            <textarea id={`${id}-c`} className="input mono" rows={1} value={value} onChange={(e) => setValue(e.target.value)} required />
          </div>
          <button type="submit" className="btn btn-sm" disabled={add.isPending}>Add credentials</button>
        </form>
        {error && <div className="error-banner" role="alert">{error}</div>}
        <div className="actions">
          <button className="btn btn-sm" disabled={genKey.isPending} onClick={() => (hasTorKey ? setRegenerating(true) : generate())}>
            {hasTorKey ? "Regenerate Tor access key" : "Generate Tor access key"}
          </button>
        </div>
      </Section>

      <Section title="What it can reach">
        <AccessList
          entries={subjectEntries({ kind: "peer", id: peer.id }, null, grants, names)}
          direction="what"
          networks={names.networks}
          onRevoke={revoke}
          empty="It can reach nothing."
        />
        <CommitPreview commit={revokeCommit} />
        <ActionRow><AddAccess fixed={{ side: "subjects", subjects: [{ kind: "peer", id: peer.id }] }} /></ActionRow>
      </Section>

      <div className="actions">
        <ShowAsColumn columnKey={`peer:${peer.id}`} />
      </div>
      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setConfirming(true)} aria-label={`Delete peer ${peer.label}`}>Delete peer</button>
      </DangerZone>

      {regenerating && (
        <ConfirmDialog title="Regenerate the Tor access key?" confirmLabel="Regenerate" onCancel={() => setRegenerating(false)} onConfirm={() => { setRegenerating(false); generate(); }}>
          <p>The old key stops working at once. Give {peer.label} the new one. A key that was pasted in stays.</p>
        </ConfirmDialog>
      )}
      {torKey && <TorKeyDialog peer={peer} result={torKey} onClose={() => setTorKey(null)} />}
      {confirming && (
        <ConfirmDialog
          title={`Delete ${peer.label}?`}
          confirmLabel="Delete peer"
          onCancel={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            del.mutate(peer.id, {
              onSuccess: () => { toast.success(`Deleted ${peer.label}`); onClose(); },
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>Grants to this peer are removed with it.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** Several peers: the groups they are in, what they can reach, and the same edits for all. */
export function PeersInspector({ peers, onCollapse, onClose }: { peers: Peer[] } & Common) {
  const names = useNameCtx();
  const toast = useToast();
  const grants = useGrants().data ?? [];
  const del = useDeletePeer();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [deleting, setDeleting] = useState(false);
  const entries = mergeEntries(peers.map((p) => subjectEntries({ kind: "peer", id: p.id }, null, grants, names)));
  const deleteAll = async () => {
    setDeleting(false);
    try {
      for (const p of peers) await del.mutateAsync(p.id);
      toast.success(`Deleted ${peers.length} peers`);
      onClose();
    } catch (e) {
      toast.error(errorText(e));
    }
  };
  return (
    <Inspector label="Peers details" title={`${peers.length} peers selected`} subtitle={peers.map((p) => p.label).join(", ")} onCollapse={onCollapse} onClose={onClose}>
      <Section title="Groups">
        <GroupPicker peerIds={peers.map((p) => p.id)} />
      </Section>
      <Section title="What they can reach">
        <AccessList entries={entries} direction="what" networks={names.networks} onRevoke={revoke} unit="peers" empty="None of them can reach anything." />
        <CommitPreview commit={revokeCommit} />
        <ActionRow><AddAccess fixed={{ side: "subjects", subjects: peers.map((p) => ({ kind: "peer" as const, id: p.id })) }} /></ActionRow>
      </Section>
      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete {peers.length} peers</button>
      </DangerZone>
      {deleting && (
        <ConfirmDialog title={`Delete ${peers.length} peers?`} confirmLabel="Delete peers" onCancel={() => setDeleting(false)} onConfirm={() => void deleteAll()}>
          <p>Grants to these peers are removed with them.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** The private half of a generated Tor key, shown this once. */
function TorKeyDialog({ peer, result, onClose }: { peer: Peer; result: TorKeyResponse; onClose: () => void }) {
  const toast = useToast();
  return (
    <div className="modal-overlay">
      <div className="modal modal-wide" role="dialog" aria-modal="true" aria-label={`Tor access key for ${peer.label}`}>
        <h2 className="modal-title">Tor access key for {peer.label}</h2>
        <p>
          This private key is shown once here. It is also kept by the daemon, so the line to give {peer.label} is always in the
          Tor access section of each app. Whoever has this key can reach the onion services {peer.label} is granted.
        </p>
        <p className="mono cred-value" data-testid="tor-private-key">{result.private_key}</p>
        <div className="modal-actions">
          <button
            className="btn"
            onClick={() => {
              void navigator.clipboard?.writeText(result.private_key).then(() => toast.success("Copied"), () => toast.error("Could not copy"));
            }}
          >
            Copy key
          </button>
          <button className="btn btn-primary" onClick={onClose}>I have copied it</button>
        </div>
      </div>
    </div>
  );
}

/** Paste keys, addresses or IPs; each becomes a peer, named by the daemon. They can all go into a
 * new group, in the same batch. */
export function AddPeersForm({ onClose }: { onClose: () => void }) {
  const id = useId();
  const [value, setValue] = useState("");
  const [grouped, setGrouped] = useState(false);
  const [group, setGroup] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const parsed = useParsedCredentials(value);
  const commit = useCommit(() => {
    setValue("");
    setGroup("");
    setGrouped(false);
  });
  const valid = (parsed.data ?? []).filter((p) => p.error === null && p.kind !== null).length;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    let fresh;
    try {
      fresh = await api.parseCredentials(value);
    } catch (err) {
      return setLocalError(errorText(err));
    }
    const result = credentialsFromParsed(fresh);
    if ("error" in result) return setLocalError(result.error);
    const refs = result.credentials.map((_, i) => `$new${i}`);
    const ops: ChangeOp[] = result.credentials.map((c, i) => ({ op: "create_peer", ref: refs[i], credentials: [c] }));
    if (grouped) ops.push({ op: "create_group", ref: "$group", label: group.trim(), members: refs });
    const n = result.credentials.length;
    void commit.runBatch(ops, `Added ${n} ${n === 1 ? "peer" : "peers"}${grouped ? ` to group ${group.trim()}` : ""}`);
  };

  const failed = commit.state.phase === "error" ? splitOperationError(commit.state.message).text : null;
  const field = failed ? errorField({ code: "invalid", message: failed }) : null;
  const groupError = failed !== null && failed.toLowerCase().includes("group") ? failed : null;
  const credentialsError = localError ?? (!groupError && field === "credentials" ? failed : null);
  const otherError = failed !== null && !groupError && !credentialsError ? failed : null;

  return (
    <Inspector label="Add peers" title="Add peers">
      <form onSubmit={submit}>
        <div className="form-row">
          <label htmlFor={`${id}-v`}>Keys, addresses or IPs</label>
          <textarea
            id={`${id}-v`}
            className="input mono"
            rows={4}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={`${CREDENTIAL_PLACEHOLDER}\nPaste several, separated by lines, commas or spaces. Each becomes a peer named after its value.`}
            required
          />
          {credentialsError && <span className="field-error" role="alert">{credentialsError}</span>}
        </div>
        {value.trim() && <ParsedChips parsed={parsed.data} />}
        <label className="check">
          <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
          Create group
        </label>
        {grouped && (
          <div className="form-row">
            <label htmlFor={`${id}-g`}>Group name</label>
            <input id={`${id}-g`} className="input" value={group} onChange={(e) => setGroup(e.target.value)} required />
            {groupError && <span className="field-error" role="alert">{groupError}</span>}
          </div>
        )}
        {otherError && <div className="error-banner" role="alert">{otherError}</div>}
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={commit.state.phase === "checking" || commit.state.phase === "applying"}>
            {valid > 0 ? `Create ${valid} ${valid === 1 ? "peer" : "peers"}` : "Create peers"}
          </button>
          <button type="button" className="btn btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </form>
      <details className="help">
        <summary>Key, address or subnet? And Tor.</summary>
        <ul className="plain-list">
          <li>
            <strong>Yggdrasil:</strong> the key identifies the node. An address (<code>200:…</code>) works on Yggdrasil too. A{" "}
            <code>300:…</code> /64 is everything that node routes, so it is wider than one host.
          </li>
          <li>
            <strong>LAN:</strong> an IP address or network (IPv6 or IPv4) is matched by its source address only, which can be faked on a
            shared network. IPv4 only works where protect-host covers the interface.
          </li>
          <li>
            <strong>Tor:</strong> a peer is identified by an access key. Use <em>Generate Tor access key</em> on the peer, or paste the
            peer&apos;s own public key. The app&apos;s Tor access section then shows the line the peer needs.
          </li>
        </ul>
      </details>
    </Inspector>
  );
}
