import { useId, useState } from "react";
import type { Peer } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/Toast";
import { CREDENTIAL_PLACEHOLDER, credentialsFromParsed, errorText } from "../lib";
import { api } from "../api";
import {
  useAddCredential, useCreatePeer, useDeletePeer, useGroups, useParsedCredentials, usePeers, useRemoveCredential,
} from "../queries";
import { CREDENTIAL_INFO, CredentialBadge, ParsedHint } from "../reach";

export default function PeersPage() {
  const peers = usePeers();
  const groups = useGroups();
  const peerLabel = (id: string) => peers.data?.find((p) => p.id === id)?.label ?? id.slice(0, 8);

  return (
    <div>
      <AddPeerForm />
      <h2 className="section-title">Peers</h2>
      {peers.isLoading && <p className="muted">Loading…</p>}
      {peers.data?.length === 0 && (
        <div className="card empty"><p>No peers yet. Add one above to grant it access to an app.</p></div>
      )}
      {peers.data?.map((p) => <PeerCard key={p.id} peer={p} groupLabel={(id) => groups.data?.find((g) => g.id === id)?.label ?? id} />)}

      <h2 className="section-title">Groups</h2>
      <p className="hint">Read-only here. Manage groups with <code>socketguard groups</code>.</p>
      {groups.data?.length === 0 && <p className="muted">No groups.</p>}
      <ul className="plain-list">
        {groups.data?.map((g) => (
          <li key={g.id} className="card">
            <strong>{g.label}</strong>
            <span className="muted"> · {g.members.length === 0 ? "no members" : g.members.map(peerLabel).join(", ")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AddPeerForm() {
  const id = useId();
  const toast = useToast();
  const create = useCreatePeer();
  const [label, setLabel] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const parsed = useParsedCredentials(value);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    let result;
    try {
      result = credentialsFromParsed(await api.parseCredentials(value));
    } catch (err) {
      return setError(errorText(err));
    }
    if ("error" in result) return setError(result.error);
    create.mutate(
      { label: label.trim(), credentials: result.credentials },
      {
        onSuccess: (p) => {
          toast.success(`Added ${p.label}`);
          setLabel("");
          setValue("");
        },
        onError: (err) => setError(errorText(err)),
      },
    );
  };

  return (
    <form className="card" onSubmit={submit}>
      <h2 className="card-title">Add a peer</h2>
      <div className="form-inline">
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Label</label>
          <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
        </div>
        <div className="form-row grow">
          <label htmlFor={`${id}-v`}>Key, address or IP</label>
          <input
            id={`${id}-v`}
            className="input mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={CREDENTIAL_PLACEHOLDER}
            required
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={create.isPending}>Add peer</button>
      </div>
      {value.trim() && <ParsedHint parsed={parsed.data} />}
      {error && <div className="error-banner" role="alert">{error}</div>}
    </form>
  );
}

function PeerCard({ peer, groupLabel }: { peer: Peer; groupLabel: (id: string) => string }) {
  const id = useId();
  const toast = useToast();
  const del = useDeletePeer();
  const add = useAddCredential();
  const remove = useRemoveCredential();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

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

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h3 className="card-title">{peer.label}</h3>
          {peer.groups.length > 0 && <div className="muted">in {peer.groups.map(groupLabel).join(", ")}</div>}
        </div>
        <button className="btn btn-danger btn-sm" onClick={() => setConfirming(true)} aria-label={`Delete peer ${peer.label}`}>
          Delete peer
        </button>
      </div>
      {peer.credentials.length === 0 && <p className="muted">No credentials: this peer is not reachable on any network.</p>}
      <ul className="plain-list">
        {peer.credentials.map((c) => (
          <li key={c.id} className="cred-row">
            <span className="muted">{CREDENTIAL_INFO[c.kind].name}</span>
            <span className="mono cred-value">{c.value}</span>
            <CredentialBadge kind={c.kind} />
            <button
              className="btn btn-danger btn-sm"
              aria-label={`Remove ${c.value} from ${peer.label}`}
              onClick={() =>
                remove.mutate({ peerId: peer.id, credentialId: c.id }, { onError: (err) => toast.error(errorText(err)) })
              }
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
      <form className="form-inline" onSubmit={addCred}>
        <div className="form-row grow">
          <label htmlFor={`${id}-c`}>Add credential to {peer.label}</label>
          <input id={`${id}-c`} className="input mono" value={value} onChange={(e) => setValue(e.target.value)} required />
        </div>
        <button type="submit" className="btn" disabled={add.isPending}>Add credential</button>
      </form>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {confirming && (
        <ConfirmDialog
          title={`Delete ${peer.label}?`}
          confirmLabel="Delete peer"
          onCancel={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            del.mutate(peer.id, {
              onSuccess: () => toast.success(`Deleted ${peer.label}`),
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>Grants to this peer are removed with it.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
