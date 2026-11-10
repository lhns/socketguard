import { useId, useState } from "react";
import { api, type ChangeOp, type Peer, type TorKeyResponse } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import GroupsSection from "../components/GroupsSection";
import { useToast } from "../components/Toast";
import {
  CREDENTIAL_PLACEHOLDER, credentialsFromParsed, errorField, errorText, splitOperationError,
} from "../lib";
import type { Focus } from "../nav";
import {
  useAddCredential, useChanges, useDeletePeer, useGenerateTorKey, useGroups, useParsedCredentials, usePeers,
  useRemoveCredential, useRenamePeer,
} from "../queries";
import { CREDENTIAL_INFO, CredentialBadge, ParsedChips } from "../reach";

export default function PeersPage({ focus = {} }: { focus?: Focus }) {
  const peers = usePeers();
  const groups = useGroups();

  return (
    <div>
      <AddPeersForm />
      <Explanation />
      <h2 className="section-title">Peers</h2>
      {peers.isLoading && <p className="muted">Loading…</p>}
      {peers.data?.length === 0 && (
        <div className="card empty"><p>No peers yet. Add one above, or while granting access to an app.</p></div>
      )}
      {peers.data?.map((p) => (
        <PeerCard
          key={p.id}
          peer={p}
          highlighted={p.id === focus.peerId}
          groupLabel={(id) => groups.data?.find((g) => g.id === id)?.label ?? id}
        />
      ))}
      <GroupsSection highlight={focus.groupId} />
    </div>
  );
}

function Explanation() {
  return (
    <details className="card help">
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
  );
}

function AddPeersForm() {
  const id = useId();
  const toast = useToast();
  const changes = useChanges();
  const [label, setLabel] = useState("");
  const [value, setValue] = useState("");
  const [perValue, setPerValue] = useState(false);
  const [errors, setErrors] = useState<{ label?: string; credentials?: string; other?: string }>({});

  const parsed = useParsedCredentials(value);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});
    let fresh;
    try {
      fresh = await api.parseCredentials(value);
    } catch (err) {
      return setErrors({ credentials: errorText(err) });
    }
    const result = credentialsFromParsed(fresh);
    if ("error" in result) return setErrors({ credentials: result.error });
    const ops: ChangeOp[] = perValue
      ? result.credentials.map((c, i) => ({ op: "create_peer", ref: `$new${i}`, label: c.value, credentials: [c] }))
      : [{ op: "create_peer", ref: "$new0", label: label.trim(), credentials: result.credentials }];
    try {
      await changes.mutateAsync({ ops, dryRun: false });
      toast.success(ops.length === 1 ? `Added ${(ops[0] as { label: string }).label}` : `Added ${ops.length} peers`);
      setLabel("");
      setValue("");
    } catch (err) {
      const text = splitOperationError(errorText(err)).text;
      const field = errorField(err);
      setErrors(field === "label" ? { label: text } : field === "credentials" ? { credentials: text } : { other: text });
    }
  };

  return (
    <form className="card" onSubmit={submit}>
      <h2 className="card-title">Add peers</h2>
      <div className="form-row">
        <label htmlFor={`${id}-v`}>Keys, addresses or IPs</label>
        <textarea
          id={`${id}-v`}
          className="input mono"
          rows={3}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={`${CREDENTIAL_PLACEHOLDER}\nPaste several, separated by lines, commas or spaces.`}
          required
        />
        {errors.credentials && <span className="field-error" role="alert">{errors.credentials}</span>}
      </div>
      {value.trim() && <ParsedChips parsed={parsed.data} />}
      <label className="check">
        <input type="checkbox" checked={perValue} onChange={(e) => setPerValue(e.target.checked)} />
        One peer per value (each named after its value)
      </label>
      {!perValue && (
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Label</label>
          <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
          {errors.label && <span className="field-error" role="alert">{errors.label}</span>}
        </div>
      )}
      {errors.other && <div className="error-banner" role="alert">{errors.other}</div>}
      <button type="submit" className="btn btn-primary" disabled={changes.isPending}>{perValue ? "Add peers" : "Add peer"}</button>
    </form>
  );
}

function PeerCard({ peer, groupLabel, highlighted }: { peer: Peer; groupLabel: (id: string) => string; highlighted: boolean }) {
  const id = useId();
  const toast = useToast();
  const del = useDeletePeer();
  const add = useAddCredential();
  const remove = useRemoveCredential();
  const rename = useRenamePeer();
  const genKey = useGenerateTorKey();
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
    genKey.mutate(peer.id, {
      onSuccess: (r) => setTorKey(r),
      onError: (err) => toast.error(errorText(err)),
    });

  return (
    <div className={`card${highlighted ? " card-highlight" : ""}`}>
      <div className="card-header">
        <div>
          {renaming === null ? (
            <h3 className="card-title">{peer.label}</h3>
          ) : (
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
              <div className="form-row">
                <label htmlFor={`${id}-r`}>New label for {peer.label}</label>
                <input id={`${id}-r`} className="input" value={renaming} onChange={(e) => setRenaming(e.target.value)} required />
                {renameError && <span className="field-error" role="alert">{renameError}</span>}
              </div>
              <button type="submit" className="btn btn-sm">Save</button>
              <button type="button" className="btn btn-sm" onClick={() => setRenaming(null)}>Cancel</button>
            </form>
          )}
          {peer.groups.length > 0 && <div className="muted">in {peer.groups.map(groupLabel).join(", ")}</div>}
        </div>
        <div className="actions">
          {renaming === null && <button className="btn btn-sm" aria-label={`Rename peer ${peer.label}`} onClick={() => setRenaming(peer.label)}>Rename</button>}
          <button className="btn btn-danger btn-sm" onClick={() => setConfirming(true)} aria-label={`Delete peer ${peer.label}`}>
            Delete peer
          </button>
        </div>
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
          <label htmlFor={`${id}-c`}>Add credentials to {peer.label}</label>
          <textarea id={`${id}-c`} className="input mono" rows={1} value={value} onChange={(e) => setValue(e.target.value)} required />
        </div>
        <button type="submit" className="btn" disabled={add.isPending}>Add credentials</button>
      </form>
      {error && <div className="error-banner" role="alert">{error}</div>}
      <div className="actions">
        <button
          className="btn btn-sm"
          disabled={genKey.isPending}
          onClick={() => (hasTorKey ? setRegenerating(true) : generate())}
        >
          {hasTorKey ? "Regenerate Tor access key" : "Generate Tor access key"}
        </button>
      </div>
      {regenerating && (
        <ConfirmDialog
          title="Regenerate the Tor access key?"
          confirmLabel="Regenerate"
          onCancel={() => setRegenerating(false)}
          onConfirm={() => {
            setRegenerating(false);
            generate();
          }}
        >
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
