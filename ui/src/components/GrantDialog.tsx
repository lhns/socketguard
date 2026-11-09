import { useEffect, useId, useRef, useState } from "react";
import { toDaemonError, type Subject } from "../api";
import { errorText, portLabel } from "../lib";
import { useApp, useCreateGrant, useCreatePeer, useGroups, usePeers } from "../queries";
import ConfirmDialog from "./ConfirmDialog";
import { useToast } from "./Toast";

interface Props {
  appId: string;
  /** A blocked source to offer as a new IP peer. */
  source?: string;
  onClose: () => void;
}

export default function GrantDialog({ appId, source, onClose }: Props) {
  const id = useId();
  const toast = useToast();
  const app = useApp(appId);
  const peers = usePeers();
  const groups = useGroups();
  const createGrant = useCreateGrant();
  const createPeer = useCreatePeer();

  const [who, setWho] = useState<string>(source ? "new" : "");
  const [port, setPort] = useState("all");
  const [newLabel, setNewLabel] = useState(source ?? "");
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // A peer created for a blocked source survives a retry after the Anyone confirmation.
  const created = useRef<Subject | null>(null);
  const firstField = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    firstField.current?.focus();
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !asking) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [asking, onClose]);

  const ports = app.data?.ports ?? [];

  async function submit(confirmOpen: boolean) {
    setError(null);
    setBusy(true);
    try {
      let subject: Subject;
      if (who === "anyone") subject = { kind: "anyone" };
      else if (who.startsWith("peer:")) subject = { kind: "peer", id: who.slice(5) };
      else if (who.startsWith("group:")) subject = { kind: "group", id: who.slice(6) };
      else if (who === "new" && source) {
        if (!created.current) {
          const peer = await createPeer.mutateAsync({
            label: newLabel.trim(),
            credentials: [{ kind: "ip", value: source, label: null }],
          });
          created.current = { kind: "peer", id: peer.id };
        }
        subject = created.current;
      } else {
        setError("Choose who to grant access to.");
        return;
      }
      const portRef = port === "all" ? null : (ports.find((p) => portLabel(p) === port) ?? null);
      await createGrant.mutateAsync({
        app_id: appId,
        port: portRef ? { port: portRef.port, proto: portRef.proto } : null,
        network_id: null,
        subject,
        confirm_open: confirmOpen,
      });
      toast.success("Access granted");
      onClose();
    } catch (e) {
      if (toDaemonError(e).code === "confirmation_required") setAsking(true);
      else setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (who === "anyone") setAsking(true);
    else void submit(false);
  }

  const title = source ? `Grant ${source} access` : "Grant access";

  return (
    <>
      <div className="modal-overlay" onClick={onClose}>
        <form
          className="modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby={`${id}-t`}
          onClick={(e) => e.stopPropagation()}
          onSubmit={onSubmit}
        >
          <h2 id={`${id}-t`} className="modal-title">{title}</h2>
          <p className="muted">App: <strong>{app.data?.name ?? "…"}</strong></p>
          <div className="form-row">
            <label htmlFor={`${id}-who`}>Who</label>
            <select id={`${id}-who`} className="input" ref={firstField} value={who} onChange={(e) => setWho(e.target.value)}>
              <option value="" disabled>Choose…</option>
              {source && <option value="new">New peer for {source}</option>}
              {(peers.data ?? []).map((p) => (
                <option key={p.id} value={`peer:${p.id}`}>{p.label}</option>
              ))}
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={`group:${g.id}`}>Group: {g.label}</option>
              ))}
              <option value="anyone">Anyone</option>
            </select>
          </div>
          {who === "new" && (
            <div className="form-row">
              <label htmlFor={`${id}-label`}>Peer label</label>
              <input id={`${id}-label`} className="input" value={newLabel} onChange={(e) => setNewLabel(e.target.value)} required />
              <p className="hint">Stored as an IP-only credential: the source address can be faked on a shared network.</p>
            </div>
          )}
          <div className="form-row">
            <label htmlFor={`${id}-port`}>Port</label>
            <select id={`${id}-port`} className="input" value={port} onChange={(e) => setPort(e.target.value)}>
              <option value="all">All ports</option>
              {ports.map((p) => (
                <option key={portLabel(p)} value={portLabel(p)}>{portLabel(p)}</option>
              ))}
            </select>
          </div>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={busy || !who}>Grant</button>
          </div>
        </form>
      </div>
      {asking && (
        <ConfirmDialog
          title="Open to anyone?"
          confirmLabel="Open to anyone"
          onCancel={() => setAsking(false)}
          onConfirm={() => {
            setAsking(false);
            void submit(true);
          }}
        >
          <p>
            Any source that can reach this machine on the app&apos;s networks will be able to
            connect. This is not limited to your peers.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
