import { useState } from "react";
import type { ManagedInfo, Network } from "../api";
import { errorText } from "../lib";
import { useSetNetworkPeers } from "../queries";
import { useToast } from "./Toast";

/** A managed network's child process, in words. */
export function childStateText(m: ManagedInfo): string {
  switch (m.state) {
    case "starting":
      return "Starting";
    case "bootstrapping":
      return m.progress !== undefined ? `Bootstrapping ${m.progress}%` : "Bootstrapping";
    case "up":
      return "Up";
    case "exited":
      return m.detail ? `Exited: ${m.detail}` : "Exited";
    case "waiting":
      return m.detail ?? "Waiting";
    case "stopped":
      return "Stopped (SocketGuard is turned off)";
    case "unavailable":
      return "Not included in this build";
  }
}

const PEER_SCHEMES = ["tcp", "tls", "quic", "ws", "wss", "socks", "sockstls"];

/** Why a peer URI is not usable, or null. Same rules as the daemon: scheme, host, port 1-65535. */
export function peerError(uri: string): string | null {
  const m = /^([a-z]+):\/\/([^/?#\s]+)/i.exec(uri);
  if (!m) return "Use the form tls://host:port";
  if (!PEER_SCHEMES.includes(m[1].toLowerCase())) return `The scheme must be one of ${PEER_SCHEMES.join(", ")}`;
  const authority = m[2];
  const hp = authority.startsWith("[") ? /^\[([^\]]+)\]:(\d+)$/.exec(authority) : /^([^:]+):(\d+)$/.exec(authority);
  if (!hp) return "The address needs a host and a port";
  const port = Number(hp[2]);
  if (port < 1 || port > 65535) return "The port must be between 1 and 65535";
  return null;
}

/** "Managed" or "your own", with the child's state for a managed one. */
export function NetworkOrigin({ network }: { network: Network }) {
  const m = network.managed;
  if (!m) return <span className="muted">your own</span>;
  return (
    <>
      <span className="muted">managed</span>
      <span className="muted" aria-label={`${network.name} state`}>
        {childStateText(m)}
      </span>
      {m.runs_as && <small className="muted">runs as {m.runs_as}</small>}
      {m.version && <small className="muted">version {m.version}</small>}
    </>
  );
}

/** What is specific to a managed network: Yggdrasil's address and peers. */
export function ManagedDetails({ network }: { network: Network }) {
  const m = network.managed;
  if (!m || network.kind !== "yggdrasil") return null;
  const peers = m.peers ?? [];
  return (
    <div className="managed-details">
      {m.address && <CopyAddress address={m.address} />}
      <p className="hint">
        {m.peers_connected
          ? `Connected to ${m.peers_connected} ${m.peers_connected === 1 ? "peer" : "peers"}.`
          : peers.length === 0
            ? "No peers yet: it only finds nodes on your LAN."
            : "Not connected to any peer yet."}
      </p>
      {/* Remounts when the saved peers change, so the draft follows the daemon. */}
      <PeersEditor key={JSON.stringify(peers)} id={network.id} saved={peers} />
    </div>
  );
}

function CopyAddress({ address }: { address: string }) {
  const toast = useToast();
  return (
    <p>
      Address <code className="mono">{address}</code>{" "}
      <button
        className="btn btn-sm"
        onClick={() => {
          void navigator.clipboard?.writeText(address).then(() => toast.success("Copied"), () => toast.error("Could not copy"));
        }}
      >
        Copy
      </button>
    </p>
  );
}

function PeersEditor({ id, saved }: { id: string; saved: string[] }) {
  const toast = useToast();
  const set = useSetNetworkPeers();
  const [peers, setPeers] = useState(saved);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const dirty = JSON.stringify(peers) !== JSON.stringify(saved);

  const add = () => {
    const uri = draft.trim();
    if (!uri) return;
    const why = peerError(uri);
    if (why) {
      setError(why);
      return;
    }
    if (!peers.includes(uri)) setPeers([...peers, uri]);
    setDraft("");
    setError(null);
  };

  return (
    <div role="group" aria-label="Peers">
      <strong>Peers</strong>
      <ul className="plain-list">
        {peers.map((p) => (
          <li key={p} className="net-row">
            <code className="mono">{p}</code>
            <button className="btn btn-sm" aria-label={`Remove peer ${p}`} onClick={() => setPeers(peers.filter((x) => x !== p))}>
              Remove
            </button>
          </li>
        ))}
      </ul>
      <div className="form-inline">
        <input
          className="input mono"
          aria-label="New peer"
          placeholder="tls://host:port"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <button className="btn btn-sm" onClick={add}>Add peer</button>
      </div>
      {error && <span className="field-error" role="alert">{error}</span>}
      <div className="actions">
        <button
          className="btn btn-primary btn-sm"
          disabled={!dirty || set.isPending}
          onClick={() =>
            set.mutate({ id, peers }, { onSuccess: () => toast.success("Peers saved"), onError: (e) => setError(errorText(e)) })
          }
        >
          Save peers
        </button>
      </div>
      <p className="hint">Saving restarts SocketGuard&apos;s node.</p>
    </div>
  );
}
