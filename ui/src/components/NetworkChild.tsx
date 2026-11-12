import { useState, type ReactNode } from "react";
import { api, type ChildInfo, type Network } from "../api";
import { errorText } from "../lib";
import { TOR_BRIDGES_URL, YGG_PUBLIC_PEERS_URL } from "../links";
import { usePortable, useSetNetworkBridges, useSetNetworkPeers } from "../queries";
import { useToast } from "./Toast";

/** The child process of a Tor or Yggdrasil network, in words. */
export function childStateText(m: ChildInfo): string {
  switch (m.state) {
    case "starting":
      return "Starting";
    case "bootstrapping": {
      const via = m.bridges?.length ? " through bridges" : "";
      return m.progress !== undefined ? `Bootstrapping ${m.progress}%${via}` : `Bootstrapping${via}`;
    }
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

/** Portable mode (ADR 0054): a killed SocketGuard cannot remove the adapter driver it installed. */
export const WINTUN_PORTABLE_NOTE =
  "Windows keeps the network driver (Wintun) installed if SocketGuard is closed unexpectedly; it is removed on a normal exit.";

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

/** What a bridge line has to look like, for messages (same wording idea as the daemon's). */
export const BRIDGE_HELP =
  "Only obfs4 bridges are supported, in the form: obfs4 IP:port FINGERPRINT cert=CERT iat-mode=0";

/** Why a pasted line is not an obfs4 bridge line, or null. The same rules as the daemon
 * (`crates/core/src/bridge.rs`), which decides: one line of printable ASCII, optional `Bridge `,
 * then `obfs4 <IPv4:port | [IPv6]:port> <40 hex> cert=<70 base64> iat-mode=<0|1|2>`. */
export function bridgeError(line: string): string | null {
  if (line.length > 300) return `Too long. ${BRIDGE_HELP}`;
  if (!/^[\x20-\x7e]*$/.test(line)) return `Use plain text on one line. ${BRIDGE_HELP}`;
  if (/["'#\\]/.test(line)) return `Quotes, # and backslashes are not allowed. ${BRIDGE_HELP}`;
  const tokens = line.split(" ").filter(Boolean);
  if (tokens[0] === "Bridge") tokens.shift();
  if (tokens.length === 0) return BRIDGE_HELP;
  if (tokens[0] !== "obfs4") return `Only obfs4 bridges are supported (this one is ${tokens[0].slice(0, 20)}). ${BRIDGE_HELP}`;
  if (tokens.length !== 5) return `Expected 5 fields, found ${tokens.length}. ${BRIDGE_HELP}`;
  const [, addr, fp, cert, iat] = tokens;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):([1-9]\d{0,4})$/.exec(addr);
  const v6 = /^\[([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)\]:([1-9]\d{0,4})$/.exec(addr);
  const octets = v4 ? v4.slice(1, 5) : [];
  const okV4 = v4 !== null && octets.every((o) => Number(o) <= 255 && (o === "0" || !o.startsWith("0")));
  const port = Number(v4 ? v4[5] : v6 ? v6[2] : 0);
  if (!(okV4 || v6) || port < 1 || port > 65535) {
    return `The address must be IPv4:port or [IPv6]:port with a port from 1 to 65535. ${BRIDGE_HELP}`;
  }
  if (!/^[0-9A-Fa-f]{40}$/.test(fp)) return `The fingerprint must be 40 hexadecimal characters. ${BRIDGE_HELP}`;
  if (!/^cert=[A-Za-z0-9+/]{70}$/.test(cert)) return `cert= must be followed by 70 base64 characters. ${BRIDGE_HELP}`;
  if (!/^iat-mode=[012]$/.test(iat)) return `The last field must be iat-mode=0, 1 or 2. ${BRIDGE_HELP}`;
  return null;
}

/** A link that opens an allow-listed page in the system browser (the window itself never
 * navigates away). */
function ExternalLink({ url, children }: { url: string; children: ReactNode }) {
  const toast = useToast();
  return (
    <a
      href={url}
      onClick={(e) => {
        e.preventDefault();
        api.openLink(url).catch((err: unknown) => toast.error(errorText(err)));
      }}
    >
      {children}
    </a>
  );
}

/** The state of the network's own Tor or Yggdrasil process, and what runs it. */
export function ChildStatus({ network }: { network: Network }) {
  const m = network.child;
  if (!m) return null;
  return (
    <>
      <span className="muted" aria-label={`${network.name} state`}>
        {childStateText(m)}
      </span>
      {m.runs_as && <small className="muted">runs as {m.runs_as}</small>}
      {m.version && <small className="muted">version {m.version}</small>}
    </>
  );
}

/** What is specific to Tor and Yggdrasil: Yggdrasil's address and peers, Tor's bridges. */
export function ChildDetails({ network }: { network: Network }) {
  const portable = usePortable();
  const m = network.child;
  if (m && network.kind === "tor") {
    return (
      <div className="child-details">
        {/* Remounts when the saved bridges change, so the draft follows the daemon. */}
        <BridgesEditor key={JSON.stringify(m.bridges ?? [])} id={network.id} saved={m.bridges ?? []} unavailable={m.bridges_unavailable} />
      </div>
    );
  }
  if (!m || network.kind !== "yggdrasil") return null;
  const peers = m.peers ?? [];
  return (
    <div className="child-details">
      {m.address && <CopyAddress address={m.address} />}
      {portable && <p className="hint">{WINTUN_PORTABLE_NOTE}</p>}
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
      <p className="hint">
        A new node only finds other nodes on your LAN. Add peers to reach further.{" "}
        <ExternalLink url={YGG_PUBLIC_PEERS_URL}>Find public peers</ExternalLink>
      </p>
    </div>
  );
}

/** The non-empty lines of pasted text, trimmed. */
function bridgeLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

function BridgesEditor({ id, saved, unavailable }: { id: string; saved: string[]; unavailable?: string }) {
  const toast = useToast();
  const set = useSetNetworkBridges();
  const [text, setText] = useState(saved.join("\n"));
  const [error, setError] = useState<string | null>(null);
  const lines = bridgeLines(text);
  const problems = lines.map((l, i) => ({ line: i + 1, why: bridgeError(l) })).filter((p) => p.why !== null);
  const dirty = JSON.stringify(lines) !== JSON.stringify(saved);
  // Without the helper nothing can be set, but bridges that are already saved can be removed.
  const blocked = unavailable !== undefined;
  const locked = blocked && saved.length === 0;

  return (
    <div role="group" aria-label="Bridges">
      <strong>Bridges (if Tor is blocked on this network)</strong>
      <p className="hint">
        Off by default: Tor connects directly. If your network blocks Tor, paste obfs4 bridge lines here, one per line.{" "}
        <ExternalLink url={TOR_BRIDGES_URL}>Get bridges from the Tor Project</ExternalLink>
      </p>
      {blocked && <p className="field-error" role="alert">{unavailable}</p>}
      <textarea
        className="input mono"
        aria-label="Bridge lines"
        rows={4}
        spellCheck={false}
        placeholder="obfs4 192.0.2.1:443 FINGERPRINT cert=… iat-mode=0"
        value={text}
        disabled={locked}
        onChange={(e) => {
          setText(e.target.value);
          setError(null);
        }}
      />
      {problems.map((p) => (
        <span key={p.line} className="field-error" role="alert">{`Line ${p.line}: ${p.why}`}</span>
      ))}
      {error && <span className="field-error" role="alert">{error}</span>}
      <div className="actions">
        <button
          className="btn btn-primary btn-sm"
          disabled={!dirty || (blocked && lines.length > 0) || problems.length > 0 || set.isPending}
          onClick={() =>
            set.mutate(
              { id, bridges: lines },
              { onSuccess: () => toast.success(lines.length ? "Bridges saved" : "Bridges turned off"), onError: (e) => setError(errorText(e)) },
            )
          }
        >
          Save bridges
        </button>
      </div>
      <p className="hint">Saving restarts SocketGuard&apos;s Tor. Only obfs4 bridges are supported.</p>
    </div>
  );
}
