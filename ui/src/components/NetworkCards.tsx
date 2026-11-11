import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, type LanCandidate, type NetworkSetup, type SetupKind, type SetupState } from "../api";
import { errorText } from "../lib";
import { useAddNetwork, useNetworkSetup } from "../queries";
import { useToast } from "./Toast";

/** The line that says where a kind of network stands. */
function stateLine(kind: SetupKind, s: SetupState): string {
  switch (s.state) {
    case "ready":
      return s.found.address
        ? `Found at ${s.found.address}${s.found.interface ? ` on ${s.found.interface}` : ""}.`
        : "Found and ready.";
    case "not_installed":
      if (s.install) {
        const name = kind === "yggdrasil" ? "Yggdrasil" : "Tor";
        return `${name} is not installed. SocketGuard can install it with ${s.install.manager}.`;
      }
      return s.missing ?? "Not installed.";
    default:
      return s.missing ?? "Needs setup.";
  }
}

/** Yggdrasil: how many peers the node has. Only a reading; its config is never edited. */
function peersLine(s: SetupState): string | null {
  const n = s.found.peers;
  if (n === undefined) return null;
  return Number(n) > 0
    ? `Connected to ${n} ${Number(n) === 1 ? "peer" : "peers"}.`
    : "No peers yet: it only finds other nodes on your LAN. Add peers in Yggdrasil's config to reach further.";
}

export default function NetworkCards() {
  const setup = useNetworkSetup();
  const data = setup.data;
  return (
    <div className="subform" aria-label="Add a network">
      <div className="net-cards-head">
        <h3 className="section-title">Add a network</h3>
        <button className="btn btn-sm" onClick={() => void setup.refetch()} disabled={setup.isFetching}>
          Check again
        </button>
      </div>
      {setup.isError && <div className="error-banner" role="alert">{errorText(setup.error)}</div>}
      {data && (
        <div className="net-cards">
          {data.lan
            .filter((l) => !l.already_added)
            .map((l) => <LanCard key={l.interface} lan={l} />)}
          {data.yggdrasil.state !== "added" && (
            <KindCard kind="yggdrasil" title="Yggdrasil" state={data.yggdrasil} data={data} />
          )}
          {data.tor.state !== "added" && <KindCard kind="tor" title="Tor" state={data.tor} data={data} />}
          {data.local.state !== "added" && <LocalCard interfaceName={data.local.found.interface} />}
          {data.lan.every((l) => l.already_added) &&
            data.yggdrasil.state === "added" &&
            data.tor.state === "added" &&
            data.local.state === "added" && <p className="hint">Every network this machine offers is added.</p>}
        </div>
      )}
    </div>
  );
}

function CardShell(props: { label: string; title: string; sub?: string; children: React.ReactNode }) {
  return (
    <article className="net-card" aria-label={props.label}>
      <header>
        <strong>{props.title}</strong>
        {props.sub && <span className="muted"> · {props.sub}</span>}
      </header>
      {props.children}
    </article>
  );
}

function LanCard({ lan }: { lan: LanCandidate }) {
  const add = useAddNetwork();
  const toast = useToast();
  const [dhcp, setDhcp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    setError(null);
    add.mutate(
      dhcp ? { type: "dhcpv6", interface: lan.interface } : { type: "slaac", interface: lan.interface },
      { onSuccess: (n) => toast.success(`Added ${n.name}`), onError: (e) => setError(errorText(e)) },
    );
  };
  return (
    <CardShell label={`LAN ${lan.interface}`} title={lan.interface} sub={lan.description}>
      <p className="hint">
        {[
          lan.is_default_route ? "default route" : null,
          lan.vlan_id != null ? `VLAN ${lan.vlan_id}` : null,
          lan.has_ipv6_prefix ? null : "no IPv6 prefix announced",
        ]
          .filter(Boolean)
          .join(" · ") || "LAN"}
      </p>
      {!lan.has_ipv6_prefix && (
        <p className="hint warn">The router announces no IPv6 prefix here. You can still add it; apps get addresses once one appears.</p>
      )}
      <label className="check">
        <input type="checkbox" checked={dhcp} onChange={(e) => setDhcp(e.target.checked)} /> uses DHCPv6
      </label>
      <div className="actions">
        <button className="btn btn-primary btn-sm" aria-label={`Add ${lan.interface}`} onClick={submit} disabled={add.isPending}>
          Add
        </button>
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
    </CardShell>
  );
}

function LocalCard({ interfaceName }: { interfaceName?: string }) {
  const add = useAddNetwork();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  return (
    <CardShell label="Local" title="Local (this machine only)">
      <p className="hint">Addresses that reach only this machine.</p>
      <div className="actions">
        <button
          className="btn btn-primary btn-sm"
          aria-label="Add Local"
          disabled={add.isPending}
          onClick={() => {
            setError(null);
            add.mutate({ type: "ula", interface: interfaceName ?? "lo" }, { onSuccess: (n) => toast.success(`Added ${n.name}`), onError: (e) => setError(errorText(e)) });
          }}
        >
          Add
        </button>
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
    </CardShell>
  );
}

function KindCard({ kind, title, state, data }: { kind: SetupKind; title: string; state: SetupState; data: NetworkSetup }) {
  const add = useAddNetwork();
  const toast = useToast();
  const setup = useNetworkSetup();
  const [panel, setPanel] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canSetUp =
    state.state === "not_running" || state.state === "not_configured" || (state.state === "not_installed" && !!state.install);

  const submit = () => {
    setError(null);
    add.mutate(kind === "yggdrasil" ? { type: "yggdrasil" } : { type: "tor", control: "127.0.0.1:9051", auth: "cookie" }, {
      onSuccess: (n) => toast.success(`Added ${n.name}`),
      onError: (e) => setError(errorText(e)),
    });
  };

  return (
    <CardShell label={title} title={title}>
      <p>{stateLine(kind, state)}</p>
      {kind === "yggdrasil" && state.state === "ready" && peersLine(state) && <p className="hint">{peersLine(state)}</p>}
      {kind === "yggdrasil" && state.state === "ready" && (
        <p className="hint">
          Once added, everything on the Yggdrasil adapter is blocked except what you open in SocketGuard.
        </p>
      )}
      <div className="actions">
        {state.state === "ready" && (
          <button className="btn btn-primary btn-sm" aria-label={`Add ${title}`} onClick={submit} disabled={add.isPending}>
            Add
          </button>
        )}
        {canSetUp && (
          <button className="btn btn-primary btn-sm" aria-expanded={panel} onClick={() => setPanel(!panel)}>
            Set up…
          </button>
        )}
        {state.state === "not_installed" && !state.install && state.download_link && (
          <button className="btn btn-sm" onClick={() => void api.openDownloadPage(state.download_link as string).catch((e) => setError(errorText(e)))}>
            Download page
          </button>
        )}
        {state.state === "not_installed" && !state.install && (
          <button className="btn btn-sm" onClick={() => void setup.refetch()} disabled={setup.isFetching}>
            Check again
          </button>
        )}
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {panel && canSetUp && <SetupPanel kind={kind} state={state} configPath={data.config_path} onDone={() => setPanel(false)} />}
    </CardShell>
  );
}

/** What the elevated command will do, and the button that runs it. */
function SetupPanel({ kind, state, configPath, onDone }: { kind: SetupKind; state: SetupState; configPath?: string; onDone: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [byHand, setByHand] = useState<string | null>(null);

  const steps: string[] = [];
  if (state.state === "not_installed" && state.install) steps.push(`Install ${kind === "tor" ? "Tor" : "Yggdrasil"}: ${state.install.command}`);
  if (state.state === "not_running") steps.push(`Start the ${kind === "tor" ? "Tor" : "Yggdrasil"} service.`);
  if (kind === "tor") {
    steps.push(
      "Use Tor's control endpoint if it has one. If not, add ControlPort 9051 and CookieAuthentication 1 to its torrc (a copy is kept as torrc.socketguard.bak) and restart Tor.",
    );
    steps.push("Tell SocketGuard where Tor's cookie file is, from the torrc, and add the Tor network.");
  } else {
    steps.push("Add the Yggdrasil network. Yggdrasil's own configuration is not touched.");
  }
  const command = `socketguard networks setup ${kind} --yes`;
  const windowsYgg = kind === "yggdrasil" && state.install?.manager === "winget";

  const run = async () => {
    if (!configPath) return;
    setBusy(true);
    setMessage(null);
    setByHand(null);
    try {
      const r = await api.runNetworkSetup(kind, configPath);
      if (r.cancelled) {
        setMessage("Cancelled: nothing was changed.");
      } else if (!r.launched) {
        setByHand(r.command);
        setMessage("This system has no way to ask for administrator rights from here. Run this in a terminal with administrator rights:");
      } else if (r.exit_code === 0) {
        toast.success(`${kind === "tor" ? "Tor" : "Yggdrasil"} is set up`);
        onDone();
      } else {
        setMessage(`The setup stopped (exit code ${r.exit_code ?? "unknown"}). Its window shows why; fix that, then check again.`);
      }
    } catch (e) {
      setMessage(errorText(e));
    } finally {
      setBusy(false);
      void qc.invalidateQueries({ queryKey: ["networkSetup"] });
      void qc.invalidateQueries({ queryKey: ["networks"] });
    }
  };

  return (
    <div className="setup-panel" role="group" aria-label={`Set up ${kind}`}>
      <p>Setting up needs administrator rights. It will:</p>
      <ol>{steps.map((s) => <li key={s}>{s}</li>)}</ol>
      {windowsYgg && (
        <p className="hint">
          Installs the Yggdrasil service and its network adapter driver; it starts with Windows. Removing the network in SocketGuard does not uninstall it.
        </p>
      )}
      <p className="hint">
        The command: <code>{command}</code>. You can undo this later with <code>{`socketguard networks setup ${kind} --undo`}</code>;
        the changes are listed in setup-log.json next to the config file.
      </p>
      <div className="actions">
        <button className="btn btn-primary btn-sm" onClick={() => void run()} disabled={busy || !configPath}>
          Run as administrator
        </button>
      </div>
      {!configPath && <p className="hint warn">The daemon did not say where its config file is.</p>}
      {message && <p role="status">{message}</p>}
      {byHand && <pre className="mono">{byHand}</pre>}
    </div>
  );
}
