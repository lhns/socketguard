import { useState } from "react";
import type { KindSetup, LanCandidate, NewNetwork } from "../api";
import { errorText } from "../lib";
import { useAddNetwork, useNetworkSetup } from "../queries";
import { useToast } from "./Toast";

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
          {data.lan.length === 0 && <p className="hint">No LAN interface found. Connect this machine to a network, then use Check again.</p>}
          {data.lan
            .filter((l) => !l.already_added)
            .map((l) => <LanCard key={l.interface} lan={l} />)}
          {!data.yggdrasil.added && <KindCard kind="yggdrasil" setup={data.yggdrasil} />}
          {!data.tor.added && <KindCard kind="tor" setup={data.tor} />}
          {data.local.state !== "added" && <LocalCard interfaceName={data.local.found.interface} />}
          {data.lan.every((l) => l.already_added) &&
            data.yggdrasil.added &&
            data.tor.added &&
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

const KIND_TEXT = {
  tor: { title: "Tor", about: "SocketGuard runs its own Tor. Nothing is installed or changed on your system." },
  yggdrasil: { title: "Yggdrasil", about: "SocketGuard runs its own Yggdrasil node. Nothing is installed or changed on your system." },
} as const;

function KindCard({ kind, setup }: { kind: "tor" | "yggdrasil"; setup: KindSetup }) {
  const add = useAddNetwork();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const { title, about } = KIND_TEXT[kind];

  const submit = () => {
    setError(null);
    const req: NewNetwork = kind === "yggdrasil" ? { type: "yggdrasil", peers: [] } : { type: "tor", bridges: [] };
    add.mutate(req, { onSuccess: (n) => toast.success(`Added ${n.name}`), onError: (e) => setError(errorText(e)) });
  };

  return (
    <CardShell label={title} title={title}>
      {setup.available ? (
        <>
          <p>{about}</p>
          {setup.version && <small className="muted">Version {setup.version}</small>}
          {setup.reason && <p className="hint warn">{setup.reason}</p>}
        </>
      ) : (
        <p>Not included in this build{setup.reason ? `: ${setup.reason}` : ""}</p>
      )}
      {setup.available && kind === "yggdrasil" && (
        <p className="hint">Once added, everything on the Yggdrasil adapter is blocked except what you open in SocketGuard.</p>
      )}
      <div className="actions">
        {setup.available && (
          <button className="btn btn-primary btn-sm" aria-label={`Add ${title}`} onClick={submit} disabled={add.isPending}>
            Add
          </button>
        )}
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
    </CardShell>
  );
}
