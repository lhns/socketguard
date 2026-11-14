import { useId, useState } from "react";
import { toDaemonError, type Network, type NewNetwork } from "../api";
import { useAddNetworkReviewed } from "../addNetwork";
import { useDeleteNetwork, useNetworks, useNetworkSetup } from "../queries";
import ConfirmDialog from "./ConfirmDialog";
import { ChildDetails, ChildStatus } from "./NetworkChild";
import NetworkCards from "./NetworkCards";
import { useToast } from "./Toast";

type Kind = "slaac" | "dhcpv6" | "ula" | "yggdrasil" | "tor";

const KIND_HELP: Record<Kind, string> = {
  slaac: "A LAN or VLAN: apps get their own addresses from the prefix the router announces. Use an existing VLAN interface (such as eth0.20) for a VLAN; SocketGuard never creates one.",
  dhcpv6: "A LAN whose router hands out addresses by DHCPv6.",
  ula: "Local addresses (fd00::/8) on an interface. On the loopback interface they reach this machine only.",
  yggdrasil: "The Yggdrasil overlay, through SocketGuard's own Yggdrasil node. One per host.",
  tor: "Onion services through SocketGuard's own Tor. One per host.",
};

export default function NetworksSection() {
  const networks = useNetworks();
  const del = useDeleteNetwork();
  const toast = useToast();
  const [removing, setRemoving] = useState<Network | null>(null);
  const [force, setForce] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const remove = (n: Network, forced: boolean) => {
    setRemoveError(null);
    del.mutate({ id: n.id, force: forced }, {
      onSuccess: () => {
        toast.success(`Removed ${n.name}`);
        setRemoving(null);
        setForce(false);
      },
      onError: (e) => {
        const err = toDaemonError(e);
        setRemoveError(err.message);
        // A Tor network that cannot confirm its services are gone offers to go anyway.
        setForce(err.code === "conflict" && n.kind === "tor");
      },
    });
  };

  return (
    <section className="card" aria-label="Networks">
      <h2 className="card-title">Networks</h2>
      <ul className="plain-list">
        {networks.data?.map((n) => (
          <li key={n.id}>
            <div className="net-row">
              <strong>{n.name}</strong>
              <span className="muted">
                {n.kind}
                {n.interface ? ` · ${n.interface}` : ""}
                {n.vlan_id != null ? ` · VLAN ${n.vlan_id}` : ""}
              </span>
              {(n.kind === "tor" || n.kind === "yggdrasil") && <ChildStatus network={n} />}
              {n.status.state === "up" ? (
                <span className="badge reach reach-ok">up</span>
              ) : (
                <span className="badge reach reach-bad" title={n.status.reason}>down: {n.status.reason}</span>
              )}
              {!n.grants_apply && <span className="muted">this machine only</span>}
              <button
                className="btn btn-danger btn-sm"
                aria-label={`Remove network ${n.name}`}
                onClick={() => {
                  setRemoveError(null);
                  setForce(false);
                  setRemoving(n);
                }}
              >
                Remove
              </button>
            </div>
            <ChildDetails network={n} />
          </li>
        ))}
      </ul>
      <NetworkCards />
      <details className="subform advanced">
        <summary>Advanced</summary>
        <AddNetworkForm />
      </details>
      {removing && (
        <ConfirmDialog
          title={`Remove network ${removing.name}?`}
          confirmLabel={force ? "Remove anyway" : "Remove network"}
          onCancel={() => setRemoving(null)}
          onConfirm={() => remove(removing, force)}
        >
          <p>
            Its addresses leave the interfaces and the grants that applied only there stop having an effect. Apps and peers stay.
          </p>
          {(removing.kind === "tor" || removing.kind === "yggdrasil") && (
            <p>SocketGuard&apos;s {removing.kind === "tor" ? "Tor" : "Yggdrasil"} stops with it.</p>
          )}
          {removeError && <div className="error-banner" role="alert">{removeError}</div>}
        </ConfirmDialog>
      )}
    </section>
  );
}

function AddNetworkForm() {
  const id = useId();
  const setup = useNetworkSetup();
  // Host interfaces to pick from; any other name can still be typed.
  const hostInterfaces = [...new Set(setup.data?.lan.map((l) => l.interface) ?? [])];
  const toast = useToast();
  const [kind, setKind] = useState<Kind>("slaac");
  const [iface, setIface] = useState("");
  const [prefix, setPrefix] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = useAddNetworkReviewed((n) => {
    toast.success(`Added ${n.name}`);
    setIface("");
    setPrefix("");
  }, setError);

  // An error that names the interface belongs to that field.
  const hasInterface = kind !== "tor" && kind !== "yggdrasil";
  const interfaceError = error !== null && hasInterface && /interface/i.test(error);

  const build = (): NewNetwork => {
    switch (kind) {
      case "slaac":
        return { type: "slaac", interface: iface.trim(), ...(prefix.trim() ? { prefix: prefix.trim() } : {}) };
      case "dhcpv6":
        return { type: "dhcpv6", interface: iface.trim() };
      case "ula":
        return { type: "ula", interface: iface.trim() };
      case "yggdrasil":
        return { type: "yggdrasil", peers: [] };
      case "tor":
        return { type: "tor", bridges: [] };
    }
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    add.submit(build());
  };

  return (
    <form className="subform" onSubmit={submit} aria-label="Add a network">
      <h3 className="section-title">Add a network by hand</h3>
      <div className="form-inline">
        <div className="form-row">
          <label htmlFor={`${id}-k`}>Type</label>
          <select id={`${id}-k`} className="input" value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
            <option value="slaac">LAN / VLAN (SLAAC)</option>
            <option value="dhcpv6">LAN (DHCPv6)</option>
            <option value="ula">Local (ULA)</option>
            <option value="yggdrasil">Yggdrasil</option>
            <option value="tor">Tor</option>
          </select>
        </div>
        {hasInterface && (
          <div className="form-row">
            <label htmlFor={`${id}-i`}>Interface</label>
            <input
              id={`${id}-i`}
              className="input mono"
              list={`${id}-hosts`}
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              placeholder="eth0 or eth0.20"
              required
            />
            <datalist id={`${id}-hosts`}>
              {hostInterfaces.map((h) => <option key={h} value={h} />)}
            </datalist>
            {interfaceError && <span className="field-error" role="alert">{error}</span>}
          </div>
        )}
        {kind === "slaac" && (
          <div className="form-row">
            <label htmlFor={`${id}-p`}>Prefix (optional)</label>
            <input id={`${id}-p`} className="input mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="auto" />
          </div>
        )}
        <button type="submit" className="btn btn-primary" disabled={add.pending}>Add network</button>
      </div>
      <p className="hint">{KIND_HELP[kind]}</p>
      {error && !interfaceError && <div className="error-banner" role="alert">{error}</div>}
      {add.dialog}
    </form>
  );
}
