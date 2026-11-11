import { useId, useState } from "react";
import { toDaemonError, type Network, type NewNetwork } from "../api";
import { errorText } from "../lib";
import { useAddNetwork, useDeleteNetwork, useExposure, useNetworks, useNetworkSetup } from "../queries";
import ConfirmDialog from "./ConfirmDialog";
import ExposureNotice, { exposedNetworks, stoppable, stopStartedService } from "./ExposureNotice";
import NetworkCards from "./NetworkCards";
import { useToast } from "./Toast";

type Kind = "slaac" | "dhcpv6" | "ula" | "yggdrasil" | "tor";

const KIND_HELP: Record<Kind, string> = {
  slaac: "A LAN or VLAN: apps get their own addresses from the prefix the router announces. Use an existing VLAN interface (such as eth0.20) for a VLAN; SocketGuard never creates one.",
  dhcpv6: "A LAN whose router hands out addresses by DHCPv6.",
  ula: "Local addresses (fd00::/8) on an interface. On the loopback interface they reach this machine only.",
  yggdrasil: "The Yggdrasil overlay. One per host. Leave the interface empty to use the one that holds the node's address.",
  tor: "Onion services through a Tor control port on this machine (127.0.0.1:9051, cookie authentication). Other control settings are edited in the config file. One per host.",
};

export default function NetworksSection() {
  const networks = useNetworks();
  const del = useDeleteNetwork();
  const toast = useToast();
  const [removing, setRemoving] = useState<Network | null>(null);
  const [force, setForce] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const configPath = useNetworkSetup().data?.config_path;
  const exposure = useExposure(removing?.id ?? "", removing?.kind === "yggdrasil");
  const exposed = exposedNetworks(exposure.data);
  const [stop, setStop] = useState(true);

  const remove = async (n: Network, forced: boolean) => {
    setRemoveError(null);
    // The service goes first: if it cannot be stopped, the block stays and nothing is removed.
    if (exposed.length > 0 && stoppable(exposed) && stop) {
      const why = await stopStartedService(configPath);
      if (why) {
        setRemoveError(why);
        return;
      }
    }
    del.mutate({ id: n.id, force: forced, confirmExposed: exposed.length > 0 }, {
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
          <li key={n.id} className="net-row">
            <strong>{n.name}</strong>
            <span className="muted">
              {n.kind}
              {n.interface ? ` · ${n.interface}` : ""}
              {n.vlan_id != null ? ` · VLAN ${n.vlan_id}` : ""}
            </span>
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
                setStop(true);
                setRemoving(n);
              }}
            >
              Remove
            </button>
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
          onConfirm={() => void remove(removing, force)}
        >
          <p>
            Its addresses leave the interfaces and the grants that applied only there stop having an effect. Apps and peers stay.
          </p>
          <ExposureNotice exposure={exposure.data} stop={stop} onStop={setStop} />
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
  const hostInterfaces = [
    ...new Set([
      ...(setup.data?.lan.map((l) => l.interface) ?? []),
      ...(setup.data?.yggdrasil.found.interface ? [setup.data.yggdrasil.found.interface] : []),
    ]),
  ];
  const toast = useToast();
  const add = useAddNetwork();
  const [kind, setKind] = useState<Kind>("slaac");
  const [iface, setIface] = useState("");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [error, setError] = useState<string | null>(null);

  // An error that names the interface belongs to that field.
  const interfaceError = error !== null && kind !== "tor" && /interface/i.test(error);

  const build = (): NewNetwork => {
    switch (kind) {
      case "slaac":
        return { type: "slaac", interface: iface.trim(), ...(prefix.trim() ? { prefix: prefix.trim() } : {}) };
      case "dhcpv6":
        return { type: "dhcpv6", interface: iface.trim() };
      case "ula":
        return { type: "ula", interface: iface.trim() };
      case "yggdrasil":
        return { type: "yggdrasil", ...(iface.trim() ? { interface: iface.trim() } : {}), ...(endpoint.trim() ? { admin_endpoint: endpoint.trim() } : {}) };
      case "tor":
        return { type: "tor", control: "127.0.0.1:9051", auth: "cookie" };
    }
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    add.mutate(build(), {
      onSuccess: (n) => {
        toast.success(`Added ${n.name}`);
        setIface("");
        setPrefix("");
        setEndpoint("");
      },
      onError: (err) => setError(errorText(err)),
    });
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
        {kind !== "tor" && (
          <div className="form-row">
            <label htmlFor={`${id}-i`}>Interface</label>
            <input
              id={`${id}-i`}
              className="input mono"
              list={`${id}-hosts`}
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              placeholder={kind === "yggdrasil" ? "found automatically" : "eth0 or eth0.20"}
              required={kind !== "yggdrasil"}
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
        {kind === "yggdrasil" && (
          <div className="form-row">
            <label htmlFor={`${id}-e`}>Admin endpoint (optional)</label>
            <input id={`${id}-e`} className="input mono" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="unix:///var/run/yggdrasil.sock" />
          </div>
        )}
        <button type="submit" className="btn btn-primary" disabled={add.isPending}>Add network</button>
      </div>
      <p className="hint">{KIND_HELP[kind]}</p>
      {error && !interfaceError && <div className="error-banner" role="alert">{error}</div>}
    </form>
  );
}
