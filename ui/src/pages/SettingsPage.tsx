import { useEffect, useState } from "react";
import { toDaemonError, type LockoutRiskInfo } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import ExposureNotice, { exposedNetworks, stoppable, stopStartedService } from "../components/ExposureNotice";
import ExportSection from "../components/ExportSection";
import NetworksSection from "../components/NetworksSection";
import { useToast } from "../components/Toast";
import { errorText } from "../lib";
import { useNav } from "../nav";
import { useExposure, useNetworks, useNetworkSetup, useSetEnabled, useSetProtectHost, useSettings, useStatus } from "../queries";

export default function SettingsPage() {
  const nav = useNav();
  const status = useStatus();
  const networks = useNetworks();
  const settings = useSettings();

  return (
    <div>
      <NetworksSection />

      <ProtectHost
        interfaces={networks.data?.flatMap((n) => (n.interface && n.grants_apply ? [n.interface] : [])) ?? []}
        current={settings.data?.protect_host_interfaces ?? status.data?.protect_host_interfaces ?? []}
        onShowApp={(search) => nav.go("apps", { search })}
      />

      <ExportSection />

      <DangerZone />
    </div>
  );
}

function DangerZone() {
  const status = useStatus();
  const toast = useToast();
  const setEnabled = useSetEnabled();
  const [confirmOff, setConfirmOff] = useState(false);
  const [stop, setStop] = useState(true);
  const [offError, setOffError] = useState<string | null>(null);
  const exposure = useExposure("all", confirmOff);
  const configPath = useNetworkSetup().data?.config_path;
  const s = status.data;

  const turnOff = async () => {
    setOffError(null);
    // The service goes first: if it cannot be stopped, SocketGuard stays on.
    const exposed = exposedNetworks(exposure.data);
    if (stoppable(exposed) && stop) {
      const why = await stopStartedService(configPath);
      if (why) {
        setOffError(why);
        return;
      }
    }
    setConfirmOff(false);
    setEnabled.mutate(false, {
      onSuccess: () => toast.success("SocketGuard is off"),
      onError: (e) => toast.error(errorText(e)),
    });
  };

  return (
    <section className="card danger-zone" aria-label="Danger zone">
      <h2 className="card-title">Daemon</h2>
      {s ? (
        <>
          <p>
            Version {s.version} · {s.counts.apps} apps ({s.counts.pending_apps} pending) · {s.counts.peers} peers ·{" "}
            {s.counts.grants} grants
          </p>
          <p>
            SocketGuard is <strong>{s.disabled ? "off" : s.unadopted ? "waiting" : "on"}</strong>.
          </p>
          {s.unadopted && !s.disabled && (
            <p>Rules from an earlier install are active, but this database doesn&apos;t know them. Adopt them?</p>
          )}
          <div className="actions">
            {s.disabled || s.unadopted ? (
              <button
                className="btn btn-primary"
                disabled={setEnabled.isPending}
                onClick={() =>
                  setEnabled.mutate(true, {
                    onSuccess: () => toast.success("SocketGuard is on"),
                    onError: (e) => toast.error(errorText(e)),
                  })
                }
              >
                {s.unadopted && !s.disabled ? "Adopt them and turn on" : "Turn SocketGuard on"}
              </button>
            ) : null}
            {!s.disabled && (
              <button
                className="btn btn-danger"
                onClick={() => {
                  setOffError(null);
                  setStop(true);
                  setConfirmOff(true);
                }}
              >
                Turn SocketGuard off
              </button>
            )}
          </div>
        </>
      ) : (
        <p className="muted">Daemon not reachable.</p>
      )}
      {confirmOff && (
        <ConfirmDialog
          title="Turn SocketGuard off?"
          confirmLabel="Turn SocketGuard off"
          onCancel={() => setConfirmOff(false)}
          onConfirm={() => void turnOff()}
        >
          <p>
            This removes all firewall rules and addresses SocketGuard added, and keeps them off, also after a restart, until you
            turn it on again. The host is then as open as the network allows: every service is reachable by whoever can reach the
            machine.
          </p>
          <ExposureNotice exposure={exposure.data} stop={stop} onStop={setStop} />
          {offError && <div className="error-banner" role="alert">{offError}</div>}
        </ConfirmDialog>
      )}
    </section>
  );
}

function ProtectHost({ interfaces, current, onShowApp }: { interfaces: string[]; current: string[]; onShowApp: (s: string) => void }) {
  const toast = useToast();
  const set = useSetProtectHost();
  const [chosen, setChosen] = useState<string[]>(current);
  const [risks, setRisks] = useState<LockoutRiskInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = current.join("\n");

  // Follow the daemon's value (changes arrive over the event stream).
  useEffect(() => {
    setChosen(key ? key.split("\n") : []);
  }, [key]);

  const options = [...new Set([...interfaces, ...current])];
  const dirty = chosen.slice().sort().join() !== current.slice().sort().join();

  function apply(force: boolean) {
    setError(null);
    set.mutate({ interfaces: chosen, force }, {
      onSuccess: (r) => {
        setRisks(null);
        toast.success(r.overridden.length ? "Protection on (risks overridden)" : "Protection updated");
      },
      onError: (e) => {
        const err = toDaemonError(e);
        if (err.code === "protect_host_refused") setRisks(Array.isArray(err.details) ? (err.details as LockoutRiskInfo[]) : []);
        else setError(err.message);
      },
    });
  }

  return (
    <section className="card" aria-label="Protect the whole host">
      <h2 className="card-title">Protect the whole host</h2>
      <p className="hint">Closes every port on the chosen interfaces unless an app has a grant, not just apps SocketGuard manages.</p>
      <p className="hint">
        IPv4 follows the interface: with protection on, only IPv4 peers (IP credentials) that have a grant get in over IPv4. With
        it off, an app that listens on IPv4 is open to everyone over IPv4, whatever its grants say.
      </p>
      <fieldset className="checks">
        <legend className="visually-hidden">Interfaces to protect</legend>
        {options.length === 0 && <p className="muted">No interfaces available.</p>}
        {options.map((i) => (
          <label key={i} className="check">
            <input
              type="checkbox"
              checked={chosen.includes(i)}
              onChange={(e) => setChosen(e.target.checked ? [...chosen, i] : chosen.filter((x) => x !== i))}
            />
            {i}
          </label>
        ))}
      </fieldset>
      {error && <div className="error-banner" role="alert">{error}</div>}
      <div className="actions">
        <button className="btn btn-primary" disabled={!dirty || set.isPending} onClick={() => apply(false)}>Apply</button>
      </div>
      {risks && (
        <ConfirmDialog
          title="This would cut off remote access"
          confirmLabel="Enable anyway"
          onCancel={() => setRisks(null)}
          onConfirm={() => apply(true)}
        >
          <p>These listeners have no grant. Protecting the host would block them, and you could lose access to this machine:</p>
          <ul className="risk-list">
            {risks.map((r) => (
              <li key={`${r.process_name}-${r.port}-${r.protocol}`}>
                {r.message}{" "}
                <button className="btn btn-sm" onClick={() => { setRisks(null); onShowApp(r.process_name); }}>
                  Grant them first ({r.process_name})
                </button>
              </li>
            ))}
          </ul>
          <p className="strong-warning"><strong>Enable anyway</strong> applies the protection regardless. You may be locked out of this machine.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}
