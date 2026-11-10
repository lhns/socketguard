import { useEffect, useState } from "react";
import { toDaemonError, type LockoutRiskInfo } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/Toast";
import { errorText } from "../lib";
import { useNetworks, useSetEnabled, useSetProtectHost, useSettings, useStatus } from "../queries";

interface Props {
  /** Open the Apps page filtered to a process. */
  onShowApp: (search: string) => void;
}

export default function SettingsPage({ onShowApp }: Props) {
  const status = useStatus();
  const networks = useNetworks();
  const settings = useSettings();
  const toast = useToast();
  const setEnabled = useSetEnabled();
  const [confirmDisable, setConfirmDisable] = useState(false);
  const s = status.data;

  return (
    <div>
      <section className="card">
        <h2 className="card-title">Networks</h2>
        <ul className="plain-list">
          {networks.data?.map((n) => (
            <li key={n.id} className="net-row">
              <strong>{n.name}</strong>
              <span className="muted">{n.kind}{n.interface ? ` · ${n.interface}` : ""}</span>
              {n.status.state === "up" ? (
                <span className="badge reach reach-ok">up</span>
              ) : (
                <span className="badge reach reach-bad" title={n.status.reason}>down: {n.status.reason}</span>
              )}
              {!n.grants_apply && <span className="muted">this machine only</span>}
            </li>
          ))}
        </ul>
        <p className="hint">Add networks with <code>socketguard networks add</code>.</p>
      </section>

      <ProtectHost interfaces={networks.data?.flatMap((n) => (n.interface && n.grants_apply ? [n.interface] : [])) ?? []}
        current={settings.data?.protect_host_interfaces ?? s?.protect_host_interfaces ?? []}
        onShowApp={onShowApp} />

      <section className="card">
        <h2 className="card-title">Addresses</h2>
        <p>
          Address mode: <strong>{settings.data ? (settings.data.address_mode === "per_app" ? "one address per app" : "one address per port") : "…"}</strong>
        </p>
      </section>

      <section className="card">
        <h2 className="card-title">Daemon</h2>
        {s ? (
          <>
            <p>
              Version {s.version} · {s.counts.apps} apps ({s.counts.pending_apps} pending) · {s.counts.peers} peers ·{" "}
              {s.counts.grants} grants
            </p>
            <p>
              Enforcement: <strong>{s.disabled ? "off" : s.unadopted ? "waiting (existing ruleset not adopted)" : "on"}</strong>
            </p>
            <div className="actions">
              {s.disabled || s.unadopted ? (
                <button className="btn btn-primary" disabled={setEnabled.isPending}
                  onClick={() => setEnabled.mutate(true, { onSuccess: () => toast.success("Enforcement on"), onError: (e) => toast.error(errorText(e)) })}>
                  {s.unadopted && !s.disabled ? "Adopt and enforce" : "Enable enforcement"}
                </button>
              ) : (
                <button className="btn btn-danger" onClick={() => setConfirmDisable(true)}>Disable enforcement</button>
              )}
            </div>
          </>
        ) : (
          <p className="muted">Daemon not reachable.</p>
        )}
        {confirmDisable && (
          <ConfirmDialog
            title="Disable enforcement?"
            confirmLabel="Disable"
            onCancel={() => setConfirmDisable(false)}
            onConfirm={() => {
              setConfirmDisable(false);
              setEnabled.mutate(false, { onSuccess: () => toast.success("Enforcement off"), onError: (e) => toast.error(errorText(e)) });
            }}
          >
            <p>All firewall rules and addresses are removed and stay off, also after a restart, until you enable enforcement again. Every service becomes reachable as the network allows.</p>
          </ConfirmDialog>
        )}
      </section>
    </div>
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
    <section className="card">
      <h2 className="card-title">Protect the whole host</h2>
      <p className="hint">Closes every port on the chosen interfaces unless an app has a grant, not just apps SocketGuard manages.</p>
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
