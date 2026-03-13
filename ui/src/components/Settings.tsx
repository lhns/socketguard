import { useEffect, useState } from "react";
import { getConfig, updateConfig, onConfigChanged, onDaemonConnected, ConfigResponse, BackendConfig } from "../api";
import { useToast } from "./Toast";

function defaultBackendConfig(type: string): BackendConfig {
  switch (type) {
    case "yggdrasil":
      return { type: "yggdrasil", interface: "" };
    case "slaac":
      return { type: "slaac", interface: "", prefix: "" };
    case "dhcpv6":
      return { type: "dhcpv6", interface: "" };
    default:
      return { type: "ula", interface: "" };
  }
}

export default function Settings() {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [formBackend, setFormBackend] = useState<BackendConfig>({ type: "ula", interface: "" });
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const load = () => {
    getConfig()
      .then((c) => {
        setConfig(c);
        setFormBackend({ ...c.backend });
      })
      .catch((e) => setError(String(e)));
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const unlistens: (() => void)[] = [];
    onConfigChanged(() => load()).then((fn) => unlistens.push(fn));
    onDaemonConnected(() => { setError(null); load(); }).then((fn) => unlistens.push(fn));
    return () => unlistens.forEach((fn) => fn());
  }, []);

  const handleTypeChange = (newType: string) => {
    if (newType === formBackend.type) return;
    const newConfig = defaultBackendConfig(newType);
    // Carry over interface if switching between types
    if (formBackend.interface) {
      newConfig.interface = formBackend.interface;
    }
    setFormBackend(newConfig);
  };

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    try {
      const req: Record<string, unknown> = {};

      // Check if backend config changed
      if (JSON.stringify(formBackend) !== JSON.stringify(config.backend)) {
        req.backend = formBackend;
      }

      if (Object.keys(req).length === 0) {
        setEditing(false);
        return;
      }

      await updateConfig(req);
      toast.success("Configuration updated");
      setEditing(false);
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSaving(false);
    }
  };

  if (error) return <div className="error-banner">Cannot connect to daemon: {error}</div>;
  if (!config) return <div className="loading">Loading configuration...</div>;

  return (
    <div>
      <div className="card-header">
        <span className="card-title">Daemon Configuration</span>
        {!editing && (
          <button className="btn btn-sm" onClick={() => setEditing(true)}>Edit</button>
        )}
      </div>

      <div className="card">
        {!editing ? (
          <div className="info-grid">
            <span className="info-label">API Address</span>
            <span className="info-value mono">{config.listen_addr}:{config.listen_port}</span>
            <span className="info-label">Backend</span>
            <span className="info-value">{config.backend.type}</span>
            <span className="info-label">Network Interface</span>
            <span className="info-value">{config.backend.interface}</span>
            {config.backend.type === "slaac" && (
              <>
                <span className="info-label">Prefix</span>
                <span className="info-value mono">
                  {config.backend.prefix || "auto (discovered)"}
                </span>
              </>
            )}
          </div>
        ) : (
          <>
            <div className="info-grid" style={{ alignItems: "center" }}>
              <span className="info-label">API Address</span>
              <span className="info-value mono" style={{ color: "var(--text-muted)" }}>
                {config.listen_addr}:{config.listen_port}
                <span style={{ fontSize: 11, marginLeft: 8, opacity: 0.6 }}>(restart required)</span>
              </span>

              <span className="info-label">Backend</span>
              <select
                className="input"
                value={formBackend.type}
                onChange={(e) => handleTypeChange(e.target.value)}
              >
                <option value="ula">ULA (local only)</option>
                <option value="yggdrasil">Yggdrasil (overlay network)</option>
                <option value="slaac">SLAAC (LAN routable)</option>
                <option value="dhcpv6">DHCPv6 (server-managed)</option>
              </select>

              <span className="info-label">Network Interface</span>
              <input
                className="input"
                value={formBackend.interface}
                placeholder={formBackend.type === "ula" ? "Loopback Pseudo-Interface 1" : "Ethernet"}
                onChange={(e) => setFormBackend({ ...formBackend, interface: e.target.value })}
              />

              {formBackend.type === "slaac" && (
                <>
                  <span className="info-label">IPv6 Prefix</span>
                  <input
                    className="input"
                    value={(formBackend as { prefix?: string }).prefix || ""}
                    placeholder="auto (discover from interface)"
                    onChange={(e) =>
                      setFormBackend({ ...formBackend, prefix: e.target.value || undefined } as BackendConfig)
                    }
                  />
                </>
              )}

            </div>

            <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? "Saving..." : "Save"}
              </button>
              <button
                className="btn"
                onClick={() => {
                  setEditing(false);
                  setFormBackend({ ...config.backend });
                }}
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
