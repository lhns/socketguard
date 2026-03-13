import { useEffect, useState } from "react";
import { getConfig, updateConfig, ConfigResponse } from "../api";
import { useToast } from "./Toast";

export default function Settings() {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ backend: "", interface: "", poll_interval_secs: 5 });
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const load = () => {
    getConfig()
      .then((c) => {
        setConfig(c);
        setForm({ backend: c.backend, interface: c.interface, poll_interval_secs: c.poll_interval_secs });
      })
      .catch((e) => setError(String(e)));
  };

  useEffect(() => { load(); }, []);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    try {
      const req: Record<string, unknown> = {};
      if (form.backend !== config.backend) req.backend = form.backend;
      if (form.interface !== config.interface) req.interface = form.interface;
      if (form.poll_interval_secs !== config.poll_interval_secs)
        req.poll_interval_secs = form.poll_interval_secs;

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
            <span className="info-value">{config.backend}</span>
            <span className="info-label">Network Interface</span>
            <span className="info-value">{config.interface}</span>
            <span className="info-label">Poll Interval</span>
            <span className="info-value">{config.poll_interval_secs}s</span>
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
                value={form.backend}
                onChange={(e) => setForm({ ...form, backend: e.target.value })}
              >
                <option value="ula">ula</option>
                <option value="yggdrasil">yggdrasil</option>
              </select>

              <span className="info-label">Network Interface</span>
              <input
                className="input"
                value={form.interface}
                onChange={(e) => setForm({ ...form, interface: e.target.value })}
              />

              <span className="info-label">Poll Interval</span>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <input
                  className="input"
                  type="number"
                  min={1}
                  max={3600}
                  value={form.poll_interval_secs}
                  onChange={(e) => setForm({ ...form, poll_interval_secs: parseInt(e.target.value) || 5 })}
                  style={{ width: 80 }}
                />
                <span className="info-label">seconds</span>
              </div>
            </div>

            <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? "Saving..." : "Save"}
              </button>
              <button
                className="btn"
                onClick={() => {
                  setEditing(false);
                  setForm({ backend: config.backend, interface: config.interface, poll_interval_secs: config.poll_interval_secs });
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
