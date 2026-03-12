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

  if (error) return <p style={{ color: "red" }}>Error connecting to daemon: {error}</p>;
  if (!config) return <p>Loading...</p>;

  if (!editing) {
    return (
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h2 style={{ margin: 0 }}>Daemon Configuration</h2>
          <button onClick={() => setEditing(true)} style={{ padding: "0.3rem 0.8rem", cursor: "pointer" }}>
            Edit
          </button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0.5rem 1.5rem", maxWidth: 500 }}>
          <strong>API Address:</strong>
          <span>{config.listen_addr}:{config.listen_port}</span>
          <strong>Backend:</strong>
          <span>{config.backend}</span>
          <strong>Network Interface:</strong>
          <span>{config.interface}</span>
          <strong>Poll Interval:</strong>
          <span>{config.poll_interval_secs}s</span>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2>Edit Configuration</h2>
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0.6rem 1.5rem", maxWidth: 500, alignItems: "center" }}>
        <strong>API Address:</strong>
        <span style={{ color: "#999" }}>{config.listen_addr}:{config.listen_port} (restart required)</span>

        <strong>Backend:</strong>
        <select
          value={form.backend}
          onChange={(e) => setForm({ ...form, backend: e.target.value })}
          style={{ padding: "0.3rem" }}
        >
          <option value="ula">ula</option>
          <option value="yggdrasil">yggdrasil</option>
        </select>

        <strong>Network Interface:</strong>
        <input
          value={form.interface}
          onChange={(e) => setForm({ ...form, interface: e.target.value })}
          style={{ padding: "0.3rem" }}
        />

        <strong>Poll Interval:</strong>
        <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <input
            type="number"
            min={1}
            max={3600}
            value={form.poll_interval_secs}
            onChange={(e) => setForm({ ...form, poll_interval_secs: parseInt(e.target.value) || 5 })}
            style={{ padding: "0.3rem", width: 80 }}
          />
          <span>seconds</span>
        </div>
      </div>

      <div style={{ marginTop: "1.2rem", display: "flex", gap: "0.5rem" }}>
        <button
          onClick={handleSave}
          disabled={saving}
          style={{ padding: "0.4rem 1rem", cursor: "pointer", background: "#333", color: "#fff", border: "1px solid #333", borderRadius: 4 }}
        >
          {saving ? "Saving..." : "Save"}
        </button>
        <button
          onClick={() => {
            setEditing(false);
            setForm({ backend: config.backend, interface: config.interface, poll_interval_secs: config.poll_interval_secs });
          }}
          style={{ padding: "0.4rem 1rem", cursor: "pointer", border: "1px solid #999", borderRadius: 4, background: "#fff" }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
