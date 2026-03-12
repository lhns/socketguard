import { useEffect, useState } from "react";
import { getConfig, ConfigResponse } from "../api";

export default function Settings() {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getConfig()
      .then(setConfig)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <p style={{ color: "red" }}>Error connecting to daemon: {error}</p>;
  if (!config) return <p>Loading...</p>;

  return (
    <div>
      <h2>Daemon Configuration</h2>
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
