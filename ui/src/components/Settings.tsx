import { useEffect, useState, useRef } from "react";
import {
  getConfig, updateConfig, onConfigChanged, onDaemonConnected,
  listBackendInstances, listInterfaces, addBackend, removeBackend,
  ConfigResponse, BackendInstanceConfig, BackendInfo, AddBackendRequest,
} from "../api";
import { useToast } from "./Toast";
import ConfirmDialog from "./ConfirmDialog";

function InterfaceSelect({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    listInterfaces()
      .then((r) => {
        setInterfaces(r.interfaces);
        if (!value && r.interfaces.length > 0) {
          onChange(r.interfaces[0]);
        }
      })
      .catch(() => {});
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const filtered = interfaces.filter((iface) =>
    iface.toLowerCase().includes((open ? filter : "").toLowerCase())
  );

  const handleSelect = (iface: string) => {
    onChange(iface);
    setFilter("");
    setOpen(false);
  };

  const displayValue = open ? filter : value;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <input
        ref={inputRef}
        className="input"
        value={displayValue}
        placeholder={placeholder || "Select interface..."}
        onChange={(e) => {
          setFilter(e.target.value);
          onChange(e.target.value);
          if (!open) setOpen(true);
        }}
        onFocus={() => {
          setOpen(true);
          setFilter(value);
        }}
        autoComplete="off"
      />
      {open && filtered.length > 0 && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            zIndex: 100,
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            marginTop: 2,
            maxHeight: 200,
            overflowY: "auto",
            boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
          }}
        >
          {filtered.map((iface) => (
            <div
              key={iface}
              onClick={() => handleSelect(iface)}
              style={{
                padding: "8px 12px",
                cursor: "pointer",
                fontSize: 13,
                fontFamily: "var(--font-mono, monospace)",
                background: iface === value ? "var(--bg-hover)" : "transparent",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) =>
                (e.currentTarget.style.background =
                  iface === value ? "var(--bg-hover)" : "transparent")
              }
            >
              {iface}
            </div>
          ))}
        </div>
      )}
      {open && filtered.length === 0 && filter && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            zIndex: 100,
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            marginTop: 2,
            padding: "8px 12px",
            fontSize: 13,
            color: "var(--text-muted)",
            boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
          }}
        >
          No matching interfaces
        </div>
      )}
    </div>
  );
}

function TypeSelect({
  value,
  onChange,
  types,
  activeSingletons,
}: {
  value: string;
  onChange: (v: string) => void;
  types: BackendInfo[];
  activeSingletons: Set<string>;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const selected = types.find((t) => t.name === value);

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <div
        className="input"
        onClick={() => setOpen(!open)}
        style={{ cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between" }}
      >
        <span>{selected ? selected.name.toUpperCase() : value.toUpperCase()}</span>
        <svg width="10" height="6" viewBox="0 0 10 6" style={{ opacity: 0.5 }}>
          <path d="M1 1l4 4 4-4" stroke="currentColor" fill="none" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>
      {open && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            zIndex: 100,
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            marginTop: 2,
            maxHeight: 200,
            overflowY: "auto",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
          }}
        >
          {types.map((t) => {
            const disabled = t.singleton && activeSingletons.has(t.name);
            return (
              <div
                key={t.name}
                onClick={() => {
                  if (!disabled) {
                    onChange(t.name);
                    setOpen(false);
                  }
                }}
                style={{
                  padding: "8px 12px",
                  cursor: disabled ? "default" : "pointer",
                  fontSize: 13,
                  opacity: disabled ? 0.4 : 1,
                  background: t.name === value ? "var(--bg-hover)" : "transparent",
                }}
                onMouseEnter={(e) => {
                  if (!disabled) e.currentTarget.style.background = "var(--bg-hover)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = t.name === value ? "var(--bg-hover)" : "transparent";
                }}
              >
                <div style={{ fontWeight: 500 }}>{t.name.toUpperCase()}</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 1 }}>
                  {t.description}
                  {t.singleton && disabled ? " (already active)" : ""}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function Settings() {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [availableTypes, setAvailableTypes] = useState<BackendInfo[]>([]);
  const [adding, setAdding] = useState(false);
  const [addType, setAddType] = useState("slaac");
  const [addInterface, setAddInterface] = useState("");
  const [addPrefix, setAddPrefix] = useState("");
  const [addId, setAddId] = useState("");
  const [saving, setSaving] = useState(false);
  const [confirm, setConfirm] = useState<{ message: string; action: () => void } | null>(null);
  const [filterMode, setFilterMode] = useState<"allowlist" | "denylist">("denylist");
  const [filterPatterns, setFilterPatterns] = useState("");
  const [savingFilter, setSavingFilter] = useState(false);
  const toast = useToast();

  const load = async () => {
    try {
      const c = await getConfig();
      setConfig(c);
      setFilterMode(c.process_filter.mode);
      setFilterPatterns(c.process_filter.patterns.join(", "));
      const b = await listBackendInstances();
      setAvailableTypes(b.available_types);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const unlistens: (() => void)[] = [];
    onConfigChanged(() => load()).then((fn) => unlistens.push(fn));
    onDaemonConnected(() => { setError(null); load(); }).then((fn) => unlistens.push(fn));
    return () => unlistens.forEach((fn) => fn());
  }, []);

  const handleAddBackend = async () => {
    if (!addInterface.trim()) {
      toast.error("Interface is required");
      return;
    }
    setSaving(true);
    try {
      const req: AddBackendRequest = {
        type: addType,
        interface: addInterface.trim(),
      };
      if (addId.trim()) req.id = addId.trim();
      if (addType === "slaac" && addPrefix.trim()) req.prefix = addPrefix.trim();

      await addBackend(req);
      toast.success("Backend added");
      setAdding(false);
      setAddInterface("");
      setAddPrefix("");
      setAddId("");
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveBackend = (inst: BackendInstanceConfig) => {
    setConfirm({
      message: `Remove backend '${inst.id}'? All addresses from this backend will be removed from all sockets.`,
      action: async () => {
        try {
          await removeBackend(inst.id);
          toast.success(`Removed backend '${inst.id}'`);
          load();
        } catch (e) {
          toast.error(String(e));
        }
      },
    });
  };

  // Determine which singleton types are already active
  const activeSingletons = new Set(
    config?.backends
      .map((b) => b.type)
      .filter((t) => {
        const info = availableTypes.find((a) => a.name === t);
        return info?.singleton;
      }) ?? []
  );

  if (error) return <div className="error-banner">Cannot connect to daemon: {error}</div>;
  if (!config) return <div className="loading">Loading configuration...</div>;

  return (
    <div>
      {confirm && (
        <ConfirmDialog
          message={confirm.message}
          onConfirm={() => { confirm.action(); setConfirm(null); }}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* General config */}
      <div className="card-header">
        <span className="card-title">Daemon Configuration</span>
      </div>
      <div className="card">
        <div className="info-grid">
          <span className="info-label">API Address</span>
          <span className="info-value mono">{config.listen_addr}:{config.listen_port}</span>
          <span className="info-label">Poll Interval</span>
          <span className="info-value">{config.poll_interval_secs}s</span>
        </div>
      </div>

      {/* Backend instances */}
      <div className="card-header">
        <span className="card-title">
          Backend Instances
          <span style={{ color: "var(--text-muted)", fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
            ({config.backends.length})
          </span>
        </span>
        {!adding && (
          <button className="btn btn-sm btn-primary" onClick={() => setAdding(true)}>
            Add Backend
          </button>
        )}
      </div>

      <div className="card">
        {config.backends.length === 0 ? (
          <div style={{ padding: "16px 0", color: "var(--text-muted)", fontSize: 13 }}>
            No backend instances configured.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Interface</th>
                  <th style={{ width: 80 }}></th>
                </tr>
              </thead>
              <tbody>
                {config.backends.map((inst) => (
                  <tr key={inst.id}>
                    <td style={{ fontWeight: 500 }}>{inst.id}</td>
                    <td>
                      <span className="badge" style={{ fontSize: 11, padding: "1px 6px" }}>
                        {inst.type}
                      </span>
                    </td>
                    <td className="mono">{inst.interface}</td>
                    <td>
                      <button
                        className="btn-danger btn-sm"
                        onClick={() => handleRemoveBackend(inst)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {adding && (
          <div style={{ marginTop: 16, padding: "16px", background: "var(--bg-hover)", borderRadius: 6 }}>
            <div className="section-title" style={{ marginBottom: 12 }}>Add Backend Instance</div>
            <div className="info-grid" style={{ alignItems: "center" }}>
              <span className="info-label">Type</span>
              <TypeSelect
                value={addType}
                onChange={setAddType}
                types={availableTypes}
                activeSingletons={activeSingletons}
              />

              <span className="info-label">Interface</span>
              <InterfaceSelect
                value={addInterface}
                onChange={setAddInterface}
                placeholder={addType === "ula" ? "Loopback Pseudo-Interface 1" : "Ethernet"}
              />

              {addType === "slaac" && (
                <>
                  <span className="info-label">Prefix</span>
                  <input
                    className="input"
                    value={addPrefix}
                    placeholder="auto (discover from interface)"
                    onChange={(e) => setAddPrefix(e.target.value)}
                  />
                </>
              )}

              <span className="info-label">Custom ID</span>
              <input
                className="input"
                value={addId}
                placeholder="auto-generated"
                onChange={(e) => setAddId(e.target.value)}
                style={{ opacity: 0.8 }}
              />
            </div>

            <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={handleAddBackend} disabled={saving}>
                {saving ? "Adding..." : "Add"}
              </button>
              <button
                className="btn"
                onClick={() => {
                  setAdding(false);
                  setAddInterface("");
                  setAddPrefix("");
                  setAddId("");
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Process Filter */}
      <div className="card-header">
        <span className="card-title">Process Filter</span>
      </div>
      <div className="card">
        <div style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
            <button
              className={`btn btn-sm${filterMode === "denylist" ? " btn-primary" : ""}`}
              onClick={() => setFilterMode("denylist")}
            >
              Denylist
            </button>
            <button
              className={`btn btn-sm${filterMode === "allowlist" ? " btn-primary" : ""}`}
              onClick={() => setFilterMode("allowlist")}
            >
              Allowlist
            </button>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            {filterMode === "denylist"
              ? "Matching processes will NOT get IPv6 addresses. Empty = allow all."
              : "Only matching processes will get IPv6 addresses. Empty = allow none."}
          </div>
          <input
            className="input"
            value={filterPatterns}
            onChange={(e) => setFilterPatterns(e.target.value)}
            placeholder="svchost*,System,OneDrive*"
            style={{ width: "100%" }}
          />
        </div>
        <button
          className="btn btn-primary btn-sm"
          disabled={savingFilter}
          onClick={async () => {
            setSavingFilter(true);
            try {
              const patterns = filterPatterns
                .split(",")
                .map((p) => p.trim())
                .filter((p) => p.length > 0);
              await updateConfig({ process_filter: { mode: filterMode, patterns } });
              toast.success("Process filter saved");
            } catch (e) {
              toast.error(String(e));
            } finally {
              setSavingFilter(false);
            }
          }}
        >
          {savingFilter ? "Saving..." : "Save Filter"}
        </button>
      </div>
    </div>
  );
}
