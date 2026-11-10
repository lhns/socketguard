import { useEffect, useMemo, useState } from "react";
import { api, onEnforcementNotice, toDaemonError, type Enforcement } from "./api";
import { errorText } from "./lib";
import { homeOf, NavContext, readMode, writeMode, type Focus, type Mode, type Page } from "./nav";
import AccessPage from "./pages/AccessPage";
import ActivityPage from "./pages/ActivityPage";
import AppsPage from "./pages/AppsPage";
import PeersPage from "./pages/PeersPage";
import SettingsPage from "./pages/SettingsPage";
import { useDaemonEvents, useStatus } from "./queries";

const PAGES: { id: Page; label: string }[] = [
  { id: "apps", label: "Apps" },
  { id: "access", label: "Access" },
  { id: "peers", label: "Peers & groups" },
  { id: "activity", label: "Activity" },
  { id: "settings", label: "Settings" },
];

function ConnectionBanner({ error }: { error: unknown }) {
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const err = toDaemonError(error);
  const hint = (err.details as { hint?: string } | undefined)?.hint;

  const start = async () => {
    setStarting(true);
    setStartError(null);
    try {
      await api.startDaemon();
    } catch (e) {
      setStartError(errorText(e));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="error-banner banner" role="alert">
      <div>
        <strong>{err.code === "connection" ? "Cannot reach the daemon." : "Daemon error."}</strong> {err.message}
        {hint && <div>{hint}</div>}
        {startError && <div>{startError}</div>}
      </div>
      {err.code === "connection" && (
        <button className="btn btn-primary btn-sm" onClick={start} disabled={starting}>
          {starting ? "Starting…" : "Start daemon"}
        </button>
      )}
    </div>
  );
}

/** Simple opens on the apps list, Advanced on the access matrix. */
function ModeSwitch({ mode, onChange }: { mode: Mode; onChange: (m: Mode) => void }) {
  return (
    <div className="mode-switch" role="group" aria-label="View">
      {(["simple", "advanced"] as const).map((m) => (
        <button key={m} className={`nav-btn${mode === m ? " active" : ""}`} aria-pressed={mode === m} onClick={() => onChange(m)}>
          {m === "simple" ? "Simple" : "Advanced"}
        </button>
      ))}
    </div>
  );
}

export default function App() {
  useDaemonEvents();
  const status = useStatus();
  const [mode, setMode] = useState<Mode>(readMode);
  const [page, setPage] = useState<Page>(() => homeOf(readMode()));
  const [focus, setFocus] = useState<Focus & { seq: number }>({ seq: 0 });
  const [notice, setNotice] = useState<Enforcement | null>(null);

  // A change the daemon saved but could not enforce everywhere yet (HTTP 202) stays visible.
  useEffect(() => onEnforcementNotice(setNotice), []);

  const nav = useMemo(
    () => ({
      go: (p: Page, f: Focus = {}) => {
        setFocus((cur) => ({ ...f, seq: cur.seq + 1 }));
        setPage(p);
      },
    }),
    [],
  );
  const switchMode = (m: Mode) => {
    writeMode(m);
    setMode(m);
    nav.go(homeOf(m));
  };
  const pending = status.data?.counts.pending_apps ?? 0;

  return (
    <NavContext.Provider value={nav}>
      <header className="header">
        <div className="header-inner">
          <h1>
            <span className="logo" aria-hidden="true">S</span>
            SocketGuard
          </h1>
          <nav className="nav" aria-label="Main">
            {PAGES.map((p) => (
              <button
                key={p.id}
                className={`nav-btn${page === p.id ? " active" : ""}`}
                aria-current={page === p.id ? "page" : undefined}
                onClick={() => nav.go(p.id)}
              >
                {p.label}
                {p.id === "apps" && pending > 0 && <span className="nav-count" aria-label={`${pending} pending`}>{pending}</span>}
              </button>
            ))}
          </nav>
          <ModeSwitch mode={mode} onChange={switchMode} />
        </div>
      </header>
      <main className="content">
        {status.error && <ConnectionBanner error={status.error} />}
        {notice && (
          <div className="warn-banner banner" role="status">
            <div>
              <strong>Saved, but not enforced everywhere yet.</strong> {notice.message}
            </div>
            <button className="btn btn-sm" onClick={() => setNotice(null)}>Dismiss</button>
          </div>
        )}
        {status.data?.disabled && (
          <div className="error-banner banner" role="status">
            <span>SocketGuard is off: no firewall rules or addresses are applied. Turn it on in Settings.</span>
            <button className="btn btn-sm" onClick={() => nav.go("settings")}>Settings</button>
          </div>
        )}
        {status.data?.unadopted && !status.data.disabled && (
          <div className="error-banner banner" role="status">
            <span>
              Rules from an earlier install are active, but this database doesn&apos;t know them. Adopt them?
              Nothing changes until you do.
            </span>
            <button className="btn btn-sm" onClick={() => nav.go("settings")}>Settings</button>
          </div>
        )}
        {page === "apps" && <AppsPage key={focus.seq} focus={focus} />}
        {page === "access" && <AccessPage key={focus.seq} />}
        {page === "peers" && <PeersPage key={focus.seq} focus={focus} />}
        {page === "activity" && <ActivityPage key={focus.seq} />}
        {page === "settings" && <SettingsPage key={focus.seq} />}
      </main>
    </NavContext.Provider>
  );
}
