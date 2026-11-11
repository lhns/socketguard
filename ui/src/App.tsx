import { useEffect, useMemo, useState } from "react";
import { api, onEnforcementNotice, toDaemonError, type Enforcement } from "./api";
import { errorText } from "./lib";
import { NavContext, type Focus, type FocusMessage, type Page } from "./nav";
import ActivityPage from "./pages/ActivityPage";
import AppsPage from "./pages/AppsPage";
import PeersPage from "./pages/PeersPage";
import ReservedPage from "./pages/ReservedPage";
import SettingsPage from "./pages/SettingsPage";
import { useDaemonEvents, useStatus } from "./queries";

const PAGES: { id: Page; label: string }[] = [
  { id: "apps", label: "Apps" },
  { id: "reserved", label: "Reserved" },
  { id: "peers", label: "Peers" },
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

export default function App() {
  useDaemonEvents();
  const status = useStatus();
  const [page, setPage] = useState<Page>("apps");
  // A page stays mounted once it has been opened, so its selection, filters and columns
  // survive following a link and coming back.
  const [visited, setVisited] = useState<Set<Page>>(new Set(["apps"]));
  const [focus, setFocus] = useState<FocusMessage>({ seq: 0 });
  const [notice, setNotice] = useState<Enforcement | null>(null);

  // A change the daemon saved but could not enforce everywhere yet (HTTP 202) stays visible.
  useEffect(() => onEnforcementNotice(setNotice), []);

  const nav = useMemo(
    () => ({
      go: (p: Page, f: Focus = {}) => {
        if (Object.keys(f).length > 0) setFocus((cur) => ({ ...f, seq: cur.seq + 1 }));
        setVisited((v) => (v.has(p) ? v : new Set(v).add(p)));
        setPage(p);
      },
    }),
    [],
  );
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
        {PAGES.map(
          (p) => visited.has(p.id) && <div key={p.id} hidden={page !== p.id}>{renderPage(p.id, focus)}</div>,
        )}
      </main>
    </NavContext.Provider>
  );
}

function renderPage(p: Page, focus: FocusMessage) {
  switch (p) {
    case "apps":
      return <AppsPage focus={focus} />;
    case "reserved":
      return <ReservedPage focus={focus} />;
    case "peers":
      return <PeersPage focus={focus} />;
    case "activity":
      return <ActivityPage />;
    case "settings":
      return <SettingsPage />;
  }
}
