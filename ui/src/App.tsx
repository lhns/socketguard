import { useState } from "react";
import { api, toDaemonError } from "./api";
import { errorText } from "./lib";
import ActivityPage from "./pages/ActivityPage";
import AppsPage from "./pages/AppsPage";
import PeersPage from "./pages/PeersPage";
import SettingsPage from "./pages/SettingsPage";
import { useDaemonEvents, useStatus } from "./queries";

type Page = "apps" | "peers" | "activity" | "settings";
const PAGES: { id: Page; label: string }[] = [
  { id: "apps", label: "Apps" },
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
  const [appsSearch, setAppsSearch] = useState("");

  const showApp = (search: string) => {
    setAppsSearch(search);
    setPage("apps");
  };
  const pending = status.data?.counts.pending_apps ?? 0;

  return (
    <>
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
                onClick={() => setPage(p.id)}
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
        {status.data?.disabled && (
          <div className="error-banner banner" role="status">
            Enforcement is off: no firewall rules are applied. Turn it on in Settings.
          </div>
        )}
        {status.data?.unadopted && (
          <div className="error-banner banner" role="status">
            An existing SocketGuard ruleset was found with an empty database and is left in place.
            Nothing is applied until you turn enforcement on in Settings (this replaces the ruleset).
          </div>
        )}
        {page === "apps" && <AppsPage key={appsSearch} initialSearch={appsSearch} />}
        {page === "peers" && <PeersPage />}
        {page === "activity" && <ActivityPage />}
        {page === "settings" && <SettingsPage onShowApp={showApp} />}
      </main>
    </>
  );
}
