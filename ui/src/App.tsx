import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, onEnforcementNotice, toDaemonError, type Enforcement } from "./api";
import ElevatedAction from "./components/ElevatedAction";
import PortableClose from "./components/PortableClose";
import { errorText } from "./lib";
import { NavContext, type Focus, type FocusMessage, type Page } from "./nav";
import ActivityPage from "./pages/ActivityPage";
import AppsPage from "./pages/AppsPage";
import PeersPage from "./pages/PeersPage";
import ReservedPage from "./pages/ReservedPage";
import SettingsPage from "./pages/SettingsPage";
import { useDaemonEvents, usePortable, useStatus } from "./queries";

const PAGES: { id: Page; label: string }[] = [
  { id: "apps", label: "Apps" },
  { id: "reserved", label: "Reserved" },
  { id: "peers", label: "Peers" },
  { id: "activity", label: "Activity" },
  { id: "settings", label: "Settings" },
];

/** What is wrong when the daemon cannot be used, and the one action that fixes it (ADR 0050). */
function ConnectionBanner({ error, portable }: { error: unknown; portable: boolean | undefined }) {
  const qc = useQueryClient();
  const err = toDaemonError(error);
  const hint = (err.details as { hint?: string } | undefined)?.hint;
  const cannotUse = err.code === "connection" || err.code === "permission_denied";
  const service = useQuery({ queryKey: ["service"], queryFn: api.serviceStatus, enabled: cannotUse && portable === false, refetchInterval: 4_000 });
  const account = useQuery({ queryKey: ["account"], queryFn: api.currentAccount, enabled: err.code === "permission_denied" && portable === false });
  const [allowed, setAllowed] = useState(false);
  const s = service.data;
  const recheck = () => {
    void qc.invalidateQueries({ queryKey: ["service"] });
    void qc.invalidateQueries({ queryKey: ["status"] });
  };

  // Portable mode (ADR 0054): there is no service; the window starts the daemon itself.
  if (cannotUse && portable) {
    return (
      <div className="error-banner banner" role="alert">
        <div>
          <p>
            SocketGuard runs from this folder and is not started. Starting it asks for administrator rights. It stops and
            removes its rules when you close this window.
          </p>
          <ElevatedAction label="Start" command="socketguard-daemon --portable ..." run={api.startPortableDaemon} onDone={recheck} />
        </div>
      </div>
    );
  }

  let action: ReactNode = null;
  if (cannotUse && s && !s.installed) {
    action = (
      <>
        <p>The SocketGuard service is not installed on this computer.</p>
        <ElevatedAction label="Install the service" command="socketguard-daemon service install" run={api.installService} onDone={recheck} />
      </>
    );
  } else if (cannotUse && s && !s.running) {
    action = (
      <>
        <p>The SocketGuard service is installed but stopped.</p>
        <ElevatedAction label="Start" command="socketguard-daemon service start" run={api.startDaemon} onDone={recheck} />
      </>
    );
  } else if (err.code === "permission_denied") {
    action = allowed ? (
      <p role="status">
        Done. Sign out of this computer and sign in again, then open SocketGuard: group membership applies from the next sign-in.
      </p>
    ) : (
      <>
        <p>The service is running, but this account may not use it.</p>
        {account.data ? (
          <ElevatedAction
            label="Allow my account"
            command={`socketguard-daemon access allow ${account.data}`}
            run={api.allowMyAccount}
            onDone={() => setAllowed(true)}
          />
        ) : (
          <p className="hint">Looking up your account name…</p>
        )}
      </>
    );
  }

  return (
    <div className="error-banner banner" role="alert">
      <div>
        <strong>{cannotUse ? "Cannot use the SocketGuard service." : "Daemon error."}</strong> {err.message}
        {hint && <div>{hint}</div>}
        {cannotUse && service.error && <div>The service state is not known: {errorText(service.error)}</div>}
        {action}
      </div>
    </div>
  );
}

export default function App() {
  useDaemonEvents();
  const status = useStatus();
  const portable = usePortable();
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

  return (
    <NavContext.Provider value={nav}>
      <header className="header">
        <div className="header-inner">
          <h1>
            <span className="logo" aria-hidden="true">S</span>
            SocketGuard
            {portable && (
              <span className="badge badge-portable" title="Portable: protection ends when you close SocketGuard.">portable</span>
            )}
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
              </button>
            ))}
          </nav>
        </div>
      </header>
      <main className="content">
        {status.error && <ConnectionBanner error={status.error} portable={portable} />}
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
      {portable && <PortableClose />}
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
