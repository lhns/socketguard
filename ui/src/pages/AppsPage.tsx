import { useMemo, useState } from "react";
import type { App, AppDetail, GrantView, Network, Peer, PeerGroup } from "../api";
import GrantDialog from "../components/GrantDialog";
import { useToast } from "../components/Toast";
import { errorText, formatBytes, portLabel, subjectLabel } from "../lib";
import {
  useActivity, useApp, useApps, useDeleteGrant, useGroups, useNetworks, usePeers, useReviewApp,
} from "../queries";
import { ReachBadge } from "../reach";

interface Props {
  initialSearch?: string;
}

export default function AppsPage({ initialSearch = "" }: Props) {
  const apps = useApps();
  const [selected, setSelected] = useState<string | null>(null);
  const [pendingOnly, setPendingOnly] = useState(false);
  const [search, setSearch] = useState(initialSearch);

  const list = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (apps.data ?? [])
      .filter((a) => !pendingOnly || !a.reviewed)
      .filter((a) => !q || a.name.toLowerCase().includes(q) || a.process_name.toLowerCase().includes(q))
      .sort((a, b) => Number(a.reviewed) - Number(b.reviewed) || a.name.localeCompare(b.name));
  }, [apps.data, pendingOnly, search]);
  const pendingCount = (apps.data ?? []).filter((a) => !a.reviewed).length;

  return (
    <div className="split">
      <section aria-label="Apps">
        <div className="toolbar">
          <input
            className="input grow"
            type="search"
            aria-label="Filter apps"
            placeholder="Filter apps"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <label className="check">
            <input type="checkbox" checked={pendingOnly} onChange={(e) => setPendingOnly(e.target.checked)} />
            Pending only ({pendingCount})
          </label>
        </div>
        {apps.isLoading && <p className="muted">Loading…</p>}
        {apps.data && list.length === 0 && (
          <div className="card empty">
            <p>{apps.data.length === 0 ? "No apps detected yet." : "No apps match."}</p>
            {apps.data.length === 0 && <p className="hint">The daemon discovers listening programs automatically.</p>}
          </div>
        )}
        <ul className="app-list">
          {list.map((a) => (
            <AppRow key={a.id} app={a} selected={a.id === selected} onSelect={() => setSelected(a.id)} />
          ))}
        </ul>
      </section>
      <section aria-label="App details">
        {selected ? (
          <AppDetailView id={selected} />
        ) : (
          <div className="card empty"><p>Select an app to see who can reach it.</p></div>
        )}
      </section>
    </div>
  );
}

function AppRow({ app, selected, onSelect }: { app: App; selected: boolean; onSelect: () => void }) {
  const listening = app.ports.filter((p) => p.listening);
  return (
    <li>
      <button className={`app-row${selected ? " selected" : ""}`} onClick={onSelect} aria-pressed={selected}>
        <span className="app-row-name">{app.name}</span>
        {!app.reviewed && <span className="badge badge-pending">pending</span>}
        <span className="muted app-row-ports">
          {listening.length ? listening.map(portLabel).join(", ") : "not listening"}
        </span>
      </button>
    </li>
  );
}

function AppDetailView({ id }: { id: string }) {
  const app = useApp(id);
  const networks = useNetworks();
  const peers = usePeers();
  const groups = useGroups();

  if (app.isLoading) return <p className="muted">Loading…</p>;
  if (app.error || !app.data) return <div className="error-banner">{errorText(app.error)}</div>;
  return <AppDetailCard app={app.data} networks={networks.data ?? []} peers={peers.data ?? []} groups={groups.data ?? []} />;
}

function AppDetailCard({ app, networks, peers, groups }: { app: AppDetail; networks: Network[]; peers: Peer[]; groups: PeerGroup[] }) {
  const toast = useToast();
  const review = useReviewApp();
  const [granting, setGranting] = useState(false);
  const netById = (id: string) => networks.find((n) => n.id === id);
  const netName = (id: string) => netById(id)?.name ?? id;

  const onlyLocal = app.addresses.length > 0 && app.addresses.every((a) => netById(a.network_id)?.grants_apply === false);

  const keepClosed = () =>
    review.mutate({ id: app.id, reviewed: true }, {
      onSuccess: () => toast.success(`${app.name} stays closed`),
      onError: (e) => toast.error(errorText(e)),
    });

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h2 className="card-title">{app.name}</h2>
          <div className="muted">
            {app.process_name}
            {app.interpreter_arg ? ` · ${app.interpreter_arg}` : ""}
            {app.exe_path ? ` · ${app.exe_path}` : ""}
          </div>
        </div>
        <div>
          {app.identity_note && (
            <span className="badge badge-pending" title="This app is told apart from other apps by more than its program path">
              {app.identity_note}
            </span>
          )}{" "}
          {!app.reviewed && <span className="badge badge-pending">pending</span>}
        </div>
      </div>

      <h3 className="section-title">Ports</h3>
      {app.ports.length === 0 ? (
        <p className="muted">No ports seen.</p>
      ) : (
        <ul className="plain-list">
          {app.ports.map((p) => (
            <li key={portLabel(p)}>
              <span className="mono">{portLabel(p)}</span>{" "}
              <span className={p.listening ? "badge reach reach-ok" : "badge reach reach-muted"}>
                {p.listening ? "listening" : "not listening"}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h3 className="section-title">Addresses</h3>
      {app.addresses.length === 0 ? (
        <p className="muted">No addresses assigned yet.</p>
      ) : (
        <ul className="plain-list">
          {app.addresses.map((a) => (
            <li key={a.id}>
              <strong>{netName(a.network_id)}</strong>{" "}
              <span className="mono">{a.locator.kind === "ipv6" ? a.locator.addr : a.locator.hostname}</span>
              {a.ports !== "all" && <span className="muted"> ({a.ports.only.map(portLabel).join(", ")})</span>}
              {netById(a.network_id)?.grants_apply === false && <span className="muted"> · this machine only</span>}
            </li>
          ))}
        </ul>
      )}

      <h3 className="section-title">Who can reach this</h3>
      {onlyLocal ? (
        <p className="muted">This machine only. Grants do not apply on the Local network.</p>
      ) : (
        <>
          {app.grants.length === 0 ? (
            <p className="muted">Nobody. The app is closed to every peer.</p>
          ) : (
            <ul className="chip-list">
              {app.grants.map((g) => (
                <GrantChip key={g.id} grant={g} peers={peers} groups={groups} networks={networks} />
              ))}
            </ul>
          )}
          <div className="actions">
            <button className="btn btn-primary" onClick={() => setGranting(true)}>Grant access…</button>
            {!app.reviewed && (
              <button className="btn" onClick={keepClosed} disabled={review.isPending}>Keep closed</button>
            )}
          </div>
        </>
      )}

      <Counters app={app} />
      {granting && <GrantDialog appId={app.id} onClose={() => setGranting(false)} />}
    </div>
  );
}

function GrantChip({ grant, peers, groups, networks }: { grant: GrantView; peers: Peer[]; groups: PeerGroup[]; networks: Network[] }) {
  const toast = useToast();
  const del = useDeleteGrant();
  const name = subjectLabel(grant.subject, peers, groups);
  const netName = (id: string) => networks.find((n) => n.id === id)?.name ?? id;
  return (
    <li className="chip">
      <span className="chip-name">{name}</span>
      {grant.port && <span className="muted">{portLabel(grant.port)}</span>}
      {grant.network_id && <span className="muted">on {netName(grant.network_id)}</span>}
      <span className="chip-reach">
        {grant.reach.map((r) => (
          <ReachBadge key={r.network_id} reach={r.reach} network={netName(r.network_id)} />
        ))}
      </span>
      <button
        className="btn btn-danger btn-sm"
        aria-label={`Revoke access for ${name}`}
        disabled={del.isPending}
        onClick={() =>
          del.mutate(grant.id, {
            onSuccess: () => toast.success("Access revoked"),
            onError: (e) => toast.error(errorText(e)),
          })
        }
      >
        Revoke
      </button>
    </li>
  );
}

function Counters({ app }: { app: AppDetail }) {
  const blocked = useActivity({ kind: "blocked", appId: app.id });
  const blockedCount = (blocked.data?.pages.flat() ?? []).reduce((n, r) => n + r.count, 0);
  const allowed = app.counters ?? [];
  if (allowed.length === 0 && blockedCount === 0) return null;
  return (
    <>
      <h3 className="section-title">Traffic</h3>
      <ul className="plain-list">
        {allowed.map((c) => (
          <li key={`${c.network_id}-${c.subject}`}>
            Allowed from {c.subject}: {c.packets} packets, {formatBytes(c.bytes)}
          </li>
        ))}
        {blockedCount > 0 && <li>Blocked attempts (recent): {blockedCount}</li>}
      </ul>
    </>
  );
}
