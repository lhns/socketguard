import { useId, useState } from "react";
import type { ActivityKind, ActivityRecord } from "../api";
import { formatTime } from "../lib";
import { errorText } from "../lib";
import { useNav } from "../nav";
import { useActivity, useApps, usePeers, useStatus } from "../queries";

const KIND_LABEL: Record<ActivityKind, string> = {
  app_discovered: "New app",
  app_removed: "App removed",
  grant_added: "Access granted",
  grant_removed: "Access revoked",
  peer_added: "Peer added",
  peer_changed: "Peer changed",
  peer_removed: "Peer removed",
  group_added: "Group added",
  group_changed: "Group changed",
  group_removed: "Group removed",
  tag_added: "Tag added",
  tag_changed: "Tag changed",
  tag_removed: "Tag removed",
  socket_group_added: "Port group added",
  socket_group_changed: "Port group changed",
  socket_group_removed: "Port group removed",
  reservation_added: "Reservation added",
  reservation_changed: "Reservation changed",
  reservation_removed: "Reservation removed",
  app_moved: "App moved",
  protect_host_changed: "Host protection changed",
  blocked: "Blocked",
  remote_admin_exposed: "Remote admin exposed",
};

/** A log of what happened. Decisions are made in Apps; a row links to the thing it is about. */
export default function ActivityPage() {
  const id = useId();
  const nav = useNav();
  const [kind, setKind] = useState<ActivityKind | "">("");
  const [appId, setAppId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [source, setSource] = useState("");
  const apps = useApps();
  const peers = usePeers();
  const status = useStatus();
  const activity = useActivity({ kind: kind || null, appId: appId || null, peerId: peerId || null });
  const all = activity.data?.pages.flat() ?? [];
  const src = source.trim().toLowerCase();
  const records = src ? all.filter((r) => (r.src ?? "").toLowerCase().includes(src)) : all;
  const appName = (aid: string | null) => (aid ? (apps.data?.find((a) => a.id === aid)?.name ?? null) : null);
  const peerLabel = (pid: string | null) => (pid ? (peers.data?.find((p) => p.id === pid)?.label ?? null) : null);
  const events = records.reduce((n, r) => n + r.count, 0);
  const pending = status.data?.counts.pending_apps ?? 0;

  return (
    <div>
      {pending > 0 && (
        <div className="warn-banner banner" role="status">
          <span>{pending} new {pending === 1 ? "app needs" : "apps need"} a decision.</span>
          <button className="btn btn-sm btn-primary" onClick={() => nav.go("apps", { pendingOnly: true })}>Review in Apps</button>
        </div>
      )}
      <div className="toolbar">
        <label htmlFor={`${id}-k`}>Kind</label>
        <select id={`${id}-k`} className="input" value={kind} onChange={(e) => setKind(e.target.value as ActivityKind | "")}>
          <option value="">All</option>
          {(Object.keys(KIND_LABEL) as ActivityKind[]).map((k) => (
            <option key={k} value={k}>{KIND_LABEL[k]}</option>
          ))}
        </select>
        <label htmlFor={`${id}-a`}>App</label>
        <select id={`${id}-a`} className="input" value={appId} onChange={(e) => setAppId(e.target.value)}>
          <option value="">All</option>
          {(apps.data ?? []).map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>
        <label htmlFor={`${id}-p`}>Peer</label>
        <select id={`${id}-p`} className="input" value={peerId} onChange={(e) => setPeerId(e.target.value)}>
          <option value="">All</option>
          {(peers.data ?? []).map((p) => (
            <option key={p.id} value={p.id}>{p.label}</option>
          ))}
        </select>
        <label htmlFor={`${id}-s`}>Source</label>
        <input id={`${id}-s`} className="input" placeholder="address contains…" value={source} onChange={(e) => setSource(e.target.value)} />
      </div>
      {activity.isLoading && <p className="muted">Loading…</p>}
      {activity.error && <div className="error-banner">{errorText(activity.error)}</div>}
      {activity.data && records.length === 0 && <div className="card empty"><p>Nothing happened yet.</p></div>}
      {records.length > 0 && (
        <p className="muted" data-testid="activity-summary">
          {records.length} {records.length === 1 ? "entry" : "entries"}, {events} {events === 1 ? "event" : "events"}
        </p>
      )}
      <ol className="timeline">
        {records.map((r) => (
          <ActivityItem key={r.id} record={r} appName={appName(r.app_id)} peerLabel={peerLabel(r.peer_id)} />
        ))}
      </ol>
      {activity.hasNextPage && (
        <div className="actions">
          <button className="btn" onClick={() => void activity.fetchNextPage()} disabled={activity.isFetchingNextPage}>
            {activity.isFetchingNextPage ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}

function ActivityItem({ record: r, appName, peerLabel }: { record: ActivityRecord; appName: string | null; peerLabel: string | null }) {
  const nav = useNav();
  const open = () => {
    if (r.app_id) nav.go("apps", { appId: r.app_id });
    else if (r.peer_id) nav.go("peers", { peerId: r.peer_id });
  };
  const linkable = r.app_id !== null || r.peer_id !== null;
  const details = [appName, peerLabel, r.src && `from ${r.src}`, r.port !== null && `port ${r.port}${r.proto ? `/${r.proto}` : ""}`]
    .filter(Boolean)
    .join(" · ");
  const body = (
    <>
      <div>
        {r.message}
        {r.count > 1 && <span className="muted"> ×{r.count}</span>}
      </div>
      {details && <div className="muted">{details}</div>}
    </>
  );

  return (
    <li className={`timeline-item kind-${r.kind}`}>
      <div className="timeline-head">
        <span className="badge badge-kind">{KIND_LABEL[r.kind]}</span>
        <time className="muted" dateTime={r.at}>{formatTime(r.at)}</time>
      </div>
      {linkable ? (
        <button className="row-link" onClick={open} aria-label={`Open ${appName ?? peerLabel ?? "item"}: ${r.message}`}>{body}</button>
      ) : (
        body
      )}
    </li>
  );
}
