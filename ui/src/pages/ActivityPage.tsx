import { useId, useState } from "react";
import type { ActivityKind, ActivityRecord } from "../api";
import GrantDialog from "../components/GrantDialog";
import { useToast } from "../components/Toast";
import { errorText, formatTime } from "../lib";
import { useActivity, useApps, useReviewApp } from "../queries";

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
  protect_host_changed: "Host protection changed",
  blocked: "Blocked",
  remote_admin_exposed: "Remote admin exposed",
};

export default function ActivityPage() {
  const id = useId();
  const [kind, setKind] = useState<ActivityKind | "">("");
  const [appId, setAppId] = useState("");
  const apps = useApps();
  const activity = useActivity({ kind: kind || null, appId: appId || null });
  const records = activity.data?.pages.flat() ?? [];
  const appName = (aid: string | null) => (aid ? (apps.data?.find((a) => a.id === aid)?.name ?? null) : null);

  return (
    <div>
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
      </div>
      {activity.isLoading && <p className="muted">Loading…</p>}
      {activity.error && <div className="error-banner">{errorText(activity.error)}</div>}
      {activity.data && records.length === 0 && <div className="card empty"><p>Nothing happened yet.</p></div>}
      <ol className="timeline">
        {records.map((r) => (
          <ActivityItem key={r.id} record={r} appName={appName(r.app_id)} />
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

function ActivityItem({ record: r, appName }: { record: ActivityRecord; appName: string | null }) {
  const toast = useToast();
  const review = useReviewApp();
  const [granting, setGranting] = useState(false);
  const discovered = r.kind === "app_discovered" && r.app_id !== null;
  const blocked = r.kind === "blocked" && r.app_id !== null && r.src !== null;

  return (
    <li className={`timeline-item kind-${r.kind}`}>
      <div className="timeline-head">
        <span className="badge badge-kind">{KIND_LABEL[r.kind]}</span>
        <time className="muted" dateTime={r.at}>{formatTime(r.at)}</time>
      </div>
      <div>
        {r.message}
        {r.count > 1 && <span className="muted"> ×{r.count}</span>}
      </div>
      <div className="muted">
        {[appName, r.src && `from ${r.src}`, r.port !== null && `port ${r.port}${r.proto ? `/${r.proto}` : ""}`]
          .filter(Boolean)
          .join(" · ")}
      </div>
      {(discovered || blocked) && (
        <div className="actions">
          {discovered && (
            <>
              <button className="btn btn-sm btn-primary" onClick={() => setGranting(true)}>Grant…</button>
              <button
                className="btn btn-sm"
                disabled={review.isPending}
                onClick={() =>
                  review.mutate({ id: r.app_id as string, reviewed: true }, {
                    onSuccess: () => toast.success("Kept closed"),
                    onError: (e) => toast.error(errorText(e)),
                  })
                }
              >
                Keep closed
              </button>
            </>
          )}
          {blocked && (
            <button className="btn btn-sm btn-primary" onClick={() => setGranting(true)}>Grant this source…</button>
          )}
        </div>
      )}
      {granting && r.app_id && (
        <GrantDialog appId={r.app_id} source={blocked ? (r.src as string) : undefined} onClose={() => setGranting(false)} />
      )}
    </li>
  );
}
