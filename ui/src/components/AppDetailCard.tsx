import { useState } from "react";
import type { AppDetail, AppPort, EffectiveAccess, Network, PortRef } from "../api";
import { membershipsOf, originLabel } from "../access";
import { errorText, formatBytes, portLabel, samePort, subjectLabel } from "../lib";
import {
  useActivity, useApp, useDeleteApp, useDeleteGrant, useGroups, useMergeApp, useNetworks, usePeers, useReviewApp,
  useSettings, useShare, useSplitApp, useTags,
} from "../queries";
import { useNav } from "../nav";
import { ReachBadge } from "../reach";
import ConfirmDialog from "./ConfirmDialog";
import GrantEditor from "./GrantEditor";
import TagDialog from "./TagDialog";
import { useToast } from "./Toast";

/** One app: its ports with addresses, tags and who can reach each port, then app-level actions. */
export default function AppDetailView({ id, onForgotten }: { id: string; onForgotten: () => void }) {
  const app = useApp(id);
  if (app.isLoading) return <p className="muted">Loading…</p>;
  if (app.error || !app.data) return <div className="error-banner">{errorText(app.error)}</div>;
  return <AppDetailCard app={app.data} onForgotten={onForgotten} />;
}

function AppDetailCard({ app, onForgotten }: { app: AppDetail; onForgotten: () => void }) {
  const toast = useToast();
  const nav = useNav();
  const review = useReviewApp();
  const forget = useDeleteApp();
  const networks = useNetworks().data ?? [];
  const tags = useTags().data ?? [];
  const settings = useSettings().data;
  const [granting, setGranting] = useState<PortRef[] | null>(null);
  const [tagging, setTagging] = useState<PortRef | "app" | null>(null);
  const [forgetting, setForgetting] = useState(false);

  const netById = (nid: string) => networks.find((n) => n.id === nid);
  const onlyLocal = app.addresses.length > 0 && app.addresses.every((a) => netById(a.network_id)?.grants_apply === false);
  const memberships = membershipsOf(app.id, tags);
  const wholeAppTags = memberships.filter((m) => m.port === null);
  const hasV4 = app.ports.some((p) => p.listening && p.family !== "v6");
  const protectsHost = (settings?.protect_host_interfaces.length ?? 0) > 0;

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
        <div className="badges">
          {app.system && <span className="badge reach reach-muted" title="An operating system service or component">system</span>}
          {app.identity_note && (
            <span className="badge badge-pending" title="This app is told apart from other apps by more than its program path">
              {app.identity_note}
            </span>
          )}
          {!app.reviewed && <span className="badge badge-pending">pending</span>}
        </div>
      </div>
      {app.identity_note === "unidentified" && (
        <p className="hint">
          SocketGuard cannot tell which program owns this socket, so it is identified by its port alone. It is closed until you
          grant access, like any other app.
        </p>
      )}

      <div className="tag-line">
        <span className="muted">Tags:</span>{" "}
        {wholeAppTags.length === 0 && <span className="muted">none</span>}
        {wholeAppTags.map((m) => (
          <button key={m.tag.id} className="tag-pill" onClick={() => nav.go("apps", { tagId: m.tag.id })} title="Show this tag">
            {m.tag.label}
          </button>
        ))}{" "}
        <button className="btn btn-sm" onClick={() => setTagging("app")}>Tag app…</button>
      </div>

      {hasV4 && (
        <p className="hint" data-testid="ipv4-status">
          {protectsHost
            ? "IPv4: closed except granted IPv4 peers (protect-host is on)."
            : "IPv4: open to everyone (protect-host is off). Grants only limit IPv6 and the other networks."}
        </p>
      )}

      <h3 className="section-title">Ports</h3>
      {onlyLocal && <p className="muted">This machine only. Grants do not apply on the Local network.</p>}
      {app.ports.length === 0 ? (
        <p className="muted">No ports seen.</p>
      ) : (
        <div className="table-wrap">
          <table className="ports-table">
            <thead>
              <tr><th>Port</th><th>Addresses</th><th>Tags</th><th>Who can reach</th><th /></tr>
            </thead>
            <tbody>
              {app.ports.map((p) => (
                <PortRow
                  key={portLabel(p)}
                  app={app}
                  port={p}
                  networks={networks}
                  showGrants={!onlyLocal}
                  onGrant={() => setGranting([{ port: p.port, proto: p.proto }])}
                  onTag={() => setTagging({ port: p.port, proto: p.proto })}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <AddressList app={app} networks={networks} />

      {!onlyLocal && <AppLevelAccess app={app} onGrant={() => setGranting([])} />}

      <div className="actions">
        {!app.reviewed && <button className="btn" onClick={keepClosed} disabled={review.isPending}>Keep closed</button>}
        {app.reviewed && (
          <button className="btn" disabled={review.isPending} onClick={() => review.mutate({ id: app.id, reviewed: false })}>
            Mark pending again
          </button>
        )}
        <button className="btn btn-danger btn-sm" onClick={() => setForgetting(true)}>Forget app</button>
      </div>

      <TorShare appId={app.id} hasOnion={app.addresses.some((a) => a.locator.kind === "onion")} />
      <Counters app={app} />

      {granting && <GrantEditor targets={[{ kind: "app", id: app.id }]} ports={granting} onClose={() => setGranting(null)} />}
      {tagging && (
        <TagDialog
          members={[{ app_id: app.id, port: tagging === "app" ? null : tagging }]}
          onClose={() => setTagging(null)}
        />
      )}
      {forgetting && (
        <ConfirmDialog
          title={`Forget ${app.name}?`}
          confirmLabel="Forget app"
          onCancel={() => setForgetting(false)}
          onConfirm={() => {
            setForgetting(false);
            forget.mutate(app.id, {
              onSuccess: () => {
                toast.success(`Forgot ${app.name}`);
                onForgotten();
              },
              onError: (e) => toast.error(errorText(e)),
            });
          }}
        >
          <p>Its addresses and grants are removed. It reappears as pending the next time it listens.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function PortRow({
  app, port, networks, showGrants, onGrant, onTag,
}: {
  app: AppDetail; port: AppPort; networks: Network[]; showGrants: boolean; onGrant: () => void; onTag: () => void;
}) {
  const toast = useToast();
  const nav = useNav();
  const split = useSplitApp();
  const tags = useTags().data ?? [];
  const ref: PortRef = { port: port.port, proto: port.proto };
  const portTags = membershipsOf(app.id, tags).filter((m) => m.port !== null && samePort(m.port, ref));

  // The address this port answers on, per network.
  const addrs = app.addresses.filter((a) => a.ports === "all" || a.ports.only.some((p) => samePort(p, ref)));
  const canSplit = (a: (typeof addrs)[number]) => a.ports === "all" && app.ports.length > 1;
  const access = app.access.filter((a) => a.port === null || samePort(a.port, ref));

  return (
    <tr>
      <td>
        <div className="mono">{portLabel(port)}</div>
        <span className={port.listening ? "badge reach reach-ok" : "badge reach reach-muted"}>
          {port.listening ? "listening" : "not listening"}
        </span>{" "}
        <span className="muted" title="Which IP versions it accepts connections over">
          {port.family === "dual" ? "IPv4+IPv6" : port.family === "v4" ? "IPv4" : "IPv6"}
        </span>
      </td>
      <td>
        {addrs.length === 0 && <span className="muted">none</span>}
        {addrs.map((a) => (
          <div key={a.id}>
            <strong>{networks.find((n) => n.id === a.network_id)?.name ?? a.network_id}</strong>{" "}
            <span className="mono">{a.locator.kind === "ipv6" ? a.locator.addr : a.locator.hostname}</span>
            {canSplit(a) && (
              <>
                {" "}
                <button
                  className="btn btn-sm"
                  disabled={split.isPending}
                  title="Give this port its own address on this network"
                  onClick={() =>
                    split.mutate({ id: app.id, req: { network_id: a.network_id, port: port.port, proto: port.proto } }, {
                      onSuccess: () => toast.success(`${portLabel(port)} has its own address`),
                      onError: (e) => toast.error(errorText(e)),
                    })
                  }
                >
                  Split {portLabel(port)}
                </button>
              </>
            )}
          </div>
        ))}
      </td>
      <td>
        {portTags.length === 0 && <span className="muted">—</span>}
        {portTags.map((m) => (
          <button key={m.tag.id} className="tag-pill" onClick={() => nav.go("apps", { tagId: m.tag.id })}>{m.tag.label}</button>
        ))}
      </td>
      <td>
        {showGrants ? <AccessChips app={app} entries={access} /> : <span className="muted">this machine only</span>}
      </td>
      <td>
        <div className="row-actions">
          {showGrants && <button className="btn btn-sm btn-primary" onClick={onGrant}>Grant {portLabel(port)}…</button>}
          <button className="btn btn-sm" onClick={onTag}>Tag port…</button>
        </div>
      </td>
    </tr>
  );
}

/** Who can reach, with where each access comes from. A direct one can be revoked here; one that
 * comes through a tag or a group is changed at its source. */
function AccessChips({ app, entries }: { app: AppDetail; entries: EffectiveAccess[] }) {
  const toast = useToast();
  const nav = useNav();
  const peers = usePeers().data ?? [];
  const groups = useGroups().data ?? [];
  const tags = useTags().data ?? [];
  const networks = useNetworks().data ?? [];
  const del = useDeleteGrant();
  if (entries.length === 0) return <span className="muted">Nobody</span>;
  return (
    <ul className="chip-list chip-list-compact">
      {entries.map((a, i) => {
        const name =
          a.subject.kind === "anyone" && a.network_id
            ? `Everyone on ${networks.find((n) => n.id === a.network_id)?.name ?? a.network_id}`
            : subjectLabel(a.subject, peers, groups);
        const reach = app.grants.find((g) => g.id === a.grant_id)?.reach ?? [];
        return (
          <li key={`${a.grant_id}-${i}`} className="chip">
            <span className="chip-name">{name}</span>
            {a.port === null && <span className="muted" title="Granted on every port">all ports</span>}
            {a.network_id && a.subject.kind !== "anyone" && (
              <span className="muted">on {networks.find((n) => n.id === a.network_id)?.name ?? a.network_id}</span>
            )}
            <span className={`badge reach ${a.origin.kind === "direct" ? "reach-muted" : "reach-warn"}`}>
              {originLabel(a.origin, tags, groups)}
            </span>
            {reach.map((r) => (
              <ReachBadge key={r.network_id} reach={r.reach} network={networks.find((n) => n.id === r.network_id)?.name} />
            ))}
            {a.origin.kind === "direct" ? (
              <button
                className="btn btn-danger btn-sm"
                aria-label={`Revoke access for ${name}`}
                disabled={del.isPending}
                onClick={() =>
                  del.mutate(a.grant_id, {
                    onSuccess: () => toast.success("Access revoked"),
                    onError: (e) => toast.error(errorText(e)),
                  })
                }
              >
                Revoke
              </button>
            ) : (
              <button
                className="btn btn-sm"
                onClick={() => (a.origin.kind === "tag" ? nav.go("apps", { tagId: a.origin.tag_id }) : nav.go("peers", { groupId: (a.origin as { group_id: string }).group_id }))}
              >
                Go to {a.origin.kind}
              </button>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function AddressList({ app, networks }: { app: AppDetail; networks: Network[] }) {
  const toast = useToast();
  const merge = useMergeApp();
  const byNetwork = new Map<string, typeof app.addresses>();
  for (const a of app.addresses) byNetwork.set(a.network_id, [...(byNetwork.get(a.network_id) ?? []), a]);
  const crowded = [...byNetwork.entries()].filter(([, list]) => list.length > 1);
  if (app.addresses.length === 0) return <p className="muted">No addresses assigned yet.</p>;
  return (
    <>
      <h3 className="section-title">Addresses</h3>
      <ul className="plain-list">
        {app.addresses.map((a) => (
          <li key={a.id}>
            <strong>{networks.find((n) => n.id === a.network_id)?.name ?? a.network_id}</strong>{" "}
            <span className="mono">{a.locator.kind === "ipv6" ? a.locator.addr : a.locator.hostname}</span>
            {a.ports !== "all" && <span className="muted"> ({a.ports.only.map(portLabel).join(", ")})</span>}
            {networks.find((n) => n.id === a.network_id)?.grants_apply === false && <span className="muted"> · this machine only</span>}
          </li>
        ))}
      </ul>
      {crowded.map(([networkId, list]) => (
        <button
          key={networkId}
          className="btn btn-sm"
          disabled={merge.isPending}
          onClick={() =>
            merge.mutate({ id: app.id, req: { network_id: networkId, address_ids: list.map((a) => a.id) } }, {
              onSuccess: () => toast.success("Addresses merged"),
              onError: (e) => toast.error(errorText(e)),
            })
          }
        >
          Merge {list.length} addresses on {networks.find((n) => n.id === networkId)?.name ?? networkId}
        </button>
      ))}
    </>
  );
}

/** Grants that apply to the whole app, and the way to add one. */
function AppLevelAccess({ app, onGrant }: { app: AppDetail; onGrant: () => void }) {
  return (
    <>
      <h3 className="section-title">Access to the whole app</h3>
      {app.grants.length === 0 ? (
        <p className="muted">No grant on the app itself.</p>
      ) : (
        <p className="muted">{app.grants.length} grant(s) on this app; see the ports above for who they let in.</p>
      )}
      <div className="actions">
        <button className="btn btn-primary" onClick={onGrant}>Grant access…</button>
      </div>
    </>
  );
}

function TorShare({ appId, hasOnion }: { appId: string; hasOnion: boolean }) {
  const share = useShare(hasOnion ? appId : null);
  const toast = useToast();
  if (!hasOnion || !share.data || share.data.tor.length === 0) return null;
  return (
    <>
      <h3 className="section-title">Tor access</h3>
      <p className="hint">
        Give each peer its line: it goes in a file named <code>&lt;name&gt;.auth_private</code> in the peer&apos;s Tor
        <code>ClientOnionAuthDir</code>. These are private keys.
      </p>
      <ul className="plain-list">
        {share.data.tor.map((t) => (
          <li key={`${t.hostname}-${t.peer_id}`}>
            <strong>{t.peer_label}</strong> <span className="muted">{t.hostname}</span>
            <div className="cred-row">
              <span className="mono cred-value">{t.auth_private}</span>
              <button
                className="btn btn-sm"
                onClick={() => {
                  void navigator.clipboard?.writeText(t.auth_private).then(() => toast.success("Copied"), () => toast.error("Could not copy"));
                }}
              >
                Copy
              </button>
            </div>
          </li>
        ))}
      </ul>
    </>
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
