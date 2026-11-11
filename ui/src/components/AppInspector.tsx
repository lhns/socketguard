import { useState } from "react";
import { appEntries, appEntriesFromGrants, mergeEntries } from "../access";
import type { AppDetail, AppPort, Network, PortRef } from "../api";
import { useCommit, useRevoke } from "../commit";
import { errorText, formatBytes, portLabel, scopeLabel } from "../lib";
import {
  useActivity, useApp, useDeleteApp, useGrants, useMergeApp, useSettings, useShare, useSplitApp,
} from "../queries";
import AccessList, { type AccessHighlight } from "./AccessList";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import TagPicker from "./TagPicker";
import { useToast } from "./Toast";

interface Common {
  highlight: AccessHighlight | null;
  onCollapse?: () => void;
  onClose: () => void;
}

/** One app: its tags, who can reach it, its ports and addresses. */
export function AppInspector({ id, ...common }: { id: string } & Common) {
  const app = useApp(id);
  if (app.isLoading) return <Inspector label="App details" title="Loading…" onClose={common.onClose} />;
  if (app.error || !app.data) {
    return (
      <Inspector label="App details" title="App" onClose={common.onClose}>
        <div className="error-banner">{errorText(app.error)}</div>
      </Inspector>
    );
  }
  return <OneApp app={app.data} {...common} />;
}

function OneApp({ app, highlight, onCollapse, onClose }: { app: AppDetail } & Common) {
  const toast = useToast();
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const settings = useSettings().data;
  const forget = useDeleteApp();
  const review = useCommit();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [forgetting, setForgetting] = useState(false);

  const netById = (nid: string) => names.networks.find((n) => n.id === nid);
  const onlyLocal = app.addresses.length > 0 && app.addresses.every((a) => netById(a.network_id)?.grants_apply === false);
  const hasV4 = app.ports.some((p) => p.listening && p.family !== "v6");
  const protectsHost = (settings?.protect_host_interfaces.length ?? 0) > 0;
  const entries = appEntries(app.id, app.access, grants, names);

  return (
    <Inspector
      label="App details"
      title={app.name}
      subtitle={
        <>
          {app.process_name}
          {app.interpreter_arg ? ` · ${app.interpreter_arg}` : ""}
          {app.exe_path ? ` · ${app.exe_path}` : ""}
        </>
      }
      badges={
        <>
          {app.system && <span className="badge reach reach-muted" title="An operating system service or component">system</span>}
          {app.identity_note && <span className="badge badge-pending" title="This app is told apart from other apps by more than its program path">{app.identity_note}</span>}
          {!app.reviewed && <span className="badge badge-pending">pending</span>}
        </>
      }
      onCollapse={onCollapse}
      onClose={onClose}
    >
      {app.identity_note === "unidentified" && (
        <p className="hint">
          SocketGuard cannot tell which program owns this socket, so it is identified by its port alone. It is closed until you
          grant access, like any other app.
        </p>
      )}

      <Section title="Tags">
        <TagPicker appIds={[app.id]} />
      </Section>

      <Section title="Who can reach it">
        {onlyLocal ? (
          <p className="muted">This machine only. Grants do not apply on the Local network.</p>
        ) : (
          <>
            {hasV4 && (
              <p className="hint" data-testid="ipv4-status">
                {protectsHost
                  ? "IPv4: closed except granted IPv4 peers (protect-host is on)."
                  : "IPv4: open to everyone (protect-host is off). Grants only limit IPv6 and the other networks."}
              </p>
            )}
            <AccessList entries={entries} direction="who" networks={names.networks} onRevoke={revoke} highlight={highlight} empty="Nobody. The app is closed." />
            <CommitPreview commit={revokeCommit} />
            <AddAccess fixed={{ side: "targets", targets: [{ kind: "app", id: app.id }] }} />
          </>
        )}
      </Section>

      <Section title="Ports">
        {app.ports.length === 0 ? (
          <p className="muted">No ports seen.</p>
        ) : (
          <ul className="plain-list port-list">
            {app.ports.map((p) => (
              <PortRow key={portLabel(p)} app={app} port={p} />
            ))}
          </ul>
        )}
      </Section>

      <Addresses app={app} networks={names.networks} />

      <div className="actions">
        {!app.reviewed && (
          <button className="btn btn-sm" onClick={() => void review.runBatch([{ op: "review", app_id: app.id, reviewed: true }], `${app.name} stays closed`)}>
            Keep closed
          </button>
        )}
        {app.reviewed && (
          <button className="btn btn-sm" onClick={() => void review.runBatch([{ op: "review", app_id: app.id, reviewed: false }], `${app.name} is pending again`)}>
            Mark pending again
          </button>
        )}
        <button className="btn btn-danger btn-sm" onClick={() => setForgetting(true)}>Forget app</button>
      </div>
      <CommitPreview commit={review} />

      <TorShare appId={app.id} hasOnion={app.addresses.some((a) => a.locator.kind === "onion")} />
      <Counters app={app} />

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
                onClose();
              },
              onError: (e) => toast.error(errorText(e)),
            });
          }}
        >
          <p>Its addresses and grants are removed. It reappears as pending the next time it listens.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

function PortRow({ app, port }: { app: AppDetail; port: AppPort }) {
  const ref: PortRef = { port: port.port, proto: port.proto };
  const [adding, setAdding] = useState(false);
  return (
    <li className="port-row">
      <span className="mono port-name">{portLabel(port)}</span>
      <span className={port.listening ? "badge reach reach-ok" : "badge reach reach-muted"}>{port.listening ? "listening" : "not listening"}</span>
      <span className="muted" title="Which IP versions it accepts connections over">
        {port.family === "dual" ? "IPv4+IPv6" : port.family === "v4" ? "IPv4" : "IPv6"}
      </span>
      <span className="port-tags">
        <TagPicker appIds={[app.id]} port={ref} />
      </span>
      {!adding && (
        <button className="btn btn-sm" aria-label={`Add access to ${portLabel(port)}`} onClick={() => setAdding(true)}>Add access</button>
      )}
      {adding && (
        <div className="port-form">
          <AddAccess fixed={{ side: "targets", targets: [{ kind: "app", id: app.id }] }} port={ref} onDone={() => setAdding(false)} />
        </div>
      )}
    </li>
  );
}

/** Each network once, with the address of the app on it; split a port off or merge them again there. */
function Addresses({ app, networks }: { app: AppDetail; networks: Network[] }) {
  const toast = useToast();
  const split = useSplitApp();
  const merge = useMergeApp();
  if (app.addresses.length === 0) {
    return <Section title="Addresses"><p className="muted">No addresses assigned yet.</p></Section>;
  }
  const byNetwork = new Map<string, AppDetail["addresses"]>();
  for (const a of app.addresses) byNetwork.set(a.network_id, [...(byNetwork.get(a.network_id) ?? []), a]);
  return (
    <Section title="Addresses">
      <ul className="plain-list">
        {[...byNetwork.entries()].map(([networkId, list]) => {
          const net = networks.find((n) => n.id === networkId);
          return (
            <li key={networkId} className="address-net">
              <strong>{net?.name ?? networkId}</strong>
              {net?.grants_apply === false && <span className="muted"> · this machine only</span>}
              {list.map((a) => (
                <div key={a.id} className="address-row">
                  <span className="mono">{a.locator.kind === "ipv6" ? a.locator.addr : a.locator.hostname}</span>
                  <span className="muted">{a.scope.kind === "all" ? (list.length > 1 ? "all other ports" : "all ports") : scopeLabel(a.scope, app.socket_groups)}</span>
                  {a.scope.kind === "all" && app.ports.length > 1 &&
                    app.ports.map((p) => (
                      <button
                        key={portLabel(p)}
                        className="btn btn-sm"
                        disabled={split.isPending}
                        title={`Give ${portLabel(p)} its own address on ${net?.name ?? networkId}`}
                        onClick={() =>
                          split.mutate({ id: app.id, req: { network_id: networkId, port: p.port, proto: p.proto } }, {
                            onSuccess: () => toast.success(`${portLabel(p)} has its own address`),
                            onError: (e) => toast.error(errorText(e)),
                          })
                        }
                      >
                        Split {portLabel(p)}
                      </button>
                    ))}
                </div>
              ))}
              {list.length > 1 && (
                <button
                  className="btn btn-sm"
                  disabled={merge.isPending}
                  onClick={() =>
                    merge.mutate({ id: app.id, req: { network_id: networkId, address_ids: list.map((a) => a.id) } }, {
                      onSuccess: () => toast.success("Addresses merged"),
                      onError: (e) => toast.error(errorText(e)),
                    })
                  }
                >
                  Merge {list.length} addresses on {net?.name ?? networkId}
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </Section>
  );
}

function TorShare({ appId, hasOnion }: { appId: string; hasOnion: boolean }) {
  const share = useShare(hasOnion ? appId : null);
  const toast = useToast();
  if (!hasOnion || !share.data || share.data.tor.length === 0) return null;
  return (
    <Section title="Tor access">
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
    </Section>
  );
}

function Counters({ app }: { app: AppDetail }) {
  const blocked = useActivity({ kind: "blocked", appId: app.id });
  const blockedCount = (blocked.data?.pages.flat() ?? []).reduce((n, r) => n + r.count, 0);
  const allowed = app.counters ?? [];
  if (allowed.length === 0 && blockedCount === 0) return null;
  return (
    <Section title="Traffic">
      <ul className="plain-list">
        {allowed.map((c) => (
          <li key={`${c.network_id}-${c.subject}`}>
            Allowed from {c.subject}: {c.packets} packets, {formatBytes(c.bytes)}
          </li>
        ))}
        {blockedCount > 0 && <li>Blocked attempts (recent): {blockedCount}</li>}
      </ul>
    </Section>
  );
}

/** Several apps: what they share, and the same edits for all of them. */
export function AppsInspector({ ids, onCollapse, onClose }: { ids: string[] } & Omit<Common, "highlight">) {
  const names = useNameCtx();
  const toast = useToast();
  const grants = useGrants().data ?? [];
  const forget = useDeleteApp();
  const review = useCommit();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [forgetting, setForgetting] = useState(false);

  const selected = names.apps.filter((a) => ids.includes(a.id));
  const entries = mergeEntries(selected.map((a) => appEntriesFromGrants(a.id, grants, names)));
  const pending = selected.filter((a) => !a.reviewed);
  const shown = selected.length > 6 ? `${selected.slice(0, 6).map((a) => a.name).join(", ")} and ${selected.length - 6} more` : selected.map((a) => a.name).join(", ");

  const forgetAll = async () => {
    setForgetting(false);
    try {
      for (const a of selected) await forget.mutateAsync(a.id);
      toast.success(`Forgot ${selected.length} apps`);
      onClose();
    } catch (e) {
      toast.error(errorText(e));
    }
  };

  return (
    <Inspector label="Apps details" title={`${selected.length} apps selected`} subtitle={shown} onCollapse={onCollapse} onClose={onClose}>
      <Section title="Tags">
        <TagPicker appIds={selected.map((a) => a.id)} />
      </Section>

      <Section title="Who can reach them">
        <AccessList entries={entries} direction="who" networks={names.networks} onRevoke={revoke} unit="apps" empty="Nobody can reach any of them." />
        <CommitPreview commit={revokeCommit} />
        <AddAccess fixed={{ side: "targets", targets: selected.map((a) => ({ kind: "app" as const, id: a.id })) }} />
      </Section>

      <div className="actions">
        <button
          className="btn btn-sm"
          disabled={pending.length === 0}
          onClick={() => void review.runBatch(pending.map((a) => ({ op: "review", app_id: a.id, reviewed: true })), `Marked ${pending.length} reviewed`)}
        >
          Mark reviewed{pending.length > 0 ? ` (${pending.length})` : ""}
        </button>
        <button className="btn btn-danger btn-sm" onClick={() => setForgetting(true)}>Forget {selected.length} apps</button>
      </div>
      <CommitPreview commit={review} />

      {forgetting && (
        <ConfirmDialog
          title={`Forget ${selected.length} apps?`}
          confirmLabel="Forget apps"
          onCancel={() => setForgetting(false)}
          onConfirm={() => void forgetAll()}
        >
          <p>Their addresses and grants are removed. Each reappears as pending the next time it listens.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}
