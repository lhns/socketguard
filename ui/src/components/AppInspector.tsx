import { useRef, useState } from "react";
import { appEntriesFromGrants, mergeEntries } from "../access";
import type { AppDetail } from "../api";
import { useCommit, useRevoke } from "../commit";
import { errorText, formatBytes } from "../lib";
import { useNav } from "../nav";
import { useActivity, useApp, useDeleteApp, useGrants, useShare } from "../queries";
import AccessList, { type AccessHighlight } from "./AccessList";
import PortsSection from "./PortsSection";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import TagPicker from "./TagPicker";
import { useToast } from "./Toast";

interface Common {
  highlight: AccessHighlight | null;
  onCollapse?: () => void;
  onClose: () => void;
}

/** One app: its ports and port groups (with tags and access on each), its addresses. */
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
  return <OneApp app={app.data} partial={app.isPlaceholderData} {...common} />;
}

/** `partial`: only what the lists know; access and counters follow with the detail. */
function OneApp({ app, partial, highlight, onCollapse, onClose }: { app: AppDetail; partial: boolean } & Common) {
  const toast = useToast();
  const names = useNameCtx();
  const forget = useDeleteApp();
  const nav = useNav();
  const review = useCommit();
  const moveTarget = useRef<string | null>(null);
  const move = useCommit(() => {
    if (moveTarget.current) nav.go("apps", { appId: moveTarget.current });
  });
  const [moving, setMoving] = useState(false);
  const [forgetting, setForgetting] = useState(false);

  // Access can be given wherever a network takes grants. An app nobody has opened yet has
  // only its Local address, so this must not be read from the app's addresses.
  const onlyLocal = names.networks.length > 0 && names.networks.every((n) => n.grants_apply === false);
  const hasV4 = app.ports.some((p) => p.listening && p.family !== "v6");

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
      {!app.reviewed && <MovedHint app={app} />}
      {app.identity_note === "unidentified" && (
        <p className="hint">
          SocketGuard cannot tell which program owns this port, so it is identified by its port alone. It is closed until you
          grant access, like any other app.
        </p>
      )}

      <PortsSection app={app} partial={partial} highlight={highlight} onlyLocal={onlyLocal} hasV4={hasV4} />

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
        <MovePicker app={app} open={moving} onOpenChange={setMoving} onPick={(to) => {
          moveTarget.current = to.id;
          setMoving(false);
          // The diff is always shown: a move changes grants, tags, addresses and bindings at once.
          void move.runBatch([{ op: "move_app", from: app.id, to: to.id, confirm_open: false }], `Transferred access to ${to.name}`, undefined, true);
        }} />
        <button className="btn btn-danger btn-sm" onClick={() => setForgetting(true)}>Forget app</button>
      </div>
      <p className="hint">{TRANSFER_HINT}</p>
      <CommitPreview commit={review} />
      <CommitPreview commit={move} title={`Transfer access to ${names.apps.find((a) => a.id === moveTarget.current)?.name ?? "the other app"}`} />

      <TorShare appId={app.id} hasOnion={app.addresses.some((a) => a.locator.kind === "onion")} />
      {!partial && <Counters app={app} />}

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

const TRANSFER_HINT =
  "Moves this app's access, tags and addresses to the app you pick. Use it when a program was moved or reinstalled and now shows up as a new app.";

/**
 * A pending app with the name of an app whose program is gone is probably that program,
 * moved: offer the transfer from the old entry, with the same review as the picker.
 */
function MovedHint({ app }: { app: AppDetail }) {
  const names = useNameCtx();
  const nav = useNav();
  const takeover = useCommit(() => nav.go("apps", { appId: app.id }));
  const old = names.apps.find((a) => a.id !== app.id && a.exe_missing && a.process_name === app.process_name);
  if (!old) return null;
  return (
    <div className="card moved-hint" role="group" aria-label="Moved program">
      <p>
        Looks like <strong>{old.name}</strong> moved. Its old entry points to a program that is no longer there.
      </p>
      <div className="actions">
        <button
          className="btn btn-primary btn-sm"
          onClick={() =>
            void takeover.runBatch([{ op: "move_app", from: old.id, to: app.id, confirm_open: false }], `Transferred access from ${old.name}`, undefined, true)
          }
        >
          Take over from the old entry
        </button>
      </div>
      <CommitPreview commit={takeover} title={`Take over from ${old.name}`} />
    </div>
  );
}

/** "Transfer access to another app…": a search over the other apps. */
function MovePicker({ app, open, onOpenChange, onPick }: { app: AppDetail; open: boolean; onOpenChange: (o: boolean) => void; onPick: (to: { id: string; name: string }) => void }) {
  const names = useNameCtx();
  const others = names.apps.filter((a) => a.id !== app.id);
  const items: PickerItem[] = [
    ...others.filter((a) => !a.system).map<PickerItem>((a) => ({ id: a.id, label: a.name, section: "Apps", state: "off" })),
    ...others.filter((a) => a.system).map<PickerItem>((a) => ({ id: a.id, label: a.name, section: "System services", state: "off" })),
  ];
  return (
    <Picker
      label="Transfer access to"
      trigger="Transfer access to another app…"
      triggerClass="btn btn-sm"
      items={items}
      onToggle={(it) => onPick({ id: it.id, name: it.label })}
      open={open}
      onOpenChange={onOpenChange}
      placeholder="Find the app that replaces it"
      empty="No other app."
    />
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
