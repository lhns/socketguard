import { useId, useState } from "react";
import { appEntriesFromGrants } from "../access";
import type { ChangeOp, PortRange, Scope, PortGroup } from "../api";
import { useCommit, useRevoke } from "../commit";
import { errorField, rangeLabel, sameScope, splitOperationError, withRange } from "../lib";
import { useNav } from "../nav";
import { useApps, useGrants } from "../queries";
import AccessList, { type AccessHighlight } from "./AccessList";
import { ActionRow, DangerZone } from "./ActionRow";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import PortRanges from "./PortRanges";

interface Common {
  onCollapse?: () => void;
  onClose: () => void;
}

const attachOp = (group_id: string, app_id: string): ChangeOp => ({ op: "attach_port_group", group_id, app_id, confirm_open: false });
const detachOp = (group_id: string, app_id: string): ChangeOp => ({ op: "detach_port_group", group_id, app_id });
const portsOp = (group_id: string, ports: PortRange[]): ChangeOp => ({ op: "update_port_group", group_id, ports, confirm_open: false });

/** One port group: its name and ports, the apps it is attached to, and who can reach it there. */
export function PortGroupInspector({ group, highlight, onCollapse, onClose }: { group: PortGroup; highlight: AccessHighlight | null } & Common) {
  const id = useId();
  const names = useNameCtx();
  const nav = useNav();
  const grants = useGrants().data ?? [];
  const edit = useCommit();
  const attach = useCommit();
  const del = useCommit(onClose);
  const { revoke, commit: revokeCommit } = useRevoke();
  const [appsOpen, setAppsOpen] = useState(false);
  const [label, setLabel] = useState(group.label);
  const [deleting, setDeleting] = useState(false);
  const [lastPort, setLastPort] = useState(false);
  const scope: Scope = { kind: "group", id: group.id };
  const dirty = label.trim() !== group.label && label.trim() !== "";

  const failed = edit.state.phase === "error" ? splitOperationError(edit.state.message).text : null;
  const nameError = failed && errorField({ code: "invalid", message: failed }) === "label" ? failed : null;

  const setPorts = (next: PortRange[], done: string, undo?: PortRange[]) =>
    void edit.runBatch([portsOp(group.id, next)], done, undo ? [portsOp(group.id, undo)] : undefined);

  const apps = names.apps;
  const attachedApps = apps.filter((a) => group.apps.includes(a.id));
  const item = (a: (typeof apps)[number], section: string): PickerItem => ({ id: a.id, label: a.name, section, state: group.apps.includes(a.id) ? "on" : "off" });
  const pickable = apps.filter((a) => a.identity_note !== "unidentified" || group.apps.includes(a.id));
  const items = [
    ...pickable.filter((a) => !a.system).map((a) => item(a, "Apps")),
    ...pickable.filter((a) => a.system).map((a) => item(a, "System services")),
  ];
  const toggleApp = (it: PickerItem) => {
    if (it.state === "on") void attach.runBatch([detachOp(group.id, it.id)], `Detached ${group.label} from ${it.label}`, [attachOp(group.id, it.id)]);
    else void attach.runBatch([attachOp(group.id, it.id)], `Attached ${group.label} to ${it.label}`);
    // The review is shown below the list, so the list gets out of its way.
    setAppsOpen(false);
  };

  return (
    <Inspector
      label="Port group details"
      title={group.label}
      subtitle={`port group · ${group.apps.length} ${group.apps.length === 1 ? "app" : "apps"}`}
      onCollapse={onCollapse}
      onClose={onClose}
    >
      <Section title="Name and ports">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty) void edit.runBatch([{ op: "update_port_group", group_id: group.id, label: label.trim(), confirm_open: false }], "Port group renamed");
          }}
        >
          <div className="form-row">
            <label htmlFor={`${id}-n`}>Name</label>
            <input id={`${id}-n`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            {nameError && <span className="field-error">{nameError}</span>}
          </div>
          <button type="submit" className="btn btn-sm" disabled={!dirty}>Rename</button>
        </form>
        <h4 className="sub-title">Ports and ranges</h4>
        <PortRanges
          ranges={group.ports}
          disabled={edit.state.phase === "checking" || edit.state.phase === "applying"}
          onAdd={(r) => {
            setLastPort(false);
            const next = withRange(group.ports, r);
            if (next !== group.ports) setPorts(next, `Added ${rangeLabel(r)} to ${group.label}`);
          }}
          onRemove={(r) => {
            const next = group.ports.filter((x) => rangeLabel(x) !== rangeLabel(r));
            setLastPort(next.length === 0);
            if (next.length > 0) setPorts(next, `Removed ${rangeLabel(r)} from ${group.label}`, group.ports);
          }}
        />
        {lastPort && <span className="field-error" role="alert">A port group needs at least one port. Delete the group instead.</span>}
        <CommitPreview commit={edit} title="Change this port group?" confirmLabel="Apply" />
      </Section>

      <Section
        title={`Attached to (${attachedApps.length})`}
        aside={
          <Picker
            label={`Apps of ${group.label}`}
            trigger="+"
            triggerClass="tag-pill tag-pill-add"
            compactLabel="Attach or detach apps"
            items={items}
            onToggle={toggleApp}
            open={appsOpen}
            onOpenChange={setAppsOpen}
            placeholder="Find an app"
            align="right"
          />
        }
      >
        <AttachedApps apps={attachedApps} />
        <CommitPreview commit={attach} title="Change where this port group is attached?" confirmLabel="Apply" />
      </Section>

      <Section title="Who can reach it">
        {attachedApps.length === 0 ? (
          <p className="muted">Not attached to any app yet.</p>
        ) : (
          <>
            {attachedApps.map((a) => {
              const all = appEntriesFromGrants(a.id, grants, names);
              const alsoAll = all.some((e) => (e.row ?? e.scope).kind === "all");
              return (
                <div key={a.id} className="per-app">
                  <h4 className="sub-title">{a.name}</h4>
                  <AccessList
                    entries={all.filter((e) => sameScope(e.row ?? e.scope, scope))}
                    direction="who"
                    networks={names.networks}
                    onRevoke={revoke}
                    highlight={highlight}
                    empty="No access on this port group alone."
                    rowScope={scope}
                  />
                  {alsoAll && (
                    <button className="link-btn also-line" onClick={() => nav.go("apps", { appId: a.id })}>
                      also reachable by everyone on All ports of {a.name}
                    </button>
                  )}
                </div>
              );
            })}
            <CommitPreview commit={revokeCommit} />
            <ActionRow><AddAccess fixed={{ side: "targets", targets: attachedApps.map((a) => ({ kind: "app" as const, id: a.id })) }} preselect={scope} rowLabel={group.label} /></ActionRow>
          </>
        )}
      </Section>

      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete port group</button>
      </DangerZone>
      <CommitPreview commit={del} />

      {deleting && (
        <ConfirmDialog
          title={`Delete port group ${group.label}?`}
          confirmLabel="Delete port group"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            void del.runBatch([{ op: "delete_port_group", group_id: group.id }], `Deleted ${group.label}`);
          }}
        >
          <p>It is detached from its apps. The daemon refuses while a grant or a tag member uses it.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

function AttachedApps({ apps }: { apps: { id: string; name: string }[] }) {
  const nav = useNav();
  if (apps.length === 0) return <p className="muted">No apps. Attach it with +.</p>;
  return (
    <ul className="plain-list member-list">
      {apps.map((a) => (
        <li key={a.id}>
          <button className="link-btn" onClick={() => nav.go("apps", { appId: a.id })}>{a.name}</button>
        </li>
      ))}
    </ul>
  );
}

/** Several port groups: where they are attached (mixed when only some have it), and Delete. */
export function PortGroupsInspector({ groups, onCollapse, onClose }: { groups: PortGroup[] } & Common) {
  const apps = useApps().data ?? [];
  const edit = useCommit();
  const del = useCommit(onClose);
  const [deleting, setDeleting] = useState(false);
  const [appsOpen, setAppsOpen] = useState(false);

  const count = (appId: string) => groups.filter((g) => g.apps.includes(appId)).length;
  const pickable = apps.filter((a) => a.identity_note !== "unidentified" || count(a.id) > 0);
  const stateOf = (appId: string): PickerItem["state"] => (count(appId) === 0 ? "off" : count(appId) === groups.length ? "on" : "mixed");
  const item = (a: (typeof apps)[number], section: string): PickerItem => ({ id: a.id, label: a.name, section, state: stateOf(a.id) });
  const items = [
    ...pickable.filter((a) => !a.system).map((a) => item(a, "Apps")),
    ...pickable.filter((a) => a.system).map((a) => item(a, "System services")),
  ];
  const toggle = (it: PickerItem) => {
    if (it.state === "on") {
      void edit.runBatch(
        groups.map((g) => detachOp(g.id, it.id)),
        `Detached ${groups.length} port groups from ${it.label}`,
        groups.map((g) => attachOp(g.id, it.id)),
      );
    } else {
      void edit.runBatch(
        groups.filter((g) => !g.apps.includes(it.id)).map((g) => attachOp(g.id, it.id)),
        `Attached to ${it.label}`,
      );
    }
    setAppsOpen(false);
  };
  const attachedTo = apps.filter((a) => count(a.id) > 0);

  return (
    <Inspector label="Port groups details" title={`${groups.length} port groups selected`} subtitle={groups.map((g) => g.label).join(", ")} onCollapse={onCollapse} onClose={onClose}>
      <Section
        title="Attached to"
        aside={
          <Picker label="Apps of the port groups" trigger="+" triggerClass="tag-pill tag-pill-add" compactLabel="Attach or detach apps" items={items} onToggle={toggle} open={appsOpen} onOpenChange={setAppsOpen} placeholder="Find an app" align="right" />
        }
      >
        {attachedTo.length === 0 ? (
          <p className="muted">No apps.</p>
        ) : (
          <ul className="plain-list member-list">
            {attachedTo.map((a) => (
              <li key={a.id}>
                <span className="name-badges">
                  <span className="name-text">{a.name}</span>
                  <span className={count(a.id) === groups.length ? "muted" : "badge reach reach-warn"}>
                    {count(a.id) === groups.length ? `all ${groups.length}` : `${count(a.id)} of ${groups.length}`}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
        <CommitPreview commit={edit} title="Change this port group?" confirmLabel="Apply" />
      </Section>
      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete {groups.length} port groups</button>
      </DangerZone>
      <CommitPreview commit={del} />
      {deleting && (
        <ConfirmDialog
          title={`Delete ${groups.length} port groups?`}
          confirmLabel="Delete port groups"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            void del.runBatch(groups.map((g) => ({ op: "delete_port_group", group_id: g.id })), `Deleted ${groups.length} port groups`);
          }}
        >
          <p>They are detached from their apps. The daemon refuses while a grant or a tag member uses one.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** A port group with ports and an optional name (the daemon names it after its ports); attach it
 * to apps afterwards. */
export function NewPortGroupForm({ onCreated, onClose }: { onCreated: () => void; onClose: () => void }) {
  const id = useId();
  const [label, setLabel] = useState("");
  const [ranges, setRanges] = useState<PortRange[]>([]);
  const commit = useCommit(onCreated);
  const defaultName = ranges.map(rangeLabel).join(", ");
  const name = label.trim() || defaultName;
  const failed = commit.state.phase === "error" ? splitOperationError(commit.state.message).text : null;
  const field = failed ? errorField({ code: "invalid", message: failed }) : null;
  return (
    <Inspector label="New port group" title="New port group">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (ranges.length === 0) return;
          void commit.runBatch(
            [{ op: "create_port_group", label: label.trim() || undefined, ports: ranges, apps: [], confirm_open: false }],
            `Created port group ${name}`,
          );
        }}
      >
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Port group name</label>
          <input id={`${id}-l`} className="input" value={label} placeholder={defaultName || "Named after its ports"} onChange={(e) => setLabel(e.target.value)} />
          {field === "label" && <span className="field-error" role="alert">{failed}</span>}
        </div>
        <div className="form-row">
          <span className="form-label">Ports and ranges</span>
          <PortRanges ranges={ranges} onAdd={(r) => setRanges(withRange(ranges, r))} onRemove={(r) => setRanges(ranges.filter((x) => rangeLabel(x) !== rangeLabel(r)))} />
          <p className="hint">For example FTP&apos;s passive range. Attach the group to the apps that use it afterwards.</p>
        </div>
        {failed && field !== "label" && <div className="error-banner" role="alert">{failed}</div>}
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={ranges.length === 0 || commit.state.phase === "checking" || commit.state.phase === "applying"}>Create port group</button>
          <button type="button" className="btn btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Inspector>
  );
}
