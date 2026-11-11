import { useRef, useState } from "react";
import { appEntries, type AccessEntry } from "../access";
import type { AppDetail, AppPort, ChangeOp, PortRange, Scope, SocketGroup } from "../api";
import { useCommit, useRevoke, type Commit } from "../commit";
import { ALL_SCOPE, portLabel, rangeLabel, sameScope, scopeKey, scopeLabel, scopeOfPort, withRange } from "../lib";
import { useGrants, useSettings, useSocketGroups } from "../queries";
import AccessList, { type AccessHighlight } from "./AccessList";
import AddAccess from "./AddAccess";
import CommitPreview from "./CommitPreview";
import { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import PortRanges from "./PortRanges";
import TagPicker from "./TagPicker";

/** What one row of an app is. */
interface RowDef {
  key: string;
  scope: Scope;
  label: string;
  port?: AppPort;
  group?: SocketGroup;
}

/** The rows of an app: All ports, each detected port, each attached port group; also a port that
 * only a grant or a tag names, so its access has a place. */
function rowsOf(app: AppDetail, entries: AccessEntry[], tagScopes: Scope[]): RowDef[] {
  const rows: RowDef[] = [{ key: "*", scope: ALL_SCOPE, label: scopeLabel(ALL_SCOPE) }];
  for (const p of app.ports) rows.push({ key: scopeKey(scopeOfPort(p)), scope: scopeOfPort(p), label: portLabel(p), port: p });
  for (const s of [...entries.map((e) => e.row ?? e.scope), ...tagScopes]) {
    if (s.kind === "port" && !rows.some((r) => sameScope(r.scope, s))) rows.push({ key: scopeKey(s), scope: s, label: scopeLabel(s) });
  }
  for (const g of app.socket_groups) rows.push({ key: `group:${g.id}`, scope: { kind: "group", id: g.id }, label: g.label, group: g });
  return rows;
}

interface Props {
  app: AppDetail;
  highlight: AccessHighlight | null;
  onlyLocal: boolean;
  hasV4: boolean;
}

/** The "Ports" section of one app: a row for All ports, one per detected port and one per
 * attached port group. Every row has the same parts: its tags, who can reach it, Add access. */
export default function PortsSection({ app, highlight, onlyLocal, hasV4 }: Props) {
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const protectsHost = (useSettings().data?.protect_host_interfaces.length ?? 0) > 0;
  const allGroups = useSocketGroups().data ?? [];
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState<string | null>(null);
  const attach = useCommit(() => setCreating(null));
  const allRow = useRef<HTMLLIElement>(null);

  const entries = appEntries(app.id, app.access, grants, names);
  const tagScopes = names.tags.flatMap((t) => t.members.filter((m) => m.app_id === app.id).map((m) => m.scope));
  const rows = rowsOf(app, entries, tagScopes);
  const hasAllEntries = entries.some((e) => (e.row ?? e.scope).kind === "all");
  const unidentified = app.identity_note === "unidentified";

  const items: PickerItem[] = allGroups.map((g) => ({
    id: g.id,
    label: g.label,
    hint: g.ports.map(rangeLabel).join(", "),
    state: g.apps.includes(app.id) ? "on" : "off",
  }));
  const toggle = (item: PickerItem) => {
    const op = (kind: "attach_socket_group" | "detach_socket_group"): ChangeOp =>
      kind === "attach_socket_group"
        ? { op: kind, group_id: item.id, app_id: app.id, confirm_open: false }
        : { op: kind, group_id: item.id, app_id: app.id };
    if (item.state === "on") void attach.runBatch([op("detach_socket_group")], `Detached ${item.label}`, [op("attach_socket_group")]);
    else void attach.runBatch([op("attach_socket_group")], `Attached ${item.label}`);
    setOpen(false);
  };

  return (
    <Section
      title="Ports"
      aside={
        unidentified ? undefined : (
          <Picker
            label="Port groups"
            trigger="Attach port group"
            triggerClass="btn btn-sm"
            items={items}
            onToggle={toggle}
            create={(typed) => ({
              label: <>Create &ldquo;{typed}&rdquo;</>,
              pick: () => {
                setCreating(typed);
                setOpen(false);
              },
            })}
            open={open}
            onOpenChange={setOpen}
            placeholder="Find or create a port group"
            empty="No port groups yet. Type a name to create one."
            align="right"
          />
        )
      }
    >
      {onlyLocal ? (
        <p className="muted">This machine only. Grants do not apply on the Local network.</p>
      ) : (
        hasV4 && (
          <p className="hint" data-testid="ipv4-status">
            {protectsHost
              ? "IPv4: closed except granted IPv4 peers (protect-host is on)."
              : "IPv4: open to everyone (protect-host is off). Grants only limit IPv6 and the other networks."}
          </p>
        )
      )}
      {app.ports.length === 0 && <p className="muted">No ports seen.</p>}

      {creating !== null && <NewPortGroup label={creating} appId={app.id} commit={attach} onCancel={() => setCreating(null)} />}
      {creating === null && <CommitPreview commit={attach} title="This lets more in" />}

      <ul className="plain-list port-list">
        {rows.map((r) => (
          <RowItem
            key={r.key}
            app={app}
            row={r}
            entries={entries.filter((e) => sameScope(e.row ?? e.scope, r.scope))}
            alsoAll={r.scope.kind !== "all" && hasAllEntries && (r.port !== undefined || r.group !== undefined)}
            onlyLocal={onlyLocal}
            anyEntries={entries.length > 0}
            highlight={highlight}
            itemRef={r.scope.kind === "all" ? allRow : undefined}
            jumpToAll={() => allRow.current?.scrollIntoView?.({ block: "nearest" })}
            onDetach={r.group ? () => {
              const g = r.group!;
              void attach.runBatch(
                [{ op: "detach_socket_group", group_id: g.id, app_id: app.id }],
                `Detached ${g.label}`,
                [{ op: "attach_socket_group", group_id: g.id, app_id: app.id, confirm_open: false }],
              );
            } : undefined}
          />
        ))}
      </ul>
    </Section>
  );
}

interface RowProps {
  app: AppDetail;
  row: RowDef;
  entries: AccessEntry[];
  /** Grants on All ports also cover this row: say so once instead of repeating them. */
  alsoAll: boolean;
  onlyLocal: boolean;
  anyEntries: boolean;
  highlight: AccessHighlight | null;
  itemRef?: React.RefObject<HTMLLIElement>;
  jumpToAll: () => void;
  onDetach?: () => void;
}

/** One row. The parts are always in this order: name, tags, who can reach it, Add access. */
function RowItem({ app, row, entries, alsoAll, onlyLocal, anyEntries, highlight, itemRef, jumpToAll, onDetach }: RowProps) {
  const names = useNameCtx();
  const { revoke, commit } = useRevoke();
  const isAll = row.scope.kind === "all";
  const empty = isAll ? (anyEntries ? "Nobody on All ports." : "Nobody. The app is closed.") : "Nobody named here.";
  return (
    <li className="port-row" ref={itemRef} data-row={row.key}>
      <div className="port-head">
        <span className={`port-name${row.group || isAll ? "" : " mono"}`}>{row.label}</span>
        {row.port && (
          <>
            <span className={row.port.listening ? "badge reach reach-ok" : "badge reach reach-muted"}>{row.port.listening ? "listening" : "not listening"}</span>
            <span className="muted" title="Which IP versions it accepts connections over">
              {row.port.family === "dual" ? "IPv4+IPv6" : row.port.family === "v4" ? "IPv4" : "IPv6"}
            </span>
          </>
        )}
        {!row.port && row.scope.kind === "port" && <span className="badge reach reach-muted">not seen</span>}
        {row.group && <span className="mono muted">{row.group.ports.map(rangeLabel).join(", ")}</span>}
        {isAll && <span className="muted">every port and port group</span>}
        {onDetach && <button className="btn btn-sm port-action" aria-label={`Detach ${row.label}`} onClick={onDetach}>Detach</button>}
      </div>
      <div className="port-tags">
        <TagPicker appIds={[app.id]} scope={row.scope} />
      </div>
      {!onlyLocal && (
        <div className="port-access">
          <AccessList entries={entries} direction="who" networks={names.networks} onRevoke={revoke} highlight={highlight} empty={empty} rowScope={row.scope} />
          {alsoAll && (
            <button className="link-btn also-line" onClick={jumpToAll}>also reachable by everyone on All ports</button>
          )}
          <CommitPreview commit={commit} />
        </div>
      )}
      {!onlyLocal && (
        <div className="port-add">
          <AddAccess fixed={{ side: "targets", targets: [{ kind: "app", id: app.id }] }} preselect={row.scope} rowLabel={row.label} />
        </div>
      )}
    </li>
  );
}

/** The ports of a port group that is created and attached in one batch. */
function NewPortGroup({ label, appId, commit, onCancel }: { label: string; appId: string; commit: Commit; onCancel: () => void }) {
  const [ranges, setRanges] = useState<PortRange[]>([]);
  const busy = commit.state.phase === "checking" || commit.state.phase === "applying";
  const reviewing = commit.state.phase === "review" || commit.state.phase === "confirm";
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    void commit.runBatch(
      [
        { op: "create_socket_group", ref: "$group", label, ports: ranges, apps: [], confirm_open: false },
        { op: "attach_socket_group", group_id: "$group", app_id: appId, confirm_open: false },
      ],
      `Created and attached ${label}`,
    );
  };
  return (
    <form className="add-form new-group" aria-label="New port group" onSubmit={submit}>
      <p className="add-lead">Ports of the new port group <strong>{label}</strong></p>
      <PortRanges ranges={ranges} onAdd={(r) => setRanges(withRange(ranges, r))} onRemove={(r) => setRanges(ranges.filter((x) => rangeLabel(x) !== rangeLabel(r)))} disabled={reviewing} />
      {!reviewing && (
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={ranges.length === 0 || busy}>Create and attach</button>
          <button type="button" className="btn btn-sm" onClick={onCancel}>Cancel</button>
        </div>
      )}
      <CommitPreview commit={commit} title="This lets more in" />
    </form>
  );
}
