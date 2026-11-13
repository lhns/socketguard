import { useId, useMemo, useRef, useState } from "react";
import { appEntriesFromGrants, grantEntries } from "../access";
import type { ChangeOp, ReservationView, Scope } from "../api";
import { useCommit } from "../commit";
import { ALL_SCOPE, errorField, scopeKey, scopeLabel, scopeOfPort, sameScope } from "../lib";
import { boundRows, conflictText, type BoundRow } from "../reservations";
import { useApps, useGrants, useList, useReservations, usePortGroups, useTags } from "../queries";
import { bindsRow } from "../matrix";
import type { AccessHighlight } from "./AccessList";
import { DangerZone, RowButton } from "./ActionRow";
import AddAccess from "./AddAccess";
import AddressLines from "./AddressLines";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import RowCard, { RowAccess } from "./RowCard";

interface Common {
  onCollapse?: () => void;
  onClose: () => void;
}

const RELEASE_TEXT = "Its addresses are given up, and the grants on it go. Ports bound to it get their own addresses again once access names them.";

/** One reservation: its name, its addresses, its own All ports row and the rows bound to it. */
export function ReservationInspector({ reservation: r, highlight, onCollapse, onClose }: { reservation: ReservationView; highlight: AccessHighlight | null } & Common) {
  const id = useId();
  const names = useNameCtx();
  const groups = useList(usePortGroups());
  const release = useCommit(onClose);
  const rename = useCommit(() => setRenaming(false));
  const bind = useCommit();
  const [renaming, setRenaming] = useState(false);
  const [label, setLabel] = useState(r.label);
  const [releasing, setReleasing] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  const rows = boundRows(r, names.apps, names.tags, groups);
  const failed = rename.state.phase === "error" ? rename.state.message : null;
  const nameError = failed && errorField({ code: "invalid", message: failed }) === "label" ? failed : null;
  const dirty = label.trim() !== "" && label.trim() !== r.label;

  const conflictOf = (row: BoundRow) => r.conflicts.some((c) => c.bindings.includes(row.bindingId));

  return (
    <Inspector
      label="Reservation details"
      title={r.label}
      subtitle={`reserved address · ${r.bindings.length === 0 ? "nothing bound" : `${r.bindings.length} ${r.bindings.length === 1 ? "binding" : "bindings"}`}`}
      badges={r.conflicts.length > 0 ? <span className="badge reach reach-warn">port conflict</span> : undefined}
      onCollapse={onCollapse}
      onClose={onClose}
    >
      {renaming ? (
        <form
          className="inline-form"
          aria-label="Rename reservation"
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty) void rename.runBatch([{ op: "rename_reservation", reservation_id: r.id, label: label.trim() }], "Reservation renamed");
          }}
        >
          <label htmlFor={`${id}-n`} className="sr-only">Name</label>
          <input id={`${id}-n`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} autoFocus required />
          <button type="submit" className="btn btn-primary btn-sm" disabled={!dirty}>Rename</button>
          <button type="button" className="btn btn-sm" onClick={() => { setRenaming(false); setLabel(r.label); }}>Cancel</button>
          {nameError && <span className="field-error">{nameError}</span>}
        </form>
      ) : (
        <div className="actions rename-line">
          <button className="btn btn-sm" onClick={() => { setLabel(r.label); setRenaming(true); }}>Rename</button>
        </div>
      )}

      <Section title="Addresses">
        <AddressLines addresses={r.addresses} networks={names.networks} empty="Gets an address when access is added." />
      </Section>

      {r.conflicts.length > 0 && (
        <div className="warn-banner conflict-block" role="alert">
          <strong>Ports claimed by several apps</strong>
          <ul className="plain-list">
            {r.conflicts.map((c, i) => (
              <li key={i}>{conflictText(c, r, names.apps, names.tags)}</li>
            ))}
          </ul>
        </div>
      )}

      <Section
        title="Ports"
        aside={
          <AddPorts
            reservation={r}
            open={pickerOpen}
            onOpenChange={setPickerOpen}
            onPick={(target, what) => {
              setPickerOpen(false);
              const op: ChangeOp = { op: "add_binding", reservation_id: r.id, target, confirm_open: false };
              void bind.runBatch([op], `Added ${what} to ${r.label}`);
            }}
          />
        }
      >
        <CommitPreview commit={bind} title="Add to this reserved address?" confirmLabel="Add" />
        <ul className="plain-list port-list">
          <AllPortsCard reservation={r} highlight={highlight} />
          {rows.map((row) => (
            <BoundCard key={row.key} reservation={r} row={row} conflict={conflictOf(row)} highlight={highlight} />
          ))}
        </ul>
        {rows.length === 0 && <p className="muted">Nothing is bound yet. Add the ports it should front.</p>}
      </Section>

      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setReleasing(true)}>Release reservation</button>
      </DangerZone>

      {releasing && (
        <ConfirmDialog
          title={`Release ${r.label}?`}
          confirmLabel="Release reservation"
          onCancel={() => setReleasing(false)}
          onConfirm={() => {
            setReleasing(false);
            void release.runBatch([{ op: "release_reservation", reservation_id: r.id, confirm_open: false }], `Released ${r.label}`);
          }}
        >
          <p>{RELEASE_TEXT}</p>
        </ConfirmDialog>
      )}
      <CommitPreview commit={release} title={`Release ${r.label}?`} confirmLabel="Release reservation" />
    </Inspector>
  );
}

/** The reservation's own "All ports": the grants on the reservation cover every bound row. */
function AllPortsCard({ reservation: r, highlight }: { reservation: ReservationView; highlight: AccessHighlight | null }) {
  const names = useNameCtx();
  const entries = grantEntries(r.grants, "subject", names);
  return (
    <RowCard
      rowKey="*"
      head={
        <>
          <span className="port-name">All ports</span>
          <span className="muted">every bound port</span>
        </>
      }
      access={<RowAccess entries={entries} rowScope={ALL_SCOPE} empty="Nobody can reach it." highlight={highlight} />}
      actions={<AddAccess fixed={{ side: "targets", targets: [{ kind: "reservation", id: r.id }] }} preselect={ALL_SCOPE} rowLabel="All ports" />}
    />
  );
}

/** A row bound to the reservation: the same grants as under its app, plus Remove. */
function BoundCard({ reservation: r, row, conflict, highlight }: { reservation: ReservationView; row: BoundRow; conflict: boolean; highlight: AccessHighlight | null }) {
  const names = useNameCtx();
  const grants = useGrants().data ?? [];
  const remove = useCommit();
  const binding = r.bindings.find((b) => b.id === row.bindingId)!;
  const entries = row.appId
    ? appEntriesFromGrants(row.appId, grants, names).filter((e) => sameScope(e.row ?? e.scope, row.scope))
    : [];
  const what = row.viaTag ? `tag ${row.viaTag.label}` : row.label;
  const empty = row.scope.kind === "all" ? "Nobody can reach it." : row.scope.kind === "group" ? "No access on this port group alone." : "No access on this port alone.";
  return (
    <RowCard
      rowKey={row.key}
      head={
        <>
          <span className="port-name">{row.label}</span>
          {row.viaTag && row.appId && <span className="badge badge-kind">via tag {row.viaTag.label}</span>}
          {conflict && <span className="badge reach reach-warn" title="Another app claims the same ports">port conflict</span>}
        </>
      }
      access={
        row.appId ? (
          <RowAccess entries={entries} rowScope={row.scope} empty={empty} highlight={highlight} />
        ) : (
          <p className="muted">This tag has no members yet.</p>
        )
      }
      actions={
        <>
          {row.appId && <AddAccess fixed={{ side: "targets", targets: [{ kind: "app", id: row.appId }] }} preselect={row.scope} rowLabel={row.label} />}
          <RowButton
            aria-label={`Remove ${what} from reservation`}
            onClick={() =>
              void remove.runBatch(
                [{ op: "remove_binding", reservation_id: r.id, binding_id: binding.id, confirm_open: false }],
                `Removed ${what} from ${r.label}`,
                [{ op: "add_binding", reservation_id: r.id, target: binding.target, confirm_open: false }],
              )
            }
          >
            Remove from reservation
          </RowButton>
          <CommitPreview commit={remove} title={`Remove ${what} from ${r.label}?`} confirmLabel="Remove" />
        </>
      }
    />
  );
}

/** "Add ports": a search over the tags and the rows of every app. */
function AddPorts({ reservation: r, open, onOpenChange, onPick }: {
  reservation: ReservationView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onPick: (target: ReservationView["bindings"][number]["target"], what: string) => void;
}) {
  const apps = useList(useApps());
  const tags = useList(useTags());
  const groups = useList(usePortGroups());
  const all = useList(useReservations());
  const targets = useRef(new Map<string, { target: ReservationView["bindings"][number]["target"]; what: string }>());

  const items = useMemo<PickerItem[]>(() => {
    targets.current.clear();
    /** The reservation a row is bound to, if any. */
    const boundTo = (appId: string, scope: Scope) =>
      all.find((x) => bindsRow(x.bindings, tags, appId, scope));
    const out: PickerItem[] = [];
    for (const t of tags) {
      const id = `tag:${t.id}`;
      const holder = all.find((x) => x.bindings.some((b) => b.target.kind === "tag" && b.target.tag_id === t.id));
      targets.current.set(id, { target: { kind: "tag", tag_id: t.id }, what: `tag ${t.label}` });
      out.push({
        id,
        label: `tag ${t.label}`,
        section: "Tags",
        state: holder?.id === r.id ? "on" : "off",
        disabled: holder !== undefined,
        hint: holder === undefined ? `${t.members.length} ${t.members.length === 1 ? "app" : "apps"}` : holder.id === r.id ? "bound here" : `in ${holder.label}`,
      });
    }
    const ordered = [...apps.filter((a) => !a.system), ...apps.filter((a) => a.system)];
    for (const a of ordered) {
      const scopes = [
        ALL_SCOPE,
        ...a.ports.map(scopeOfPort),
        ...groups.filter((g) => g.apps.includes(a.id)).map((g) => ({ kind: "group" as const, id: g.id })),
      ];
      for (const scope of scopes) {
        const id = `row:${a.id}:${scopeKey(scope)}`;
        const holder = boundTo(a.id, scope);
        targets.current.set(id, { target: { kind: "app", app_id: a.id, scope }, what: `${a.name} · ${scopeLabel(scope, groups)}` });
        out.push({
          id,
          label: scopeLabel(scope, groups),
          section: a.name,
          state: holder?.id === r.id ? "on" : "off",
          disabled: holder !== undefined,
          hint: holder === undefined ? undefined : holder.id === r.id ? "bound here" : `in ${holder.label}`,
        });
      }
    }
    return out;
  }, [apps, tags, groups, all, r.id]);

  return (
    <Picker
      label={`Ports of ${r.label}`}
      trigger="Add ports"
      triggerClass="btn btn-sm"
      items={items}
      onToggle={(it) => {
        const t = targets.current.get(it.id);
        if (t) onPick(t.target, t.what);
      }}
      open={open}
      onOpenChange={onOpenChange}
      placeholder="Find an app, a port or a tag"
      empty="No apps yet."
      align="right"
    />
  );
}

/** Several reservations: Release them together. */
export function ReservationsInspector({ reservations, onCollapse, onClose }: { reservations: ReservationView[] } & Common) {
  const release = useCommit(onClose);
  const [releasing, setReleasing] = useState(false);
  const shown = reservations.length > 6 ? `${reservations.slice(0, 6).map((r) => r.label).join(", ")} and ${reservations.length - 6} more` : reservations.map((r) => r.label).join(", ");

  const releaseAll = () => {
    setReleasing(false);
    void release.runBatch(
      reservations.map<ChangeOp>((r) => ({ op: "release_reservation", reservation_id: r.id, confirm_open: false })),
      `Released ${reservations.length} reservations`,
    );
  };

  return (
    <Inspector label="Reservations details" title={`${reservations.length} reservations selected`} subtitle={shown} onCollapse={onCollapse} onClose={onClose}>
      <DangerZone>
        <button className="btn btn-danger btn-sm" onClick={() => setReleasing(true)}>Release {reservations.length}</button>
      </DangerZone>
      {releasing && (
        <ConfirmDialog
          title={`Release ${reservations.length} reservations?`}
          confirmLabel="Release reservations"
          onCancel={() => setReleasing(false)}
          onConfirm={releaseAll}
        >
          <p>{RELEASE_TEXT}</p>
        </ConfirmDialog>
      )}
      <CommitPreview commit={release} title={`Release ${reservations.length} reservations?`} confirmLabel="Release reservations" />
    </Inspector>
  );
}

/** The inline form of "New reservation". */
export function NewReservationForm({ onCreated, onClose }: { onCreated: (label: string) => void; onClose: () => void }) {
  const id = useId();
  const [label, setLabel] = useState("");
  const commit = useCommit(() => onCreated(label.trim()));
  const busy = commit.state.phase === "checking" || commit.state.phase === "applying";
  const failed = commit.state.phase === "error" ? commit.state.message : null;
  return (
    <Inspector label="New reservation" title="New reservation" onClose={onClose}>
      <form
        className="add-form"
        aria-label="New reservation"
        onSubmit={(e) => {
          e.preventDefault();
          const name = label.trim();
          if (!name) return;
          void commit.runBatch([{ op: "create_reservation", label: name, bindings: [], confirm_open: false }], `Reserved address ${name} created`);
        }}
      >
        <p className="hint">A named address that stays the same and can front ports of several apps. Add the ports after creating it.</p>
        <div className="form-row">
          <label htmlFor={`${id}-n`}>Name</label>
          <input id={`${id}-n`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. public-web" autoFocus required />
          {failed && <span className="field-error">{failed}</span>}
        </div>
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={!label.trim() || busy}>Create</button>
          <button type="button" className="btn btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Inspector>
  );
}
