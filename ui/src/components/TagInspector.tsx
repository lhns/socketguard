import { useId, useState } from "react";
import { grantEntries, mergeEntries } from "../access";
import { toDaemonError, type Scope, type Tag } from "../api";
import { useCommit, useRevoke } from "../commit";
import { ALL_SCOPE, errorField, errorText, sameScope, scopeKey, scopeLabel, scopeOfPort, splitOperationError } from "../lib";
import { useNav } from "../nav";
import { useApps, useDeleteTag, useGrants, useList, usePortGroups, useReservations, useUpdateTag } from "../queries";
import AccessList, { type AccessHighlight } from "./AccessList";
import AddAccess from "./AddAccess";
import AddToReserved from "./AddToReserved";
import CommitPreview from "./CommitPreview";
import ConfirmDialog from "./ConfirmDialog";
import Inspector, { Section, useNameCtx } from "./Inspector";
import Picker, { type PickerItem } from "./Picker";
import { useToast } from "./Toast";

const patternsOf = (text: string) => text.split("\n").map((p) => p.trim()).filter(Boolean);

interface Common {
  onCollapse?: () => void;
  onClose: () => void;
}

/** One tag: its name and patterns, its members, and who can reach them. */
export function TagInspector({ tag, highlight, onCollapse, onClose }: { tag: Tag; highlight: AccessHighlight | null } & Common) {
  const id = useId();
  const toast = useToast();
  const names = useNameCtx();
  const grants = (useGrants().data ?? []).filter((g) => g.target.kind === "tag" && g.target.id === tag.id);
  const bound = useList(useReservations()).some((r) => r.bindings.some((b) => b.target.kind === "tag" && b.target.tag_id === tag.id));
  const update = useUpdateTag();
  const del = useDeleteTag();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [label, setLabel] = useState(tag.label);
  const [patterns, setPatterns] = useState(tag.patterns.join("\n"));
  const [error, setError] = useState<{ field: string; text: string } | null>(null);
  const [asking, setAsking] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const dirty = label.trim() !== tag.label || patternsOf(patterns).join("\n") !== tag.patterns.join("\n");

  const save = (confirm_open: boolean) => {
    setError(null);
    update.mutate({ id: tag.id, req: { label: label.trim(), patterns: patternsOf(patterns), confirm_open } }, {
      onSuccess: () => toast.success("Tag saved"),
      onError: (err) => {
        // New patterns would put apps into a tag that is open to anyone.
        if (toDaemonError(err).code === "confirmation_required") setAsking(true);
        else setError({ field: errorField(err), text: errorText(err) });
      },
    });
  };

  return (
    <Inspector label="Tag details" title={tag.label} subtitle={`tag · ${tag.members.length} ${tag.members.length === 1 ? "member" : "members"}`} onCollapse={onCollapse} onClose={onClose}>
      <Section title="Name and patterns">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            save(false);
          }}
        >
          <div className="form-row">
            <label htmlFor={`${id}-n`}>Name</label>
            <input id={`${id}-n`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            {error?.field === "label" && <span className="field-error">{error.text}</span>}
          </div>
          <div className="form-row">
            <label htmlFor={`${id}-p`}>Auto-match patterns (one per line)</label>
            <textarea id={`${id}-p`} className="input mono" rows={2} value={patterns} onChange={(e) => setPatterns(e.target.value)} placeholder="nginx*" />
            <p className="hint">Programs whose name or path match join the tag, now and when they are first seen.</p>
            {error?.field === "patterns" && <span className="field-error">{error.text}</span>}
          </div>
          {error && error.field !== "label" && error.field !== "patterns" && <div className="error-banner" role="alert">{error.text}</div>}
          <button type="submit" className="btn btn-sm" disabled={!dirty || update.isPending}>Save tag</button>
        </form>
      </Section>

      <Section title={`Members (${tag.members.length})`}>
        <Members tag={tag} />
      </Section>

      <Section title="Who can reach its members">
        <AccessList entries={grantEntries(grants, "subject", names)} direction="who" networks={names.networks} onRevoke={revoke} highlight={highlight} empty="No grants on this tag." />
        <CommitPreview commit={revokeCommit} />
        <AddAccess fixed={{ side: "targets", targets: [{ kind: "tag", id: tag.id }] }} />
      </Section>

      {!bound && <AddToReserved target={{ kind: "tag", tag_id: tag.id }} />}

      <div className="actions">
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete tag</button>
      </div>

      {asking && (
        <ConfirmDialog title="Open more apps to anyone?" confirmLabel="Save and open" onCancel={() => setAsking(false)} onConfirm={() => { setAsking(false); save(true); }}>
          <p>This tag is open to anyone, and the new patterns put apps into it. Those apps will be open to anyone too.</p>
        </ConfirmDialog>
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete tag ${tag.label}?`}
          confirmLabel="Delete tag"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            del.mutate(tag.id, {
              onSuccess: () => { toast.success("Tag deleted"); onClose(); },
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>The grants on this tag are removed with it. The apps stay.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** The members of a tag, each as `app · row`, and a picker: choose an app, then its rows. */
function Members({ tag }: { tag: Tag }) {
  const nav = useNav();
  const apps = useApps().data ?? [];
  const portGroups = usePortGroups().data ?? [];
  const commit = useCommit();
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<string | null>(null);
  const appName = (appId: string) => apps.find((a) => a.id === appId)?.name ?? appId.slice(0, 8);
  const inTag = new Set(tag.members.map((m) => m.app_id));
  const item = (a: (typeof apps)[number], section: string): PickerItem => ({ id: a.id, label: a.name, section, state: inTag.has(a.id) ? "mixed" : "off" });
  const items = [
    ...apps.filter((a) => !a.system).map((a) => item(a, "Apps")),
    ...apps.filter((a) => a.system).map((a) => item(a, "System services")),
  ];
  const picked = apps.find((a) => a.id === chosen);
  const rows: Scope[] = picked
    ? [
        ALL_SCOPE,
        ...picked.ports.map((p) => scopeOfPort(p)),
        ...portGroups.filter((g) => g.apps.includes(picked.id)).map<Scope>((g) => ({ kind: "group", id: g.id })),
      ]
    : [];
  const has = (appId: string, scope: Scope) => tag.members.some((m) => m.app_id === appId && sameScope(m.scope, scope));
  const toggleRow = (appId: string, scope: Scope) => {
    const what = `${appName(appId)} · ${scopeLabel(scope, portGroups)}`;
    if (has(appId, scope)) {
      void commit.runBatch(
        [{ op: "remove_tag_member", tag_id: tag.id, app_id: appId, scope }],
        `Removed ${what} from ${tag.label}`,
        [{ op: "add_tag_member", tag_id: tag.id, app_id: appId, scope, confirm_open: false }],
      );
    } else {
      void commit.runBatch([{ op: "add_tag_member", tag_id: tag.id, app_id: appId, scope, confirm_open: false }], `Added ${what} to ${tag.label}`);
    }
  };
  return (
    <>
      {tag.members.length === 0 ? (
        <p className="muted">No members. Add apps here, or select apps and use + next to their tags in the details.</p>
      ) : (
        <ul className="plain-list member-list">
          {tag.members.map((m) => (
            <li key={`${m.app_id}-${scopeKey(m.scope)}`} className="member-item">
              <span>
                <button className="link-btn" onClick={() => nav.go("apps", { appId: m.app_id })}>{appName(m.app_id)}</button>
                <span className="muted"> · {scopeLabel(m.scope, portGroups)}</span>
              </span>
              <button
                className="btn-icon"
                aria-label={`Remove ${appName(m.app_id)} · ${scopeLabel(m.scope, portGroups)}`}
                title="Remove from the tag"
                onClick={() => toggleRow(m.app_id, m.scope)}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      {tag.excluded.length > 0 && <p className="hint">Kept out by hand: {tag.excluded.map(appName).join(", ")}.</p>}
      <div className="tag-row">
        <Picker
          label={`Members of ${tag.label}`}
          trigger="+"
          triggerClass="tag-pill tag-pill-add"
          compactLabel="Add or remove members"
          items={items}
          onToggle={(it) => {
            setChosen(it.id);
            setOpen(false);
          }}
          open={open}
          onOpenChange={setOpen}
          placeholder="Find an app"
        />
      </div>
      {picked && (
        <div className="scope-row" role="group" aria-label={`Rows of ${picked.name} in ${tag.label}`}>
          <span className="muted">{picked.name}:</span>
          {rows.map((scope) => (
            <button key={scopeKey(scope)} type="button" className={`scope-chip${scope.kind === "port" ? " mono" : ""}`} aria-pressed={has(picked.id, scope)} onClick={() => toggleRow(picked.id, scope)}>
              {scopeLabel(scope, portGroups)}
            </button>
          ))}
          <button type="button" className="btn-icon" aria-label="Done choosing rows" title="Done" onClick={() => setChosen(null)}>×</button>
        </div>
      )}
      <CommitPreview commit={commit} title="Joining this tag lets more in" />
    </>
  );
}

/** Several tags: the access they share, and the same edits for all of them. */
export function TagsInspector({ tags, onCollapse, onClose }: { tags: Tag[] } & Common) {
  const names = useNameCtx();
  const toast = useToast();
  const grants = useGrants().data ?? [];
  const del = useDeleteTag();
  const { revoke, commit: revokeCommit } = useRevoke();
  const [deleting, setDeleting] = useState(false);
  const entries = mergeEntries(tags.map((t) => grantEntries(grants.filter((g) => g.target.kind === "tag" && g.target.id === t.id), "subject", names)));
  const deleteAll = async () => {
    setDeleting(false);
    try {
      for (const t of tags) await del.mutateAsync(t.id);
      toast.success(`Deleted ${tags.length} tags`);
      onClose();
    } catch (e) {
      toast.error(errorText(e));
    }
  };
  return (
    <Inspector label="Tags details" title={`${tags.length} tags selected`} subtitle={tags.map((t) => t.label).join(", ")} onCollapse={onCollapse} onClose={onClose}>
      <Section title="Who can reach their members">
        <AccessList entries={entries} direction="who" networks={names.networks} onRevoke={revoke} unit="tags" empty="No grants on these tags." />
        <CommitPreview commit={revokeCommit} />
        <AddAccess fixed={{ side: "targets", targets: tags.map((t) => ({ kind: "tag" as const, id: t.id })) }} />
      </Section>
      <div className="actions">
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete {tags.length} tags</button>
      </div>
      {deleting && (
        <ConfirmDialog title={`Delete ${tags.length} tags?`} confirmLabel="Delete tags" onCancel={() => setDeleting(false)} onConfirm={() => void deleteAll()}>
          <p>The grants on these tags are removed with them. The apps stay.</p>
        </ConfirmDialog>
      )}
    </Inspector>
  );
}

/** A tag with no members yet, perhaps only patterns. */
export function NewTagForm({ onCreated, onClose }: { onCreated: (label: string) => void; onClose: () => void }) {
  const id = useId();
  const [label, setLabel] = useState("");
  const [patterns, setPatterns] = useState("");
  const commit = useCommit(() => onCreated(label.trim()));
  const failed = commit.state.phase === "error" ? splitOperationError(commit.state.message).text : null;
  const field = failed ? errorField({ code: "invalid", message: failed }) : null;
  return (
    <Inspector label="New tag" title="New tag">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void commit.runBatch([{ op: "create_tag", label: label.trim(), patterns: patternsOf(patterns) }], `Created tag ${label.trim()}`);
        }}
      >
        <div className="form-row">
          <label htmlFor={`${id}-l`}>Tag name</label>
          <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
          {field === "label" && <span className="field-error" role="alert">{failed}</span>}
        </div>
        <div className="form-row">
          <label htmlFor={`${id}-p`}>Auto-match patterns (one per line, optional)</label>
          <textarea id={`${id}-p`} className="input mono" rows={2} value={patterns} onChange={(e) => setPatterns(e.target.value)} placeholder="nginx*" />
          <p className="hint">Programs whose name or path match join the tag, now and when they are first seen, so one grant on the tag covers future services too.</p>
          {field === "patterns" && <span className="field-error" role="alert">{failed}</span>}
        </div>
        {failed && field !== "label" && field !== "patterns" && <div className="error-banner" role="alert">{failed}</div>}
        <div className="actions">
          <button type="submit" className="btn btn-primary btn-sm" disabled={commit.state.phase === "checking" || commit.state.phase === "applying"}>Create tag</button>
          <button type="button" className="btn btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Inspector>
  );
}
