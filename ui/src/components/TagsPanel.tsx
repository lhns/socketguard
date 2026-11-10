import { useId, useState } from "react";
import type { Tag } from "../api";
import { errorField, errorText, portLabel, splitOperationError, subjectLabel } from "../lib";
import {
  useApps, useChanges, useDeleteGrant, useDeleteTag, useGrants, useGroups, useNetworks, usePeers, useTags, useUpdateTag,
} from "../queries";
import { ReachBadge } from "../reach";
import ConfirmDialog from "./ConfirmDialog";
import GrantEditor from "./GrantEditor";
import { useToast } from "./Toast";

interface Props {
  /** The tag the app list is filtered by. */
  active: string | null;
  onFilter: (tagId: string | null) => void;
}

const patternsOf = (text: string) => text.split("\n").map((p) => p.trim()).filter(Boolean);

/** Tags: filter the app list by one, create, edit, and manage what a tag grants. */
export default function TagsPanel({ active, onFilter }: Props) {
  const tags = useTags();
  const [creating, setCreating] = useState(false);
  const tag = (tags.data ?? []).find((t) => t.id === active) ?? null;

  return (
    <section className="card tags-panel" aria-label="Tags">
      <div className="card-header">
        <h2 className="card-title">Tags</h2>
        <button className="btn btn-sm" onClick={() => setCreating(!creating)}>{creating ? "Close" : "New tag…"}</button>
      </div>
      {tags.data?.length === 0 && !creating && (
        <p className="muted">
          No tags. A tag groups apps (or single ports) so one grant covers all of them, including programs that start
          listening later.
        </p>
      )}
      <ul className="chip-row">
        {(tags.data ?? []).map((t) => (
          <li key={t.id}>
            <button
              className={`tag-pill${t.id === active ? " tag-pill-active" : ""}`}
              aria-pressed={t.id === active}
              onClick={() => onFilter(t.id === active ? null : t.id)}
            >
              {t.label} <span className="muted">{t.members.length}</span>
            </button>
          </li>
        ))}
      </ul>
      {creating && <NewTagForm onDone={() => setCreating(false)} />}
      {tag && <TagEditor key={tag.id} tag={tag} onGone={() => onFilter(null)} />}
    </section>
  );
}

function NewTagForm({ onDone }: { onDone: () => void }) {
  const id = useId();
  const toast = useToast();
  const changes = useChanges();
  const [label, setLabel] = useState("");
  const [patterns, setPatterns] = useState("");
  const [error, setError] = useState<{ field: string; text: string } | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await changes.mutateAsync({
        ops: [{ op: "create_tag", label: label.trim(), patterns: patternsOf(patterns) }],
        dryRun: false,
      });
      toast.success(`Created tag ${label.trim()}`);
      onDone();
    } catch (err) {
      setError({ field: errorField(err), text: splitOperationError(errorText(err)).text });
    }
  };

  return (
    <form className="subform" onSubmit={submit}>
      <div className="form-row">
        <label htmlFor={`${id}-l`}>Tag name</label>
        <input id={`${id}-l`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
        {error?.field === "label" && <span className="field-error">{error.text}</span>}
      </div>
      <div className="form-row">
        <label htmlFor={`${id}-p`}>Auto-match patterns (one per line, optional)</label>
        <textarea id={`${id}-p`} className="input mono" rows={2} value={patterns} onChange={(e) => setPatterns(e.target.value)} placeholder="nginx*" />
        <p className="hint">Programs whose name or path match join the tag when they are first seen.</p>
        {error?.field === "patterns" && <span className="field-error">{error.text}</span>}
      </div>
      {error && error.field !== "label" && error.field !== "patterns" && <div className="error-banner" role="alert">{error.text}</div>}
      <button type="submit" className="btn btn-primary" disabled={changes.isPending}>Create tag</button>
    </form>
  );
}

function TagEditor({ tag, onGone }: { tag: Tag; onGone: () => void }) {
  const id = useId();
  const toast = useToast();
  const apps = useApps().data ?? [];
  const peers = usePeers().data ?? [];
  const groups = useGroups().data ?? [];
  const networks = useNetworks().data ?? [];
  const grants = (useGrants().data ?? []).filter((g) => g.target.kind === "tag" && g.target.id === tag.id);
  const update = useUpdateTag();
  const del = useDeleteTag();
  const delGrant = useDeleteGrant();
  const changes = useChanges();
  const [label, setLabel] = useState(tag.label);
  const [patterns, setPatterns] = useState(tag.patterns.join("\n"));
  const [error, setError] = useState<{ field: string; text: string } | null>(null);
  const [granting, setGranting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const appName = (appId: string) => apps.find((a) => a.id === appId)?.name ?? appId.slice(0, 8);
  const dirty = label.trim() !== tag.label || patternsOf(patterns).join("\n") !== tag.patterns.join("\n");

  const save = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    update.mutate({ id: tag.id, req: { label: label.trim(), patterns: patternsOf(patterns) } }, {
      onSuccess: () => toast.success("Tag saved"),
      onError: (err) => setError({ field: errorField(err), text: errorText(err) }),
    });
  };

  const removeMember = (m: Tag["members"][number]) =>
    changes.mutate({ ops: [{ op: "remove_tag_member", tag_id: tag.id, app_id: m.app_id, ...(m.port ? { port: m.port } : {}) }], dryRun: false }, {
      onError: (err) => toast.error(errorText(err)),
    });

  return (
    <div className="subform tag-editor" role="group" aria-label={`Tag ${tag.label}`}>
      <form onSubmit={save}>
        <div className="form-inline">
          <div className="form-row">
            <label htmlFor={`${id}-n`}>Name</label>
            <input id={`${id}-n`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} required />
            {error?.field === "label" && <span className="field-error">{error.text}</span>}
          </div>
          <div className="form-row grow">
            <label htmlFor={`${id}-p`}>Auto-match patterns (one per line)</label>
            <textarea id={`${id}-p`} className="input mono" rows={2} value={patterns} onChange={(e) => setPatterns(e.target.value)} />
            {error?.field === "patterns" && <span className="field-error">{error.text}</span>}
          </div>
          <button type="submit" className="btn" disabled={!dirty || update.isPending}>Save tag</button>
        </div>
        {error && error.field !== "label" && error.field !== "patterns" && <div className="error-banner" role="alert">{error.text}</div>}
      </form>

      <h3 className="section-title">Members ({tag.members.length})</h3>
      {tag.members.length === 0 && <p className="muted">No members. Select apps in the list and use Tag… to add them, or open an app to tag one of its ports.</p>}
      <ul className="plain-list">
        {tag.members.map((m) => (
          <li key={`${m.app_id}-${m.port ? portLabel(m.port) : "*"}`} className="cred-row">
            <span>{appName(m.app_id)}</span>
            <span className="muted">{m.port ? portLabel(m.port) : "all ports"}</span>
            <button className="btn btn-sm" aria-label={`Remove ${appName(m.app_id)} from ${tag.label}`} onClick={() => removeMember(m)}>Remove</button>
          </li>
        ))}
      </ul>
      {tag.excluded.length > 0 && <p className="hint">Kept out by hand: {tag.excluded.map(appName).join(", ")}.</p>}

      <h3 className="section-title">Access granted to this tag</h3>
      {grants.length === 0 ? (
        <p className="muted">No grants on this tag.</p>
      ) : (
        <ul className="chip-list">
          {grants.map((g) => {
            const name = subjectLabel(g.subject, peers, groups);
            return (
              <li key={g.id} className="chip">
                <span className="chip-name">{name}</span>
                {g.port && <span className="muted">{portLabel(g.port)}</span>}
                {g.network_id && <span className="muted">on {networks.find((n) => n.id === g.network_id)?.name ?? g.network_id}</span>}
                <span className="chip-reach">
                  {g.reach.map((r) => <ReachBadge key={r.network_id} reach={r.reach} network={networks.find((n) => n.id === r.network_id)?.name} />)}
                </span>
                <button className="btn btn-danger btn-sm" aria-label={`Revoke tag access for ${name}`} onClick={() =>
                  delGrant.mutate(g.id, { onSuccess: () => toast.success("Access revoked"), onError: (err) => toast.error(errorText(err)) })}>
                  Revoke
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <div className="actions">
        <button className="btn btn-primary" onClick={() => setGranting(true)}>Grant access to {tag.label}…</button>
        <button className="btn btn-danger btn-sm" onClick={() => setDeleting(true)}>Delete tag</button>
      </div>
      {granting && <GrantEditor targets={[{ kind: "tag", id: tag.id }]} onClose={() => setGranting(false)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete tag ${tag.label}?`}
          confirmLabel="Delete tag"
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            setDeleting(false);
            del.mutate(tag.id, {
              onSuccess: () => { toast.success("Tag deleted"); onGone(); },
              onError: (err) => toast.error(errorText(err)),
            });
          }}
        >
          <p>The grants on this tag are removed with it. The apps stay.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
