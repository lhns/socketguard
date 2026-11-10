import { useEffect, useId, useMemo, useState } from "react";
import type { ChangeOp, TagMember } from "../api";
import { ChangeList, useDryRun } from "../batch";
import { errorField, errorText, splitOperationError } from "../lib";
import { useChanges, useNetworks, useTags } from "../queries";
import { useToast } from "./Toast";

interface Props {
  /** What to put in the tag: whole apps, or single ports. */
  members: TagMember[];
  onClose: () => void;
}

const NEW = "__new__";

/** Put apps (or ports) into a tag, creating the tag first if needed: one batch. */
export default function TagDialog({ members, onClose }: Props) {
  const id = useId();
  const toast = useToast();
  const tags = useTags();
  const networks = useNetworks();
  const changes = useChanges();
  const [choice, setChoice] = useState("");
  const [label, setLabel] = useState("");
  const [patterns, setPatterns] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const ready = choice !== "" && (choice !== NEW || label.trim() !== "");
  const ops = useMemo(() => {
    if (!ready) return [] as ChangeOp[];
    const out: ChangeOp[] = [];
    let tagId = choice;
    if (choice === NEW) {
      tagId = "$tag";
      out.push({
        op: "create_tag",
        ref: tagId,
        label: label.trim(),
        patterns: patterns.split("\n").map((p) => p.trim()).filter(Boolean),
      });
    }
    for (const m of members) {
      out.push({ op: "add_tag_member", tag_id: tagId, app_id: m.app_id, confirm_open: false, ...(m.port ? { port: m.port } : {}) });
    }
    return out;
  }, [ready, choice, label, patterns, members]);
  const dry = useDryRun(ops);
  const failure = error ?? (dry.state === "error" ? dry.message : null);
  const failed = failure ? splitOperationError(failure) : null;
  const labelError = failed && errorField({ code: "invalid", message: failed.text }) === "label" ? failed.text : null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await changes.mutateAsync({ ops, dryRun: false });
      toast.success(`Tagged ${members.length} ${members.length === 1 ? "item" : "items"}`);
      onClose();
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <form className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby={`${id}-t`} onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h2 id={`${id}-t`} className="modal-title">Tag {members.length} {members.length === 1 ? "item" : "items"}</h2>
        <div className="form-row">
          <label htmlFor={`${id}-tag`}>Tag</label>
          <select id={`${id}-tag`} className="input" value={choice} onChange={(e) => setChoice(e.target.value)}>
            <option value="" disabled>Choose…</option>
            {(tags.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
            <option value={NEW}>New tag…</option>
          </select>
        </div>
        {choice === NEW && (
          <>
            <div className="form-row">
              <label htmlFor={`${id}-label`}>New tag name</label>
              <input id={`${id}-label`} className="input" value={label} onChange={(e) => setLabel(e.target.value)} />
              {labelError && <span className="field-error">{labelError}</span>}
            </div>
            <div className="form-row">
              <label htmlFor={`${id}-pat`}>Auto-match patterns (one per line, optional)</label>
              <textarea id={`${id}-pat`} className="input mono" rows={2} value={patterns} onChange={(e) => setPatterns(e.target.value)} placeholder="nginx*" />
              <p className="hint">Programs matching a pattern (by name or path) join the tag when they are first seen, so a grant on the tag covers future services too.</p>
            </div>
          </>
        )}
        {ready && dry.state === "ok" && <ChangeList changes={dry.result.changes} networks={networks.data ?? []} />}
        {failed && !labelError && <div className="error-banner" role="alert">{failed.text}</div>}
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={!ready || dry.state === "error" || changes.isPending}>Tag</button>
        </div>
      </form>
    </div>
  );
}
