import { useId, useState } from "react";
import { api, type ApplyResponse, type ExportDocument } from "../api";
import { errorText, saveTextFile } from "../lib";
import { useApplyState } from "../queries";
import ConfirmDialog from "./ConfirmDialog";
import { useToast } from "./Toast";

/** Export the whole configuration, or paste one and apply it after a preview of the diff. */
export default function ExportSection() {
  const id = useId();
  const toast = useToast();
  const apply = useApplyState();
  const [exported, setExported] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<ApplyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const doExport = async () => {
    setError(null);
    try {
      setExported(JSON.stringify(await api.exportState(), null, 2));
    } catch (e) {
      setError(errorText(e));
    }
  };

  const download = () => {
    if (exported === null) return;
    try {
      saveTextFile(exported, "socketguard-export.json");
    } catch {
      toast.error("Could not save the file; copy the text instead.");
    }
  };

  const parse = (): ExportDocument | null => {
    try {
      return JSON.parse(text) as ExportDocument;
    } catch (e) {
      setError(`That is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
      return null;
    }
  };

  const doPreview = async () => {
    setError(null);
    setPreview(null);
    const document_ = parse();
    if (!document_) return;
    try {
      setPreview(await api.applyState({ document: document_, dry_run: true, confirm_open: false }));
    } catch (e) {
      setError(errorText(e));
    }
  };

  const doApply = () => {
    const document_ = parse();
    if (!document_) return;
    apply.mutate({ document: document_, dry_run: false, confirm_open: preview?.confirm_open_required ?? false }, {
      onSuccess: (r) => {
        toast.success(`Applied ${r.changes.length} changes`);
        setPreview(null);
        setText("");
      },
      onError: (e) => setError(errorText(e)),
    });
  };

  return (
    <section className="card" aria-label="Export and import">
      <h2 className="card-title">Export and import</h2>
      <p className="hint">
        The export holds settings, peers (with their credentials), groups and grants. Grants on tags are not part of it. Importing
        replaces the current state with the document: whatever it lacks is deleted. Preview first.
      </p>
      <div className="actions">
        <button className="btn" onClick={doExport}>Export</button>
        {exported !== null && (
          <>
            <button className="btn" onClick={() => void navigator.clipboard?.writeText(exported).then(() => toast.success("Copied"), () => toast.error("Could not copy"))}>Copy</button>
            <button className="btn" onClick={download}>Save as file</button>
          </>
        )}
      </div>
      {exported !== null && (
        <textarea className="input mono" readOnly rows={8} aria-label="Exported configuration" value={exported} style={{ width: "100%" }} />
      )}
      <div className="form-row">
        <label htmlFor={`${id}-import`}>Import a document</label>
        <textarea
          id={`${id}-import`}
          className="input mono"
          rows={6}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setPreview(null);
          }}
          placeholder="Paste an export here"
        />
      </div>
      <div className="actions">
        <button className="btn" onClick={doPreview} disabled={text.trim() === ""}>Preview changes</button>
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {preview && (
        <div aria-label="Import preview">
          {preview.changes.length === 0 ? (
            <p className="muted">Nothing would change.</p>
          ) : (
            <ul className="plain-list change-list">
              {preview.changes.map((c, i) => (
                <li key={i} className={`change change-${c.kind}`}>
                  <span className="change-item">{c.kind} {c.item.replace("_", " ")}</span>
                  <span className="change-name">{c.name}</span>
                  {c.detail && <span className="muted">{c.detail}</span>}
                  {c.opens_to_anyone && <span className="badge reach reach-bad">opens to anyone</span>}
                </li>
              ))}
            </ul>
          )}
          <div className="actions">
            <button className="btn btn-primary" disabled={preview.changes.length === 0 || apply.isPending} onClick={() => (preview.confirm_open_required ? setConfirming(true) : doApply())}>
              Apply {preview.changes.length} changes
            </button>
          </div>
        </div>
      )}
      {confirming && (
        <ConfirmDialog
          title="Apply changes that affect Anyone?"
          confirmLabel="Apply anyway"
          onCancel={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            doApply();
          }}
        >
          <p>Some of these changes affect what Anyone can reach. Apply them?</p>
        </ConfirmDialog>
      )}
    </section>
  );
}
