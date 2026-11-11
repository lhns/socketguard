import { useEffect, useId, useState } from "react";
import { api } from "../api";
import { forgetColumns } from "../columns";
import { errorText, saveTextFile } from "../lib";
import ElevatedAction from "./ElevatedAction";

/**
 * "Remove SocketGuard…" (ADR 0050): what goes, whether settings and keys go too, an export
 * first, then the daemon's own uninstall run as administrator. The window forgets its own
 * storage and closes afterwards.
 */
export default function RemoveDialog({ onCancel }: { onCancel: () => void }) {
  const titleId = useId();
  const [purge, setPurge] = useState(false);
  const [exported, setExported] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const exportFirst = async () => {
    setExportError(null);
    try {
      saveTextFile(JSON.stringify(await api.exportState(), null, 2), "socketguard-export.json");
      setExported(true);
    } catch (e) {
      setExportError(errorText(e));
    }
  };

  const finish = async () => {
    setDone(true);
    // Synchronously here, so it is gone before the window closes; the backend wipes the
    // rest of the webview profile as well.
    forgetColumns();
    try {
      await api.clearLocalUiSettings();
    } catch {
      // Leftover window settings are harmless; closing matters more.
    }
    try {
      await api.quitApp();
    } catch {
      // Not running inside the app (or it refused): the removal itself is done.
    }
  };

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby={titleId} onClick={(e) => e.stopPropagation()}>
        <h2 id={titleId} className="modal-title">Remove SocketGuard?</h2>
        <div className="modal-body">
          {done ? (
            <p role="status">SocketGuard is removed. This window closes now.</p>
          ) : (
            <>
              <p>This takes SocketGuard off this computer. It removes:</p>
              <ul>
                <li>the firewall rules and the addresses SocketGuard added</li>
                <li>the SocketGuard service</li>
                <li>the access group, if SocketGuard created it</li>
                <li>the changes made by network setup</li>
              </ul>
              <label className="check">
                <input type="checkbox" checked={purge} onChange={(e) => setPurge(e.target.checked)} />
                Also delete settings and keys?
              </label>
              <p className="hint">
                {purge
                  ? "The database is deleted: apps, peers, grants and the onion keys."
                  : "Settings, grants and keys stay on disk, so installing SocketGuard again finds them."}{" "}
                An export holds settings, peers and grants, but not the onion private keys. Onion addresses cannot be recovered.
              </p>
              <div className="actions">
                <button className="btn btn-sm" onClick={() => void exportFirst()}>Export first</button>
                {exported && <span role="status">Saved socketguard-export.json.</span>}
              </div>
              {exportError && <div className="error-banner" role="alert">{exportError}</div>}
              <ElevatedAction
                label="Remove SocketGuard"
                command={`socketguard-daemon uninstall --yes ${purge ? "--purge" : "--keep-data"}`}
                run={() => api.removeSocketguard(purge)}
                onDone={() => void finish()}
              />
            </>
          )}
        </div>
        {!done && (
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onCancel}>Cancel</button>
          </div>
        )}
      </div>
    </div>
  );
}
