import { useEffect, useId, useMemo, useState } from "react";
import type { ChangeOp } from "../api";
import { ChangeList, useDryRun } from "../batch";
import { errorText, networkName, portLabel, subjectLabel } from "../lib";
import { useApps, useChanges, useGrants, useGroups, useNetworks, usePeers } from "../queries";
import { useToast } from "./Toast";

/** Revoke some of the grants on the selected apps, in one batch. */
export default function RevokeDialog({ appIds, onClose }: { appIds: string[]; onClose: () => void }) {
  const id = useId();
  const toast = useToast();
  const apps = useApps().data ?? [];
  const peers = usePeers().data ?? [];
  const groups = useGroups().data ?? [];
  const networks = useNetworks().data ?? [];
  const grants = (useGrants().data ?? []).filter((g) => g.target.kind === "app" && appIds.includes(g.target.id));
  const changes = useChanges();
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const ops = useMemo<ChangeOp[]>(() => [...chosen].map((grant_id) => ({ op: "remove_grant", grant_id })), [chosen]);
  const dry = useDryRun(ops);
  const toggle = (gid: string, on: boolean) => {
    const next = new Set(chosen);
    if (on) next.add(gid);
    else next.delete(gid);
    setChosen(next);
  };
  const describe = (g: (typeof grants)[number]) =>
    `${apps.find((a) => a.id === (g.target as { id: string }).id)?.name ?? "app"} · ${g.port ? portLabel(g.port) : "all ports"} · ${subjectLabel(g.subject, peers, groups)} · ${networkName(networks, g.network_id)}`;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await changes.mutateAsync({ ops, dryRun: false });
      toast.success(`Revoked ${ops.length} grant${ops.length === 1 ? "" : "s"}`);
      onClose();
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <form className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby={`${id}-t`} onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h2 id={`${id}-t`} className="modal-title">Revoke access</h2>
        {grants.length === 0 ? (
          <p className="muted">The selected apps have no grants of their own. Access that comes through a tag or a group is changed there.</p>
        ) : (
          <>
            <div className="actions">
              <button type="button" className="btn btn-sm" onClick={() => setChosen(new Set(grants.map((g) => g.id)))}>Select all</button>
              <button type="button" className="btn btn-sm" onClick={() => setChosen(new Set())}>Select none</button>
            </div>
            <ul className="plain-list">
              {grants.map((g) => (
                <li key={g.id}>
                  <label className="check">
                    <input type="checkbox" checked={chosen.has(g.id)} onChange={(e) => toggle(g.id, e.target.checked)} />
                    {describe(g)}
                  </label>
                </li>
              ))}
            </ul>
          </>
        )}
        {dry.state === "ok" && <ChangeList changes={dry.result.changes} networks={networks} />}
        {(error ?? (dry.state === "error" ? dry.message : null)) && (
          <div className="error-banner" role="alert">{error ?? (dry.state === "error" ? dry.message : "")}</div>
        )}
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-danger" disabled={ops.length === 0 || changes.isPending}>
            Revoke {ops.length || ""}
          </button>
        </div>
      </form>
    </div>
  );
}
