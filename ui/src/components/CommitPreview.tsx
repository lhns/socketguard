import { ChangeList } from "../batch";
import type { Commit } from "../commit";
import { openWording } from "../lib";
import { useNetworks } from "../queries";
import ConfirmDialog from "./ConfirmDialog";

/** What an edit would change, shown where it was made, with the one Apply (see commit.ts). */
export default function CommitPreview({ commit, title = "This lets more in" }: { commit: Commit; title?: string }) {
  const networks = useNetworks().data ?? [];
  const { state } = commit;

  if (state.phase === "checking") return <p className="muted commit-note">Checking…</p>;
  if (state.phase === "error") {
    return <div className="error-banner commit-note" role="alert">{state.message}</div>;
  }
  if (state.phase !== "review" && state.phase !== "confirm") return null;

  // "on n-lan" in a change's detail names the network a grant to Anyone is limited to.
  const names = state.changes
    .filter((c) => c.opens_to_anyone)
    .map((c) => networks.find((n) => c.detail === `on ${n.id}`)?.name)
    .filter((n): n is string => n !== undefined);
  const everywhere = state.changes.some((c) => c.opens_to_anyone && !c.detail?.startsWith("on "));
  const word = openWording(everywhere ? [] : [...new Set(names)]);

  return (
    <section className="commit-preview" aria-label="Review before applying">
      <h4 className="commit-title">{title}</h4>
      <ChangeList changes={state.changes} networks={networks} />
      <div className="actions">
        <button type="button" className="btn btn-primary btn-sm" onClick={commit.apply}>Apply</button>
        <button type="button" className="btn btn-sm" onClick={commit.cancel}>Cancel</button>
      </div>
      {state.phase === "confirm" && (
        <ConfirmDialog
          title={`Open to ${word.replace(/^Anyone$/, "anyone").replace(/^Everyone/, "everyone")}?`}
          confirmLabel="Open it"
          onCancel={commit.declineOpen}
          onConfirm={commit.confirmOpen}
        >
          <p>
            {everywhere || names.length === 0
              ? "Any source that can reach this machine on the networks of these apps will be able to connect. This is not limited to your peers."
              : `Any host on ${[...new Set(names)].join(", ")} will be able to connect, nothing is verified. Hosts on other networks, even when routed here, will not.`}
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
