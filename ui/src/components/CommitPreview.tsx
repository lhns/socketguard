import { ChangeList } from "../batch";
import type { Commit } from "../commit";
import { openWording } from "../lib";
import { useNetworks } from "../queries";
import ConfirmDialog from "./ConfirmDialog";

interface Props {
  commit: Commit;
  /** The question of the dialog when something is given, as "Give access?" (not for Anyone). */
  title?: string;
  /** The verb on its button ("Give access"). */
  confirmLabel?: string;
}

/** What `useCommit` shows: "Checking…" and errors in place, and the one confirmation dialog
 * (ADR 0042). The Anyone form has a warning on top and a button named after what it opens. */
export default function CommitPreview({ commit, title = "Give access?", confirmLabel = "Give access" }: Props) {
  const networks = useNetworks().data ?? [];
  const { state } = commit;

  if (state.phase === "checking") return <p className="muted commit-note">Checking…</p>;
  if (state.phase === "error") {
    return <div className="error-banner commit-note" role="alert">{state.message}</div>;
  }
  if (state.phase !== "confirm") return null;

  const common = { onCancel: commit.cancel, onConfirm: commit.confirm, busy: state.busy, error: state.error };
  const list = <ChangeList changes={state.changes} networks={networks} />;
  if (!state.opens) {
    return (
      <ConfirmDialog title={title} confirmLabel={confirmLabel} danger={false} {...common}>
        {list}
      </ConfirmDialog>
    );
  }

  // "on n-lan" in a change's detail names the network a grant to Anyone is limited to.
  const opening = state.changes.filter((c) => c.opens_to_anyone);
  const names = [...new Set(opening.map((c) => networks.find((n) => c.detail === `on ${n.id}`)?.name).filter((n): n is string => n !== undefined))];
  const everywhere = opening.some((c) => !c.detail?.startsWith("on "));
  const where = everywhere || names.length === 0 ? "every network that takes grants" : names.join(", ");
  // Grants read "Anyone to nginx 443/tcp"; other changes (a tag member, a binding) name themselves.
  const things = [...new Set(opening.map((c) => c.name.replace(/^Anyone to /, "")))];
  const what = things.length === 1 ? things[0] : `${things.length} things`;
  const who = openWording(everywhere ? [] : names).replace(/^Anyone$/, "anyone").replace(/^Everyone/, "everyone");
  return (
    <ConfirmDialog
      title={`Open ${what} to ${who}?`}
      confirmLabel={`Open ${what} to anyone`}
      warning={
        <>
          <strong>This opens {what} to anyone on {where}.</strong>{" "}
          {everywhere || names.length === 0
            ? "Any source that can reach this machine on those networks will be able to connect. This is not limited to your peers."
            : "Nothing is verified. Hosts on other networks, even when routed here, will not."}
        </>
      }
      {...common}
    >
      {list}
    </ConfirmDialog>
  );
}
