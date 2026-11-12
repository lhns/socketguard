// The one rule for every edit that changes who can reach what:
//   1. ask the daemon what the batch would do (a dry run);
//   2. if nobody gains access, apply it at once (an edit that only closes also gets an Undo);
//   3. otherwise ONE confirmation dialog lists the changes; when something is opened to Anyone it
//      is the same dialog in its warning form, and its button is what applies with `confirm_open`.
// There is no inline review (ADR 0042).
// Group membership has no batch operation, so the same steps run on a description the UI
// builds itself: joining a group that has grants gives its members that access.
import { useCallback, useRef, useState } from "react";
import { toDaemonError, type BatchChange, type ChangeOp, type ChangesResponse, type PeerGroup } from "./api";
import type { AccessEntry } from "./access";
import { confirmAll, grantInverse } from "./batch";
import { useToast, type ToastAction } from "./components/Toast";
import { errorText, scopeLabel, targetLabel } from "./lib";
import { useApps, useChanges, useGrants, useList, usePeers, useSetGroupMembers, useTags } from "./queries";

export type CommitState =
  | { phase: "idle" }
  | { phase: "checking" }
  /** The confirmation dialog is open. `opens`: it is the Anyone form. An apply error stays here. */
  | { phase: "confirm"; changes: BatchChange[]; opens: boolean; busy: boolean; error: string | null }
  | { phase: "applying" }
  | { phase: "error"; message: string };

interface Check {
  changes: BatchChange[];
  /** Somebody gains access to something they could not reach. */
  widens: boolean;
  /** Something is opened to Anyone, which needs the confirmation. */
  opens: boolean;
}

/** One edit: how to look at it, how to apply it and, if it only closes, how to take it back. */
interface Edit {
  done: string;
  check: () => Promise<Check>;
  /** Answers the `refs` of a batch. */
  apply: (confirmed: boolean) => Promise<ChangesResponse["refs"] | void>;
  undo?: () => Promise<void>;
  /** A button on the success toast, from the ids the batch created (when there is no Undo). */
  link?: (refs: ChangesResponse["refs"]) => ToastAction;
  /** Show the dialog even when nobody gains access (an edit that moves a lot, such as move_app). */
  alwaysReview?: boolean;
}

const IDLE: CommitState = { phase: "idle" };

/** `useCommit()` per place that edits; render its state with `<CommitPreview commit={...} />`. */
export function useCommit(onDone?: () => void) {
  const toast = useToast();
  const changes = useChanges();
  const setMembers = useSetGroupMembers();
  const apps = useList(useApps());
  const tags = useList(useTags());
  const peers = useList(usePeers());
  const grants = useList(useGrants());
  const [state, setState] = useState<CommitState>(IDLE);
  /** The edit whose dialog is open. */
  const waiting = useRef<{ edit: Edit; changes: BatchChange[]; opens: boolean } | null>(null);

  const finish = useCallback(
    async (edit: Edit, confirmed: boolean, seen: BatchChange[], opens: boolean) => {
      const dialog = waiting.current !== null;
      if (dialog) setState({ phase: "confirm", changes: seen, opens, busy: true, error: null });
      else setState({ phase: "applying" });
      let refs: ChangesResponse["refs"];
      try {
        refs = (await edit.apply(confirmed)) ?? {};
      } catch (e) {
        if (!confirmed && toDaemonError(e).code === "confirmation_required") {
          // The dry run did not flag it: the same dialog, in its Anyone form.
          waiting.current = { edit, changes: seen, opens: true };
          setState({ phase: "confirm", changes: seen, opens: true, busy: false, error: null });
        } else if (dialog) {
          setState({ phase: "confirm", changes: seen, opens, busy: false, error: errorText(e) });
        } else {
          setState({ phase: "error", message: errorText(e) });
        }
        return;
      }
      waiting.current = null;
      setState(IDLE);
      const undo = edit.undo;
      toast.success(
        edit.done,
        undo
          ? {
              label: "Undo",
              onClick: () => {
                undo().then(
                  () => toast.success("Undone"),
                  (e) => toast.error(errorText(e)),
                );
              },
            }
          : edit.link?.(refs),
      );
      onDone?.();
    },
    [toast, onDone],
  );

  const run = useCallback(
    async (edit: Edit) => {
      setState({ phase: "checking" });
      let check: Check;
      try {
        check = await edit.check();
      } catch (e) {
        setState({ phase: "error", message: errorText(e) });
        return;
      }
      if (!check.widens && !check.opens && !edit.alwaysReview) return finish(edit, false, check.changes, false);
      waiting.current = { edit, changes: check.changes, opens: check.opens };
      setState({ phase: "confirm", changes: check.changes, opens: check.opens, busy: false, error: null });
    },
    [finish],
  );

  /** A batch. `undo` is the inverse batch of an edit that only closes; `alwaysReview` shows the
   * dialog before applying whatever the reach; `link` adds a button to the toast. */
  const runBatch = useCallback(
    (ops: ChangeOp[], done: string, undo?: ChangeOp[], alwaysReview = false, link?: Edit["link"]) =>
      run({
        done,
        alwaysReview,
        link,
        check: async () => {
          const r = await changes.mutateAsync({ ops: confirmAll(ops), dryRun: true });
          return {
            changes: r.changes,
            widens: r.changes_reach,
            opens: r.changes.some((c) => c.opens_to_anyone),
          };
        },
        apply: async (confirmed) => {
          return (await changes.mutateAsync({ ops: confirmed ? confirmAll(ops) : ops, dryRun: false })).refs;
        },
        undo: undo
          ? async () => {
              await changes.mutateAsync({ ops: confirmAll(undo), dryRun: false });
            }
          : undefined,
      }),
    [run, changes],
  );

  /** Replace the members of a group. */
  const runGroupMembers = useCallback(
    (group: PeerGroup, next: string[], done: string) => {
      const before = group.members;
      const added = next.filter((id) => !before.includes(id));
      const groupGrants = grants.filter((g) => g.subject.kind === "group" && g.subject.id === group.id);
      const peerName = (id: string) => peers.find((p) => p.id === id)?.label ?? id.slice(0, 8);
      return run({
        done,
        check: async () => {
          if (added.length === 0 || groupGrants.length === 0) return { changes: [], widens: false, opens: false };
          const what = groupGrants.map(
            (g) => `${targetLabel(g.target, apps, tags)}${g.scope.kind !== "all" ? ` ${scopeLabel(g.scope)}` : ""}`,
          );
          const shown = what.length > 3 ? `${what.slice(0, 3).join(", ")} and ${what.length - 3} more` : what.join(", ");
          return {
            changes: added.map<BatchChange>((id) => ({
              kind: "create",
              item: "group",
              name: `${peerName(id)} in group ${group.label}`,
              detail: `gains access to ${shown}`,
              opens_to_anyone: false,
              reach: [],
            })),
            widens: true,
            opens: false,
          };
        },
        apply: async () => {
          await setMembers.mutateAsync({ id: group.id, peerIds: next });
        },
        undo:
          added.length === 0
            ? async () => {
                await setMembers.mutateAsync({ id: group.id, peerIds: before });
              }
            : undefined,
      });
    },
    [run, grants, peers, apps, tags, setMembers],
  );

  /** The dialog's button: apply, with the Anyone confirmation when the dialog was the Anyone form. */
  const confirm = useCallback(() => {
    const w = waiting.current;
    if (w) void finish(w.edit, w.opens, w.changes, w.opens);
  }, [finish]);

  const cancel = useCallback(() => {
    waiting.current = null;
    setState(IDLE);
  }, []);

  return { state, runBatch, runGroupMembers, confirm, cancel };
}

export type Commit = ReturnType<typeof useCommit>;

/** Revoke from an access list: it only closes, so it applies at once and can be undone. */
export function useRevoke() {
  const commit = useCommit();
  const revoke = (entry: AccessEntry) => {
    void commit.runBatch(
      entry.grants.map<ChangeOp>((g) => ({ op: "remove_grant", grant_id: g.id })),
      entry.grants.length > 1 ? `Revoked ${entry.grants.length} grants` : "Access revoked",
      entry.grants.map(grantInverse),
    );
  };
  return { revoke, commit };
}
