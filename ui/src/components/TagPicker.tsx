import { useState } from "react";
import type { ChangeOp, Scope } from "../api";
import { useCommit } from "../commit";
import { ALL_SCOPE, sameScope, scopeLabel } from "../lib";
import { useNav } from "../nav";
import { usePortGroups, useTags } from "../queries";
import CommitPreview from "./CommitPreview";
import Picker, { type PickerItem } from "./Picker";

interface Props {
  /** The apps to tag: one, or several (a tag some of them have shows as mixed). */
  appIds: string[];
  /** Tag one row of the app (a port or a port group) instead of All ports. */
  scope?: Scope;
}

/** The tags of the selected apps. The first one shown is a tag the app has; the rest are a
 * search away, and a typed name that does not exist can be created and applied in one step. */
export default function TagPicker({ appIds, scope: rowScope }: Props) {
  const nav = useNav();
  const tags = (useTags().data ?? []);
  const portGroups = usePortGroups().data ?? [];
  const [open, setOpen] = useState(false);
  const commit = useCommit();
  const scope = rowScope ?? ALL_SCOPE;
  const named = rowScope !== undefined;
  const what = named ? scopeLabel(scope, portGroups) : "";

  const has = (tagId: string, appId: string) =>
    tags.find((t) => t.id === tagId)?.members.some((m) => m.app_id === appId && sameScope(m.scope, scope)) ?? false;
  const count = (tagId: string) => appIds.filter((a) => has(tagId, a)).length;

  const items: PickerItem[] = tags.map((t) => {
    const n = count(t.id);
    return {
      id: t.id,
      label: t.label,
      hint: t.patterns.length > 0 ? "auto-match" : undefined,
      state: n === 0 ? "off" : n === appIds.length ? "on" : "mixed",
    };
  });

  const toggle = (item: PickerItem) => {
    const suffix = named && scope.kind !== "all" ? ` ${what}` : "";
    if (item.state === "on") {
      const ops: ChangeOp[] = appIds.map((app_id) => ({ op: "remove_tag_member", tag_id: item.id, app_id, scope, confirm_open: false }));
      const undo: ChangeOp[] = appIds.map((app_id) => ({ op: "add_tag_member", tag_id: item.id, app_id, scope, confirm_open: false }));
      void commit.runBatch(ops, `Removed from ${item.label}${suffix}`, undo);
    } else {
      const ops: ChangeOp[] = appIds
        .filter((a) => !has(item.id, a))
        .map((app_id) => ({ op: "add_tag_member", tag_id: item.id, app_id, scope, confirm_open: false }));
      void commit.runBatch(ops, `Added to ${item.label}${suffix}`);
    }
    // A review is shown below the control, so the list gets out of its way.
    setOpen(false);
  };

  const create = (typed: string) => ({
    label: <>Create &ldquo;{typed}&rdquo;</>,
    pick: () => {
      const ops: ChangeOp[] = [
        { op: "create_tag", ref: "$tag", label: typed, patterns: [] },
        ...appIds.map<ChangeOp>((app_id) => ({ op: "add_tag_member", tag_id: "$tag", app_id, scope, confirm_open: false })),
      ];
      void commit.runBatch(ops, `Created tag ${typed}`);
      setOpen(false);
    },
  });

  const mine = tags.filter((t) => count(t.id) > 0);
  return (
    <div className="tag-picker">
      <div className="tag-row">
        {mine.map((t) => (
            <button
              key={t.id}
              className={`tag-pill${count(t.id) < appIds.length ? " tag-pill-partial" : ""}`}
              title={count(t.id) < appIds.length ? `${count(t.id)} of ${appIds.length} have it. Show the tag.` : "Show the tag"}
              onClick={() => nav.go("apps", { tagId: t.id })}
            >
              {t.label}{count(t.id) < appIds.length ? ` ${count(t.id)}/${appIds.length}` : ""}
            </button>
        ))}
        {!named && mine.length === 0 && <span className="muted">no tags</span>}
        <Picker
          label={named ? `Tags of ${what}` : "Tags"}
          trigger="+"
          triggerClass="tag-pill tag-pill-add"
          compactLabel={named ? `Add or remove tags of ${what}` : "Add or remove tags"}
          items={items}
          onToggle={toggle}
          create={(typed) => create(typed)}
          open={open}
          onOpenChange={setOpen}
          placeholder="Find or create a tag"
          empty="No tags yet. Type a name to create one."
        />
      </div>
      <CommitPreview commit={commit} title="Change tags?" confirmLabel="Apply" />
    </div>
  );
}
