import { useState } from "react";
import type { BindingTarget } from "../api";
import { useCommit } from "../commit";
import { useNav } from "../nav";
import { useList, useReservations } from "../queries";
import { useFormOpen } from "./ActionRow";
import CommitPreview from "./CommitPreview";
import Picker, { type PickerItem } from "./Picker";

/** "Add to reserved address…" for a row of an app or a tag: pick a reservation (or create one
 * named after the typed text) and bind the target to it, as one batch under the commit rule. */
export default function AddToReserved({ target }: { target: BindingTarget }) {
  const nav = useNav();
  const reservations = useList(useReservations());
  const commit = useCommit();
  const [open, setOpen] = useState(false);
  const stepAside = useFormOpen(false);

  const items: PickerItem[] = reservations.map((r) => ({
    id: r.id,
    label: r.label,
    hint: `${r.bindings.length} ${r.bindings.length === 1 ? "binding" : "bindings"}`,
    state: "off",
  }));
  const show = (reservationId: string) => ({ label: "Show reserved address", onClick: () => nav.go("reserved", { reservationId }) });

  if (stepAside) return null;
  return (
    <div className="add-reserved">
      <Picker
        label="Reserved addresses"
        trigger="Add to reserved address…"
        triggerClass="btn btn-sm"
        items={items}
        onToggle={(it) => {
          setOpen(false);
          void commit.runBatch(
            [{ op: "add_binding", reservation_id: it.id, target, confirm_open: false }],
            `Added to ${it.label}`,
            undefined,
            false,
            () => show(it.id),
          );
        }}
        create={(typed) => ({
          label: <>Create &ldquo;{typed}&rdquo;</>,
          pick: () => {
            setOpen(false);
            void commit.runBatch(
              [{ op: "create_reservation", ref: "$res", label: typed, bindings: [target], confirm_open: false }],
              `Added to ${typed}`,
              undefined,
              false,
              (refs) => show(refs["$res"] ?? ""),
            );
          },
        })}
        open={open}
        onOpenChange={setOpen}
        placeholder="Find or create a reserved address"
        empty="No reserved addresses yet. Type a name to create one."
      />
      <CommitPreview commit={commit} title="Add to reserved address?" confirmLabel="Add to reserved address" />
    </div>
  );
}
