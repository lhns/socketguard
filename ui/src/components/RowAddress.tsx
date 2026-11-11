import { useState } from "react";
import type { AppDetail, Scope } from "../api";
import { useCommit } from "../commit";
import { sameScope } from "../lib";
import { bindsRow } from "../matrix";
import { useNav } from "../nav";
import { useReservations } from "../queries";
import AddToReserved from "./AddToReserved";
import AddressLines, { ReserveForm } from "./AddressLines";
import CommitPreview from "./CommitPreview";
import { useNameCtx } from "./Inspector";

interface Props {
  app: AppDetail;
  scope: Scope;
  /** Grants do not apply (Local on loopback): only the All ports row shows an address. */
  onlyLocal: boolean;
}

/** The "Address" part of a row card: the automatic address per network (with Reserve…) and
 * "Add to reserved address…", or the reserved address the row is reached on. */
export default function RowAddress({ app, scope, onlyLocal }: Props) {
  const names = useNameCtx();
  const nav = useNav();
  const reservations = useReservations().data ?? [];
  const [reserving, setReserving] = useState<string | null>(null);
  const commit = useCommit(() => setReserving(null));

  const bound = reservations.find((r) => bindsRow(r.bindings, names.tags, app.id, scope));
  if (onlyLocal && scope.kind !== "all") return null;

  let body;
  if (bound) {
    body = (
      <>
        <p>
          Reached on reserved address{" "}
          <button className="link-btn" aria-label={`Go to reservation ${bound.label}`} onClick={() => nav.go("reserved", { reservationId: bound.id })}>
            {bound.label}
          </button>
        </p>
        <AddressLines addresses={bound.addresses} networks={names.networks} empty="Gets an address when access is added." />
      </>
    );
  } else {
    const own = app.addresses.filter((a) => !a.reservation_id && sameScope(a.scope, scope));
    const target = own.find((a) => a.id === reserving);
    body = (
      <>
        <AddressLines
          addresses={own}
          networks={names.networks}
          empty="Gets an address when access is added."
          onReserve={onlyLocal ? undefined : (a) => setReserving(a.id)}
        />
        {target && (
          <ReserveForm
            busy={commit.state.phase === "checking" || commit.state.phase === "applying"}
            onSubmit={(label) => void commit.runBatch([{ op: "reserve_address", address_id: target.id, label }], `Reserved as ${label}`)}
            onCancel={() => setReserving(null)}
          />
        )}
        <CommitPreview commit={commit} title="This lets more in" />
        {!onlyLocal && <AddToReserved target={{ kind: "app", app_id: app.id, scope }} />}
      </>
    );
  }
  return (
    <div className="port-address">
      <h4 className="part-label">Address</h4>
      {body}
    </div>
  );
}
