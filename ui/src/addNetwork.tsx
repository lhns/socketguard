// Adding a network lets the grants that already exist take effect on it (ADR 0066). So the add is
// reviewed first, as every edit that gives access is (see commit.ts): ask the daemon what would
// take effect; if nothing does, add at once; otherwise ONE confirmation dialog lists it, in its
// warning form when a grant to Anyone is among it.
import { useState, type ReactNode } from "react";
import { api, toDaemonError, type Network, type NetworkAddPreview, type NewNetwork } from "./api";
import { ChangeList } from "./batch";
import ConfirmDialog from "./components/ConfirmDialog";
import { errorText } from "./lib";
import { useAddNetwork, useNetworks } from "./queries";

type Review =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "confirm"; req: NewNetwork; preview: NetworkAddPreview; busy: boolean; error: string | null };

/** What the person calls the network that is about to be added. */
function labelOf(req: NewNetwork): string {
  if (req.id) return req.id;
  if (req.type === "tor") return "Tor";
  if (req.type === "yggdrasil") return "Yggdrasil";
  return req.interface;
}

/** `submit(req)` adds a network after the review; `dialog` goes into the page's JSX. `onAdded`
 * and `onError` are the page's own reactions (a toast, a message under the form). */
export function useAddNetworkReviewed(onAdded: (n: Network) => void, onError: (message: string) => void) {
  const add = useAddNetwork();
  const networks = useNetworks().data ?? [];
  const [review, setReview] = useState<Review>({ phase: "idle" });

  const submit = async (req: NewNetwork): Promise<void> => {
    setReview({ phase: "checking" });
    let preview: NetworkAddPreview;
    try {
      preview = await api.previewAddNetwork(req);
    } catch (e) {
      setReview({ phase: "idle" });
      onError(errorText(e));
      return;
    }
    if (preview.gains.length === 0) return run(req, false, null);
    setReview({ phase: "confirm", req, preview, busy: false, error: null });
  };

  /** The add itself; `shown` is the open dialog, whose error line takes a failure. */
  const run = async (req: NewNetwork, confirmOpen: boolean, shown: Review | null): Promise<void> => {
    try {
      const network = await add.mutateAsync(confirmOpen ? { ...req, confirm_open: true } : req);
      setReview({ phase: "idle" });
      onAdded(network);
    } catch (e) {
      if (!confirmOpen && toDaemonError(e).code === "confirmation_required") {
        // The grants changed since the preview: look again.
        return submit(req);
      }
      if (shown?.phase === "confirm") setReview({ ...shown, busy: false, error: errorText(e) });
      else {
        setReview({ phase: "idle" });
        onError(errorText(e));
      }
    }
  };

  let dialog: ReactNode = null;
  if (review.phase === "confirm") {
    const { req, preview, busy, error } = review;
    const label = labelOf(req);
    // The new network is not in the list yet: name it for the reach badges.
    const id = preview.gains[0]?.reach?.[0]?.network_id ?? label;
    const named: Network[] = [...networks, { id, kind: "lan", name: label, interface: null, grants_apply: true, status: { state: "up" } }];
    const list = <ChangeList changes={preview.gains} networks={named} />;
    const common = {
      busy,
      error,
      onCancel: () => setReview({ phase: "idle" }),
      onConfirm: () => {
        const shown: Review = { ...review, busy: true, error: null };
        setReview(shown);
        void run(req, preview.confirm_open_required, shown);
      },
    };
    if (!preview.confirm_open_required) {
      dialog = (
        <ConfirmDialog title={`Add ${label}?`} confirmLabel="Add network" danger={false} {...common}>
          <p>Access you already gave takes effect on {label} as soon as it is added:</p>
          {list}
        </ConfirmDialog>
      );
    } else {
      const things = [...new Set(preview.gains.filter((c) => c.opens_to_anyone).map((c) => c.name.replace(/^Anyone to /, "")))];
      const what = things.length === 1 ? things[0] : `${things.length} things`;
      dialog = (
        <ConfirmDialog
          title={`Open ${what} to anyone on ${label}?`}
          confirmLabel="Add and open to anyone"
          warning={
            <>
              <strong>Adding {label} opens {what} to anyone on it.</strong>{" "}
              Grants to Anyone take effect on every network that takes grants, so any source that can reach this machine on {label} will be able to connect. This is not limited to your peers.
            </>
          }
          {...common}
        >
          {list}
        </ConfirmDialog>
      );
    }
  }

  return { submit: (req: NewNetwork) => void submit(req), pending: add.isPending || review.phase !== "idle", dialog };
}
