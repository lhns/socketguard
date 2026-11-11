import { useState } from "react";
import type { Address, Network } from "../api";
import { rangeLabel } from "../lib";
import { useToast } from "./Toast";

export const locatorText = (a: Address) => (a.locator.kind === "ipv6" ? a.locator.addr : a.locator.hostname);

/** The locator in monospace with a Copy button. */
export function Locator({ address }: { address: Address }) {
  const toast = useToast();
  const text = locatorText(address);
  return (
    <>
      <span className="mono address-locator">{text}</span>
      <button
        type="button"
        className="btn btn-sm"
        aria-label={`Copy ${text}`}
        onClick={() => {
          void navigator.clipboard?.writeText(text).then(() => toast.success("Copied"), () => toast.error("Could not copy"));
        }}
      >
        Copy
      </button>
    </>
  );
}

interface Props {
  addresses: Address[];
  networks: Network[];
  /** Shown when there is no address. */
  empty?: string;
  /** With it every automatic address has a "Reserve…" action. */
  onReserve?: (address: Address) => void;
}

/** One line per address: network · locator (Copy) · up or closed; ports it leaves out and Tor
 * notes underneath. */
export default function AddressLines({ addresses, networks, empty, onReserve }: Props) {
  if (addresses.length === 0) return empty ? <p className="muted address-empty">{empty}</p> : null;
  return (
    <ul className="plain-list address-list">
      {addresses.map((a) => {
        const net = networks.find((n) => n.id === a.network_id);
        return (
          <li key={a.id} className="address-item">
            <div className="address-row">
              <span className="address-name">{net?.name ?? a.network_id}</span>
              <span className="muted" aria-hidden="true">·</span>
              <Locator address={a} />
              <span className={`badge reach ${a.up ? "reach-ok" : "reach-muted"}`}>{a.up ? "up" : "closed"}</span>
              {onReserve && !a.reservation_id && (
                <button type="button" className="btn btn-sm address-reserve" aria-label={`Reserve ${net?.name ?? ""} address`} onClick={() => onReserve(a)}>
                  Reserve…
                </button>
              )}
            </div>
            {a.excluded.length > 0 && (
              <p className="muted address-note">
                Not served here: {a.excluded.map(rangeLabel).join(", ")} (another app is listening on {a.excluded.length === 1 ? "it" : "them"})
              </p>
            )}
            {a.notes.map((n) => (
              <p key={n} className="muted address-note">{n}</p>
            ))}
          </li>
        );
      })}
    </ul>
  );
}

/** Asks for a name, inline, to reserve one automatic address. */
export function ReserveForm({ busy, onSubmit, onCancel }: { busy: boolean; onSubmit: (label: string) => void; onCancel: () => void }) {
  const [label, setLabel] = useState("");
  return (
    <form
      className="inline-form"
      aria-label="Reserve address"
      onSubmit={(e) => {
        e.preventDefault();
        if (label.trim()) onSubmit(label.trim());
      }}
    >
      <input className="input" aria-label="Name of the reserved address" placeholder="Name, e.g. public-web" value={label} onChange={(e) => setLabel(e.target.value)} autoFocus />
      <button type="submit" className="btn btn-primary btn-sm" disabled={!label.trim() || busy}>Reserve</button>
      <button type="button" className="btn btn-sm" onClick={onCancel}>Cancel</button>
    </form>
  );
}
