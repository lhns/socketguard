import { useId, useState } from "react";
import type { PortRange } from "../api";
import { parseRange, rangeLabel } from "../lib";

interface Props {
  ranges: PortRange[];
  /** A valid range was typed. */
  onAdd: (range: PortRange) => void;
  onRemove: (range: PortRange) => void;
  /** An edit is being checked or reviewed. */
  disabled?: boolean;
}

/** Ports and ranges as removable chips with one input: `80/tcp`, `53/udp`, `50000-51000/tcp`.
 * What is typed is checked here; the daemon has the last word on the edit. */
export default function PortRanges({ ranges, onAdd, onRemove, disabled }: Props) {
  const id = useId();
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const add = () => {
    if (text.trim() === "") return;
    const r = parseRange(text);
    if (typeof r === "string") {
      setError(r);
      return;
    }
    setError(null);
    setText("");
    onAdd(r);
  };

  return (
    <div className="port-ranges">
      {ranges.length === 0 ? (
        <p className="muted">No ports yet.</p>
      ) : (
        <ul className="chip-row" aria-label="Ports of the group">
          {ranges.map((r) => (
            <li key={rangeLabel(r)} className="subject-chip">
              <span className="mono">{rangeLabel(r)}</span>
              <button type="button" className="btn-icon" aria-label={`Remove ${rangeLabel(r)}`} title={`Remove ${rangeLabel(r)}`} disabled={disabled} onClick={() => onRemove(r)}>
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="range-add">
        <label htmlFor={id} className="sr-only">Add a port or range</label>
        <input
          id={id}
          className="input mono"
          placeholder="80/tcp, 53/udp or 50000-51000/tcp"
          value={text}
          disabled={disabled}
          aria-invalid={error !== null}
          onChange={(e) => {
            setText(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <button type="button" className="btn btn-sm" disabled={disabled || text.trim() === ""} onClick={add}>Add</button>
      </div>
      {error && <span className="field-error" role="alert">{error}</span>}
    </div>
  );
}
