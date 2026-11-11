import { useState } from "react";
import type { SetupRun } from "../api";
import { errorText } from "../lib";

/** What an elevated run came to, in words; null when it worked. */
export function elevatedFailure(r: SetupRun): string | null {
  if (r.cancelled) return "Cancelled: nothing was changed.";
  if (!r.launched) {
    return "This system has no way to ask for administrator rights from here. Run this in a terminal with administrator rights:";
  }
  if (r.exit_code !== 0) return `The command stopped (exit code ${r.exit_code ?? "unknown"}). Run it in a terminal with administrator rights to see why.`;
  return null;
}

/**
 * A button that runs one command with administrator rights, with the exact command shown
 * first. `run` starts it; `onDone` is called when it finished with exit code 0.
 */
export default function ElevatedAction({
  label,
  command,
  run,
  onDone,
  disabled,
}: {
  label: string;
  command: string;
  run: () => Promise<SetupRun>;
  onDone: () => void;
  disabled?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [byHand, setByHand] = useState<string | null>(null);

  const go = async () => {
    setBusy(true);
    setMessage(null);
    setByHand(null);
    try {
      const r = await run();
      const failure = elevatedFailure(r);
      if (failure === null) {
        onDone();
      } else {
        setMessage(failure);
        if (!r.launched) setByHand(r.command);
      }
    } catch (e) {
      setMessage(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="elevated-action">
      <p className="hint">
        This runs with administrator rights, after the system asks you: <code>{command}</code>
      </p>
      <div className="actions">
        <button className="btn btn-primary btn-sm" onClick={() => void go()} disabled={busy || disabled}>
          {busy ? "Working…" : label}
        </button>
      </div>
      {message && <p role="status">{message}</p>}
      {byHand && <pre className="mono">{byHand}</pre>}
    </div>
  );
}
