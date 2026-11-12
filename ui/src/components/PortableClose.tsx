import { useEffect, useRef, useState } from "react";
import { api, onCloseRequested, toDaemonError } from "../api";

type Phase =
  | { kind: "idle" }
  | { kind: "removing" }
  | { kind: "left"; left: string[] }
  | { kind: "timeout" };

type Subscribe = typeof onCloseRequested;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Wait until the daemon no longer answers; false when it still does after `limitMs`. */
async function daemonGone(pollMs: number, limitMs: number): Promise<boolean> {
  const until = Date.now() + limitMs;
  for (;;) {
    try {
      await api.status();
    } catch (e) {
      if (toDaemonError(e).code === "connection") return true;
    }
    if (Date.now() >= until) return false;
    await sleep(pollMs);
  }
}

/**
 * Portable mode (ADR 0054): closing the window stops the daemon, which removes its rules and
 * addresses. The window waits for that and reports what could not be removed, instead of
 * quitting at once. Renders nothing until the user closes the window.
 */
export default function PortableClose({
  subscribe = onCloseRequested,
  pollMs = 400,
  limitMs = 15_000,
}: {
  subscribe?: Subscribe;
  pollMs?: number;
  limitMs?: number;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const closing = useRef(false);
  const opts = useRef({ pollMs, limitMs });
  opts.current = { pollMs, limitMs };

  useEffect(() => {
    let off: (() => void) | undefined;
    let gone = false;
    void subscribe(async (e) => {
      e.preventDefault();
      if (closing.current) return;
      closing.current = true;
      const started = Date.now();
      setPhase({ kind: "removing" });
      try {
        await api.shutdown();
      } catch {
        // Already unreachable: nothing to stop.
      }
      if (!(await daemonGone(opts.current.pollMs, opts.current.limitMs))) {
        setPhase({ kind: "timeout" });
        return;
      }
      try {
        const exit = await api.portableLastExit();
        // A record from an earlier run does not count; allow for clock and rounding slack.
        if (exit && exit.at >= started / 1000 - 5 && exit.left.length > 0) {
          setPhase({ kind: "left", left: exit.left });
          return;
        }
      } catch {
        // No record: nothing known to be left.
      }
      void api.quitApp();
    }).then((u) => {
      if (gone) u();
      else off = u;
    });
    return () => {
      gone = true;
      off?.();
    };
  }, [subscribe]);

  if (phase.kind === "idle") return null;
  return (
    <div className="modal-overlay">
      {phase.kind === "removing" ? (
        <div className="modal" role="status">
          <p>Removing rules…</p>
        </div>
      ) : (
        <div className="modal" role="alertdialog" aria-modal="true" aria-label="SocketGuard could not finish">
          {phase.kind === "left" ? (
            <>
              <p>Some things could not be removed:</p>
              <ul className="risk-list">
                {phase.left.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </>
          ) : (
            <p>SocketGuard did not stop in time. Its rules are removed when the process ends.</p>
          )}
          <div className="modal-actions">
            <button type="button" className="btn btn-danger" onClick={() => void api.quitApp()}>Close anyway</button>
          </div>
        </div>
      )}
    </div>
  );
}
