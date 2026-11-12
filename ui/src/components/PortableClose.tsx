import { useEffect, useRef, useState } from "react";
import { api, onCloseRequested, toDaemonError } from "../api";

type Phase =
  | { kind: "idle" }
  | { kind: "removing" }
  | { kind: "left"; left: string[] }
  | { kind: "timeout" };

type Subscribe = typeof onCloseRequested;

type Outcome = { kind: "record"; left: string[] } | { kind: "none" } | { kind: "timeout" };

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Wait for the daemon's verdict. The daemon answers the shutdown request, stops serving, and only
 * then tears down and writes `last-exit.log`, so the pipe going away does not mean it is done:
 * wait for a record newer than the close. A daemon that is gone and leaves no record within
 * `goneGraceMs` is taken as nothing known to be left.
 */
async function verdict(started: number, pollMs: number, limitMs: number, goneGraceMs: number): Promise<Outcome> {
  const until = Date.now() + limitMs;
  let goneSince: number | null = null;
  for (;;) {
    try {
      const exit = await api.portableLastExit();
      // A record from an earlier run does not count; allow for clock and rounding slack.
      if (exit && exit.at >= started / 1000 - 5) return { kind: "record", left: exit.left };
    } catch {
      // Unreadable: treated as no record yet.
    }
    let answering = true;
    try {
      await api.status();
    } catch (e) {
      answering = toDaemonError(e).code !== "connection";
    }
    if (answering) goneSince = null;
    else if (goneSince === null) goneSince = Date.now();
    else if (Date.now() - goneSince >= goneGraceMs) return { kind: "none" };
    if (Date.now() >= until) return { kind: "timeout" };
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
  goneGraceMs = 2_500,
}: {
  subscribe?: Subscribe;
  pollMs?: number;
  limitMs?: number;
  goneGraceMs?: number;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const closing = useRef(false);
  const opts = useRef({ pollMs, limitMs, goneGraceMs });
  opts.current = { pollMs, limitMs, goneGraceMs };

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
      const o = opts.current;
      const result = await verdict(started, o.pollMs, o.limitMs, o.goneGraceMs);
      if (result.kind === "timeout") {
        setPhase({ kind: "timeout" });
        return;
      }
      if (result.kind === "record" && result.left.length > 0) {
        setPhase({ kind: "left", left: result.left });
        return;
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
