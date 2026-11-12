# ADR 0046: Unidentified Sockets Become Apps; System Components Are Flagged

## Status

Accepted. Amends ADR 0027 (the amendment on unattributable sockets).

## Date

2026-11-10

## Context

ADR 0027 dropped listening sockets whose owner could not be identified: merging them into one "unknown" app would have let each inherit the others' grants. The cost showed in the first live session: a listener the daemon could not attribute (a protected Windows process, a socket no readable process holds) was invisible, so it was neither addressed nor ruled on. An unmanaged listener is a silent gap. Separately, a host has dozens of OS services in the list next to the user's own programs.

## Decision

- **Unidentified sockets are apps.** A socket whose process cannot be identified (Windows: the process cannot be resolved; Linux: no process holds it, or processes of different programs or users hold it) becomes an app with the identity `unknown:<proto>/<port>`, name `unknown:tcp/8080` and `identity_note` `unidentified`. The port is the identity, so every such socket is its own app and grants never carry over from one to another, which was the point of ADR 0027's rule. It survives restarts. PID 0 stays excluded (it is not a process).
- **`App.system`.** A flag for OS components, set by the monitor from what it already reads:
  - Windows: the executable lies under `%SystemRoot%`, or the process is `System`, `svchost.exe` or `services.exe`.
  - Linux: an owner below uid 1000 whose process runs in a systemd service unit (read from `/proc/<pid>/cgroup`) or from `/usr/sbin`, `/usr/lib`, `/lib` or `/sbin`.
  - macOS: the executable lies under `/System` or `/usr/libexec`.

  The flag is stored (schema v6) and only groups apps for display; it changes no rule.

## Consequences

- Nothing that listens is invisible. A new unidentified listener appears as a pending app, closed until granted, like any other.
- The identity is coarse: two different unknown programs on the same port are one app until they can be told apart.
- The `system` flag is a heuristic that can be wrong either way; frontends show system apps as a collapsible group rather than hiding them.
