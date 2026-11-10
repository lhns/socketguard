# ADR 0035: Test Strategy and CI

## Status

Accepted. Extends ADR 0025.

## Date

2026-11-09

## Context

ADR 0025 made the engine testable with mocks, but there were no API tests, no firewall enforcement tests, no frontend tests, no lint and no CI. The in-memory SQLite test pool could give each connection its own empty database. The redesign's main promise, "closed unless granted", can only be trusted if it is tested against a real packet filter.

## Decision

Each layer is tested where it is cheapest to test:

- **Pure renderers and producers:** `DesiredRuleset` production and each firewall renderer get golden tests with `insta`. The activity aggregation is a pure function with unit tests.
- **Engine:** ADR 0025's mock infrastructure, with scenarios rewritten for the new model. The in-memory DB pool is fixed to share one database.
- **API:** a harness drives the axum `Router` with `oneshot`; every route is tested, including authorization refusals. A coverage test checks every route has a client method and a CLI command (ADR 0033).
- **Enforcement:** netns tests run real nftables, gated on `SOCKETGUARD_NETNS_TESTS=1`. They check that a wildcard bind is unreachable via global, link-local and `200:` addresses, a granted peer gets through, a forged `200:` source from the LAN is dropped, stopping the daemon keeps the host closed, and a blocked probe produces an activity record.
- **Telemetry:** engine and API tests assert spans and metrics through the OTel SDK's in-memory exporters.
- **CLI:** `insta` snapshots of output, and `assert_cmd` end-to-end against an in-process daemon with mocks.
- **UI:** ESLint, `tsc --noEmit`, Vitest with React Testing Library and Tauri `mockIPC`.
- **CI:** Forgejo Actions (`.forgejo/workflows/`) runs fmt, `clippy -D warnings`, `cargo test`, and, in the `ui` job, lint, typecheck and Vitest. Netns tests run in a separate `netns` job: a probe step tries `ip netns add` and `nft list tables`, and the tests run only if the runner is privileged enough; otherwise the job skips them with a warning (`::warning::`) and stays green. CI must be green for every merge.
- WFP and pf enforcement are verified by live tests on real hosts, not in CI.

## Consequences

- The security promise is tested against a real kernel firewall on Linux.
- CI depends on a privileged runner for the netns job.
- Windows and macOS enforcement regressions are caught only by manual live tests.
