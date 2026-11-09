# ADR 0034: Observability with OpenTelemetry and a Local Activity Store

## Status

Accepted

## Date

2026-11-09

## Context

Users need to see what SocketGuard blocked and discovered ("who tried to reach this?") without running monitoring infrastructure. Operators who already run a collector want standard telemetry. The daemon already instruments with `tracing`.

## Decision

- **One event pipeline, two consumers:** an optional external collector, and the local Activity view in the CLI and UI. The local view never needs a collector.
- **`tracing` stays the instrumentation API**, with layers added: `tracing-opentelemetry` (traces), `opentelemetry-appender-tracing` (logs), and the `opentelemetry` metrics SDK.
- **Export is OTLP**, configured through the standard `OTEL_EXPORTER_OTLP_*` and `OTEL_SERVICE_NAME` variables plus a config block. Nothing set means nothing exported.
- **Traces:** reconcile cycles, ruleset render and apply, backend allocation, Yggdrasil node queries, and API requests via `tower-http` `TraceLayer`. The client crate propagates W3C trace context, so a CLI or UI action is one trace across client and daemon.
- **Metrics:** gauges for apps, addresses, peers and grants; reconcile duration and errors; firewall apply duration; allowed and blocked packets per app, network and grant; blocked attempts per scope.
- **Bounded cardinality:** labels use app, network and peer labels only. Unknown source IPs never become labels.
- **Activity store:** domain events (app discovered, grant and peer changes, protect-host toggled, blocked attempts) go to a bounded `activity` table, pruned by age and row count, and are emitted as OTel log records. Blocked attempts carry source, app or port and the matched peer if any, aggregated per (source, app) per minute. Served by `GET /api/activity` (filterable, paged) and an `activity` SSE event.
- **Data sources per platform:** nftables named counters and rate-limited NFLOG on scope drops; on Windows, WFP net-event subscription and filter counters where available; pf counters only.

## Consequences

- Blocked attempts are visible locally on Linux and Windows; on macOS only as counts until pflog capture is added (ADR 0036).
- Source IPs live in the activity table, not in metric labels, so metric storage stays bounded.
- Telemetry adds dependencies and a startup config path, but is inert unless configured.
