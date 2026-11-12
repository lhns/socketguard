# Local OpenTelemetry sandbox (optional)

1. `docker compose up` in this directory.
2. Run the daemon with `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` (OTLP/HTTP).
   Optional: `OTEL_SERVICE_NAME`, `OTEL_SDK_DISABLED=true`. Without an endpoint nothing is exported.
3. Traces: http://localhost:16686 (Jaeger). Metrics: http://localhost:9090 (Prometheus).
4. Logs are printed by the collector (`docker compose logs otel-collector`).
