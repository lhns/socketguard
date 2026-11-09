//! OpenTelemetry plumbing. `tracing` stays the instrumentation API; this module adds
//! trace, log and metric export over OTLP/HTTP (protobuf).
//!
//! Export is opt-in through the standard environment: a signal is exported only when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` or its signal-specific variant
//! (`OTEL_EXPORTER_OTLP_{TRACES,LOGS,METRICS}_ENDPOINT`) is set. `OTEL_SDK_DISABLED=true`
//! turns everything off. `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` are honoured.
//! With nothing set no exporter (and no background thread) is created.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::{
    logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider, Resource,
};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

const DEFAULT_SERVICE_NAME: &str = "socketguard-daemon";

/// Which signals have an OTLP endpoint configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signals {
    pub traces: bool,
    pub logs: bool,
    pub metrics: bool,
}

impl Signals {
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let set = |k: &str| get(k).is_some_and(|v| !v.trim().is_empty());
        if get("OTEL_SDK_DISABLED").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            return Self {
                traces: false,
                logs: false,
                metrics: false,
            };
        }
        let general = set("OTEL_EXPORTER_OTLP_ENDPOINT");
        Self {
            traces: general || set("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            logs: general || set("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
            metrics: general || set("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"),
        }
    }
}

/// Owns the SDK providers; call [`Telemetry::shutdown`] before exit to flush.
#[derive(Default)]
pub struct Telemetry {
    tracer: Option<SdkTracerProvider>,
    logger: Option<SdkLoggerProvider>,
    meter: Option<SdkMeterProvider>,
}

fn resource() -> Resource {
    // The builder's default detectors read OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES;
    // the explicit name is only a fallback.
    Resource::builder()
        .with_service_name(DEFAULT_SERVICE_NAME)
        .build()
}

impl Telemetry {
    /// Build exporters for the configured signals. A failure to build an exporter is
    /// reported on stderr and that signal is skipped; it never stops the daemon.
    pub fn build(signals: Signals) -> Self {
        let mut t = Self::default();
        if signals.traces {
            match SpanExporter::builder().with_http().build() {
                Ok(exp) => {
                    t.tracer = Some(
                        SdkTracerProvider::builder()
                            .with_resource(resource())
                            .with_batch_exporter(exp)
                            .build(),
                    )
                }
                Err(e) => eprintln!("[socketguard] OTLP trace exporter disabled: {e}"),
            }
        }
        if signals.logs {
            match LogExporter::builder().with_http().build() {
                Ok(exp) => {
                    t.logger = Some(
                        SdkLoggerProvider::builder()
                            .with_resource(resource())
                            .with_batch_exporter(exp)
                            .build(),
                    )
                }
                Err(e) => eprintln!("[socketguard] OTLP log exporter disabled: {e}"),
            }
        }
        if signals.metrics {
            match MetricExporter::builder().with_http().build() {
                Ok(exp) => {
                    let provider = SdkMeterProvider::builder()
                        .with_resource(resource())
                        .with_periodic_exporter(exp)
                        .build();
                    opentelemetry::global::set_meter_provider(provider.clone());
                    t.meter = Some(provider);
                }
                Err(e) => eprintln!("[socketguard] OTLP metric exporter disabled: {e}"),
            }
        }
        t
    }

    /// Install the global `tracing` subscriber: console output plus whichever OTel
    /// layers are active. `filter` applies to everything.
    pub fn install(&self, filter: EnvFilter) {
        let trace_layer = self
            .tracer
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("socketguard")));
        // Keep the exporters' own HTTP stack out of the log pipeline, otherwise
        // exporting a log produces another log.
        let log_layer = self.logger.as_ref().map(|p| {
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(p).with_filter(
                Targets::new()
                    .with_default(LevelFilter::TRACE)
                    .with_target("hyper", LevelFilter::OFF)
                    .with_target("hyper_util", LevelFilter::OFF)
                    .with_target("reqwest", LevelFilter::OFF)
                    .with_target("h2", LevelFilter::OFF)
                    .with_target("opentelemetry", LevelFilter::OFF),
            )
        });
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(trace_layer)
            .with(log_layer)
            .init();
    }

    /// Flush and stop all providers. Blocks briefly; call once at shutdown.
    pub fn shutdown(self) {
        if let Some(p) = self.tracer {
            if let Err(e) = p.shutdown() {
                eprintln!("[socketguard] OTel trace shutdown: {e}");
            }
        }
        if let Some(p) = self.logger {
            if let Err(e) = p.shutdown() {
                eprintln!("[socketguard] OTel log shutdown: {e}");
            }
        }
        if let Some(p) = self.meter {
            if let Err(e) = p.shutdown() {
                eprintln!("[socketguard] OTel metric shutdown: {e}");
            }
        }
    }
}

/// Initialise logging and (if configured) OpenTelemetry export.
pub fn init(filter: EnvFilter) -> Telemetry {
    let telemetry = Telemetry::build(Signals::from_env());
    telemetry.install(filter);
    telemetry
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use std::collections::HashMap;

    fn signals(vars: &[(&str, &str)]) -> Signals {
        let m: HashMap<_, _> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Signals::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn nothing_set_means_nothing_exported() {
        assert_eq!(
            signals(&[]),
            Signals {
                traces: false,
                logs: false,
                metrics: false
            }
        );
    }

    #[test]
    fn general_and_specific_endpoints() {
        assert_eq!(
            signals(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://x:4318")]),
            Signals {
                traces: true,
                logs: true,
                metrics: true
            }
        );
        assert_eq!(
            signals(&[(
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "http://x:4318/v1/traces"
            )]),
            Signals {
                traces: true,
                logs: false,
                metrics: false
            }
        );
        assert!(
            !signals(&[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://x:4318"),
                ("OTEL_SDK_DISABLED", "true")
            ])
            .traces
        );
    }

    #[test]
    fn tracing_span_reaches_exporter() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("reconcile", cycle = 1);
            let _guard = span.enter();
        });
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name, "reconcile");
    }

    #[tokio::test]
    async fn exporters_build_and_shut_down_inside_runtime() {
        // Unreachable endpoint: only checks that building and shutting down the real
        // HTTP exporters inside a tokio runtime neither panics nor hangs.
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9");
        let t = Telemetry::build(Signals {
            traces: true,
            logs: true,
            metrics: true,
        });
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        assert!(t.tracer.is_some() && t.logger.is_some() && t.meter.is_some());
        tokio::task::spawn_blocking(move || t.shutdown())
            .await
            .unwrap();
    }
}
