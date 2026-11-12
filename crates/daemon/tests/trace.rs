//! Trace propagation: an incoming W3C `traceparent` becomes the parent of the request span
//! (ADR 0034). Its own test binary, because it installs a thread-local `tracing` subscriber
//! and the callsite caches of other tests running in parallel would hide the spans.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use tower::ServiceExt;

#[tokio::test]
async fn requests_continue_the_callers_trace() {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_subscriber::layer::SubscriberExt;

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
    // The test runs on one thread, so a thread-local default sees the request's spans.
    let _guard = tracing::subscriber::set_default(subscriber);

    let d = Daemon::new().await;
    let req = Request::builder()
        .uri("/api/status")
        .header(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )
        .body(Body::empty())
        .unwrap();
    let resp = d.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The span ends with the response body.
    drop(resp);
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|s| s.name == "GET /api/status")
        .unwrap_or_else(|| {
            panic!(
                "request span in {:?}",
                spans.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        span.span_context.trace_id().to_string(),
        "0af7651916cd43dd8448eb211c80319c"
    );
    assert_eq!(span.parent_span_id.to_string(), "b7ad6b7169203331");
}
