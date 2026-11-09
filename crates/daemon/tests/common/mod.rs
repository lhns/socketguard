//! Shared helpers for daemon integration tests.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::engine::Engine;
use socketguard_daemon::test_support::*;
use socketguard_daemon::{api, AppState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

pub const TEST_TOKEN: &str = "test-token";

/// Engine with mock firewall/network/monitor and no backends.
pub fn empty_engine() -> Engine {
    Engine::new_injectable(
        Box::new(MockSocketMonitor::new(vec![])),
        Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![])))),
        Arc::new(MockNetworkInterface::new(Arc::new(Mutex::new(vec![])))),
        HashMap::new(),
        vec![],
    )
}

/// Router over a fresh in-memory state. Keep the returned state to inspect the DB.
pub async fn test_app(config: DaemonConfig) -> (Router, Arc<AppState>) {
    let state = test_app_state(empty_engine(), config).await;
    (api::router(state.clone()), state)
}

/// Send one request through the router (no network). Returns status and parsed JSON
/// body (`Null` if the body is empty or not JSON).
pub async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}
