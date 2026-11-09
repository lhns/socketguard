mod common;

use axum::http::{Method, StatusCode};
use common::*;
use socketguard_core::config::DaemonConfig;

#[tokio::test]
async fn status_requires_valid_token() {
    let (app, _state) = test_app(DaemonConfig::default()).await;

    let (status, body) = call(&app, Method::GET, "/api/status", Some(TEST_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("version").is_some());

    let (status, _) = call(&app, Method::GET, "/api/status", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(&app, Method::GET, "/api/status", Some("wrong"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
