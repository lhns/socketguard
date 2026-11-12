//! Portable mode (ADR 0054) at the API and the config file: SocketGuard's own Tor and
//! Yggdrasil (`managed`, ADR 0052) are accepted, an existing (unmanaged) one is refused.
//!
//! Portable mode is process-wide state, so this is a test binary of its own, and it exists
//! on Windows only (the one system that has the mode).
#![cfg(windows)]

mod common;

use axum::http::{Method, StatusCode};
use common::call;
use serde_json::json;
use socketguard_core::config::DaemonConfig;
use socketguard_daemon::api;
use socketguard_daemon::config_file;
use socketguard_daemon::test_support::*;

fn portable() {
    socketguard_core::portable::request();
    assert!(socketguard_core::portable::is_portable());
}

#[tokio::test]
async fn the_api_takes_a_managed_tor_and_refuses_an_existing_one_in_portable_mode() {
    portable();
    let h = ManagedHarness::new();
    let state = h.app_state(DaemonConfig::default()).await;
    let app = api::router(state);

    let (s, body) = call(
        &app,
        Method::POST,
        "/api/networks",
        Some(json!({"type": "tor", "managed": true})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");

    // (A managed Yggdrasil is not added here: starting it would ask the real driver store.)

    // An existing node: refused, with the reason.
    let (s, body) = call(
        &app,
        Method::POST,
        "/api/networks",
        Some(json!({"id": "mine", "type": "tor"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid");
    assert!(
        body["message"].as_str().unwrap().contains("portable"),
        "{body}"
    );
}

#[test]
fn the_config_file_takes_a_managed_tor_and_refuses_an_existing_one_in_portable_mode() {
    portable();
    let dir = std::env::temp_dir().join(format!("sg-pconf-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("socketguard.json");

    std::fs::write(
        &path,
        r#"{"backends":[{"id":"tor","type":"tor","managed":true},
            {"id":"ygg","type":"yggdrasil","managed":true,"peers":["tls://a.example:443"]}]}"#,
    )
    .unwrap();
    let config = config_file::load(&path).unwrap().unwrap();
    assert_eq!(config.backends.len(), 2);

    std::fs::write(&path, r#"{"backends":[{"id":"tor","type":"tor"}]}"#).unwrap();
    let err = format!("{:#}", config_file::load(&path).unwrap_err());
    assert!(
        err.contains("portable") && err.contains("network 'tor'"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
