//! Shared helpers for daemon integration tests.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use socketguard_core::config::{BackendConfig, BackendInstanceConfig, DaemonConfig};
use socketguard_core::{ListeningSocket, Protocol};
use socketguard_daemon::engine::{ActiveBackend, Engine};
use socketguard_daemon::test_support::*;
use socketguard_daemon::{api, AppState};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

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

/// A daemon with a Local, a LAN and a Yggdrasil network (mocks) and a controllable set
/// of listening sockets.
pub struct Daemon {
    pub state: Arc<AppState>,
    pub app: Router,
    pub sockets: Arc<Mutex<Vec<ListeningSocket>>>,
    pub fw: Arc<MockFirewall>,
}

pub const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

impl Daemon {
    /// Networks `local` (lo), `lan` (eth0) and `ygg` (ygg0), and an `nginx` on tcp 80
    /// already reconciled into an app.
    pub async fn new() -> Self {
        let fw_calls = Arc::new(Mutex::new(Vec::new()));
        let fw = Arc::new(MockFirewall::new(fw_calls));
        let net = MockNetworkInterface::new(Arc::new(Mutex::new(Vec::new())));
        let monitor = MockSocketMonitor::new(vec![listener("nginx", 80)]);
        let sockets = monitor.sockets.clone();

        let mut backends = HashMap::new();
        let mut configs = Vec::new();
        for (id, config, mock) in [
            (
                "local",
                BackendConfig::Ula {
                    interface: "lo".into(),
                },
                MockIpv6Backend::new("fd00:1:2:3::", 128, "lo"),
            ),
            (
                "lan",
                BackendConfig::Slaac {
                    interface: "eth0".into(),
                    prefix: None,
                },
                {
                    let m = MockIpv6Backend::new("2001:db8:1:2::", 128, "eth0");
                    m.set_prefix("2001:db8:1:2::");
                    m
                },
            ),
            (
                "ygg",
                BackendConfig::Yggdrasil {
                    interface: "ygg0".into(),
                    admin_endpoint: None,
                },
                {
                    let m = MockIpv6Backend::new("300:1:2:3::", 128, "ygg0");
                    m.set_prefix("300:1:2:3::");
                    m
                },
            ),
        ] {
            let cfg = BackendInstanceConfig {
                id: id.to_string(),
                backend: config,
            };
            backends.insert(
                id.to_string(),
                ActiveBackend {
                    config: cfg.clone(),
                    backend: Box::new(mock),
                },
            );
            configs.push(cfg);
        }
        let ids = configs.iter().map(|c| c.id.clone()).collect();
        let engine =
            Engine::new_injectable(Box::new(monitor), fw.clone(), Arc::new(net), backends, ids);
        let state = test_app_state(
            engine,
            DaemonConfig {
                backends: configs,
                ..DaemonConfig::default()
            },
        )
        .await;
        let app = api::router(state.clone());
        let d = Self {
            state,
            app,
            sockets,
            fw,
        };
        d.reconcile().await;
        d
    }

    pub async fn reconcile(&self) {
        let mut engine = self.state.engine.write().await;
        engine.reconcile(&self.state).await.unwrap();
    }

    /// The id of the only app.
    pub async fn app_id(&self) -> String {
        let apps = self.state.db.list_apps().await.unwrap();
        assert_eq!(apps.len(), 1);
        apps[0].id.clone()
    }

    pub async fn get(&self, path: &str) -> (StatusCode, serde_json::Value) {
        call(&self.app, Method::GET, path, None).await
    }

    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        call(&self.app, method, path, Some(body)).await
    }

    pub async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.send(Method::POST, path, body).await
    }

    pub async fn delete(&self, path: &str) -> (StatusCode, serde_json::Value) {
        call(&self.app, Method::DELETE, path, None).await
    }

    /// Create a peer holding a Yggdrasil key; returns its id.
    pub async fn ygg_peer(&self, label: &str) -> String {
        let (s, body) = self
            .post(
                "/api/peers",
                serde_json::json!({"label": label, "credentials": [{"kind": "ygg_key", "value": KEY}]}),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().to_string()
    }
}

pub fn listener(name: &str, port: u16) -> ListeningSocket {
    ListeningSocket {
        pid: 1000,
        process_name: name.to_string(),
        port,
        protocol: Protocol::Tcp,
        bind_address: IpAddr::V6("::".parse().unwrap()),
        exe_path: Some(format!("/usr/bin/{name}")),
        cmdline: Some(vec![name.to_string()]),
    }
}

/// Send one request through the router (no network). Returns status and parsed JSON
/// body (`Null` if the body is empty or not JSON).
pub async fn call(
    app: &Router,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().method(method).uri(path);
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
