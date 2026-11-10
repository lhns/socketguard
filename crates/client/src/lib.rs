//! Typed async client for the SocketGuard local API (ADR 0032, 0033), shared by the CLI and
//! the Tauri backend. It speaks HTTP/1.1 over the platform transport (Unix socket or Windows
//! named pipe), one connection per request, and has one method per route of the API.
//!
//! The endpoint is `SOCKETGUARD_SOCKET` if set, else the platform default. With the `otel`
//! feature every request carries the `traceparent` of the current OpenTelemetry context.

mod routes;
mod sse;
mod transport;

pub use routes::{Route, CLIENT_ROUTES};
pub use socketguard_core::api_types::ApiEvent;
pub use sse::{EventStream, SseParser, SseRaw};

use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::{de::DeserializeOwned, Serialize};
use socketguard_core::api_types::{
    ApiError, ApplyRequest, ApplyResponse, DisableRequest, Enforcement, ExportDocument,
    MergeRequest, NewGroup, NewNetwork, NewPeer, ProtectHostRequest, ProtectHostResponse,
    ReviewRequest, SetMembers, SplitRequest, StatusResponse, UpdateLabel, UpdateSettings,
};
use socketguard_core::{
    ActivityQuery, ActivityRecord, Address, App, AppDetail, Credential, GrantView, Network,
    NewCredential, NewGrant, Peer, PeerGroup, Settings,
};
use std::sync::Arc;

/// Environment variable that overrides the endpoint (socket path or pipe name).
pub const ENDPOINT_ENV: &str = "SOCKETGUARD_SOCKET";

/// What went wrong with a call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The daemon could not be reached.
    #[error("cannot reach the daemon at {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: std::io::Error,
    },
    /// The daemon answered with an error.
    #[error("{message}")]
    Api {
        status: u16,
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },
    /// The connection broke, or the answer was not what the API promises.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    /// The API error code (`not_found`, `confirmation_required`, ...), if the daemon sent one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The HTTP status of an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether the daemon refused for lack of confirmation.
    pub fn is_confirmation_required(&self) -> bool {
        self.code() == Some(socketguard_core::api_types::error_code::CONFIRMATION_REQUIRED)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The result of a change that is saved but may not be enforced everywhere yet. The
/// daemon answers 202 then, with `enforcement` saying what is pending (e.g. Tor is down
/// and an onion service could not be taken off the network yet); it keeps retrying.
#[derive(Debug, Clone, PartialEq)]
pub struct Saved<T> {
    pub value: T,
    pub enforcement: Option<Enforcement>,
}

type HeaderHook = Arc<dyn Fn(&mut HeaderMap) + Send + Sync>;

/// Client for one daemon endpoint. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    endpoint: String,
    hook: Option<HeaderHook>,
}

/// Filter for [`Client::list_grants`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct GrantQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Serialize)]
struct ActivityParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<socketguard_core::ActivityKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<i64>,
}

impl Client {
    /// A client for an explicit socket path (Unix) or pipe name (Windows).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            hook: default_hook(),
        }
    }

    /// The endpoint from `SOCKETGUARD_SOCKET`, else the platform default.
    pub fn from_env() -> Self {
        Self::new(default_endpoint())
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Run `hook` on the headers of every request, e.g. to inject trace context. Replaces
    /// the default hook.
    pub fn with_header_hook(
        mut self,
        hook: impl Fn(&mut HeaderMap) + Send + Sync + 'static,
    ) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }

    async fn send(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        let mut uri = route.fill(params);
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            uri.push('?');
            uri.push_str(&q);
        }
        let mut builder = Request::builder()
            .method(route.method.clone())
            .uri(uri)
            .header(header::HOST, "localhost");
        let has_body = body.is_some();
        if has_body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let mut req = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Error::Protocol(e.to_string()))?;
        if let Some(hook) = &self.hook {
            hook(req.headers_mut());
        }
        if !req.headers().contains_key(header::ACCEPT) {
            req.headers_mut()
                .insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        }

        let stream = transport::connect(&self.endpoint)
            .await
            .map_err(|source| Error::Connect {
                endpoint: self.endpoint.clone(),
                source,
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Send, check the status and return the body.
    async fn call_raw(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes> {
        Ok(self.call_status(route, params, query, body).await?.1)
    }

    /// Like [`Client::call_raw`], with the success status.
    async fn call_status(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Bytes)> {
        let resp = self.send(route, params, query, body).await?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?
            .to_bytes();
        if status.is_success() {
            Ok((status, bytes))
        } else {
            Err(api_error(status, &bytes))
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        route: &Route,
        params: &[&str],
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        let bytes = self.call_raw(route, params, query, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("bad response: {e}")))
    }

    async fn call_unit(&self, route: &Route, params: &[&str], body: Option<Vec<u8>>) -> Result<()> {
        self.call_raw(route, params, None, body).await.map(|_| ())
    }

    /// A call whose answer may carry a pending-enforcement notice (HTTP 202).
    async fn call_saved<T: DeserializeOwned>(
        &self,
        route: &Route,
        params: &[&str],
        body: Option<Vec<u8>>,
    ) -> Result<Saved<T>> {
        let (status, bytes) = self.call_status(route, params, None, body).await?;
        let bad = |e: serde_json::Error| Error::Protocol(format!("bad response: {e}"));
        let enforcement = if status == StatusCode::ACCEPTED {
            #[derive(serde::Deserialize)]
            struct Notice {
                enforcement: Enforcement,
            }
            Some(
                serde_json::from_slice::<Notice>(&bytes)
                    .map_err(bad)?
                    .enforcement,
            )
        } else {
            None
        };
        // An empty body (204) is the unit value.
        let value = if bytes.is_empty() {
            serde_json::from_value(serde_json::Value::Null)
        } else {
            serde_json::from_slice(&bytes)
        };
        // A 202 to a delete carries only the notice, which is not a `()`.
        let value = match value {
            Ok(v) => v,
            Err(_) if enforcement.is_some() => {
                serde_json::from_value(serde_json::Value::Null).map_err(bad)?
            }
            Err(e) => return Err(bad(e)),
        };
        Ok(Saved { value, enforcement })
    }

    // ─── Status and events ───────────────────────────────────────────────────

    pub async fn status(&self) -> Result<StatusResponse> {
        self.call(&routes::STATUS, &[], None, None).await
    }

    /// Subscribe to the push events. The stream ends when the daemon closes the connection.
    pub async fn events(&self) -> Result<EventStream> {
        let resp = self.send(&routes::EVENTS, &[], None, None).await?;
        let status = resp.status();
        if !status.is_success() {
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?
                .to_bytes();
            return Err(api_error(status, &bytes));
        }
        Ok(sse::stream(resp.into_body()))
    }

    // ─── Apps ────────────────────────────────────────────────────────────────

    /// All apps, or only those without a decision yet.
    pub async fn list_apps(&self, pending_only: bool) -> Result<Vec<App>> {
        let q = pending_only.then(|| "pending=true".to_string());
        self.call(&routes::LIST_APPS, &[], q, None).await
    }

    pub async fn get_app(&self, id: &str) -> Result<AppDetail> {
        self.call(&routes::GET_APP, &[id], None, None).await
    }

    /// Forget an app. It reappears as pending the next time it listens.
    pub async fn delete_app(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_APP, &[id], None).await
    }

    pub async fn review_app(&self, id: &str, reviewed: bool) -> Result<AppDetail> {
        self.call(
            &routes::REVIEW_APP,
            &[id],
            None,
            json(&ReviewRequest { reviewed }),
        )
        .await
    }

    pub async fn split_app(&self, id: &str, req: &SplitRequest) -> Result<Saved<Address>> {
        self.call_saved(&routes::SPLIT_APP, &[id], json(req)).await
    }

    pub async fn merge_app(&self, id: &str, req: &MergeRequest) -> Result<Saved<Address>> {
        self.call_saved(&routes::MERGE_APP, &[id], json(req)).await
    }

    // ─── Peers ───────────────────────────────────────────────────────────────

    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        self.call(&routes::LIST_PEERS, &[], None, None).await
    }

    pub async fn create_peer(&self, req: &NewPeer) -> Result<Peer> {
        self.call(&routes::CREATE_PEER, &[], None, json(req)).await
    }

    pub async fn get_peer(&self, id: &str) -> Result<Peer> {
        self.call(&routes::GET_PEER, &[id], None, None).await
    }

    pub async fn update_peer(&self, id: &str, label: &str) -> Result<Peer> {
        let body = json(&UpdateLabel {
            label: label.to_string(),
        });
        self.call(&routes::UPDATE_PEER, &[id], None, body).await
    }

    pub async fn delete_peer(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_PEER, &[id], None).await
    }

    pub async fn add_credential(
        &self,
        peer_id: &str,
        req: &NewCredential,
    ) -> Result<Saved<Credential>> {
        self.call_saved(&routes::ADD_CREDENTIAL, &[peer_id], json(req))
            .await
    }

    pub async fn remove_credential(&self, peer_id: &str, credential_id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::REMOVE_CREDENTIAL, &[peer_id, credential_id], None)
            .await
    }

    // ─── Peer groups ─────────────────────────────────────────────────────────

    pub async fn list_groups(&self) -> Result<Vec<PeerGroup>> {
        self.call(&routes::LIST_GROUPS, &[], None, None).await
    }

    pub async fn create_group(&self, req: &NewGroup) -> Result<PeerGroup> {
        self.call(&routes::CREATE_GROUP, &[], None, json(req)).await
    }

    pub async fn get_group(&self, id: &str) -> Result<PeerGroup> {
        self.call(&routes::GET_GROUP, &[id], None, None).await
    }

    pub async fn update_group(&self, id: &str, label: &str) -> Result<PeerGroup> {
        let body = json(&UpdateLabel {
            label: label.to_string(),
        });
        self.call(&routes::UPDATE_GROUP, &[id], None, body).await
    }

    pub async fn delete_group(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_GROUP, &[id], None).await
    }

    /// Replace a group's members.
    pub async fn set_group_members(
        &self,
        id: &str,
        peer_ids: &[String],
    ) -> Result<Saved<PeerGroup>> {
        let body = json(&SetMembers {
            peer_ids: peer_ids.to_vec(),
        });
        self.call_saved(&routes::SET_GROUP_MEMBERS, &[id], body)
            .await
    }

    // ─── Grants ──────────────────────────────────────────────────────────────

    pub async fn list_grants(&self, filter: &GrantQuery) -> Result<Vec<GrantView>> {
        let q = serde_urlencoded::to_string(filter).ok();
        self.call(&routes::LIST_GRANTS, &[], q, None).await
    }

    /// Create a grant. To Anyone it needs `confirm_open: true`, else the error code is
    /// `confirmation_required`.
    pub async fn create_grant(&self, req: &NewGrant) -> Result<Saved<GrantView>> {
        self.call_saved(&routes::CREATE_GRANT, &[], json(req)).await
    }

    pub async fn delete_grant(&self, id: &str) -> Result<Saved<()>> {
        self.call_saved(&routes::DELETE_GRANT, &[id], None).await
    }

    // ─── Networks ────────────────────────────────────────────────────────────

    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        self.call(&routes::LIST_NETWORKS, &[], None, None).await
    }

    pub async fn add_network(&self, req: &NewNetwork) -> Result<Network> {
        self.call(&routes::ADD_NETWORK, &[], None, json(req)).await
    }

    /// Remove a network. With `force`, a Tor network goes even if its onion services
    /// could not be removed (the daemon otherwise answers 409 `conflict`).
    pub async fn delete_network(&self, id: &str, force: bool) -> Result<()> {
        let query = force.then(|| "force=true".to_string());
        self.call_raw(&routes::DELETE_NETWORK, &[id], query, None)
            .await
            .map(|_| ())
    }

    // ─── Settings ────────────────────────────────────────────────────────────

    pub async fn get_settings(&self) -> Result<Settings> {
        self.call(&routes::GET_SETTINGS, &[], None, None).await
    }

    pub async fn update_settings(&self, req: &UpdateSettings) -> Result<Settings> {
        self.call(&routes::UPDATE_SETTINGS, &[], None, json(req))
            .await
    }

    /// Turn whole-host protection on for `interfaces` (empty list: off). The daemon refuses
    /// with code `protect_host_refused` (details: the risks) unless `force`.
    pub async fn set_protect_host(&self, req: &ProtectHostRequest) -> Result<ProtectHostResponse> {
        self.call(&routes::SET_PROTECT_HOST, &[], None, json(req))
            .await
    }

    // ─── Activity, export, maintenance ───────────────────────────────────────

    pub async fn activity(&self, query: &ActivityQuery) -> Result<Vec<ActivityRecord>> {
        let params = ActivityParams {
            since: query.since,
            kind: query.kind,
            app: query.app_id.as_deref(),
            peer: query.peer_id.as_deref(),
            limit: query.limit,
            before: query.before,
        };
        let q = serde_urlencoded::to_string(&params).ok();
        self.call(&routes::ACTIVITY, &[], q, None).await
    }

    pub async fn export(&self) -> Result<ExportDocument> {
        self.call(&routes::EXPORT, &[], None, None).await
    }

    /// Diff `req.document` against the daemon's state and, unless `dry_run`, apply it.
    pub async fn apply(&self, req: &ApplyRequest) -> Result<ApplyResponse> {
        self.call(&routes::APPLY, &[], None, json(req)).await
    }

    /// Remove all firewall rules and addresses (needs `confirm`) and keep them off, also
    /// across restarts, until [`Client::enable`].
    pub async fn disable(&self, confirm: bool) -> Result<()> {
        self.call_unit(&routes::DISABLE, &[], json(&DisableRequest { confirm }))
            .await
    }

    /// Clear `disable` and put the rules and addresses back.
    pub async fn enable(&self) -> Result<()> {
        self.call_unit(&routes::ENABLE, &[], None).await
    }
}

fn json<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    // Serializing the API's own types cannot fail.
    serde_json::to_vec(v).ok()
}

fn api_error(status: StatusCode, body: &[u8]) -> Error {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => Error::Api {
            status: status.as_u16(),
            code: e.code,
            message: e.message,
            details: e.details,
        },
        Err(_) => Error::Api {
            status: status.as_u16(),
            code: "unknown".to_string(),
            message: format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
            details: None,
        },
    }
}

/// The endpoint to use when none is given.
pub fn default_endpoint() -> String {
    if let Ok(p) = std::env::var(ENDPOINT_ENV) {
        if !p.trim().is_empty() {
            return p;
        }
    }
    if cfg!(windows) {
        socketguard_core::config::DEFAULT_API_PIPE.to_string()
    } else {
        socketguard_core::config::DEFAULT_API_SOCKET.to_string()
    }
}

#[cfg(feature = "otel")]
fn default_hook() -> Option<HeaderHook> {
    Some(Arc::new(inject_trace_context))
}

#[cfg(not(feature = "otel"))]
fn default_hook() -> Option<HeaderHook> {
    None
}

/// Add `traceparent` (and `tracestate`) from the current OpenTelemetry context, using the
/// globally installed text-map propagator.
#[cfg(feature = "otel")]
pub fn inject_trace_context(headers: &mut HeaderMap) {
    struct Injector<'a>(&'a mut HeaderMap);
    impl opentelemetry::propagation::Injector for Injector<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let (Ok(k), Ok(v)) = (
                header::HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                self.0.insert(k, v);
            }
        }
    }
    opentelemetry::global::get_text_map_propagator(|p| {
        p.inject_context(&opentelemetry::Context::current(), &mut Injector(headers))
    });
}

#[cfg(all(test, feature = "otel"))]
mod otel_tests {
    use super::*;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };

    #[test]
    fn the_current_context_becomes_a_traceparent_header() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let cx = opentelemetry::Context::current().with_remote_span_context(SpanContext::new(
            TraceId::from_hex("0af7651916cd43dd8448eb211c80319c").unwrap(),
            SpanId::from_hex("b7ad6b7169203331").unwrap(),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        ));
        let _guard = cx.attach();
        let mut headers = HeaderMap::new();
        inject_trace_context(&mut headers);
        assert_eq!(
            headers["traceparent"],
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        );
        // A client built with the feature uses it by default.
        assert!(Client::new("x").hook.is_some());
    }
}
