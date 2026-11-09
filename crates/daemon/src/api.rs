//! HTTP API. Phase 6 replaces this with API v1; until then only the status endpoint and
//! the event stream exist so the daemon runs.

use crate::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::sse::{Event, KeepAlive, Sse},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use futures_util::stream::Stream;
use futures_util::StreamExt;
use socketguard_core::api_types::{ApiError, StatusResponse};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;

/// Push notifications for frontends (SSE event names in `name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEvent {
    AppsChanged,
    /// A new, pending app; carries its id.
    AppDiscovered(String),
    PeersChanged,
    GrantsChanged,
    NetworksChanged,
    SettingsChanged,
    Activity,
}

impl DaemonEvent {
    pub fn name(&self) -> &'static str {
        match self {
            DaemonEvent::AppsChanged => "apps_changed",
            DaemonEvent::AppDiscovered(_) => "app_discovered",
            DaemonEvent::PeersChanged => "peers_changed",
            DaemonEvent::GrantsChanged => "grants_changed",
            DaemonEvent::NetworksChanged => "networks_changed",
            DaemonEvent::SettingsChanged => "settings_changed",
            DaemonEvent::Activity => "activity",
        }
    }

    /// The SSE data: the app id for a discovery, empty otherwise.
    pub fn data(&self) -> String {
        match self {
            DaemonEvent::AppDiscovered(id) => id.clone(),
            _ => String::new(),
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/events", get(sse_events))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            let token = &value[7..];
            if token == state.api_token {
                next.run(req).await.into_response()
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiError {
                        error: "invalid bearer token".into(),
                    }),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "missing or malformed Authorization header".into(),
            }),
        )
            .into_response(),
    }
}

async fn status() -> impl IntoResponse {
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn sse_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        futures_util::future::ready(
            result
                .ok()
                .map(|ev| Ok(Event::default().event(ev.name()).data(ev.data()))),
        )
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
