//! The local HTTP API v1 (ADR 0032, 0033; reference in docs/api.md). Served over a Unix
//! socket or a named pipe by [`crate::transport`]; there is no TCP listener, no token and
//! no CORS. Handlers translate between HTTP and the engine and hold no logic of their own.

use crate::apply;
use crate::engine::{Engine, EngineError, GrantFilter, ProtectHostError};
use crate::ruleset::LockoutRisk;
use crate::AppState;
use axum::{
    body::Body,
    extract::{FromRequest, FromRequestParts, MatchedPath, Path, Request, State},
    http::{request::Parts, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put, MethodRouter},
    Json, Router,
};
use futures_util::stream::Stream;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use socketguard_core::api_types::{
    error_code, event_name, ApiError, ApplyRequest, AttachPortGroup, ChangesRequest, Counts,
    DisableRequest, Enforcement, EnforcementNotice, EnforcementStatus, ExposureQuery,
    LockoutRiskInfo, MemberQuery, MoveAppRequest, NewBinding, NewGroup, NewNetwork, NewPeer,
    NewPortGroup, NewReservation, NewTag, NewTagMember, ParseCredentialsRequest,
    ProtectHostRequest, ProtectHostResponse, ReserveRequest, SetMembers, SetPeers,
    StatusResponse, UpdateLabel, UpdatePortGroup, UpdateTag,
};
use socketguard_core::config::{BackendConfig, BackendInstanceConfig};
use socketguard_core::{ActivityQuery, NewCredential, NewGrant};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::trace::TraceLayer;
use tracing::Span;

/// Push notifications for frontends (SSE event names in `name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEvent {
    AppsChanged,
    /// A new app; carries its id.
    AppDiscovered(String),
    PeersChanged,
    GrantsChanged,
    TagsChanged,
    PortGroupsChanged,
    ReservationsChanged,
    AddressesChanged,
    NetworksChanged,
    SettingsChanged,
    Activity,
}

impl DaemonEvent {
    pub fn name(&self) -> &'static str {
        match self {
            DaemonEvent::AppsChanged => event_name::APPS_CHANGED,
            DaemonEvent::AppDiscovered(_) => event_name::APP_DISCOVERED,
            DaemonEvent::PeersChanged => event_name::PEERS_CHANGED,
            DaemonEvent::GrantsChanged => event_name::GRANTS_CHANGED,
            DaemonEvent::TagsChanged => event_name::TAGS_CHANGED,
            DaemonEvent::PortGroupsChanged => event_name::PORT_GROUPS_CHANGED,
            DaemonEvent::ReservationsChanged => event_name::RESERVATIONS_CHANGED,
            DaemonEvent::AddressesChanged => event_name::ADDRESSES_CHANGED,
            DaemonEvent::NetworksChanged => event_name::NETWORKS_CHANGED,
            DaemonEvent::SettingsChanged => event_name::SETTINGS_CHANGED,
            DaemonEvent::Activity => event_name::ACTIVITY,
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

// ─── Routes ──────────────────────────────────────────────────────────────────

/// Every route of the API. The router is built from this table, so it is also the list
/// the coverage tests compare against the client crate and the CLI.
pub const ROUTES: &[(Method, &str)] = &[
    (Method::GET, "/api/status"),
    (Method::GET, "/api/events"),
    (Method::GET, "/api/apps"),
    (Method::GET, "/api/apps/{id}"),
    (Method::DELETE, "/api/apps/{id}"),
    (Method::POST, "/api/apps/{id}/move"),
    (Method::GET, "/api/apps/{id}/share"),
    (Method::GET, "/api/peers"),
    (Method::POST, "/api/peers"),
    (Method::GET, "/api/peers/{id}"),
    (Method::PATCH, "/api/peers/{id}"),
    (Method::DELETE, "/api/peers/{id}"),
    (Method::POST, "/api/credentials/parse"),
    (Method::POST, "/api/peers/{id}/credentials"),
    (Method::DELETE, "/api/peers/{id}/credentials/{cred_id}"),
    (Method::POST, "/api/peers/{id}/tor-key"),
    (Method::GET, "/api/peer-groups"),
    (Method::POST, "/api/peer-groups"),
    (Method::GET, "/api/peer-groups/{id}"),
    (Method::PATCH, "/api/peer-groups/{id}"),
    (Method::DELETE, "/api/peer-groups/{id}"),
    (Method::PUT, "/api/peer-groups/{id}/members"),
    (Method::GET, "/api/grants"),
    (Method::POST, "/api/grants"),
    (Method::DELETE, "/api/grants/{id}"),
    (Method::POST, "/api/changes"),
    (Method::GET, "/api/tags"),
    (Method::POST, "/api/tags"),
    (Method::GET, "/api/tags/{id}"),
    (Method::PATCH, "/api/tags/{id}"),
    (Method::DELETE, "/api/tags/{id}"),
    (Method::POST, "/api/tags/{id}/members"),
    (Method::DELETE, "/api/tags/{id}/members/{app_id}"),
    (Method::GET, "/api/port-groups"),
    (Method::POST, "/api/port-groups"),
    (Method::GET, "/api/port-groups/{id}"),
    (Method::PUT, "/api/port-groups/{id}"),
    (Method::DELETE, "/api/port-groups/{id}"),
    (Method::PUT, "/api/port-groups/{id}/apps/{app_id}"),
    (Method::DELETE, "/api/port-groups/{id}/apps/{app_id}"),
    (Method::GET, "/api/reservations"),
    (Method::POST, "/api/reservations"),
    (Method::GET, "/api/reservations/{id}"),
    (Method::PUT, "/api/reservations/{id}"),
    (Method::DELETE, "/api/reservations/{id}"),
    (Method::POST, "/api/reservations/{id}/bindings"),
    (
        Method::DELETE,
        "/api/reservations/{id}/bindings/{binding_id}",
    ),
    (Method::GET, "/api/addresses"),
    (Method::POST, "/api/addresses/{id}/reserve"),
    (Method::GET, "/api/networks"),
    (Method::GET, "/api/networks/setup"),
    (Method::POST, "/api/networks"),
    (Method::DELETE, "/api/networks/{id}"),
    (Method::PUT, "/api/networks/{id}/peers"),
    (Method::GET, "/api/exposure"),
    (Method::GET, "/api/settings"),
    (Method::PUT, "/api/settings/protect-host"),
    (Method::GET, "/api/activity"),
    (Method::GET, "/api/export"),
    (Method::POST, "/api/apply"),
    (Method::POST, "/api/disable"),
    (Method::POST, "/api/enable"),
];

type Shared = Arc<AppState>;

/// The handler for one entry of [`ROUTES`]. A route without a handler fails the router
/// build, which every API test hits.
fn handler(method: &Method, path: &str) -> MethodRouter<Shared> {
    match (method.as_str(), path) {
        ("GET", "/api/status") => get(status),
        ("GET", "/api/events") => get(sse_events),
        ("GET", "/api/apps") => get(apps_list),
        ("GET", "/api/apps/{id}") => get(app_get),
        ("DELETE", "/api/apps/{id}") => delete(app_delete),
        ("POST", "/api/apps/{id}/move") => post(app_move),
        ("GET", "/api/apps/{id}/share") => get(app_share),
        ("GET", "/api/peers") => get(peers_list),
        ("POST", "/api/peers") => post(peer_create),
        ("GET", "/api/peers/{id}") => get(peer_get),
        ("PATCH", "/api/peers/{id}") => patch(peer_update),
        ("DELETE", "/api/peers/{id}") => delete(peer_delete),
        ("POST", "/api/credentials/parse") => post(credentials_parse),
        ("POST", "/api/peers/{id}/credentials") => post(credential_add),
        ("DELETE", "/api/peers/{id}/credentials/{cred_id}") => delete(credential_remove),
        ("POST", "/api/peers/{id}/tor-key") => post(tor_key_generate),
        ("GET", "/api/peer-groups") => get(groups_list),
        ("POST", "/api/peer-groups") => post(group_create),
        ("GET", "/api/peer-groups/{id}") => get(group_get),
        ("PATCH", "/api/peer-groups/{id}") => patch(group_update),
        ("DELETE", "/api/peer-groups/{id}") => delete(group_delete),
        ("PUT", "/api/peer-groups/{id}/members") => put(group_members),
        ("GET", "/api/grants") => get(grants_list),
        ("POST", "/api/grants") => post(grant_create),
        ("DELETE", "/api/grants/{id}") => delete(grant_delete),
        ("POST", "/api/changes") => post(changes_post),
        ("GET", "/api/tags") => get(tags_list),
        ("POST", "/api/tags") => post(tag_create),
        ("GET", "/api/tags/{id}") => get(tag_get),
        ("PATCH", "/api/tags/{id}") => patch(tag_update),
        ("DELETE", "/api/tags/{id}") => delete(tag_delete),
        ("POST", "/api/tags/{id}/members") => post(tag_member_add),
        ("DELETE", "/api/tags/{id}/members/{app_id}") => delete(tag_member_remove),
        ("GET", "/api/port-groups") => get(port_groups_list),
        ("POST", "/api/port-groups") => post(port_group_create),
        ("GET", "/api/port-groups/{id}") => get(port_group_get),
        ("PUT", "/api/port-groups/{id}") => put(port_group_update),
        ("DELETE", "/api/port-groups/{id}") => delete(port_group_delete),
        ("PUT", "/api/port-groups/{id}/apps/{app_id}") => put(port_group_attach),
        ("DELETE", "/api/port-groups/{id}/apps/{app_id}") => delete(port_group_detach),
        ("GET", "/api/reservations") => get(reservations_list),
        ("POST", "/api/reservations") => post(reservation_create),
        ("GET", "/api/reservations/{id}") => get(reservation_get),
        ("PUT", "/api/reservations/{id}") => put(reservation_rename),
        ("DELETE", "/api/reservations/{id}") => delete(reservation_release),
        ("POST", "/api/reservations/{id}/bindings") => post(binding_add),
        ("DELETE", "/api/reservations/{id}/bindings/{binding_id}") => delete(binding_remove),
        ("GET", "/api/addresses") => get(addresses_list),
        ("POST", "/api/addresses/{id}/reserve") => post(address_reserve),
        ("GET", "/api/networks") => get(networks_list),
        ("GET", "/api/networks/setup") => get(networks_setup),
        ("POST", "/api/networks") => post(network_create),
        ("DELETE", "/api/networks/{id}") => delete(network_delete),
        ("PUT", "/api/networks/{id}/peers") => put(network_peers),
        ("GET", "/api/exposure") => get(exposure_get),
        ("GET", "/api/settings") => get(settings_get),
        ("PUT", "/api/settings/protect-host") => put(protect_host_put),
        ("GET", "/api/activity") => get(activity_list),
        ("GET", "/api/export") => get(export_get),
        ("POST", "/api/apply") => post(apply_post),
        ("POST", "/api/disable") => post(disable_post),
        ("POST", "/api/enable") => post(enable_post),
        _ => unreachable!("route {method} {path} has no handler"),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let mut router: Router<Shared> = Router::new();
    for (method, path) in ROUTES {
        router = router.route(path, handler(method, path));
    }
    router
        .fallback(|| async {
            ApiErr::new(
                StatusCode::NOT_FOUND,
                error_code::NOT_FOUND,
                "no such route",
            )
        })
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_request_span)
                .on_request(())
                .on_response(|resp: &Response, _: std::time::Duration, span: &Span| {
                    span.record("http.response.status_code", resp.status().as_u16());
                }),
        )
        .with_state(state)
}

// ─── Tracing ─────────────────────────────────────────────────────────────────

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// A span per request, parented to the caller's W3C `traceparent` so CLI or UI actions
/// and the daemon's work form one trace (ADR 0034).
fn make_request_span(req: &Request<Body>) -> Span {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let name = format!("{} {route}", req.method());
    let span = tracing::info_span!(
        "api request",
        otel.name = %name,
        http.request.method = %req.method(),
        http.route = %route,
        http.response.status_code = tracing::field::Empty,
    );
    let parent = opentelemetry::global::get_text_map_propagator(|p| {
        p.extract(&HeaderExtractor(req.headers()))
    });
    let _ = span.set_parent(parent);
    span
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// An error response: status plus the [`ApiError`] body.
pub struct ApiErr {
    status: StatusCode,
    body: ApiError,
}

impl ApiErr {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiError {
                code: code.to_string(),
                message: message.into(),
                details: None,
            },
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error_code::INVALID, message)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

impl From<EngineError> for ApiErr {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::NotFound(_) => {
                Self::new(StatusCode::NOT_FOUND, error_code::NOT_FOUND, e.to_string())
            }
            EngineError::Invalid(_) => Self::invalid(e.to_string()),
            EngineError::Conflict(_) => {
                Self::new(StatusCode::CONFLICT, error_code::CONFLICT, e.to_string())
            }
            EngineError::LocalNetwork => Self::new(
                StatusCode::BAD_REQUEST,
                error_code::LOCAL_NETWORK,
                e.to_string(),
            ),
            EngineError::ConfirmationRequired => Self::new(
                StatusCode::CONFLICT,
                error_code::CONFIRMATION_REQUIRED,
                e.to_string(),
            ),
            EngineError::Internal(err) => {
                tracing::error!("API request failed: {err:#}");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_code::INTERNAL,
                    "internal error",
                )
            }
        }
    }
}

impl From<anyhow::Error> for ApiErr {
    fn from(e: anyhow::Error) -> Self {
        EngineError::Internal(e).into()
    }
}

type ApiResult<T> = Result<T, ApiErr>;

/// The success response of a change that may need a network to enforce it: `ok` (with
/// `body`, if any) when nothing is pending, else 202 with the same body and an
/// `enforcement` field (a body of its own for deletes). The change is saved either way.
fn saved<T: serde::Serialize>(engine: &Engine, ok: StatusCode, body: Option<T>) -> Response {
    let Some(pending) = engine.enforcement_pending() else {
        return match body {
            Some(b) => (ok, Json(b)).into_response(),
            None => ok.into_response(),
        };
    };
    let json = match body.map(serde_json::to_value) {
        Some(Ok(serde_json::Value::Object(mut m))) => {
            m.insert(
                "enforcement".to_string(),
                serde_json::to_value(&pending).unwrap_or_default(),
            );
            serde_json::Value::Object(m)
        }
        _ => serde_json::to_value(EnforcementNotice {
            enforcement: pending,
        })
        .unwrap_or_default(),
    };
    (StatusCode::ACCEPTED, Json(json)).into_response()
}

fn risk_info(r: &LockoutRisk) -> LockoutRiskInfo {
    LockoutRiskInfo {
        process_name: r.process_name.clone(),
        port: r.port,
        protocol: r.protocol,
        bind_address: r.bind_address.to_string(),
        message: r.to_string(),
    }
}

// Extractors that fail with the API's error body instead of axum's plain text.

pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiErr;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiErr> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(e) => Err(ApiErr::invalid(e.body_text())),
        }
    }
}

pub struct ApiQuery<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiErr> {
        axum::extract::Query::<T>::try_from_uri(&parts.uri)
            .map(|q| ApiQuery(q.0))
            .map_err(|e| ApiErr::invalid(e.body_text()))
    }
}

// ─── Status and events ───────────────────────────────────────────────────────

async fn status(State(state): State<Shared>) -> ApiResult<Json<StatusResponse>> {
    let engine = state.engine.read().await;
    let apps = engine.list_apps(&state).await?;
    let addresses = state.db.list_addresses().await?.len() as u32;
    let config = state.config.read().await;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        networks: engine.networks_described(),
        protect_host_interfaces: engine.settings(&state).await?.protect_host_interfaces,
        disabled: state.db.disabled().await,
        unadopted: state.db.unadopted().await?,
        counts: Counts {
            apps: apps.len() as u32,
            addresses,
            peers: engine.list_peers(&state).await?.len() as u32,
            groups: engine.list_groups(&state).await?.len() as u32,
            grants: state.db.list_grants().await?.len() as u32,
        },
        config_path: state.config_path.as_ref().map(|p| p.display().to_string()),
        db_path: Some(config.db_path.clone()),
        socket: Some(if cfg!(windows) {
            config.api_pipe.clone()
        } else {
            config.api_socket.clone()
        }),
        service_installed: crate::service::installed_hint(),
        bundled: state.bundled.info(),
    }))
}

async fn sse_events(
    State(state): State<Shared>,
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

// ─── Apps ────────────────────────────────────────────────────────────────────

async fn apps_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let apps = engine.list_apps(&state).await?;
    Ok(Json(apps).into_response())
}

async fn app_get(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_app(&state, &id).await?).into_response())
}

async fn app_delete(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_app(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

/// What an app's granted Tor peers need to connect (their client authorization lines).
async fn app_share(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.share(&state, &id).await?).into_response())
}

async fn app_move(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<MoveAppRequest>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine
        .move_app(&state, &id, &req.to, req.confirm_open)
        .await?;
    Ok(saved(
        &engine,
        StatusCode::OK,
        Some(engine.get_app(&state, &req.to).await?),
    ))
}

// ─── Reservations and addresses ──────────────────────────────────────────────

async fn reservations_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_reservations(&state).await?).into_response())
}

async fn reservation_get(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_reservation(&state, &id).await?).into_response())
}

async fn reservation_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewReservation>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let view = engine
        .create_reservation(&state, &req.label, req.bindings, req.confirm_open)
        .await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(view)))
}

async fn reservation_rename(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdateLabel>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let view = engine.rename_reservation(&state, &id, &req.label).await?;
    Ok(saved(&engine, StatusCode::OK, Some(view)))
}

async fn reservation_release(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.release_reservation(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

async fn binding_add(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<NewBinding>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let view = engine
        .add_binding(&state, &id, req.target, req.confirm_open)
        .await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(view)))
}

async fn binding_remove(
    State(state): State<Shared>,
    Path((id, binding_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let view = engine.remove_binding(&state, &id, &binding_id).await?;
    Ok(saved(&engine, StatusCode::OK, Some(view)))
}

async fn addresses_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_addresses(&state).await?).into_response())
}

async fn address_reserve(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ReserveRequest>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let view = engine.reserve_address(&state, &id, &req.label).await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(view)))
}

// ─── Peers ───────────────────────────────────────────────────────────────────

async fn peers_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_peers(&state).await?).into_response())
}

async fn peer_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewPeer>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let peer = engine
        .create_peer(&state, req.label.as_deref().unwrap_or(""), &req.credentials)
        .await?;
    Ok((StatusCode::CREATED, Json(peer)).into_response())
}

async fn credentials_parse(ApiJson(req): ApiJson<ParseCredentialsRequest>) -> ApiResult<Response> {
    Ok(Json(socketguard_core::parse_input(&req.text)).into_response())
}

async fn peer_get(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_peer(&state, &id).await?).into_response())
}

async fn peer_update(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdateLabel>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.update_peer_label(&state, &id, &req.label).await?).into_response())
}

async fn peer_delete(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_peer(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

async fn credential_add(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<NewCredential>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let c = engine.add_credential(&state, &id, &req).await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(c)))
}

/// Generate a Tor client key for the peer. The private key is in the answer and stays
/// readable through `share`.
async fn tor_key_generate(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let key = engine.generate_tor_key(&state, &id).await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(key)))
}

async fn credential_remove(
    State(state): State<Shared>,
    Path((id, cred_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.remove_credential(&state, &id, &cred_id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

// ─── Peer groups ─────────────────────────────────────────────────────────────

async fn groups_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_groups(&state).await?).into_response())
}

async fn group_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewGroup>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let g = engine
        .create_group(&state, &req.label, &req.members)
        .await?;
    Ok((StatusCode::CREATED, Json(g)).into_response())
}

async fn group_get(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_group(&state, &id).await?).into_response())
}

async fn group_update(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdateLabel>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.rename_group(&state, &id, &req.label).await?).into_response())
}

async fn group_delete(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_group(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

async fn group_members(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SetMembers>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let group = engine.set_group_members(&state, &id, &req.peer_ids).await?;
    Ok(saved(&engine, StatusCode::OK, Some(group)))
}

// ─── Grants ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
struct GrantParams {
    app: Option<String>,
    tag: Option<String>,
    reservation: Option<String>,
    peer: Option<String>,
    group: Option<String>,
}

async fn grants_list(
    State(state): State<Shared>,
    ApiQuery(q): ApiQuery<GrantParams>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let grants = engine
        .list_grants(
            &state,
            GrantFilter {
                app_id: q.app,
                tag_id: q.tag,
                reservation_id: q.reservation,
                peer_id: q.peer,
                group_id: q.group,
            },
        )
        .await?;
    Ok(Json(grants).into_response())
}

async fn grant_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewGrant>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let grant = engine.create_grant(&state, &req).await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(grant)))
}

async fn grant_delete(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_grant(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

/// Many changes at once, atomically, with one firewall update (ADR 0045).
async fn changes_post(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<ChangesRequest>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let result = engine.apply_changes(&state, &req).await?;
    if req.dry_run {
        return Ok(Json(result).into_response());
    }
    Ok(saved(&engine, StatusCode::OK, Some(result)))
}

// ─── Tags ────────────────────────────────────────────────────────────────────

async fn tags_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_tags(&state).await?).into_response())
}

async fn tag_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewTag>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let tag = engine
        .create_tag(&state, &req.label, &req.patterns, &req.members)
        .await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(tag)))
}

async fn tag_get(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_tag(&state, &id).await?).into_response())
}

async fn tag_update(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdateTag>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let tag = engine
        .update_tag(
            &state,
            &id,
            req.label.as_deref(),
            req.patterns.as_deref(),
            req.confirm_open,
        )
        .await?;
    Ok(saved(&engine, StatusCode::OK, Some(tag)))
}

async fn tag_delete(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_tag(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

async fn tag_member_add(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<NewTagMember>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let tag = engine
        .add_tag_member(&state, &id, &req.app_id, req.scope, req.confirm_open)
        .await?;
    Ok(saved(&engine, StatusCode::OK, Some(tag)))
}

async fn tag_member_remove(
    State(state): State<Shared>,
    Path((id, app_id)): Path<(String, String)>,
    ApiQuery(q): ApiQuery<MemberQuery>,
) -> ApiResult<Response> {
    let scope = q.scope().map_err(ApiErr::invalid)?;
    let engine = state.engine.read().await;
    let tag = engine
        .remove_tag_member(&state, &id, &app_id, scope)
        .await?;
    Ok(saved(&engine, StatusCode::OK, Some(tag)))
}

// ─── Port groups ───────────────────────────────────────────────────────────

async fn port_groups_list(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.list_port_groups(&state).await?).into_response())
}

async fn port_group_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewPortGroup>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let group = engine
        .create_port_group(
            &state,
            req.label.as_deref(),
            &req.ports,
            &req.apps,
            req.confirm_open,
        )
        .await?;
    Ok(saved(&engine, StatusCode::CREATED, Some(group)))
}

async fn port_group_get(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.get_port_group(&state, &id).await?).into_response())
}

async fn port_group_update(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdatePortGroup>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let group = engine
        .update_port_group(
            &state,
            &id,
            req.label.as_deref(),
            req.ports.as_deref(),
            req.confirm_open,
        )
        .await?;
    Ok(saved(&engine, StatusCode::OK, Some(group)))
}

async fn port_group_delete(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    engine.delete_port_group(&state, &id).await?;
    Ok(saved(&engine, StatusCode::NO_CONTENT, None::<()>))
}

async fn port_group_attach(
    State(state): State<Shared>,
    Path((id, app_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<AttachPortGroup>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let group = engine
        .attach_port_group(&state, &id, &app_id, req.confirm_open)
        .await?;
    Ok(saved(&engine, StatusCode::OK, Some(group)))
}

async fn port_group_detach(
    State(state): State<Shared>,
    Path((id, app_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let group = engine.detach_port_group(&state, &id, &app_id).await?;
    Ok(saved(&engine, StatusCode::OK, Some(group)))
}

// ─── Networks ────────────────────────────────────────────────────────────────

async fn networks_list(State(state): State<Shared>) -> ApiResult<Response> {
    Ok(Json(state.engine.read().await.networks()).into_response())
}

/// What can be added on this host and how far each kind is (ADR 0048). Reads only; the
/// probes run off the runtime, after the engine lock is released.
async fn networks_setup(State(state): State<Shared>) -> ApiResult<Response> {
    let (existing, block) = {
        let engine = state.engine.read().await;
        (
            crate::setup::Existing::from_networks(&engine.networks()),
            engine.yggdrasil_block(&state).await,
        )
    };
    let config_path = state.config_path.clone();
    let bundled = state.bundled.clone();
    let mut setup = tokio::task::spawn_blocking(move || {
        crate::setup::detect(
            &crate::setup::SystemProbes::default(),
            &existing,
            config_path.as_deref(),
            &bundled,
        )
    })
    .await
    .map_err(anyhow::Error::from)?;
    setup.yggdrasil_block = block;
    Ok(Json(setup).into_response())
}

async fn network_create(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<NewNetwork>,
) -> ApiResult<Response> {
    let id = req
        .id
        .filter(|i| !i.trim().is_empty())
        .unwrap_or_else(|| req.backend.default_id());
    if id == "setup" {
        return Err(ApiErr::invalid("\"setup\" is not a usable network id"));
    }
    check_managed(&state, &req.backend)?;
    check_tor_settings(&state, &req.backend).await?;
    let inst = BackendInstanceConfig {
        id,
        backend: req.backend,
    };
    // The write lock stays held until the file is written: two requests cannot save each
    // other's stale list.
    let mut engine = state.engine.write().await;
    let (network, applied) = engine.add_network(&state, inst).await?;
    persist_networks(&state, &engine).await;
    if let Err(e) = applied {
        // Saved and live, but the rules (and so the network's block) are not in force:
        // say so instead of a plain 201 (ADR 0051).
        let mut body = serde_json::to_value(&network).unwrap_or_default();
        if let Some(m) = body.as_object_mut() {
            m.insert(
                "enforcement".to_string(),
                serde_json::to_value(Enforcement {
                    status: EnforcementStatus::Failed,
                    message: format!(
                        "the network was added but the firewall rules could not be applied, \
                         so it is not closed yet; retrying ({e:#})"
                    ),
                })
                .unwrap_or_default(),
            );
        }
        return Ok((StatusCode::ACCEPTED, Json(body)).into_response());
    }
    Ok(saved(&engine, StatusCode::CREATED, Some(network)))
}

/// Replace the peers of a managed Yggdrasil network.
async fn network_peers(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SetPeers>,
) -> ApiResult<Response> {
    let mut engine = state.engine.write().await;
    let network = engine.set_peers(&state, &id, req.peers).await?;
    persist_networks(&state, &engine).await;
    Ok(Json(network).into_response())
}

#[derive(serde::Deserialize, Default)]
struct NetworkDeleteParams {
    #[serde(default)]
    force: bool,
    /// Remove a Yggdrasil network although its node keeps running (ADR 0051).
    #[serde(default)]
    confirm_exposed: bool,
}

async fn network_delete(
    State(state): State<Shared>,
    Path(id): Path<String>,
    ApiQuery(q): ApiQuery<NetworkDeleteParams>,
) -> ApiResult<StatusCode> {
    let mut engine = state.engine.write().await;
    if !q.confirm_exposed && !state.db.disabled().await {
        let exposure = engine.exposure(&state, Some(&id)).await?;
        if exposure.networks.iter().any(|n| n.node_running) {
            return Err(ApiErr {
                status: StatusCode::CONFLICT,
                body: ApiError {
                    code: error_code::CONFIRMATION_REQUIRED.to_string(),
                    message: "the network's software keeps running and its programs become \
                              reachable over it; confirm with confirm_exposed"
                        .to_string(),
                    details: serde_json::to_value(exposure).ok(),
                },
            });
        }
    }
    engine.remove_network(&state, &id, q.force).await?;
    persist_networks(&state, &engine).await;
    Ok(StatusCode::NO_CONTENT)
}

/// What becomes reachable without the block of a network (`without` an id, else all).
async fn exposure_get(
    State(state): State<Shared>,
    ApiQuery(q): ApiQuery<ExposureQuery>,
) -> ApiResult<Response> {
    let without = q.without.filter(|w| w != "all");
    let engine = state.engine.read().await;
    Ok(Json(engine.exposure(&state, without.as_deref()).await?).into_response())
}

/// A managed network (ADR 0052) needs the files of this build; any API caller may add one.
fn check_managed(state: &AppState, backend: &BackendConfig) -> Result<(), ApiErr> {
    if !backend.is_managed() {
        return Ok(());
    }
    backend.validate_managed().map_err(ApiErr::invalid)?;
    let files = match backend {
        BackendConfig::Tor { .. } => state.bundled.tor().map(|_| ()),
        _ => state.bundled.yggdrasil().map(|_| ()),
    };
    files.map_err(ApiErr::invalid)
}

/// The Tor settings the API accepts: the defaults, or exactly what the config file already
/// has for a Tor network. Every `socketguard` group member may call the API, and the Tor
/// control endpoint decides who receives the onion keys (a Unix socket or an
/// authentication of their choosing would hand them over), so anything else is for the
/// administrator who edits the file. The file is read afresh: `state.config` also holds
/// what the API added itself.
async fn check_tor_settings(state: &AppState, backend: &BackendConfig) -> Result<(), ApiErr> {
    if !matches!(backend, BackendConfig::Tor { .. })
        || *backend == BackendConfig::default_tor()
        || (backend.is_managed() && backend.validate_managed().is_ok())
    {
        return Ok(());
    }
    let from_file = match &state.config_path {
        Some(path) => tokio::fs::read_to_string(path).await.ok(),
        None => None,
    }
    .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
    .and_then(|doc| doc.get("backends").cloned())
    .and_then(|b| serde_json::from_value::<Vec<BackendInstanceConfig>>(b).ok())
    .unwrap_or_default();
    if from_file.iter().any(|b| b.backend == *backend) {
        return Ok(());
    }
    Err(ApiErr::invalid(
        "a Tor network made through the API uses the default control port and authentication; \
         other settings (control address, auth, cookie_path, ...) go in the config file, which \
         only an administrator can edit",
    ))
}

/// Save the network list to the config file so it survives a restart. The change is
/// already live, so a failure is logged rather than failing the request. The caller holds
/// the engine's write lock, so the list is current and writes do not interleave.
async fn persist_networks(state: &AppState, engine: &Engine) {
    let Some(path) = &state.config_path else {
        return;
    };
    let mut config = state.config.read().await.clone();
    config.backends = engine.backend_configs();
    let path = path.clone();
    let result =
        tokio::task::spawn_blocking(move || crate::config_file::persist_backends(&path, &config))
            .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Networks not saved to the config file: {e:#}"),
        Err(e) => tracing::warn!("Saving the config file failed: {e}"),
    }
}

// ─── Settings ────────────────────────────────────────────────────────────────

async fn settings_get(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(engine.settings(&state).await?).into_response())
}

async fn protect_host_put(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<ProtectHostRequest>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    match engine
        .set_protect_host(&state, req.interfaces, req.force)
        .await
    {
        Ok(risks) => Ok(Json(ProtectHostResponse {
            settings: engine.settings(&state).await?,
            overridden: risks.iter().map(risk_info).collect(),
        })
        .into_response()),
        Err(e) => Err(match e {
            ProtectHostError::Lockout(ref risks) => {
                let infos: Vec<LockoutRiskInfo> = risks.iter().map(risk_info).collect();
                ApiErr {
                    status: StatusCode::CONFLICT,
                    body: ApiError {
                        code: error_code::PROTECT_HOST_REFUSED.to_string(),
                        message: e.to_string(),
                        details: serde_json::to_value(infos).ok(),
                    },
                }
            }
            ProtectHostError::Invalid(msg) => ApiErr::invalid(msg),
            ProtectHostError::Other(e) => e.into(),
        }),
    }
}

// ─── Activity, export, maintenance ───────────────────────────────────────────

async fn activity_list(
    State(state): State<Shared>,
    ApiQuery(q): ApiQuery<ActivityQuery>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    let records = engine.activity(&state, &q).await?;
    Ok(Json(records).into_response())
}

async fn export_get(State(state): State<Shared>) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(apply::export(&engine, &state).await?).into_response())
}

async fn apply_post(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<ApplyRequest>,
) -> ApiResult<Response> {
    let engine = state.engine.read().await;
    Ok(Json(apply::apply(&engine, &state, req).await?).into_response())
}

async fn disable_post(
    State(state): State<Shared>,
    ApiJson(req): ApiJson<DisableRequest>,
) -> ApiResult<StatusCode> {
    if !req.confirm {
        return Err(ApiErr::new(
            StatusCode::CONFLICT,
            error_code::CONFIRMATION_REQUIRED,
            "disabling removes every SocketGuard firewall rule and address; confirm it with {\"confirm\": true}",
        ));
    }
    state.engine.read().await.disable(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn enable_post(State(state): State<Shared>) -> ApiResult<StatusCode> {
    state.engine.read().await.enable(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}
