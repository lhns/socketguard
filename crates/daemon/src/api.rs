use crate::AppState;
use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::sse::{Event, KeepAlive, Sse},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use futures_util::stream::Stream;
use futures_util::StreamExt;
use socketguard_core::api_types::*;
use socketguard_core::config::{BackendInstanceConfig, DaemonConfig};
use std::convert::Infallible;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;

#[derive(Debug, Clone)]
pub enum DaemonEvent {
    SocketsChanged,
    ConfigChanged,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/sockets", get(list_sockets))
        .route("/api/sockets/{id}", get(get_socket))
        .route("/api/sockets/{id}/acl/allow", post(allow_ip_all))
        .route("/api/sockets/{id}/acl/{entry_id}", delete(remove_acl_entry))
        .route("/api/sockets/{id}/policy", put(update_policy_all))
        // Per-backend routes (ADR 0017)
        .route("/api/sockets/{id}/backends/{backend_id}/policy", put(update_backend_policy))
        .route("/api/sockets/{id}/backends/{backend_id}/acl/allow", post(allow_backend_ip))
        .route("/api/sockets/{id}/backends/{backend_id}/acl/{entry_id}", delete(remove_acl_entry))
        .route("/api/config", get(get_config))
        .route("/api/config", put(update_config))
        .route("/api/backends", get(list_backends))
        .route("/api/backends", post(add_backend))
        .route("/api/backends/{id}", delete(remove_backend))
        .route("/api/interfaces", get(list_interfaces))
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

async fn sse_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        futures_util::future::ready(match result {
            Ok(event) => {
                let event_name = match event {
                    DaemonEvent::SocketsChanged => "sockets_changed",
                    DaemonEvent::ConfigChanged => "config_changed",
                };
                Some(Ok(Event::default().event(event_name).data("")))
            }
            Err(_) => None,
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn bad_request(msg: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: msg.into(),
        }),
    )
}

fn not_found(msg: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            error: msg.into(),
        }),
    )
}

fn internal_error(msg: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: msg.into(),
        }),
    )
}

fn conflict(msg: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        Json(ApiError {
            error: msg.into(),
        }),
    )
}

async fn list_sockets(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.list_sockets().await {
        Ok(sockets) => Json(SocketListResponse { sockets }).into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn get_socket(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let socket = match state.db.get_socket(&id).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    };

    let acl = match state.db.get_acl(&id).await {
        Ok(a) => a,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };

    Json(SocketDetailResponse { socket, acl }).into_response()
}

/// Add ACL entry to ALL backends for a socket (fan-out, legacy compat).
async fn allow_ip_all(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AllowIpRequest>,
) -> impl IntoResponse {
    if req.allowed_ip.parse::<Ipv6Addr>().is_err() {
        return bad_request(format!("invalid IPv6 address: '{}'", req.allowed_ip)).into_response();
    }

    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state
        .db
        .add_acl_entry_all_backends(&id, &req.allowed_ip, req.label.as_deref())
        .await
    {
        Ok(entries) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &id).await {
                tracing::warn!("Firewall update failed after adding ACL entries: {e}");
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            (StatusCode::CREATED, Json(entries)).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

/// Add ACL entry for a specific backend (ADR 0017).
async fn allow_backend_ip(
    State(state): State<Arc<AppState>>,
    Path((id, backend_id)): Path<(String, String)>,
    Json(req): Json<AllowIpRequest>,
) -> impl IntoResponse {
    if req.allowed_ip.parse::<Ipv6Addr>().is_err() {
        return bad_request(format!("invalid IPv6 address: '{}'", req.allowed_ip)).into_response();
    }

    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state
        .db
        .add_acl_entry(&id, &backend_id, &req.allowed_ip, req.label.as_deref())
        .await
    {
        Ok(entry) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &id).await {
                tracing::warn!("Firewall update failed after adding ACL entry: {e}");
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn remove_acl_entry(
    State(state): State<Arc<AppState>>,
    Path((id, entry_id)): Path<(String, i64)>,
) -> impl IntoResponse {
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.delete_acl_entry(entry_id).await {
        Ok(_) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &id).await {
                tracing::warn!("Firewall update failed after removing ACL entry: {e}");
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

/// Set policy on ALL backends for a socket (fan-out, legacy compat).
async fn update_policy_all(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.update_policy_all_backends(&id, req.policy).await {
        Ok(_) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &id).await {
                return internal_error(format!("Policy saved but firewall update failed: {e}"))
                    .into_response();
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

/// Set policy on a specific backend for a socket (ADR 0017).
async fn update_backend_policy(
    State(state): State<Arc<AppState>>,
    Path((id, backend_id)): Path<(String, String)>,
    Json(req): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.update_address_policy(&id, &backend_id, req.policy).await {
        Ok(_) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &id).await {
                return internal_error(format!("Policy saved but firewall update failed: {e}"))
                    .into_response();
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    Json(ConfigResponse {
        listen_addr: config.listen_addr.clone(),
        listen_port: config.listen_port,
        backends: config.backends.clone(),
        poll_interval_secs: config.poll_interval_secs,
        process_filter: config.process_filter.clone(),
    })
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    if let Some(interval) = req.poll_interval_secs {
        if interval == 0 || interval > 3600 {
            return bad_request("poll_interval_secs must be between 1 and 3600").into_response();
        }
    }
    if let Some(ref backends) = req.backends {
        if let Err(e) = DaemonConfig::validate_backends(backends) {
            return bad_request(e).into_response();
        }
    }

    let mut config = state.config.write().await;
    if let Some(backends) = req.backends {
        config.backends = backends;
    }
    if let Some(interval) = req.poll_interval_secs {
        config.poll_interval_secs = interval;
    }
    if let Some(process_filter) = req.process_filter {
        config.process_filter = process_filter;
    }
    let _ = state.events.send(DaemonEvent::ConfigChanged);
    StatusCode::OK.into_response()
}

async fn list_backends(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    Json(BackendsResponse {
        available_types: vec![
            BackendInfo {
                name: socketguard_core::BackendType::Ula,
                description: "Random ULA addresses (fd00::/8) - local only, no external dependencies".to_string(),
                available: true,
                singleton: true,
            },
            BackendInfo {
                name: socketguard_core::BackendType::Yggdrasil,
                description: "Yggdrasil-derived addresses (200::/7) - routable on Yggdrasil overlay".to_string(),
                available: true,
                singleton: true,
            },
            BackendInfo {
                name: socketguard_core::BackendType::Slaac,
                description: "SLAAC addresses from existing /64 prefix - routable on LAN".to_string(),
                available: true,
                singleton: false,
            },
            BackendInfo {
                name: socketguard_core::BackendType::Dhcpv6,
                description: "DHCPv6 addresses from a DHCPv6 server - server-managed, routable".to_string(),
                available: true,
                singleton: false,
            },
        ],
        active_instances: config.backends.clone(),
    })
}

async fn add_backend(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddBackendRequest>,
) -> impl IntoResponse {
    let id = req.id.unwrap_or_else(|| req.backend.default_id());

    if id.is_empty() {
        return bad_request("backend instance ID must not be empty").into_response();
    }
    if req.backend.interface().is_empty() {
        return bad_request("interface must not be empty").into_response();
    }

    let inst = BackendInstanceConfig {
        id: id.clone(),
        backend: req.backend,
    };

    // Check constraints
    {
        let config = state.config.read().await;
        let mut proposed = config.backends.clone();
        proposed.push(inst.clone());
        if let Err(e) = DaemonConfig::validate_backends(&proposed) {
            return conflict(e).into_response();
        }
    }

    // Add to engine (allocates addresses for all sockets)
    {
        let mut engine = state.engine.write().await;
        engine.add_backend_instance(&state, &inst).await;
    }

    // Update config
    {
        let mut config = state.config.write().await;
        config.backends.push(inst.clone());
    }

    let _ = state.events.send(DaemonEvent::ConfigChanged);
    let _ = state.events.send(DaemonEvent::SocketsChanged);
    (StatusCode::CREATED, Json(inst)).into_response()
}

async fn remove_backend(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Check that the backend exists
    {
        let config = state.config.read().await;
        if !config.backends.iter().any(|b| b.id == id) {
            return not_found(format!("backend instance '{}' not found", id)).into_response();
        }
    }

    // Remove from engine (cleans up addresses)
    {
        let mut engine = state.engine.write().await;
        engine.remove_backend_instance(&state, &id).await;
    }

    // Update config
    {
        let mut config = state.config.write().await;
        config.backends.retain(|b| b.id != id);
    }

    let _ = state.events.send(DaemonEvent::ConfigChanged);
    let _ = state.events.send(DaemonEvent::SocketsChanged);
    StatusCode::NO_CONTENT.into_response()
}

async fn list_interfaces() -> impl IntoResponse {
    let network = crate::network::create_network_interface();
    match network.list_interfaces() {
        Ok(interfaces) => Json(InterfacesResponse { interfaces }).into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}
