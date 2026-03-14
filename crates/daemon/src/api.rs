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
        // ACL group routes (ADR 0018)
        .route("/api/acl-groups", get(list_acl_groups))
        .route("/api/acl-groups", post(create_acl_group))
        .route("/api/acl-groups/{id}", get(get_acl_group))
        .route("/api/acl-groups/{id}", put(update_acl_group))
        .route("/api/acl-groups/{id}", delete(delete_acl_group))
        .route("/api/acl-groups/{id}/members", post(add_acl_group_members))
        .route("/api/acl-groups/{id}/members/{socket_id}", delete(remove_acl_group_member))
        .route("/api/acl-groups/{id}/acl", post(add_acl_group_entry))
        .route("/api/acl-groups/{id}/acl/{entry_id}", delete(remove_acl_group_entry))
        // Socket group routes (ADR 0018)
        .route("/api/socket-groups", get(list_socket_groups))
        .route("/api/socket-groups", post(create_socket_group))
        .route("/api/socket-groups/{id}", delete(delete_socket_group))
        .route("/api/socket-groups/{id}/members", post(add_socket_group_members))
        .route("/api/socket-groups/{id}/members/{socket_id}", delete(remove_socket_group_member))
        // Config, backends, interfaces, events
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

// ======== Socket endpoints ========

async fn list_sockets(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sockets = match state.db.list_sockets().await {
        Ok(s) => s,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };

    let acl_groups = match build_acl_group_responses(&state).await {
        Ok(g) => g,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };

    let socket_groups = match build_socket_group_responses(&state).await {
        Ok(g) => g,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };

    Json(SocketListResponse { sockets, acl_groups, socket_groups }).into_response()
}

async fn build_acl_group_responses(state: &AppState) -> anyhow::Result<Vec<AclGroupResponse>> {
    let groups = state.db.list_acl_groups().await?;
    let mut responses = Vec::new();
    for group in groups {
        let entries = state.db.get_acl_group_entries(&group.id).await?;
        let members = state.db.get_acl_group_members(&group.id).await?;
        responses.push(AclGroupResponse { group, entries, members });
    }
    Ok(responses)
}

async fn build_socket_group_responses(state: &AppState) -> anyhow::Result<Vec<SocketGroupResponse>> {
    let groups = state.db.list_socket_groups().await?;
    let mut responses = Vec::new();
    for group in groups {
        let addresses = state.db.get_socket_group_addresses(&group.id).await?;
        let members = state.db.get_socket_group_members(&group.id).await?;
        responses.push(SocketGroupResponse { group, addresses, members });
    }
    Ok(responses)
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

    let acl_group_id = socket.acl_group_id.clone();

    Json(SocketDetailResponse { socket, acl, acl_group_id }).into_response()
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

// ======== ACL Group endpoints (ADR 0018) ========

async fn list_acl_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match build_acl_group_responses(&state).await {
        Ok(groups) => Json(groups).into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn create_acl_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAclGroupRequest>,
) -> impl IntoResponse {
    if req.label.trim().is_empty() {
        return bad_request("label must not be empty").into_response();
    }
    match state.db.create_acl_group(&req.label).await {
        Ok(group) => {
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            (StatusCode::CREATED, Json(AclGroupResponse {
                group,
                entries: vec![],
                members: vec![],
            })).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn get_acl_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let group = match state.db.get_acl_group(&id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    };
    let entries = match state.db.get_acl_group_entries(&id).await {
        Ok(e) => e,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };
    let members = match state.db.get_acl_group_members(&id).await {
        Ok(m) => m,
        Err(e) => return internal_error(e.to_string()).into_response(),
    };
    Json(AclGroupResponse { group, entries, members }).into_response()
}

async fn update_acl_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAclGroupRequest>,
) -> impl IntoResponse {
    match state.db.get_acl_group(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.update_acl_group(&id, req.label.as_deref(), req.policy).await {
        Ok(_) => {
            // Re-apply firewall for all member sockets
            if let Ok(members) = state.db.get_acl_group_members(&id).await {
                let engine = state.engine.read().await;
                for socket_id in &members {
                    if let Err(e) = engine.apply_socket_acl(&state, socket_id).await {
                        tracing::warn!("Failed to update firewall for socket {socket_id} after group update: {e}");
                    }
                }
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn delete_acl_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_acl_group(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    // Get members before deleting so we can re-apply firewall
    let members = state.db.get_acl_group_members(&id).await.unwrap_or_default();

    match state.db.delete_acl_group(&id).await {
        Ok(_) => {
            let engine = state.engine.read().await;
            for socket_id in &members {
                if let Err(e) = engine.apply_socket_acl(&state, socket_id).await {
                    tracing::warn!("Failed to update firewall for socket {socket_id} after group deletion: {e}");
                }
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn add_acl_group_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddToGroupRequest>,
) -> impl IntoResponse {
    match state.db.get_acl_group(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    for socket_id in &req.socket_ids {
        if let Err(e) = state.db.add_to_acl_group(&id, socket_id).await {
            return internal_error(format!("Failed to add socket {socket_id}: {e}")).into_response();
        }
    }

    // Re-apply firewall for newly added members
    let engine = state.engine.read().await;
    for socket_id in &req.socket_ids {
        if let Err(e) = engine.apply_socket_acl(&state, socket_id).await {
            tracing::warn!("Failed to update firewall for socket {socket_id}: {e}");
        }
    }

    let _ = state.events.send(DaemonEvent::SocketsChanged);
    StatusCode::OK.into_response()
}

async fn remove_acl_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, socket_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.remove_from_acl_group(&id, &socket_id).await {
        Ok(_) => {
            if let Err(e) = state.engine.read().await.apply_socket_acl(&state, &socket_id).await {
                tracing::warn!("Failed to update firewall for socket {socket_id}: {e}");
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn add_acl_group_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddAclGroupEntryRequest>,
) -> impl IntoResponse {
    if req.allowed_ip.parse::<Ipv6Addr>().is_err() {
        return bad_request(format!("invalid IPv6 address: '{}'", req.allowed_ip)).into_response();
    }

    match state.db.get_acl_group(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.add_acl_group_entry(&id, &req.backend_id, &req.allowed_ip, req.label.as_deref()).await {
        Ok(entry) => {
            // Re-apply firewall for all members
            if let Ok(members) = state.db.get_acl_group_members(&id).await {
                let engine = state.engine.read().await;
                for socket_id in &members {
                    if let Err(e) = engine.apply_socket_acl(&state, socket_id).await {
                        tracing::warn!("Failed to update firewall for socket {socket_id}: {e}");
                    }
                }
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn remove_acl_group_entry(
    State(state): State<Arc<AppState>>,
    Path((id, entry_id)): Path<(String, i64)>,
) -> impl IntoResponse {
    match state.db.get_acl_group(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("ACL group not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.remove_acl_group_entry(entry_id).await {
        Ok(_) => {
            if let Ok(members) = state.db.get_acl_group_members(&id).await {
                let engine = state.engine.read().await;
                for socket_id in &members {
                    if let Err(e) = engine.apply_socket_acl(&state, socket_id).await {
                        tracing::warn!("Failed to update firewall for socket {socket_id}: {e}");
                    }
                }
            }
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

// ======== Socket Group endpoints (ADR 0018) ========

async fn list_socket_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match build_socket_group_responses(&state).await {
        Ok(groups) => Json(groups).into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn create_socket_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSocketGroupRequest>,
) -> impl IntoResponse {
    if req.label.trim().is_empty() {
        return bad_request("label must not be empty").into_response();
    }
    match state.db.create_socket_group(&req.label, &req.app_name).await {
        Ok(group) => {
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            (StatusCode::CREATED, Json(SocketGroupResponse {
                group,
                addresses: vec![],
                members: vec![],
            })).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn delete_socket_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_socket_group(&id).await {
        Ok(_) => {
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn add_socket_group_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddToGroupRequest>,
) -> impl IntoResponse {
    for socket_id in &req.socket_ids {
        if let Err(e) = state.db.add_socket_to_group(&id, socket_id).await {
            return internal_error(format!("Failed to add socket {socket_id}: {e}")).into_response();
        }
    }
    let _ = state.events.send(DaemonEvent::SocketsChanged);
    StatusCode::OK.into_response()
}

async fn remove_socket_group_member(
    State(state): State<Arc<AppState>>,
    Path((_id, socket_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.db.remove_socket_from_group(&socket_id).await {
        Ok(_) => {
            let _ = state.events.send(DaemonEvent::SocketsChanged);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

// ======== Config, Backends, Interfaces ========

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
