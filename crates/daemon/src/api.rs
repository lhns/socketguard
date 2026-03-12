use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use socketguard_core::api_types::*;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/sockets", get(list_sockets))
        .route("/api/sockets/{id}", get(get_socket))
        .route("/api/sockets/{id}/acl", put(update_acl))
        .route("/api/sockets/{id}/acl/allow", post(allow_ip))
        .route("/api/sockets/{id}/acl/{entry_id}", delete(remove_acl_entry))
        .route("/api/sockets/{id}/policy", put(update_policy))
        .route("/api/config", get(get_config))
        .route("/api/config", put(update_config))
        .route("/api/backends", get(list_backends))
        .layer(CorsLayer::permissive())
        .with_state(state)
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

async fn update_acl(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> impl IntoResponse {
    // Validate socket exists
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    // Validate all IPs before making any changes
    for entry in &req.entries {
        if entry.allowed_ip.parse::<Ipv6Addr>().is_err() {
            return bad_request(format!("invalid IPv6 address: '{}'", entry.allowed_ip))
                .into_response();
        }
    }

    let entries: Vec<(String, Option<String>)> = req
        .entries
        .into_iter()
        .map(|e| (e.allowed_ip, e.label))
        .collect();

    match state.db.replace_acl(&id, &entries).await {
        Ok(_) => {
            if let Err(e) = state.engine.apply_socket_acl(&state, &id).await {
                return internal_error(format!("ACL saved but firewall update failed: {e}"))
                    .into_response();
            }
            StatusCode::OK.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn allow_ip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AllowIpRequest>,
) -> impl IntoResponse {
    // Validate IPv6 address
    if req.allowed_ip.parse::<Ipv6Addr>().is_err() {
        return bad_request(format!("invalid IPv6 address: '{}'", req.allowed_ip)).into_response();
    }

    // Validate socket exists
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state
        .db
        .add_acl_entry(&id, &req.allowed_ip, req.label.as_deref())
        .await
    {
        Ok(entry) => {
            if let Err(e) = state.engine.apply_socket_acl(&state, &id).await {
                tracing::warn!("Firewall update failed after adding ACL entry: {e}");
            }
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn remove_acl_entry(
    State(state): State<Arc<AppState>>,
    Path((id, entry_id)): Path<(String, i64)>,
) -> impl IntoResponse {
    // Validate socket exists
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.delete_acl_entry(entry_id).await {
        Ok(_) => {
            if let Err(e) = state.engine.apply_socket_acl(&state, &id).await {
                tracing::warn!("Firewall update failed after removing ACL entry: {e}");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    // Validate socket exists
    match state.db.get_socket(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("socket not found").into_response(),
        Err(e) => return internal_error(e.to_string()).into_response(),
    }

    match state.db.update_policy(&id, req.policy).await {
        Ok(_) => {
            if let Err(e) = state.engine.apply_socket_acl(&state, &id).await {
                return internal_error(format!("Policy saved but firewall update failed: {e}"))
                    .into_response();
            }
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
        backend: config.backend,
        interface: config.interface.clone(),
        poll_interval_secs: config.poll_interval_secs,
    })
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    // Validate config values
    if let Some(interval) = req.poll_interval_secs {
        if interval == 0 || interval > 3600 {
            return bad_request("poll_interval_secs must be between 1 and 3600").into_response();
        }
    }
    if let Some(ref iface) = req.interface {
        if iface.is_empty() {
            return bad_request("interface must not be empty").into_response();
        }
    }

    let mut config = state.config.write().await;
    if let Some(backend) = req.backend {
        config.backend = backend;
    }
    if let Some(iface) = req.interface {
        config.interface = iface;
    }
    if let Some(interval) = req.poll_interval_secs {
        config.poll_interval_secs = interval;
    }
    StatusCode::OK.into_response()
}

async fn list_backends() -> impl IntoResponse {
    Json(BackendsResponse {
        backends: vec![
            BackendInfo {
                name: socketguard_core::BackendType::Ula,
                description: "Random ULA addresses (fd00::/8) - no external dependencies".to_string(),
                available: true,
            },
            BackendInfo {
                name: socketguard_core::BackendType::Yggdrasil,
                description: "Yggdrasil-derived addresses (200::/7) - requires ed25519 keypair generation".to_string(),
                available: true,
            },
        ],
    })
}
