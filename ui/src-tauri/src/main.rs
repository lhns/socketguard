#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use socketguard_core::api_types::*;
use socketguard_core::config::BackendInstanceConfig;
use socketguard_core::Policy;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;
use tauri::Emitter;

const DEFAULT_API: &str = "http://127.0.0.1:9476";

fn api_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        std::env::var("SOCKETGUARD_API").unwrap_or_else(|_| DEFAULT_API.to_string())
    })
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .expect("failed to build HTTP client")
    })
}

/// Shared, re-readable API token.
fn token_store() -> &'static Arc<RwLock<Option<String>>> {
    static STORE: OnceLock<Arc<RwLock<Option<String>>>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(RwLock::new(read_api_token())))
}

fn read_api_token() -> Option<String> {
    std::fs::read_to_string(socketguard_core::api_token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

fn get_token() -> Result<String, String> {
    let store = token_store();
    {
        let guard = store.read().unwrap();
        if let Some(ref t) = *guard {
            return Ok(t.clone());
        }
    }
    // Token not cached yet — try reading from disk (daemon may have started since)
    refresh_token()
}

/// Re-read token from disk (after a 401 / daemon restart).
fn refresh_token() -> Result<String, String> {
    let store = token_store();
    let mut guard = store.write().unwrap();
    *guard = read_api_token();
    guard
        .clone()
        .ok_or_else(|| "API token not available after refresh".into())
}

/// Send a request with Bearer auth, retry once on 401 after refreshing the token.
async fn authed_request(
    build: impl Fn(&str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, String> {
    let token = get_token()?;
    let resp = build(&token).send().await.map_err(|e| e.to_string())?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let token = refresh_token()?;
        return build(&token).send().await.map_err(|e| e.to_string());
    }

    Ok(resp)
}

/// Check response status; on non-success parse ApiError body.
async fn check_response(resp: reqwest::Response) -> Result<(), String> {
    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

// ======== Socket commands ========

#[tauri::command]
async fn list_sockets() -> Result<SocketListResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/sockets", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_socket(id: String) -> Result<SocketDetailResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/sockets/{id}", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn allow_ip(socket_id: String, ip: String, label: Option<String>) -> Result<(), String> {
    let req = AllowIpRequest {
        allowed_ip: ip,
        label,
    };
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/sockets/{socket_id}/acl/allow", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn remove_acl_entry(socket_id: String, entry_id: i64) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!(
                "{}/api/sockets/{socket_id}/acl/{entry_id}",
                api_base()
            ))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn set_policy(socket_id: String, policy: String) -> Result<(), String> {
    let policy: Policy = policy.parse().map_err(|e: String| e)?;
    let req = UpdatePolicyRequest { policy };
    let resp = authed_request(|token| {
        client()
            .put(format!("{}/api/sockets/{socket_id}/policy", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn set_backend_policy(
    socket_id: String,
    backend_id: String,
    policy: String,
) -> Result<(), String> {
    let policy: Policy = policy.parse().map_err(|e: String| e)?;
    let req = UpdatePolicyRequest { policy };
    let resp = authed_request(|token| {
        client()
            .put(format!(
                "{}/api/sockets/{socket_id}/backends/{backend_id}/policy",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn allow_backend_ip(
    socket_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<(), String> {
    let req = AllowIpRequest {
        allowed_ip: ip,
        label,
    };
    let resp = authed_request(|token| {
        client()
            .post(format!(
                "{}/api/sockets/{socket_id}/backends/{backend_id}/acl/allow",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

// ======== ACL Group commands (ADR 0018) ========

#[tauri::command]
async fn list_acl_groups() -> Result<Vec<AclGroupResponse>, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/acl-groups", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_acl_group(label: String) -> Result<AclGroupResponse, String> {
    let req = CreateAclGroupRequest { label };
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/acl-groups", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    if resp.status().is_success() {
        resp.json().await.map_err(|e| e.to_string())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn get_acl_group(id: String) -> Result<AclGroupResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/acl-groups/{id}", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_acl_group(
    id: String,
    label: Option<String>,
    policy: Option<String>,
) -> Result<(), String> {
    let policy = match policy {
        Some(p) => Some(p.parse::<Policy>().map_err(|e: String| e)?),
        None => None,
    };
    let req = UpdateAclGroupRequest { label, policy };
    let resp = authed_request(|token| {
        client()
            .put(format!("{}/api/acl-groups/{id}", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn delete_acl_group(id: String) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!("{}/api/acl-groups/{id}", api_base()))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn add_to_acl_group(group_id: String, socket_ids: Vec<String>) -> Result<(), String> {
    let req = AddToGroupRequest { socket_ids };
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/acl-groups/{group_id}/members", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn remove_from_acl_group(group_id: String, socket_id: String) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!(
                "{}/api/acl-groups/{group_id}/members/{socket_id}",
                api_base()
            ))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn add_acl_group_entry(
    group_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<(), String> {
    let req = AddAclGroupEntryRequest {
        backend_id,
        allowed_ip: ip,
        label,
    };
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/acl-groups/{group_id}/acl", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn remove_acl_group_entry(group_id: String, entry_id: i64) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!(
                "{}/api/acl-groups/{group_id}/acl/{entry_id}",
                api_base()
            ))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

// ======== Socket Group commands (ADR 0018) ========

#[tauri::command]
async fn list_socket_groups() -> Result<Vec<SocketGroupResponse>, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/socket-groups", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_socket_group(
    label: String,
    app_name: String,
) -> Result<SocketGroupResponse, String> {
    let req = CreateSocketGroupRequest { label, app_name };
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/socket-groups", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    if resp.status().is_success() {
        resp.json().await.map_err(|e| e.to_string())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn update_socket_group(id: String, label: String) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Req {
        label: Option<String>,
    }
    let req = Req { label: Some(label) };
    let resp = authed_request(|token| {
        client()
            .put(format!("{}/api/socket-groups/{id}", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn delete_socket_group(id: String) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!("{}/api/socket-groups/{id}", api_base()))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn add_socket_to_socket_group(
    group_id: String,
    socket_ids: Vec<String>,
) -> Result<(), String> {
    let req = AddToGroupRequest { socket_ids };
    let resp = authed_request(|token| {
        client()
            .post(format!(
                "{}/api/socket-groups/{group_id}/members",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn remove_socket_from_socket_group(
    group_id: String,
    socket_id: String,
) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!(
                "{}/api/socket-groups/{group_id}/members/{socket_id}",
                api_base()
            ))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

// ======== Socket Group address policy & ACL ========

#[tauri::command]
async fn set_socket_group_address_policy(
    group_id: String,
    backend_id: String,
    policy: String,
) -> Result<(), String> {
    let policy: Policy = policy.parse().map_err(|e: String| e)?;
    let req = UpdatePolicyRequest { policy };
    let resp = authed_request(|token| {
        client()
            .put(format!(
                "{}/api/socket-groups/{group_id}/backends/{backend_id}/policy",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn add_socket_group_acl_entry(
    group_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<(), String> {
    let req = AllowIpRequest {
        allowed_ip: ip,
        label,
    };
    let resp = authed_request(|token| {
        client()
            .post(format!(
                "{}/api/socket-groups/{group_id}/backends/{backend_id}/acl",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn remove_socket_group_acl_entry(group_id: String, entry_id: i64) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!(
                "{}/api/socket-groups/{group_id}/acl/{entry_id}",
                api_base()
            ))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

// ======== Socket Group ACL Group (ADR 0020) ========

#[tauri::command]
async fn set_socket_group_acl_group(
    group_id: String,
    acl_group_id: Option<String>,
) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Req {
        acl_group_id: Option<String>,
    }
    let req = Req { acl_group_id };
    let resp = authed_request(|token| {
        client()
            .put(format!(
                "{}/api/socket-groups/{group_id}/acl-group",
                api_base()
            ))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    check_response(resp).await
}

// ======== Config, Backends, Interfaces, Events, Daemon ========

#[tauri::command]
async fn get_config() -> Result<ConfigResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/config", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_config(config: UpdateConfigRequest) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .put(format!("{}/api/config", api_base()))
            .bearer_auth(token)
            .json(&config)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn list_interfaces() -> Result<InterfacesResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/interfaces", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_backend_instances() -> Result<BackendsResponse, String> {
    let resp = authed_request(|token| {
        client()
            .get(format!("{}/api/backends", api_base()))
            .bearer_auth(token)
    })
    .await?;
    resp.json().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_backend(req: AddBackendRequest) -> Result<BackendInstanceConfig, String> {
    let resp = authed_request(|token| {
        client()
            .post(format!("{}/api/backends", api_base()))
            .bearer_auth(token)
            .json(&req)
    })
    .await?;
    if resp.status().is_success() {
        resp.json().await.map_err(|e| e.to_string())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn remove_backend(id: String) -> Result<(), String> {
    let resp = authed_request(|token| {
        client()
            .delete(format!("{}/api/backends/{id}", api_base()))
            .bearer_auth(token)
    })
    .await?;
    check_response(resp).await
}

#[tauri::command]
async fn subscribe_events(app: tauri::AppHandle) -> Result<(), String> {
    tokio::spawn(async move {
        loop {
            match connect_sse(&app).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("SSE connection error: {e}");
                }
            }
            let _ = app.emit("daemon_disconnected", ());
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    Ok(())
}

async fn connect_sse(app: &tauri::AppHandle) -> Result<(), String> {
    let token = get_token().unwrap_or_default();
    let resp = reqwest::Client::new()
        .get(format!("{}/api/events", api_base()))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let token = refresh_token()?;
        let resp = reqwest::Client::new()
            .get(format!("{}/api/events", api_base()))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        return process_sse_stream(app, resp).await;
    }

    let _ = app.emit("daemon_connected", ());
    process_sse_stream(app, resp).await
}

async fn process_sse_stream(app: &tauri::AppHandle, resp: reqwest::Response) -> Result<(), String> {
    let _ = app.emit("daemon_connected", ());

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buf.find("\n\n") {
            let message = buf[..pos].to_string();
            buf = buf[pos + 2..].to_string();

            for line in message.lines() {
                if let Some(event_name) = line.strip_prefix("event: ") {
                    let event_name = event_name.trim();
                    let _ = app.emit(event_name, ());
                }
            }
        }
    }

    Ok(())
}

#[tauri::command]
async fn start_daemon() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let daemon = exe.parent().unwrap().join("socketguard-daemon.exe");
    if !daemon.exists() {
        return Err("socketguard-daemon.exe not found next to UI executable".into());
    }
    spawn_elevated(&daemon).map_err(|e| e.to_string())
}

fn spawn_elevated(path: &Path) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_HIDE,
        )
    };

    let code = result.0 as isize;
    if code > 32 {
        Ok(())
    } else {
        anyhow::bail!("ShellExecuteW failed with code {code}")
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            list_sockets,
            get_socket,
            allow_ip,
            remove_acl_entry,
            set_policy,
            set_backend_policy,
            allow_backend_ip,
            // ACL groups (ADR 0018)
            list_acl_groups,
            create_acl_group,
            get_acl_group,
            update_acl_group,
            delete_acl_group,
            add_to_acl_group,
            remove_from_acl_group,
            add_acl_group_entry,
            remove_acl_group_entry,
            // Socket groups (ADR 0018)
            list_socket_groups,
            create_socket_group,
            update_socket_group,
            delete_socket_group,
            add_socket_to_socket_group,
            remove_socket_from_socket_group,
            set_socket_group_address_policy,
            add_socket_group_acl_entry,
            remove_socket_group_acl_entry,
            set_socket_group_acl_group,
            // Config, backends, events
            get_config,
            update_config,
            list_interfaces,
            list_backend_instances,
            add_backend,
            remove_backend,
            subscribe_events,
            start_daemon,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}
