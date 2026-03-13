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
    let guard = store.read().unwrap();
    guard
        .clone()
        .ok_or_else(|| "API token not available — is the daemon running?".into())
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

async fn process_sse_stream(
    app: &tauri::AppHandle,
    resp: reqwest::Response,
) -> Result<(), String> {
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
