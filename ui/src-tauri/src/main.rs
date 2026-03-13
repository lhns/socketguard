#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use socketguard_core::api_types::*;
use socketguard_core::Policy;
use std::path::Path;
use std::sync::OnceLock;
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

#[tauri::command]
async fn list_sockets() -> Result<SocketListResponse, String> {
    client()
        .get(format!("{}/api/sockets", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_socket(id: String) -> Result<SocketDetailResponse, String> {
    client()
        .get(format!("{}/api/sockets/{id}", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn allow_ip(socket_id: String, ip: String, label: Option<String>) -> Result<(), String> {
    let req = AllowIpRequest {
        allowed_ip: ip,
        label,
    };
    let resp = client()
        .post(format!("{}/api/sockets/{socket_id}/acl/allow", api_base()))
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn remove_acl_entry(socket_id: String, entry_id: i64) -> Result<(), String> {
    let resp = client()
        .delete(format!(
            "{}/api/sockets/{socket_id}/acl/{entry_id}",
            api_base()
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn set_policy(socket_id: String, policy: String) -> Result<(), String> {
    let policy: Policy = policy.parse().map_err(|e: String| e)?;
    let req = UpdatePolicyRequest { policy };
    let resp = client()
        .put(format!("{}/api/sockets/{socket_id}/policy", api_base()))
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn get_config() -> Result<ConfigResponse, String> {
    client()
        .get(format!("{}/api/config", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_config(config: UpdateConfigRequest) -> Result<(), String> {
    let resp = client()
        .put(format!("{}/api/config", api_base()))
        .json(&config)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn subscribe_events(app: tauri::AppHandle) -> Result<(), String> {
    tokio::spawn(async move {
        loop {
            match connect_sse(&app).await {
                Ok(()) => {} // stream ended normally
                Err(e) => {
                    eprintln!("SSE connection error: {e}");
                }
            }
            let _ = app.emit("daemon_disconnected", ());
            // Reconnect after 3s backoff
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    Ok(())
}

async fn connect_sse(app: &tauri::AppHandle) -> Result<(), String> {
    let resp = reqwest::Client::new()
        .get(format!("{}/api/events", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let _ = app.emit("daemon_connected", ());

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        // Process complete SSE messages (double newline delimited)
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

    // ShellExecuteW returns HINSTANCE; values > 32 indicate success
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
            subscribe_events,
            start_daemon,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}
