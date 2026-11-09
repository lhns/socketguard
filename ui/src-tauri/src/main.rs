#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use std::path::Path;
use std::time::Duration;
use tauri::Emitter;

// ======== Data commands ========
//
// The model changed (ADR 0027) and API v1 is in place (redesign phase 6), but the UI is
// rewritten against the client crate in phase 7b. Until then the
// commands stay registered so the frontend's invoke() calls resolve; they all fail.

const NOT_AVAILABLE: &str = "not available until the UI is rewritten (redesign phase 7b)";

#[tauri::command]
async fn list_sockets() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn get_socket(id: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn allow_ip(
    socket_id: String,
    ip: String,
    label: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_acl_entry(socket_id: String, entry_id: i64) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn set_policy(socket_id: String, policy: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn set_backend_policy(
    socket_id: String,
    backend_id: String,
    policy: String,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn allow_backend_ip(
    socket_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn list_acl_groups() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn create_acl_group(label: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn get_acl_group(id: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn update_acl_group(
    id: String,
    label: Option<String>,
    policy: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn delete_acl_group(id: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn add_to_acl_group(
    group_id: String,
    socket_ids: Vec<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_from_acl_group(
    group_id: String,
    socket_id: String,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn add_acl_group_entry(
    group_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_acl_group_entry(
    group_id: String,
    entry_id: i64,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn list_socket_groups() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn create_socket_group(label: String, app_name: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn update_socket_group(id: String, label: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn delete_socket_group(id: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn add_socket_to_socket_group(
    group_id: String,
    socket_ids: Vec<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_socket_from_socket_group(
    group_id: String,
    socket_id: String,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn set_socket_group_address_policy(
    group_id: String,
    backend_id: String,
    policy: String,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn add_socket_group_acl_entry(
    group_id: String,
    backend_id: String,
    ip: String,
    label: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_socket_group_acl_entry(
    group_id: String,
    entry_id: i64,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn set_socket_group_acl_group(
    group_id: String,
    acl_group_id: Option<String>,
) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn get_config() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn update_config(config: serde_json::Value) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn list_interfaces() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn list_backend_instances() -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn add_backend(req: serde_json::Value) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
}

#[tauri::command]
async fn remove_backend(id: String) -> Result<serde_json::Value, String> {
    Err(NOT_AVAILABLE.into())
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

/// Forward the daemon's push events to the frontend as Tauri events of the same name.
async fn connect_sse(app: &tauri::AppHandle) -> Result<(), String> {
    let client = socketguard_client::Client::from_env();
    let mut events = client.events().await.map_err(|e| e.to_string())?;
    let _ = app.emit("daemon_connected", ());
    while let Some(event) = events.next().await {
        let event = event.map_err(|e| e.to_string())?;
        let _ = app.emit(event.name(), ());
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
