#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use std::time::Duration;
use tauri::Emitter;

// ======== Data commands ========
//
// Thin wrappers over `socketguard_client::Client` (ADR 0033): one command per API call the
// UI needs. Errors reach the frontend as `{code, message, details}`.

use serde::Serialize;
use socketguard_client::{Client, Error as ClientError, GrantQuery};
use socketguard_core::api_types::{
    ChangesRequest, ChangesResponse, NewPeer, NewTag, ProtectHostRequest, ProtectHostResponse,
    ShareResponse, StatusResponse, TorKeyResponse, UpdateTag,
};
use socketguard_core::{
    ActivityQuery, ActivityRecord, App, AppDetail, Credential, GrantView, Network, NewCredential,
    NewGrant, ParsedCredential, Peer, PeerGroup, PortRef, Settings, Tag, TagMember,
};

/// Error shape the frontend branches on. API errors keep the daemon's code
/// (`confirmation_required`, `protect_host_refused`, ...); `connection` means the daemon
/// could not be reached.
#[derive(Debug, Serialize)]
struct UiError {
    code: String,
    message: String,
    details: Option<serde_json::Value>,
}

const ACCESS_HINT: &str = if cfg!(windows) {
    "Make sure the daemon is running and your account is in the local group 'SocketGuard Users'."
} else {
    "Make sure the daemon is running and your user is in the 'socketguard' group."
};

impl From<ClientError> for UiError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connect { endpoint, source } => UiError {
                code: "connection".into(),
                message: format!("Cannot reach the daemon at {endpoint}: {source}"),
                details: Some(serde_json::json!({ "endpoint": endpoint, "hint": ACCESS_HINT })),
            },
            ClientError::Api {
                code,
                message,
                details,
                ..
            } => UiError {
                code,
                message,
                details,
            },
            ClientError::Protocol(m) => UiError {
                code: "protocol".into(),
                message: m,
                details: None,
            },
        }
    }
}

type CmdResult<T> = Result<T, UiError>;

fn client() -> Client {
    Client::from_env()
}

#[tauri::command]
async fn status() -> CmdResult<StatusResponse> {
    Ok(client().status().await?)
}

#[tauri::command]
async fn list_apps() -> CmdResult<Vec<App>> {
    Ok(client().list_apps(false).await?)
}

#[tauri::command]
async fn get_app(id: String) -> CmdResult<AppDetail> {
    Ok(client().get_app(&id).await?)
}

#[tauri::command]
async fn review_app(id: String, reviewed: bool) -> CmdResult<AppDetail> {
    Ok(client().review_app(&id, reviewed).await?)
}

#[tauri::command]
async fn list_peers() -> CmdResult<Vec<Peer>> {
    Ok(client().list_peers().await?)
}

#[tauri::command]
async fn create_peer(req: NewPeer) -> CmdResult<Peer> {
    Ok(client().create_peer(&req).await?)
}

#[tauri::command]
async fn parse_credentials(text: String) -> CmdResult<Vec<ParsedCredential>> {
    Ok(client().parse_credentials(&text).await?)
}

// Commands built on `Saved<T>` drop its `enforcement` notice (HTTP 202); the UI does not show it yet.
#[tauri::command]
async fn add_credential(peer_id: String, req: NewCredential) -> CmdResult<Credential> {
    Ok(client().add_credential(&peer_id, &req).await?.value)
}

#[tauri::command]
async fn remove_credential(peer_id: String, credential_id: String) -> CmdResult<()> {
    client().remove_credential(&peer_id, &credential_id).await?;
    Ok(())
}

#[tauri::command]
async fn delete_peer(id: String) -> CmdResult<()> {
    client().delete_peer(&id).await?;
    Ok(())
}

#[tauri::command]
async fn list_groups() -> CmdResult<Vec<PeerGroup>> {
    Ok(client().list_groups().await?)
}

#[tauri::command]
async fn list_grants() -> CmdResult<Vec<GrantView>> {
    Ok(client().list_grants(&GrantQuery::default()).await?)
}

#[tauri::command]
async fn create_grant(req: NewGrant) -> CmdResult<GrantView> {
    Ok(client().create_grant(&req).await?.value)
}

#[tauri::command]
async fn delete_grant(id: String) -> CmdResult<()> {
    client().delete_grant(&id).await?;
    Ok(())
}

/// Many changes at once: all or nothing, one firewall update (ADR 0045).
#[tauri::command]
async fn changes(req: ChangesRequest) -> CmdResult<ChangesResponse> {
    Ok(client().changes(&req).await?.value)
}

#[tauri::command]
async fn list_tags() -> CmdResult<Vec<Tag>> {
    Ok(client().list_tags().await?)
}

#[tauri::command]
async fn create_tag(req: NewTag) -> CmdResult<Tag> {
    Ok(client().create_tag(&req).await?.value)
}

#[tauri::command]
async fn get_tag(id: String) -> CmdResult<Tag> {
    Ok(client().get_tag(&id).await?)
}

#[tauri::command]
async fn update_tag(id: String, req: UpdateTag) -> CmdResult<Tag> {
    Ok(client().update_tag(&id, &req).await?.value)
}

#[tauri::command]
async fn delete_tag(id: String) -> CmdResult<()> {
    client().delete_tag(&id).await?;
    Ok(())
}

#[tauri::command]
async fn add_tag_member(tag_id: String, member: TagMember) -> CmdResult<Tag> {
    Ok(client().add_tag_member(&tag_id, &member).await?.value)
}

#[tauri::command]
async fn remove_tag_member(
    tag_id: String,
    app_id: String,
    port: Option<PortRef>,
) -> CmdResult<Tag> {
    Ok(client()
        .remove_tag_member(&tag_id, &app_id, port)
        .await?
        .value)
}

/// Generate a Tor client key for a peer; the answer carries the private key.
#[tauri::command]
async fn generate_tor_key(peer_id: String) -> CmdResult<TorKeyResponse> {
    Ok(client().generate_tor_key(&peer_id).await?.value)
}

#[tauri::command]
async fn share_app(id: String) -> CmdResult<ShareResponse> {
    Ok(client().share_app(&id).await?)
}

#[tauri::command]
async fn list_networks() -> CmdResult<Vec<Network>> {
    Ok(client().list_networks().await?)
}

#[tauri::command]
async fn get_settings() -> CmdResult<Settings> {
    Ok(client().get_settings().await?)
}

#[tauri::command]
async fn set_protect_host(req: ProtectHostRequest) -> CmdResult<ProtectHostResponse> {
    Ok(client().set_protect_host(&req).await?)
}

#[tauri::command]
async fn activity(query: ActivityQuery) -> CmdResult<Vec<ActivityRecord>> {
    Ok(client().activity(&query).await?)
}

#[tauri::command]
async fn enable() -> CmdResult<()> {
    Ok(client().enable().await?)
}

#[tauri::command]
async fn disable(confirm: bool) -> CmdResult<()> {
    Ok(client().disable(confirm).await?)
}

#[tauri::command]
async fn subscribe_events(app: tauri::AppHandle) -> Result<(), String> {
    // One bridge per process: a frontend reload calls this again.
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
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

#[cfg(windows)]
#[tauri::command]
async fn start_daemon() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let daemon = exe.parent().unwrap().join("socketguard-daemon.exe");
    if !daemon.exists() {
        return Err("socketguard-daemon.exe not found next to UI executable".into());
    }
    spawn_elevated(&daemon)
}

/// Launch the daemon through the UAC prompt (`runas`).
#[cfg(windows)]
fn spawn_elevated(path: &std::path::Path) -> Result<(), String> {
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
        Err(format!("ShellExecuteW failed with code {code}"))
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn start_daemon() -> Result<(), String> {
    Err("Starting the daemon from the UI is only supported on Windows; start it with systemd or sudo.".into())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            status,
            list_apps,
            get_app,
            review_app,
            list_peers,
            create_peer,
            parse_credentials,
            add_credential,
            remove_credential,
            delete_peer,
            list_groups,
            list_grants,
            create_grant,
            delete_grant,
            changes,
            list_tags,
            create_tag,
            get_tag,
            update_tag,
            delete_tag,
            add_tag_member,
            remove_tag_member,
            generate_tor_key,
            share_app,
            list_networks,
            get_settings,
            set_protect_host,
            activity,
            enable,
            disable,
            subscribe_events,
            start_daemon,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}
