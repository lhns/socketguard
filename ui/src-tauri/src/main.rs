#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use std::time::Duration;
use tauri::Emitter;

// ======== Data commands ========
//
// Thin wrappers over `socketguard_client::Client` (ADR 0033, 0042): one command per API
// route. Errors reach the frontend as `{code, message, details}`. The coverage test in
// crates/cli/tests/coverage.rs reads this file and fails when a route has no command here.

use serde::Serialize;
use socketguard_client::{Client, Error as ClientError, GrantQuery, Saved};
use socketguard_core::api_types::{
    ApplyRequest, ApplyResponse, ChangesRequest, ChangesResponse, Enforcement, ExportDocument,
    MergeRequest, NewGroup, NewNetwork, NewPeer, NewTag, ProtectHostRequest, ProtectHostResponse,
    ShareResponse, SplitRequest, StatusResponse, TorKeyResponse, UpdateSettings, UpdateTag,
};
use socketguard_core::{
    ActivityQuery, ActivityRecord, Address, App, AppDetail, Credential, GrantView, Network,
    NewCredential, NewGrant, ParsedCredential, Peer, PeerGroup, PortRef, Settings, Tag, TagMember,
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

/// What a change returns to the frontend: the value and, after an HTTP 202, the notice that
/// the change is saved but not yet enforced. The frontend shows it.
#[derive(Debug, Serialize)]
struct Done<T> {
    value: T,
    enforcement: Option<Enforcement>,
}

impl<T> From<Saved<T>> for Done<T> {
    fn from(s: Saved<T>) -> Self {
        Done {
            value: s.value,
            enforcement: s.enforcement,
        }
    }
}

type DoneResult<T> = CmdResult<Done<T>>;

fn client() -> Client {
    Client::from_env()
}

// ─── Status ──────────────────────────────────────────────────────────────

#[tauri::command]
async fn status() -> CmdResult<StatusResponse> {
    Ok(client().status().await?)
}

// ─── Apps ────────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_apps() -> CmdResult<Vec<App>> {
    Ok(client().list_apps(false).await?)
}

#[tauri::command]
async fn get_app(id: String) -> CmdResult<AppDetail> {
    Ok(client().get_app(&id).await?)
}

#[tauri::command]
async fn delete_app(id: String) -> DoneResult<()> {
    Ok(client().delete_app(&id).await?.into())
}

#[tauri::command]
async fn review_app(id: String, reviewed: bool) -> CmdResult<AppDetail> {
    Ok(client().review_app(&id, reviewed).await?)
}

#[tauri::command]
async fn split_app(id: String, req: SplitRequest) -> DoneResult<Address> {
    Ok(client().split_app(&id, &req).await?.into())
}

#[tauri::command]
async fn merge_app(id: String, req: MergeRequest) -> DoneResult<Address> {
    Ok(client().merge_app(&id, &req).await?.into())
}

#[tauri::command]
async fn share_app(id: String) -> CmdResult<ShareResponse> {
    Ok(client().share_app(&id).await?)
}

// ─── Peers ───────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_peers() -> CmdResult<Vec<Peer>> {
    Ok(client().list_peers().await?)
}

#[tauri::command]
async fn create_peer(req: NewPeer) -> CmdResult<Peer> {
    Ok(client().create_peer(&req).await?)
}

#[tauri::command]
async fn get_peer(id: String) -> CmdResult<Peer> {
    Ok(client().get_peer(&id).await?)
}

#[tauri::command]
async fn update_peer(id: String, label: String) -> CmdResult<Peer> {
    Ok(client().update_peer(&id, &label).await?)
}

#[tauri::command]
async fn delete_peer(id: String) -> DoneResult<()> {
    Ok(client().delete_peer(&id).await?.into())
}

#[tauri::command]
async fn parse_credentials(text: String) -> CmdResult<Vec<ParsedCredential>> {
    Ok(client().parse_credentials(&text).await?)
}

#[tauri::command]
async fn add_credential(peer_id: String, req: NewCredential) -> DoneResult<Credential> {
    Ok(client().add_credential(&peer_id, &req).await?.into())
}

#[tauri::command]
async fn remove_credential(peer_id: String, credential_id: String) -> DoneResult<()> {
    Ok(client()
        .remove_credential(&peer_id, &credential_id)
        .await?
        .into())
}

/// Generate a Tor client key for a peer; the answer carries the private key.
#[tauri::command]
async fn generate_tor_key(peer_id: String) -> DoneResult<TorKeyResponse> {
    Ok(client().generate_tor_key(&peer_id).await?.into())
}

// ─── Groups ──────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_groups() -> CmdResult<Vec<PeerGroup>> {
    Ok(client().list_groups().await?)
}

#[tauri::command]
async fn create_group(req: NewGroup) -> CmdResult<PeerGroup> {
    Ok(client().create_group(&req).await?)
}

#[tauri::command]
async fn get_group(id: String) -> CmdResult<PeerGroup> {
    Ok(client().get_group(&id).await?)
}

#[tauri::command]
async fn update_group(id: String, label: String) -> CmdResult<PeerGroup> {
    Ok(client().update_group(&id, &label).await?)
}

#[tauri::command]
async fn delete_group(id: String) -> DoneResult<()> {
    Ok(client().delete_group(&id).await?.into())
}

#[tauri::command]
async fn set_group_members(id: String, peer_ids: Vec<String>) -> DoneResult<PeerGroup> {
    Ok(client().set_group_members(&id, &peer_ids).await?.into())
}

// ─── Grants and batch changes ────────────────────────────────────────────

#[tauri::command]
async fn list_grants() -> CmdResult<Vec<GrantView>> {
    Ok(client().list_grants(&GrantQuery::default()).await?)
}

#[tauri::command]
async fn create_grant(req: NewGrant) -> DoneResult<GrantView> {
    Ok(client().create_grant(&req).await?.into())
}

#[tauri::command]
async fn delete_grant(id: String) -> DoneResult<()> {
    Ok(client().delete_grant(&id).await?.into())
}

/// Many changes at once: all or nothing, one firewall update (ADR 0045).
#[tauri::command]
async fn changes(req: ChangesRequest) -> DoneResult<ChangesResponse> {
    Ok(client().changes(&req).await?.into())
}

// ─── Tags ────────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_tags() -> CmdResult<Vec<Tag>> {
    Ok(client().list_tags().await?)
}

#[tauri::command]
async fn create_tag(req: NewTag) -> DoneResult<Tag> {
    Ok(client().create_tag(&req).await?.into())
}

#[tauri::command]
async fn get_tag(id: String) -> CmdResult<Tag> {
    Ok(client().get_tag(&id).await?)
}

#[tauri::command]
async fn update_tag(id: String, req: UpdateTag) -> DoneResult<Tag> {
    Ok(client().update_tag(&id, &req).await?.into())
}

#[tauri::command]
async fn delete_tag(id: String) -> DoneResult<()> {
    Ok(client().delete_tag(&id).await?.into())
}

#[tauri::command]
async fn add_tag_member(tag_id: String, member: TagMember, confirm_open: bool) -> DoneResult<Tag> {
    Ok(client()
        .add_tag_member(&tag_id, &member, confirm_open)
        .await?
        .into())
}

#[tauri::command]
async fn remove_tag_member(
    tag_id: String,
    app_id: String,
    port: Option<PortRef>,
) -> DoneResult<Tag> {
    Ok(client()
        .remove_tag_member(&tag_id, &app_id, port)
        .await?
        .into())
}

// ─── Networks and settings ───────────────────────────────────────────────

#[tauri::command]
async fn list_networks() -> CmdResult<Vec<Network>> {
    Ok(client().list_networks().await?)
}

#[tauri::command]
async fn add_network(req: NewNetwork) -> CmdResult<Network> {
    Ok(client().add_network(&req).await?)
}

#[tauri::command]
async fn delete_network(id: String, force: bool) -> CmdResult<()> {
    Ok(client().delete_network(&id, force).await?)
}

#[tauri::command]
async fn get_settings() -> CmdResult<Settings> {
    Ok(client().get_settings().await?)
}

#[tauri::command]
async fn update_settings(req: UpdateSettings) -> CmdResult<Settings> {
    Ok(client().update_settings(&req).await?)
}

#[tauri::command]
async fn set_protect_host(req: ProtectHostRequest) -> CmdResult<ProtectHostResponse> {
    Ok(client().set_protect_host(&req).await?)
}

// ─── Activity, export, enforcement ───────────────────────────────────────

#[tauri::command]
async fn activity(query: ActivityQuery) -> CmdResult<Vec<ActivityRecord>> {
    Ok(client().activity(&query).await?)
}

#[tauri::command]
async fn export_state() -> CmdResult<ExportDocument> {
    Ok(client().export().await?)
}

#[tauri::command]
async fn apply_state(req: ApplyRequest) -> CmdResult<ApplyResponse> {
    Ok(client().apply(&req).await?)
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
            delete_app,
            review_app,
            split_app,
            merge_app,
            share_app,
            list_peers,
            create_peer,
            get_peer,
            update_peer,
            delete_peer,
            parse_credentials,
            add_credential,
            remove_credential,
            generate_tor_key,
            list_groups,
            create_group,
            get_group,
            update_group,
            delete_group,
            set_group_members,
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
            list_networks,
            add_network,
            delete_network,
            get_settings,
            update_settings,
            set_protect_host,
            activity,
            export_state,
            apply_state,
            enable,
            disable,
            subscribe_events,
            start_daemon,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}
