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
    ApplyRequest, ApplyResponse, AttachPortGroup, ChangesRequest, ChangesResponse, Enforcement,
    ExportDocument, MoveAppRequest, NewBinding, NewGroup, NewNetwork, NewPeer, NewPortGroup,
    NewReservation, NewTag, ProtectHostRequest, ProtectHostResponse, ReserveRequest, ShareResponse,
    StatusResponse, TorKeyResponse, UpdatePortGroup, UpdateTag,
};
use socketguard_core::setup::NetworkSetup;
use socketguard_core::{
    ActivityQuery, ActivityRecord, Address, App, AppDetail, Credential, GrantView, Network,
    NewCredential, NewGrant, ParsedCredential, Peer, PeerGroup, PortGroup, ReservationView, Scope,
    Settings, Tag, TagMember,
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
    "Make sure the SocketGuard service is running and your account is in the local group 'SocketGuard Users'."
} else {
    "Make sure the SocketGuard service is running and your user is in the 'socketguard' group."
};

impl From<ClientError> for UiError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connect { endpoint, source } => UiError {
                // The service answers on its socket, but this account may not use it.
                code: if source.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission_denied"
                } else {
                    "connection"
                }
                .into(),
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
    Ok(client().list_apps().await?)
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
async fn move_app(id: String, req: MoveAppRequest) -> DoneResult<AppDetail> {
    Ok(client().move_app(&id, &req).await?.into())
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
async fn delete_tag(id: String, confirm_open: bool) -> DoneResult<()> {
    Ok(client().delete_tag(&id, confirm_open).await?.into())
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
    scope: Scope,
    confirm_open: bool,
) -> DoneResult<Tag> {
    Ok(client()
        .remove_tag_member(&tag_id, &app_id, &scope, confirm_open)
        .await?
        .into())
}

// ─── Port groups ───────────────────────────────────────────────────────

#[tauri::command]
async fn list_port_groups() -> CmdResult<Vec<PortGroup>> {
    Ok(client().list_port_groups().await?)
}

#[tauri::command]
async fn create_port_group(req: NewPortGroup) -> DoneResult<PortGroup> {
    Ok(client().create_port_group(&req).await?.into())
}

#[tauri::command]
async fn get_port_group(id: String) -> CmdResult<PortGroup> {
    Ok(client().get_port_group(&id).await?)
}

#[tauri::command]
async fn update_port_group(id: String, req: UpdatePortGroup) -> DoneResult<PortGroup> {
    Ok(client().update_port_group(&id, &req).await?.into())
}

#[tauri::command]
async fn delete_port_group(id: String) -> DoneResult<()> {
    Ok(client().delete_port_group(&id).await?.into())
}

#[tauri::command]
async fn attach_port_group(
    id: String,
    app_id: String,
    req: AttachPortGroup,
) -> DoneResult<PortGroup> {
    Ok(client()
        .attach_port_group(&id, &app_id, req.confirm_open)
        .await?
        .into())
}

#[tauri::command]
async fn detach_port_group(id: String, app_id: String) -> DoneResult<PortGroup> {
    Ok(client().detach_port_group(&id, &app_id).await?.into())
}

// ─── Addresses and reservations ──────────────────────────────────────────

#[tauri::command]
async fn list_addresses() -> CmdResult<Vec<Address>> {
    Ok(client().list_addresses().await?)
}

#[tauri::command]
async fn list_reservations() -> CmdResult<Vec<ReservationView>> {
    Ok(client().list_reservations().await?)
}

#[tauri::command]
async fn get_reservation(id: String) -> CmdResult<ReservationView> {
    Ok(client().get_reservation(&id).await?)
}

#[tauri::command]
async fn create_reservation(req: NewReservation) -> DoneResult<ReservationView> {
    Ok(client().create_reservation(&req).await?.into())
}

#[tauri::command]
async fn rename_reservation(id: String, label: String) -> DoneResult<ReservationView> {
    Ok(client().rename_reservation(&id, &label).await?.into())
}

#[tauri::command]
async fn release_reservation(id: String, confirm_open: bool) -> DoneResult<()> {
    Ok(client()
        .release_reservation(&id, confirm_open)
        .await?
        .into())
}

#[tauri::command]
async fn add_binding(id: String, req: NewBinding) -> DoneResult<ReservationView> {
    Ok(client().add_binding(&id, &req).await?.into())
}

#[tauri::command]
async fn remove_binding(
    id: String,
    binding_id: String,
    confirm_open: bool,
) -> DoneResult<ReservationView> {
    Ok(client()
        .remove_binding(&id, &binding_id, confirm_open)
        .await?
        .into())
}

#[tauri::command]
async fn reserve_address(id: String, req: ReserveRequest) -> DoneResult<ReservationView> {
    Ok(client().reserve_address(&id, &req).await?.into())
}

// ─── Networks and settings ───────────────────────────────────────────────

#[tauri::command]
async fn list_networks() -> CmdResult<Vec<Network>> {
    Ok(client().list_networks().await?)
}

#[tauri::command]
async fn network_setup() -> CmdResult<NetworkSetup> {
    Ok(client().network_setup().await?)
}

#[tauri::command]
async fn add_network(req: NewNetwork) -> DoneResult<Network> {
    Ok(client().add_network(&req).await?.into())
}

#[tauri::command]
async fn set_network_peers(id: String, peers: Vec<String>) -> CmdResult<Network> {
    Ok(client().set_peers(&id, &peers).await?)
}

#[tauri::command]
async fn set_network_lan_discovery(
    id: String,
    enabled: bool,
    confirm_open: bool,
) -> CmdResult<Network> {
    Ok(client()
        .set_lan_discovery(&id, enabled, confirm_open)
        .await?)
}

#[tauri::command]
async fn set_network_bridges(id: String, bridges: Vec<String>) -> CmdResult<Network> {
    Ok(client().set_bridges(&id, &bridges).await?)
}

/// The pages the window may open in the system browser. A fixed list: the frontend names a
/// page, it never supplies an address that something else interprets (`file:`, a program).
/// Keep in step with `ui/src/links.ts`.
///
/// - Tor bridges: the Tor Project's BridgeDB, where bridge lines are requested.
/// - Yggdrasil public peers: the project's own repository of public peers, the page its
///   configuration documentation (https://yggdrasil-network.github.io/configuration.html,
///   "Public Peers") links to.
const OPEN_LINK_ALLOWED: &[&str] = &[
    "https://bridges.torproject.org/",
    "https://github.com/yggdrasil-network/public-peers",
];

/// Open an allow-listed page in the system browser.
#[tauri::command]
async fn open_link(url: String) -> CmdResult<()> {
    if !OPEN_LINK_ALLOWED.contains(&url.as_str()) {
        return Err(UiError {
            code: "invalid".into(),
            message: "that page cannot be opened from here".into(),
            details: None,
        });
    }
    open_in_browser(&url).map_err(|e| UiError {
        code: "open_failed".into(),
        message: format!("could not open the browser: {e}"),
        details: None,
    })
}

#[cfg(windows)]
fn open_in_browser(url: &str) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (verb, file) = (wide("open"), wide(url));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // Values above 32 mean success.
    if r.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecute returned {}", r.0 as isize))
    }
}

#[cfg(not(windows))]
fn open_in_browser(url: &str) -> Result<(), String> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("{program}: {e}"))
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

/// Portable mode only (ADR 0054): end the daemon through its teardown.
#[tauri::command]
async fn shutdown() -> CmdResult<()> {
    Ok(client().shutdown().await?)
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

// ─── The service, access and removal (ADR 0050) ──────────────────────────
//
// Everything that changes the host is a command of `socketguard-daemon`, run through the
// system's elevation prompt. The window never starts a daemon of its own.

#[derive(Debug, Serialize)]
struct ServiceStatus {
    installed: bool,
    running: bool,
}

/// Run `socketguard-daemon <args>` with administrator rights and wait for it.
async fn run_daemon_elevated(args: Vec<String>) -> CmdResult<SetupRun> {
    let command = format!("socketguard-daemon {}", args.join(" "));
    let Ok(daemon) = sibling("socketguard-daemon") else {
        return Ok(SetupRun {
            launched: false,
            cancelled: false,
            exit_code: None,
            command,
        });
    };
    let run = tokio::task::spawn_blocking(move || elevated_run(&daemon, &args, false))
        .await
        .map_err(|e| internal(e.to_string()))?;
    Ok(setup_run(run, command))
}

/// Whether the service is installed and running; needs no administrator rights.
#[tauri::command]
async fn service_status() -> CmdResult<ServiceStatus> {
    let daemon = sibling("socketguard-daemon")?;
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(daemon);
        cmd.args(["service", "status", "--json"]);
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000); // CREATE_NO_WINDOW
        let out = cmd.output().map_err(|e| internal(e.to_string()))?;
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .ok()
            .and_then(|v| Some((v.get("installed")?.as_bool()?, v.get("running")?.as_bool()?)))
            .map(|(installed, running)| ServiceStatus { installed, running })
            .ok_or_else(|| internal("service status gave no answer".into()))
    })
    .await
    .map_err(|e| internal(e.to_string()))?
}

/// Start the SocketGuard service, installing it first when it is not installed.
#[tauri::command]
async fn start_daemon() -> CmdResult<SetupRun> {
    let installed = service_status().await.map(|s| s.installed).unwrap_or(true);
    let action = if installed { "start" } else { "install" };
    run_daemon_elevated(vec!["service".into(), action.into()]).await
}

/// Install the service (it starts at once).
#[tauri::command]
async fn install_service() -> CmdResult<SetupRun> {
    run_daemon_elevated(vec!["service".into(), "install".into()]).await
}

/// The account this window runs as, in the form `access allow` takes: `DOMAIN\user` for a
/// domain account on Windows, the plain name otherwise.
fn account_name() -> CmdResult<String> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    #[cfg(windows)]
    let name = var("USERNAME").map(|user| match (var("USERDOMAIN"), var("COMPUTERNAME")) {
        (Some(d), Some(c)) if !d.eq_ignore_ascii_case(&c) => format!("{d}\\{user}"),
        _ => user,
    });
    #[cfg(not(windows))]
    let name = var("USER").or_else(|| {
        let out = std::process::Command::new("id").arg("-un").output().ok()?;
        let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (!s.is_empty()).then_some(s)
    });
    name.filter(|n| !n.contains(['"', '\n', '\r']))
        .ok_or_else(|| internal("cannot tell which account this is".into()))
}

#[tauri::command]
async fn current_account() -> CmdResult<String> {
    account_name()
}

/// Add this account to the group that may use the service (applies from the next sign-in).
#[tauri::command]
async fn allow_my_account() -> CmdResult<SetupRun> {
    let account = account_name()?;
    run_daemon_elevated(vec!["access".into(), "allow".into(), account]).await
}

/// Remove SocketGuard from this computer. `purge` also deletes the settings and keys;
/// otherwise they stay. Always silent: the window has asked already.
#[tauri::command]
async fn remove_socketguard(purge: bool) -> CmdResult<SetupRun> {
    let keep = if purge { "--purge" } else { "--keep-data" };
    run_daemon_elevated(vec!["uninstall".into(), "--yes".into(), keep.into()]).await
}

/// Forget this window's own local storage (the columns shown in Apps, and whatever else the
/// webview keeps). Only the webview profile of this app is touched.
#[tauri::command]
async fn clear_local_ui_settings(window: tauri::WebviewWindow) -> CmdResult<()> {
    let _ = window.eval("try { localStorage.removeItem('socketguard.columns'); } catch (e) {}");
    window
        .clear_all_browsing_data()
        .map_err(|e| internal(e.to_string()))
}

/// Close the window and the app.
#[tauri::command]
async fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

// ─── Elevated runs ──────────────────────────────────────────────────────

/// How an elevated run of a SocketGuard command ended, as the frontend needs it.
#[derive(Debug, Serialize)]
struct SetupRun {
    /// The elevated command ran. False: it did not start (no elevation helper, or the
    /// prompt was cancelled); `command` is what to run by hand.
    launched: bool,
    cancelled: bool,
    exit_code: Option<i32>,
    command: String,
}

/// A program installed next to this executable (`base` without the platform suffix).
fn sibling(base: &str) -> Result<std::path::PathBuf, UiError> {
    let exe = std::env::current_exe().map_err(|e| internal(e.to_string()))?;
    let name = format!("{base}{}", std::env::consts::EXE_SUFFIX);
    let path = sibling_candidates(exe.parent(), &name)
        .into_iter()
        .find(|p| p.exists());
    path.ok_or_else(|| UiError {
        code: "not_found".into(),
        message: format!("{name} was not found next to the SocketGuard window"),
        details: None,
    })
}

/// Where `name` may be: next to the executable, and on macOS also in
/// `/Library/Application Support/SocketGuard`, where the installer puts the CLI and the
/// daemon (the app itself is inside an `.app` bundle; ADR 0065).
fn sibling_candidates(exe_dir: Option<&std::path::Path>, name: &str) -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = exe_dir.map(|d| d.join(name)).into_iter().collect();
    if cfg!(target_os = "macos") {
        v.push(std::path::Path::new("/Library/Application Support/SocketGuard").join(name));
    }
    v
}

fn internal(message: String) -> UiError {
    UiError {
        code: "internal".into(),
        message,
        details: None,
    }
}

fn setup_run(run: ElevatedRun, command: String) -> SetupRun {
    match run {
        ElevatedRun::Done(code) => SetupRun {
            launched: true,
            cancelled: false,
            exit_code: code,
            command,
        },
        ElevatedRun::Cancelled => SetupRun {
            launched: true,
            cancelled: true,
            exit_code: None,
            command,
        },
        ElevatedRun::Unavailable => SetupRun {
            launched: false,
            cancelled: false,
            exit_code: None,
            command,
        },
    }
}

enum ElevatedRun {
    Done(Option<i32>),
    /// The person declined the prompt: not an error.
    Cancelled,
    /// No way to ask for administrator rights here.
    Unavailable,
}

/// UAC (`runas`), in a visible console (that the CLI keeps open at the end with `--pause`)
/// or hidden.
#[cfg(windows)]
fn elevated_run(cli: &std::path::Path, args: &[String], visible: bool) -> ElevatedRun {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    let process = match shell_execute_runas(cli, args, visible) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut code = None;
    unsafe {
        if WaitForSingleObject(process, INFINITE) == WAIT_OBJECT_0 {
            let mut c = 0u32;
            if GetExitCodeProcess(process, &mut c).is_ok() {
                code = Some(c as i32);
            }
        }
        let _ = CloseHandle(process);
    }
    ElevatedRun::Done(code)
}

/// Start `cli args` elevated through UAC and return its process handle. The error is the
/// outcome to report: declined, or no way to ask.
#[cfg(windows)]
fn shell_execute_runas(
    cli: &std::path::Path,
    args: &[String],
    visible: bool,
) -> Result<windows::Win32::Foundation::HANDLE, ElevatedRun> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let verb = wide("runas");
    let file = wide(&cli.to_string_lossy());
    let params = wide(
        &args
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: if visible { SW_SHOWNORMAL.0 } else { SW_HIDE.0 },
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut info) }.is_err() {
        // ERROR_CANCELLED (1223): the UAC prompt was declined.
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(1223) {
                ElevatedRun::Cancelled
            } else {
                ElevatedRun::Unavailable
            },
        );
    }
    Ok(info.hProcess)
}

/// Single-quote for a POSIX shell.
#[cfg(not(windows))]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// pkexec on Linux, osascript on macOS; nothing else is tried.
#[cfg(not(windows))]
fn elevated_run(cli: &std::path::Path, args: &[String], _visible: bool) -> ElevatedRun {
    use std::process::Command;
    let status = if cfg!(target_os = "macos") {
        let line = std::iter::once(cli.to_string_lossy().to_string())
            .chain(args.iter().cloned())
            .map(|a| sh_quote(&a))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            line.replace('\\', "\\\\").replace('"', "\\\"")
        );
        Command::new("osascript").args(["-e", &script]).status()
    } else {
        Command::new("pkexec").arg(cli).args(args).status()
    };
    match status {
        Ok(s) => match s.code() {
            // pkexec: 126 = not authorized, 127 = dismissed. osascript: -128 = cancelled.
            Some(126) | Some(127) if !cfg!(target_os = "macos") => ElevatedRun::Cancelled,
            code => ElevatedRun::Done(code),
        },
        Err(_) => ElevatedRun::Unavailable,
    }
}

// ─── Portable mode (ADR 0054) ────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PortableInfo {
    /// This window runs from a folder (a `portable` file next to it, or `--portable`).
    portable: bool,
}

/// Known without the daemon: the window decides what to show when the daemon is not there.
#[tauri::command]
async fn portable_info() -> PortableInfo {
    PortableInfo {
        portable: socketguard_core::portable::is_portable(),
    }
}

/// What the last portable run left (`data\last-exit.log`), if there is a record.
#[derive(Debug, Serialize)]
struct PortableExit {
    /// Unix seconds.
    at: u64,
    /// Empty: everything was removed.
    left: Vec<String>,
}

#[tauri::command]
async fn portable_last_exit() -> CmdResult<Option<PortableExit>> {
    let Some(dir) = socketguard_core::portable::data_dir() else {
        return Ok(None);
    };
    let file = dir.join(socketguard_core::portable::LAST_EXIT_FILE);
    Ok(std::fs::read_to_string(file)
        .ok()
        .and_then(|t| socketguard_core::portable::parse_last_exit(&t))
        .map(|(at, left)| PortableExit { at, left }))
}

/// Start `socketguard-daemon --portable --owner-pid <this window> --allow-user <this account>`
/// with administrator rights, hidden, and wait until its pipe answers. The daemon ends when
/// this process does. Reported like the other elevated runs: `exit_code` 0 is a daemon that
/// answers, another number a daemon that stopped, none one that never answered.
#[tauri::command]
async fn start_portable_daemon() -> CmdResult<SetupRun> {
    let daemon = sibling("socketguard-daemon")?;
    let installed = service_status().await.map(|s| s.installed).unwrap_or(false);
    if installed {
        return Err(UiError {
            code: "service_installed".into(),
            message: "The SocketGuard service is installed on this computer. Portable mode does \
                      not run beside it: remove the service first."
                .into(),
            details: None,
        });
    }
    #[cfg(windows)]
    {
        let Some(sid) = socketguard_core::winsid::current_user_sid() else {
            return Err(internal("cannot tell which account this is".into()));
        };
        let args: Vec<String> = [
            "--portable",
            "--owner-pid",
            &std::process::id().to_string(),
            "--allow-user",
            &sid,
        ]
        .map(String::from)
        .to_vec();
        let command = format!("socketguard-daemon {}", args.join(" "));
        let launched = {
            let (d, a) = (daemon.clone(), args.clone());
            tokio::task::spawn_blocking(move || {
                shell_execute_runas(&d, &a, false).map(|h| h.0 as isize)
            })
            .await
            .map_err(|e| internal(e.to_string()))?
        };
        let process = match launched {
            Ok(p) => p,
            Err(other) => return Ok(setup_run(other, command)),
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let code = loop {
            if client().status().await.is_ok() {
                break Some(0);
            }
            if let Some(code) = process_exit_code(process) {
                break Some(code);
            }
            if std::time::Instant::now() > deadline {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        close_process(process);
        Ok(setup_run(ElevatedRun::Done(code), command))
    }
    #[cfg(not(windows))]
    {
        let _ = daemon;
        Err(UiError {
            code: "invalid".into(),
            message: "portable mode exists on Windows only".into(),
            details: None,
        })
    }
}

/// The exit code of a process started above, if it has ended.
#[cfg(windows)]
fn process_exit_code(process: isize) -> Option<i32> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetExitCodeProcess;
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0u32;
    // SAFETY: the handle came from ShellExecuteEx and is open until `close_process`.
    let got = unsafe { GetExitCodeProcess(HANDLE(process as *mut _), &mut code) }.is_ok();
    (got && code != STILL_ACTIVE).then_some(code as i32)
}

#[cfg(windows)]
fn close_process(process: isize) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    // SAFETY: closes the handle once.
    let _ = unsafe { CloseHandle(HANDLE(process as *mut _)) };
}

fn main() {
    // Portable mode (ADR 0054): a `portable` file next to this program, or `--portable`. The
    // window's browser data then stays in the folder too, not under the user's profile.
    if std::env::args().any(|a| a == socketguard_core::portable::FLAG) {
        socketguard_core::portable::request();
    }
    if socketguard_core::portable::is_portable() {
        if let Some(dir) = socketguard_core::portable::exe_dir() {
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", dir.join("ui-data"));
        }
    }
    tauri::Builder::default()
        // Portable mode: closing the window must stop the daemon first. Keep the window open
        // and let the frontend run the close flow; it ends the app with `quit_app`. A second
        // close always closes, so a frontend that does not answer cannot keep the window open:
        // the daemon watches this process and tears down when it ends.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                static ASKED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if socketguard_core::portable::is_portable()
                    && !ASKED.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    api.prevent_close();
                    let _ = window.emit("portable_close_requested", ());
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            list_apps,
            get_app,
            delete_app,
            move_app,
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
            list_port_groups,
            create_port_group,
            get_port_group,
            update_port_group,
            delete_port_group,
            attach_port_group,
            detach_port_group,
            list_networks,
            network_setup,
            add_network,
            set_network_peers,
            set_network_lan_discovery,
            set_network_bridges,
            open_link,
            delete_network,
            list_addresses,
            list_reservations,
            get_reservation,
            create_reservation,
            rename_reservation,
            release_reservation,
            add_binding,
            remove_binding,
            reserve_address,
            get_settings,
            set_protect_host,
            activity,
            export_state,
            apply_state,
            enable,
            disable,
            shutdown,
            portable_info,
            portable_last_exit,
            start_portable_daemon,
            subscribe_events,
            start_daemon,
            install_service,
            service_status,
            current_account,
            allow_my_account,
            remove_socketguard,
            clear_local_ui_settings,
            quit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}

#[cfg(test)]
mod tests {
    use super::sibling_candidates;
    use std::path::Path;

    #[test]
    fn the_executable_directory_comes_first() {
        let c = sibling_candidates(Some(Path::new("/opt/sg")), "socketguard-daemon");
        assert_eq!(c[0], Path::new("/opt/sg").join("socketguard-daemon"));
        // The programs' directory is a fallback on macOS only, where the app sits in a bundle.
        assert_eq!(c.len(), if cfg!(target_os = "macos") { 2 } else { 1 });
        if cfg!(target_os = "macos") {
            assert_eq!(
                c[1],
                Path::new("/Library/Application Support/SocketGuard/socketguard-daemon")
            );
        }
    }
}
