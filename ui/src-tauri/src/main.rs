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
    ExportDocument, ExposureResponse, MoveAppRequest, NewBinding, NewGroup, NewNetwork, NewPeer,
    NewPortGroup, NewReservation, NewTag, ProtectHostRequest, ProtectHostResponse, ReserveRequest,
    ShareResponse, StatusResponse, TorKeyResponse, UpdatePortGroup, UpdateTag,
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
async fn remove_tag_member(tag_id: String, app_id: String, scope: Scope) -> DoneResult<Tag> {
    Ok(client()
        .remove_tag_member(&tag_id, &app_id, &scope)
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
async fn release_reservation(id: String) -> DoneResult<()> {
    Ok(client().release_reservation(&id).await?.into())
}

#[tauri::command]
async fn add_binding(id: String, req: NewBinding) -> DoneResult<ReservationView> {
    Ok(client().add_binding(&id, &req).await?.into())
}

#[tauri::command]
async fn remove_binding(id: String, binding_id: String) -> DoneResult<ReservationView> {
    Ok(client().remove_binding(&id, &binding_id).await?.into())
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
async fn delete_network(id: String, force: bool, confirm_exposed: bool) -> CmdResult<()> {
    Ok(client().delete_network(&id, force, confirm_exposed).await?)
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

/// Where `name` may be: next to the executable, and on macOS also in `/usr/local/bin`, where
/// the installer puts the CLI and the daemon (the app itself is inside an `.app` bundle).
fn sibling_candidates(exe_dir: Option<&std::path::Path>, name: &str) -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = exe_dir.map(|d| d.join(name)).into_iter().collect();
    if cfg!(target_os = "macos") {
        v.push(std::path::Path::new("/usr/local/bin").join(name));
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

/// What becomes reachable over Yggdrasil without SocketGuard's block (ADR 0051).
#[tauri::command]
async fn exposure(without: Option<String>) -> CmdResult<ExposureResponse> {
    Ok(client().exposure(without.as_deref()).await?)
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
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
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
        return if std::io::Error::last_os_error().raw_os_error() == Some(1223) {
            ElevatedRun::Cancelled
        } else {
            ElevatedRun::Unavailable
        };
    }
    let process = info.hProcess;
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

fn main() {
    tauri::Builder::default()
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
            exposure,
            add_network,
            set_network_peers,
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
        // /usr/local/bin is a fallback on macOS only, where the app sits in a bundle.
        assert_eq!(c.len(), if cfg!(target_os = "macos") { 2 } else { 1 });
        if cfg!(target_os = "macos") {
            assert_eq!(c[1], Path::new("/usr/local/bin/socketguard-daemon"));
        }
    }
}
