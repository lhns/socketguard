//! Portable mode in the daemon (ADR 0054): a daemon started from a folder by a window, with
//! everything it needs in that folder, that removes its rules and addresses when the window
//! ends, when the machine logs off or shuts down, or when it is told to.
//!
//! What ends it: the process named by `--owner-pid` (watched on its own thread), the console
//! events (Ctrl+C, close) through a control handler, logoff and shutdown through a hidden
//! window (a process that loads `user32.dll` no longer gets those two through the console
//! handler, Microsoft's SetConsoleCtrlHandler remarks), and `POST /api/shutdown`. All of
//! them call [`request_stop`]; `run` then stops serving and runs the teardown once, the
//! same code as "turn off".

use crate::service::{ServiceManager, WINDOWS_SERVICE};
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub use socketguard_core::portable::{last_exit_line, LAST_EXIT_FILE};
/// Written while a daemon runs; one found at start was left by a daemon that did not end
/// cleanly.
pub const SESSION_FILE: &str = "session.json";

// ─── Options ─────────────────────────────────────────────────────────────────

/// `--owner-pid` and `--allow-user` of the daemon's command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// The process whose end ends the daemon (the window that started it).
    pub owner_pid: Option<u32>,
    /// The SID of the account that may use the API pipe besides SYSTEM and Administrators.
    pub allow_user: Option<String>,
}

static ALLOW_SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The account the pipe admits besides SYSTEM and Administrators.
pub fn allowed_sid() -> Option<&'static str> {
    ALLOW_SID.get().map(String::as_str)
}

/// A SID in its string form: `S-1-` and dash-separated numbers. Nothing else is put into
/// the pipe's security descriptor.
pub fn valid_sid(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    s.len() <= 184
        && parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

// ─── Drop events ─────────────────────────────────────────────────────────────

static DROPS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// The firewall cannot deliver blocked-connection events (said in the status).
pub fn drop_events_unavailable() {
    DROPS_UNAVAILABLE.store(true, Ordering::SeqCst);
}

pub fn drop_events() -> bool {
    !DROPS_UNAVAILABLE.load(Ordering::SeqCst)
}

// ─── Stopping ────────────────────────────────────────────────────────────────

static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Ask the daemon to tear down and exit. Callable from any thread, any number of times.
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
    WAKE.notify_one();
}

/// Resolves once [`request_stop`] was called (also if it was called before).
pub async fn stop_requested() {
    if STOP.load(Ordering::SeqCst) {
        return;
    }
    WAKE.notified().await;
}

/// The teardown has finished: handlers that must not return before it may.
pub fn mark_done() {
    DONE.store(true, Ordering::SeqCst);
}

/// Block this (non-async) thread until [`mark_done`] or `limit`.
pub fn wait_done(limit: Duration) {
    let end = std::time::Instant::now() + limit;
    while !DONE.load(Ordering::SeqCst) && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ─── Refusing to run beside the service ──────────────────────────────────────

/// A portable daemon does not start beside the installed service: both would own the same
/// firewall objects and the service's rules are persistent (ADR 0054).
pub fn refuse_beside_service(mgr: &mut dyn ServiceManager) -> Result<()> {
    match mgr.status() {
        Ok(s) if s.installed => bail!(
            "the {WINDOWS_SERVICE} service is installed on this computer. Portable mode does not \
             run beside it: remove the service (socketguard-daemon uninstall) or use the installed \
             SocketGuard"
        ),
        Ok(_) => Ok(()),
        // Cannot tell: starting a second owner of the firewall objects is the worse error.
        Err(e) => bail!("cannot tell whether the {WINDOWS_SERVICE} service is installed: {e:#}"),
    }
}

/// The installed service does not run while a portable daemon does.
pub fn refuse_beside_portable(portable_running: bool) -> Result<()> {
    if portable_running {
        bail!(
            "a portable SocketGuard is running on this computer (pipe {}). Close it first: the \
             installed service does not run beside it",
            socketguard_core::portable::API_PIPE
        );
    }
    Ok(())
}

/// Whether something serves the portable pipe (without connecting to it).
pub fn portable_daemon_running() -> bool {
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND};
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        let name = HSTRING::from(socketguard_core::portable::API_PIPE);
        // SAFETY: a plain query with a NUL-terminated name; a zero wait returns at once.
        unsafe {
            if WaitNamedPipeW(&name, 0).as_bool() {
                return true;
            }
            // Busy (all instances in use) still means a server; only "no such pipe" does not.
            GetLastError() != ERROR_FILE_NOT_FOUND
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// ─── What the last run left ──────────────────────────────────────────────────

/// Record how the run ended, in `data_dir`. Best effort: the exit goes on regardless.
pub fn write_last_exit(data_dir: &Path, left: &[String]) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = last_exit_line(secs, left);
    if let Err(e) = std::fs::write(data_dir.join(LAST_EXIT_FILE), format!("{line}\n")) {
        tracing::warn!("Could not write {LAST_EXIT_FILE}: {e}");
    }
    // A clean end leaves no session record; a kill leaves it, and the next start says so.
    let _ = std::fs::remove_file(data_dir.join(SESSION_FILE));
}

/// Note that a daemon is running, and warn about a record a killed one left.
pub fn write_session(data_dir: &Path, owner_pid: Option<u32>) {
    let file = data_dir.join(SESSION_FILE);
    if file.exists() {
        tracing::warn!(
            "{} was left by a daemon that did not end cleanly; addresses it added are removed \
             now",
            file.display()
        );
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = serde_json::json!({
        "pid": std::process::id(),
        "owner_pid": owner_pid,
        "started": secs,
    });
    if let Err(e) = std::fs::write(&file, body.to_string()) {
        tracing::warn!("Could not write {}: {e}", file.display());
    }
}

// ─── The teardown ────────────────────────────────────────────────────────────

/// The same code as "turn off" (rules, addresses and the networks' own state removed), then
/// the latch put back as it was: portable mode comes up on at every start unless the person
/// turned it off. Returns what could not be removed, as sentences.
pub async fn teardown(state: &crate::AppState) -> Vec<String> {
    let was_disabled = state.db.disabled().await;
    let result = state.engine.read().await.disable(state).await;
    let mut left: Vec<String> = match state.db.list_owned_addresses().await {
        Ok(rows) => rows
            .iter()
            .map(|o| format!("address {} on {}", o.addr, o.interface))
            .collect(),
        Err(e) => vec![format!("the address records cannot be read: {e:#}")],
    };
    if let Err(e) = result {
        if left.is_empty() {
            left.push(format!("{e:#}"));
        }
        tracing::error!("Teardown did not finish: {e:#}");
    }
    if let Err(e) = state.db.set_disabled(was_disabled).await {
        tracing::warn!("Could not restore the on/off setting: {e}");
    }
    left
}

// ─── The data folder ─────────────────────────────────────────────────────────

/// Create the data folder and restrict it to SYSTEM and Administrators plus read access for
/// the account of `--allow-user`. A volume without access control lists (FAT, exFAT) cannot
/// protect anything: the database is then left as it is, once, with a warning (also in the
/// status), and the run goes on.
pub fn prepare_data_dir(dir: &Path) -> Result<()> {
    use anyhow::Context;
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    #[cfg(windows)]
    {
        if crate::state::volume_supports_acls(dir, crate::state::system_volume_flags) {
            if let Err(e) = crate::state::protect_portable_dir(dir, allowed_sid()) {
                let allow =
                    std::env::var(crate::state::ALLOW_UNPROTECTED_DB_ENV).as_deref() == Ok("1");
                if !allow {
                    return Err(e).with_context(|| {
                        format!(
                            "cannot restrict {} to SYSTEM and Administrators",
                            dir.display()
                        )
                    });
                }
                eprintln!("[socketguard] could not restrict {}: {e:#}", dir.display());
            }
        } else {
            crate::state::give_up_protection();
            eprintln!(
                "[socketguard] warning: the volume of {} has no access control (FAT/exFAT): the \
                 database, which holds onion service keys, cannot be protected from other users",
                dir.display()
            );
        }
    }
    Ok(())
}

// ─── Starting ────────────────────────────────────────────────────────────────

/// Everything a portable daemon checks and sets up before it reads its config: supported
/// here, administrator, no installed service, no other portable daemon, the pipe account,
/// and the things that will end it.
pub fn prepare(opts: &RunOptions) -> Result<()> {
    if let Err(e) = socketguard_core::portable::ensure_supported() {
        bail!("{e}");
    }
    if !socketguard_core::portable::is_portable() {
        if opts.owner_pid.is_some() || opts.allow_user.is_some() {
            bail!("--owner-pid and --allow-user belong to portable mode (--portable)");
        }
        return Ok(());
    }
    let mut host = crate::host::SystemHost;
    crate::host::require_admin(&host, "portable mode")?;
    crate::service::with_system_manager(&mut host, |m| refuse_beside_service(m))?;
    if portable_daemon_running() {
        bail!(
            "another portable SocketGuard is already running (pipe {})",
            socketguard_core::portable::API_PIPE
        );
    }
    if let Some(sid) = &opts.allow_user {
        if !valid_sid(sid) {
            bail!("--allow-user needs a SID such as S-1-5-21-1-2-3-1001, not {sid:?}");
        }
        let _ = ALLOW_SID.set(sid.clone());
    }
    if socketguard_core::portable::ignored_config_override().is_some() {
        eprintln!("[socketguard] SOCKETGUARD_CONFIG is ignored in portable mode");
    }
    #[cfg(windows)]
    {
        if let Some(pid) = opts.owner_pid {
            win::watch_owner(pid)?;
        }
        win::install_handlers();
    }
    #[cfg(not(windows))]
    let _ = opts;
    Ok(())
}

#[cfg(windows)]
mod win {
    use super::{request_stop, wait_done};
    use anyhow::{bail, Result};
    use std::time::Duration;
    use windows::core::{w, BOOL};
    use windows::Win32::Foundation::{
        CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
    };
    use windows::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
        CTRL_SHUTDOWN_EVENT,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_ENDSESSION, WM_QUERYENDSESSION,
        WNDCLASSW,
    };

    struct Owner(HANDLE);
    // SAFETY: a process handle may be waited on from any thread.
    unsafe impl Send for Owner {}

    /// Stop the daemon when process `pid` is gone. A process that cannot be watched is an
    /// error: the daemon would outlive its window and leave the rules in place.
    pub fn watch_owner(pid: u32) -> Result<()> {
        // SAFETY: plain handle calls; the handle is closed by the thread that waits on it.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.map_err(|e| {
            anyhow::anyhow!("cannot watch the owner process {pid}: {e} (is it still running?)")
        })?;
        let owner = Owner(handle);
        std::thread::Builder::new()
            .name("owner-watch".into())
            .spawn(move || {
                let owner = owner;
                // SAFETY: the handle is valid until closed below.
                unsafe {
                    WaitForSingleObject(owner.0, INFINITE);
                    let _ = CloseHandle(owner.0);
                }
                tracing::info!("The owner process {pid} ended");
                request_stop();
            })
            .map_err(|e| anyhow::anyhow!("cannot start the owner watch: {e}"))?;
        Ok(())
    }

    /// Windows ends a console process a few seconds after it calls the handler, so close,
    /// logoff and shutdown wait here for the teardown to finish before returning.
    unsafe extern "system" fn on_console_event(kind: u32) -> BOOL {
        match kind {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                request_stop();
                BOOL(1)
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                request_stop();
                wait_done(Duration::from_secs(4));
                BOOL(1)
            }
            _ => BOOL(0),
        }
    }

    unsafe extern "system" fn on_window_message(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            // Do not veto: protection ending with the session is the point.
            WM_QUERYENDSESSION => LRESULT(1),
            // wParam false: another program vetoed and the session goes on.
            WM_ENDSESSION if wparam.0 != 0 => {
                request_stop();
                wait_done(Duration::from_secs(20));
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    /// Console events through the control handler; logoff and shutdown through a hidden
    /// top-level window on a thread of its own (a message-only window gets no broadcast
    /// messages, and creating any window makes the console handler stop receiving those
    /// two events).
    pub fn install_handlers() {
        // SAFETY: registers a handler with a static lifetime.
        if let Err(e) = unsafe { SetConsoleCtrlHandler(Some(on_console_event), true) } {
            tracing::warn!("Cannot register the console control handler: {e}");
        }
        let started = std::thread::Builder::new()
            .name("end-session".into())
            .spawn(|| {
                if let Err(e) = message_loop() {
                    tracing::warn!("The logoff/shutdown watch is not running: {e:#}");
                }
            });
        if let Err(e) = started {
            tracing::warn!("Cannot start the logoff/shutdown watch: {e}");
        }
    }

    fn message_loop() -> Result<()> {
        // SAFETY: the usual window-class and message-loop calls; every pointer is to a
        // static string or a local that outlives the call.
        unsafe {
            let instance: HINSTANCE = GetModuleHandleW(None)?.into();
            let class = w!("SocketGuardPortableEndSession");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(on_window_message),
                hInstance: instance,
                lpszClassName: class,
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                bail!("RegisterClassW failed");
            }
            // Never shown: no WS_VISIBLE, no ShowWindow.
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class,
                w!("SocketGuard"),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                None,
                None,
                Some(instance),
                None,
            )?;
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        // The loop only ends if the window is destroyed; the handlers above keep working.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::FakeServiceManager;

    #[test]
    fn a_sid_is_digits_and_dashes_only() {
        assert!(valid_sid("S-1-5-21-1004336348-1177238915-682003330-512"));
        assert!(valid_sid("S-1-5-32-544"));
        assert!(!valid_sid(""));
        assert!(!valid_sid("S-1-5"));
        assert!(!valid_sid("S-1-5-21-1)(A;;GA;;;WD"));
        assert!(!valid_sid("S-1-5-x"));
        assert!(!valid_sid("S-1-5--1"));
        assert!(!valid_sid("Everyone"));
        assert!(!valid_sid("s-1-5-21-1"));
    }

    #[test]
    fn portable_does_not_start_beside_the_installed_service() {
        let mut absent = FakeServiceManager::default();
        assert!(refuse_beside_service(&mut absent).is_ok());
        let mut installed = FakeServiceManager {
            installed: true,
            ..Default::default()
        };
        let msg = refuse_beside_service(&mut installed)
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("SocketGuard") && msg.contains("service is installed"),
            "{msg}"
        );
        // Installed but stopped is still a conflict: it starts with the machine.
        assert!(refuse_beside_service(&mut installed).is_err());
    }

    #[test]
    fn the_service_does_not_run_beside_a_portable_daemon() {
        assert!(refuse_beside_portable(false).is_ok());
        let msg = refuse_beside_portable(true).unwrap_err().to_string();
        assert!(
            msg.contains("portable") && msg.contains("socketguard-portable"),
            "{msg}"
        );
    }

    #[test]
    fn the_last_exit_line_names_what_is_left() {
        assert_eq!(
            last_exit_line(5, &[]),
            "5 clean: rules and addresses removed"
        );
        assert_eq!(
            last_exit_line(5, &["address fd00::1 on Ethernet".into(), "x".into()]),
            "5 LEFT: address fd00::1 on Ethernet; x"
        );
    }

    #[test]
    fn a_session_record_marks_a_run_and_a_clean_exit_removes_it() {
        let dir = std::env::temp_dir().join(format!("sg-portable-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        write_session(&dir, Some(7));
        assert!(dir.join(SESSION_FILE).is_file());
        write_last_exit(&dir, &[]);
        assert!(!dir.join(SESSION_FILE).exists());
        let text = std::fs::read_to_string(dir.join(LAST_EXIT_FILE)).unwrap();
        assert!(text.contains("clean"), "{text}");
        write_last_exit(&dir, &["address fd00::1 on Ethernet".into()]);
        let text = std::fs::read_to_string(dir.join(LAST_EXIT_FILE)).unwrap();
        assert!(text.contains("LEFT"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A killed portable daemon leaves addresses on adapters, with no rules. The next start
    /// removes every recorded one, wanted or not (the first reconcile puts the wanted back).
    #[tokio::test]
    async fn the_start_sweep_removes_every_recorded_address() {
        use crate::test_support::*;
        let d = standard_daemon(vec![], None).await;
        let (a, b): (std::net::Ipv6Addr, std::net::Ipv6Addr) =
            ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap());
        for x in [a, b] {
            d.state
                .db
                .claim_address(x, "lo", Some("local"))
                .await
                .unwrap();
            d.net.plant_address("lo", x);
        }
        let failed = d.state.engine.read().await.sweep_all_owned(&d.state).await;
        assert_eq!(failed, 0);
        assert!(d.net.addresses("lo").is_empty());
        assert!(d.state.db.list_owned_addresses().await.unwrap().is_empty());
    }

    /// The teardown is "turn off", then the on/off setting is put back: portable mode comes up
    /// on at the next start unless the person had turned it off.
    #[tokio::test]
    async fn teardown_removes_everything_and_restores_the_latch() {
        use crate::test_support::*;
        let d = standard_daemon(vec![], None).await;
        let x: std::net::Ipv6Addr = "fd00::7".parse().unwrap();
        d.state
            .db
            .claim_address(x, "lo", Some("local"))
            .await
            .unwrap();
        d.net.plant_address("lo", x);
        assert!(!d.state.db.disabled().await);
        let left = teardown(&d.state).await;
        assert!(left.is_empty(), "{left:?}");
        assert!(d.net.addresses("lo").is_empty());
        assert!(!d.state.db.disabled().await, "the latch is back to off");
        assert!(d.fw_calls.lock().unwrap().contains(&FirewallCall::Disable));

        // Turned off by the person before closing: stays off.
        d.state.db.set_disabled(true).await.unwrap();
        assert!(teardown(&d.state).await.is_empty());
        assert!(d.state.db.disabled().await);
    }

    /// What cannot be removed is named, so the window can show it.
    #[tokio::test]
    async fn teardown_names_what_it_could_not_remove() {
        use crate::test_support::*;
        let d = standard_daemon(vec![], None).await;
        let x: std::net::Ipv6Addr = "fd00::9".parse().unwrap();
        d.state
            .db
            .claim_address(x, "lo", Some("local"))
            .await
            .unwrap();
        d.net.plant_address("lo", x);
        d.net.set_remove_failing(true);
        let left = teardown(&d.state).await;
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(
            left[0].contains("fd00::9") && left[0].contains("lo"),
            "{left:?}"
        );
    }

    #[tokio::test]
    async fn a_stop_request_made_before_waiting_is_not_lost() {
        // Process-wide state: this is the only test that touches it.
        request_stop();
        tokio::time::timeout(Duration::from_secs(2), stop_requested())
            .await
            .expect("stop_requested returns");
    }
}
