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

mod session;

use crate::service::{ServiceManager, WINDOWS_SERVICE};
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub use session::{
    remove_wintun_driver, session_log, write_last_exit, write_session, SessionLog, SESSION_FILE,
};
pub use socketguard_core::portable::{last_exit_line, LAST_EXIT_FILE};

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

/// The SID of one account in its string form: `S-1-5-21-a-b-c-rid` (local, domain or
/// Microsoft account) or `S-1-12-1-a-b-c-d` (Entra ID). Well-known group SIDs such as
/// Everyone (`S-1-1-0`) or Authenticated Users (`S-1-5-11`) would open the pipe and the data
/// folder to every local user, so they are refused. Nothing else is put into the pipe's
/// security descriptor.
pub fn valid_sid(s: &str) -> bool {
    let Some(rest) = s
        .strip_prefix("S-1-5-21-")
        .or_else(|| s.strip_prefix("S-1-12-1-"))
    else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    s.len() <= 184
        && parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// What Windows says a SID names (`SID_NAME_USE`, reduced to what the check needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    User,
    /// A group or alias: `Domain Users`, `Users`, ...
    Group,
    /// Anything else (a well-known SID, a computer, a label, ...).
    Other,
    /// The SID does not resolve to an account.
    Unresolved,
}

/// `--allow-user` must name one user: the shape check cannot tell `...-1001` from a domain
/// group such as Domain Users (`...-513`), the lookup can.
pub fn require_user(sid: &str, kind: AccountKind) -> Result<(), String> {
    match kind {
        AccountKind::User => Ok(()),
        AccountKind::Group => Err(format!(
            "--allow-user {sid} is a group, not a user: it would open the pipe to every member"
        )),
        AccountKind::Other => Err(format!(
            "--allow-user {sid} is not a user account (it names something else)"
        )),
        AccountKind::Unresolved => Err(format!(
            "--allow-user {sid} does not resolve to an account on this machine or its domain"
        )),
    }
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
            bail!(
                "--allow-user needs the SID of one account (S-1-5-21-... or S-1-12-1-...), \
                 not {sid:?}: a group such as Everyone would open the pipe to every user"
            );
        }
        #[cfg(windows)]
        if let Err(e) = require_user(sid, win::account_kind(sid)) {
            bail!("{e}");
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
mod win;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::FakeServiceManager;

    #[test]
    fn a_sid_is_digits_and_dashes_only() {
        assert!(valid_sid("S-1-5-21-1004336348-1177238915-682003330-512"));
        assert!(!valid_sid(""));
        assert!(!valid_sid("S-1-5"));
        assert!(!valid_sid("S-1-5-21-1)(A;;GA;;;WD"));
        assert!(!valid_sid("S-1-5-x"));
        assert!(!valid_sid("S-1-5--1"));
        assert!(!valid_sid("Everyone"));
        assert!(!valid_sid("s-1-5-21-1"));
    }

    #[test]
    fn only_a_user_account_may_be_allowed() {
        assert!(require_user("S-1-5-21-1-2-3-1001", AccountKind::User).is_ok());
        let group = require_user("S-1-5-21-1-2-3-513", AccountKind::Group).unwrap_err();
        assert!(group.contains("is a group"), "{group}");
        let other = require_user("S-1-5-21-1-2-3-1", AccountKind::Other).unwrap_err();
        assert!(other.contains("not a user"), "{other}");
        let none = require_user("S-1-5-21-1-2-3-9", AccountKind::Unresolved).unwrap_err();
        assert!(none.contains("does not resolve"), "{none}");
    }

    /// What the UI passes (its own account) must be accepted.
    #[cfg(windows)]
    #[test]
    fn the_sid_of_the_current_account_is_accepted() {
        let sid = socketguard_core::winsid::current_user_sid().unwrap();
        assert!(valid_sid(&sid), "{sid}");
        assert_eq!(win::account_kind(&sid), AccountKind::User);
    }

    #[cfg(windows)]
    #[test]
    fn a_group_and_an_unknown_sid_are_not_users() {
        // The Users group has no S-1-5-21 form, so only the lookup tells.
        assert_eq!(win::account_kind("S-1-5-32-545"), AccountKind::Group);
        assert_eq!(
            win::account_kind("S-1-5-21-1-2-3-99999"),
            AccountKind::Unresolved
        );
    }

    #[test]
    fn only_account_sids_are_accepted() {
        assert!(valid_sid("S-1-12-1-1-2-3-4"));
        // Everyone, Authenticated Users, Users, Administrators, SYSTEM, Interactive
        for group in [
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
            "S-1-5-32-544",
            "S-1-5-18",
            "S-1-5-4",
        ] {
            assert!(!valid_sid(group), "{group}");
        }
        // an account SID has the domain's three numbers and the account's own
        assert!(!valid_sid("S-1-5-21"));
        assert!(!valid_sid("S-1-12-1"));
        assert!(!valid_sid("S-1-5-21-1-2-3"));
        assert!(!valid_sid("S-1-5-21-1-2-3-4-5"));
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
