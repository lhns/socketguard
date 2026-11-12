//! The managed Tor network (ADR 0052): SocketGuard runs its own `tor` as a child process.
//!
//! The existing Tor backend (`tor.rs`, `tor_control.rs`) does the work over the control
//! port; this module is what is specific to a Tor the daemon started itself: where its
//! files live, the `torrc` it is started with, who it runs as, and how to reach and trust
//! its control port. The control address and the cookie path are built here from the state
//! directory, never from what Tor says about itself (ADR 0040), and the cookie is vetted
//! against the account Tor runs as.

use super::managed::ManagedCtx;
use super::tor_control::{AuthOptions, Control, Endpoint};
use crate::account::{self, Accounts};
use crate::children::{ChildHealth, ChildSpec, ChildStatus, HealthCheck, RunAs, StatusHandle};
use anyhow::{anyhow, Context, Result};
use socketguard_core::config::TorAuth;
use socketguard_core::{ChildState, ManagedInfo};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The directory of the managed Tor under the state directory.
pub const DIR: &str = "tor";

/// Where the managed Tor keeps its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorPaths {
    pub dir: PathBuf,
    pub torrc: PathBuf,
    /// Unix: the control socket.
    pub control_socket: PathBuf,
    /// Windows: the file Tor writes its chosen control port to.
    pub control_port_file: PathBuf,
    pub cookie: PathBuf,
}

impl TorPaths {
    pub fn new(state_dir: &Path) -> Self {
        let dir = state_dir.join(DIR);
        Self {
            torrc: dir.join("torrc"),
            control_socket: dir.join("control"),
            control_port_file: dir.join("control-port"),
            cookie: dir.join("control_auth_cookie"),
            dir,
        }
    }
}

/// Who the managed Tor runs as: the unprivileged account when it exists and the daemon may
/// start processes as it, else the daemon's own account, saying why.
pub fn resolve_run_as(accounts: &dyn Accounts) -> RunAs {
    let (_, root) = accounts.daemon();
    if cfg!(windows) {
        return if accounts.portable() {
            RunAs::Portable
        } else {
            resolve_windows(accounts, root)
        };
    }
    match accounts.lookup(account::NAME) {
        Some(ids) if root => RunAs::Account {
            name: account::NAME.into(),
            uid: ids.uid,
            gid: ids.gid,
        },
        Some(_) => RunAs::Daemon {
            note: Some(format!(
                "the daemon is not running as root, so it cannot start Tor as {}",
                account::NAME
            )),
        },
        None => RunAs::Daemon {
            note: Some(format!("{} does not exist", account::NAME)),
        },
    }
}

/// Windows: LocalService when the daemon can really log it on (only SYSTEM may), else the
/// daemon's own account, saying why. Decided here, before the data directory is protected
/// for the account and the owner of the cookie is expected, so those, the account shown and
/// the way the child is started all follow the same answer.
fn resolve_windows(accounts: &dyn Accounts, is_system: bool) -> RunAs {
    let why = if !is_system {
        "the daemon is not SYSTEM, so it cannot start Tor as LocalService".to_string()
    } else {
        match accounts.local_service_logon() {
            Ok(()) => return RunAs::LocalService,
            Err(e) => format!("could not log LocalService on: {e}"),
        }
    };
    RunAs::Daemon { note: Some(why) }
}

/// Windows: the SID that owns the files the child writes (the cookie): LocalService's when
/// it runs as that, else `own`, the daemon's account.
fn cookie_owner(run_as: &RunAs, own: Option<String>) -> Option<String> {
    if *run_as == RunAs::LocalService {
        Some("S-1-5-19".into())
    } else {
        own
    }
}

/// A path as a `torrc` argument: quoted, with forward slashes on Windows (inside quotes a
/// backslash would be an escape).
fn quote(path: &Path) -> String {
    let mut s = path.display().to_string();
    if cfg!(windows) {
        s = s.replace('\\', "/");
    }
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The `torrc` Tor is started with, written again at every start. No SOCKS port (nothing
/// connects through it), a control endpoint only the daemon can reach, cookie
/// authentication with the file at the path the daemon chose, and nothing else: no geoip
/// files, no transports, no relay. The account is not set here: the daemon starts Tor as it.
pub fn torrc(paths: &TorPaths, windows: bool) -> String {
    let mut t = String::from(
        "# Written by SocketGuard each time it starts Tor; changes made here are overwritten.\n",
    );
    t.push_str(&format!("DataDirectory {}\n", quote(&paths.dir)));
    t.push_str("SocksPort 0\n");
    if windows {
        t.push_str("ControlPort auto\n");
        t.push_str(&format!(
            "ControlPortWriteToFile {}\n",
            quote(&paths.control_port_file)
        ));
    } else {
        t.push_str(&format!("ControlSocket {}\n", quote(&paths.control_socket)));
    }
    t.push_str("CookieAuthentication 1\n");
    t.push_str(&format!("CookieAuthFile {}\n", quote(&paths.cookie)));
    t.push_str("Log notice stdout\n");
    t
}

/// `PORT=127.0.0.1:51234` in the file `ControlPortWriteToFile` produces.
pub fn parse_port_file(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("PORT="))
        .map(str::to_string)
        .filter(|a| !a.is_empty())
}

/// The managed Tor of one network: how to reach it, how to start it, how it stands.
#[derive(Clone)]
pub struct ManagedTor {
    id: String,
    ctx: ManagedCtx,
    status: StatusHandle,
    paths: Result<TorPaths, String>,
}

impl ManagedTor {
    pub fn new(id: &str, ctx: &ManagedCtx) -> Self {
        Self {
            id: id.to_string(),
            status: ctx.children.handle(id),
            paths: ctx.state_dir().map(TorPaths::new),
            ctx: ctx.clone(),
        }
    }

    pub fn child(&self) -> ChildStatus {
        self.status.get()
    }

    pub fn is_up(&self) -> bool {
        self.child().state == ChildState::Up
    }

    /// Why the network is down while the child is not `Up`; empty when it is. `detailed`
    /// adds what changes all the time (the percent, the last log line); the short form is
    /// stable so a repeated failure is logged once.
    pub fn reason(&self, detailed: bool) -> String {
        let s = self.child();
        let or = |d: Option<String>, fallback: &str| d.unwrap_or_else(|| fallback.to_string());
        match s.state {
            ChildState::Up => String::new(),
            ChildState::Stopped => "SocketGuard is turned off".into(),
            ChildState::Waiting => or(s.detail, "waiting"),
            ChildState::Unavailable => or(s.detail, "Tor is not available"),
            ChildState::Starting => "Tor is starting".into(),
            ChildState::Bootstrapping => match (detailed, s.progress) {
                (true, Some(p)) => format!("bootstrapping {p}%"),
                _ => "Tor is bootstrapping".into(),
            },
            ChildState::Exited => {
                if detailed {
                    or(s.detail, "Tor exited")
                } else {
                    "Tor exited".into()
                }
            }
        }
    }

    /// The card of the network.
    pub fn info(&self) -> ManagedInfo {
        let s = self.child();
        ManagedInfo {
            state: s.state,
            progress: s.progress,
            detail: s.detail,
            runs_as: s
                .runs_as
                .or_else(|| Some(resolve_run_as(self.ctx.accounts.as_ref()).describe())),
            version: self.ctx.bundled.version_of("tor"),
            address: None,
            peers: vec![],
            peers_connected: None,
        }
    }

    fn paths(&self) -> Result<&TorPaths> {
        self.paths.as_ref().map_err(|e| anyhow!("{e}"))
    }

    /// The control endpoint and how to vet and authenticate it, built from our own paths and
    /// the account Tor runs as.
    pub fn connect_params(&self) -> Result<(Endpoint, AuthOptions)> {
        let paths = self.paths()?;
        let endpoint = if cfg!(windows) {
            let text = std::fs::read_to_string(&paths.control_port_file)
                .context("Tor has not written its control port yet")?;
            Endpoint::Tcp(parse_port_file(&text).context("Tor wrote no control port")?)
        } else {
            Endpoint::Unix(paths.control_socket.display().to_string())
        };
        let run_as = resolve_run_as(self.ctx.accounts.as_ref());
        let mut opts = AuthOptions {
            auth: TorAuth::Cookie,
            cookie_path: Some(paths.cookie.display().to_string()),
            cookie_dir: Some(paths.dir.display().to_string()),
            ..AuthOptions::default()
        };
        if cfg!(windows) {
            // LocalService owns the files it writes; when the daemon's own account runs
            // Tor, that account's SID does.
            opts.cookie_owner = cookie_owner(&run_as, own_sid());
        } else if cfg!(target_os = "linux") {
            // Only Linux can tell who is on the other end of a Unix socket.
            opts.expect_tor_uid = Some(match &run_as {
                RunAs::Account { uid, .. } => *uid,
                _ => self.ctx.accounts.daemon().0,
            });
        }
        Ok((endpoint, opts))
    }

    /// An authenticated control connection, whatever the child's state says.
    pub fn connect(&self) -> Result<Control> {
        let (endpoint, opts) = self.connect_params()?;
        Control::connect(&endpoint, &opts)
    }

    /// The child to run, or why this build cannot run one.
    pub fn spec(&self) -> Result<ChildSpec, String> {
        let files = self.ctx.bundled.tor()?;
        let paths = self.paths.clone()?;
        let run_as = resolve_run_as(self.ctx.accounts.as_ref());
        let mut env = vec![];
        if cfg!(target_os = "linux") {
            // The shipped tor has no RPATH: libevent, OpenSSL and zlib sit beside it.
            env.push((
                "LD_LIBRARY_PATH".to_string(),
                files.dir.display().to_string(),
            ));
        }
        let prepare_paths = paths.clone();
        let prepare_as = run_as.clone();
        Ok(ChildSpec {
            name: "tor".into(),
            program: files.binary,
            args: vec![
                "-f".into(),
                paths.torrc.display().to_string(),
                // Tor ends itself when the daemon is gone, however it went.
                "--__OwningControllerProcess".into(),
                self.ctx.daemon_pid.to_string(),
            ],
            env,
            cwd: Some(paths.dir.clone()),
            run_as,
            data_dir: paths.dir,
            pid_file: Some(crate::children::pid_file(self.ctx.state_dir()?, &self.id)),
            guarded: false,
            // Every control check of the daemon is a "connection" in Tor's log.
            quiet_patterns: vec!["New control connection opened".into()],
            health: Some(Arc::new(TorHealth(self.clone()))),
            before_start: Some(Arc::new(move || prepare(&prepare_paths, &prepare_as))),
            on_exit: None,
            start_deadline: None,
            on_deadline: None,
            config_tag: String::new(),
        })
    }
}

#[cfg(windows)]
fn own_sid() -> Option<String> {
    super::tor_control::winacl::current_user_sid().ok()
}

#[cfg(not(windows))]
fn own_sid() -> Option<String> {
    None
}

/// Up when Tor has bootstrapped, asked over the control port.
struct TorHealth(ManagedTor);

impl HealthCheck for TorHealth {
    fn check(&self) -> ChildHealth {
        match self.0.connect().and_then(|mut c| c.bootstrap_progress()) {
            Ok(p) if p >= 100 => ChildHealth::Up,
            Ok(p) => ChildHealth::Bootstrapping(p),
            Err(_) => ChildHealth::Starting,
        }
    }
}

/// Before each start: the data directory exists, is private to the account Tor runs as,
/// holds no leftovers of an earlier run that could be mistaken for the new one, and has a
/// fresh `torrc`.
pub fn prepare(paths: &TorPaths, run_as: &RunAs) -> Result<(), String> {
    let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");
    std::fs::create_dir_all(&paths.dir)
        .map_err(|e| fail(&format!("cannot create {}", paths.dir.display()), &e))?;
    crate::install::record_owned_directory_once(&paths.dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| fail(&format!("cannot protect {}", paths.dir.display()), &e))?;
    }
    #[cfg(windows)]
    {
        // SYSTEM and Administrators, and LocalService only when Tor runs as it: an ACE for
        // an account that does not own the files would fail the vetting of the cookie.
        crate::state::protect_service_dir(&paths.dir, *run_as == RunAs::LocalService)
            .map_err(|e| fail(&format!("cannot protect {}", paths.dir.display()), &e))?;
    }
    #[cfg(unix)]
    if let RunAs::Account { uid, gid, .. } = run_as {
        hand_over(&paths.dir, *uid, *gid)?;
    }
    // Stale endpoints and cookie: whatever answers must be the Tor started now.
    for f in [
        &paths.control_socket,
        &paths.control_port_file,
        &paths.cookie,
    ] {
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(fail(&format!("cannot remove {}", f.display()), &e)),
        }
    }
    write_torrc(paths)?;
    #[cfg(unix)]
    if let RunAs::Account { uid, gid, .. } = run_as {
        chown(&paths.torrc, *uid, *gid)?;
        // The state directory is private to root (it holds the database); the account
        // must be able to reach its own directory below it, and nothing else.
        if let Some(parent) = paths.dir.parent() {
            allow_traverse(parent)?;
        }
    }
    #[cfg(not(unix))]
    let _ = run_as;
    Ok(())
}

/// Let every account enter `dir` (execute, not list or read) without changing anything else.
#[cfg(unix)]
pub(super) fn allow_traverse(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o001 != 0 {
        return Ok(());
    }
    std::fs::set_permissions(
        dir,
        std::fs::Permissions::from_mode((mode & 0o7777) | 0o001),
    )
    .map_err(|e| format!("cannot let the Tor account enter {}: {e}", dir.display()))
}

/// `lchown` (never follows a link) `p` to `uid`/`gid`.
#[cfg(unix)]
pub(super) fn chown(p: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("bad path {}", p.display()))?;
    // SAFETY: `c` is a valid NUL-terminated path; lchown does not follow links.
    let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot give {} to uid {uid}: {}",
            p.display(),
            std::io::Error::last_os_error()
        ))
    }
}

/// Make `dir` belong to the account. A directory of another uid (the account was recreated,
/// or Tor ran as someone else before) holds state this account cannot use, and the daemon,
/// running as root, must not walk a tree that an unprivileged process controls to change
/// owners in it: its contents are removed and Tor starts afresh.
#[cfg(unix)]
pub(super) fn hand_over(dir: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(dir).map_err(|e| e.to_string())?.uid();
    if owner != uid {
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let removed = if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                std::fs::remove_dir_all(entry.path())
            } else {
                std::fs::remove_file(entry.path())
            };
            removed.map_err(|e| format!("cannot clear {}: {e}", entry.path().display()))?;
        }
    }
    chown(dir, uid, gid)
}

/// Create `torrc` fresh and exclusively: the directory belongs to the account Tor runs as,
/// so a link planted there must not make the daemon write somewhere else.
fn write_torrc(paths: &TorPaths) -> Result<(), String> {
    write_fresh(&paths.torrc, &torrc(paths, cfg!(windows)), 0o644)
}

/// Write `text` to a new file `path` (an old one is removed first), exclusively and never
/// through a link, with `mode` on Unix. For files the daemon writes into a directory that
/// belongs to the unprivileged account of a child.
pub(super) fn write_fresh(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    use std::io::Write;
    let fail = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(fail(e)),
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = open.open(path).map_err(fail)?;
    f.write_all(text.as_bytes()).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::FakeAccounts;
    use crate::bundled::Bundled;
    use crate::children::Supervisor;

    fn paths() -> TorPaths {
        TorPaths::new(Path::new("/var/lib/socketguard"))
    }

    #[test]
    fn torrc_for_unix_is_exactly_this() {
        assert_eq!(
            torrc(&paths(), false),
            "# Written by SocketGuard each time it starts Tor; changes made here are overwritten.\n\
             DataDirectory \"/var/lib/socketguard/tor\"\n\
             SocksPort 0\n\
             ControlSocket \"/var/lib/socketguard/tor/control\"\n\
             CookieAuthentication 1\n\
             CookieAuthFile \"/var/lib/socketguard/tor/control_auth_cookie\"\n\
             Log notice stdout\n"
        );
    }

    #[test]
    fn torrc_for_windows_lets_tor_pick_the_port_and_say_so() {
        let p = TorPaths::new(Path::new("C:/ProgramData/SocketGuard"));
        let t = torrc(&p, true);
        assert!(t.contains("ControlPort auto\n"));
        assert!(
            t.contains("ControlPortWriteToFile \"C:/ProgramData/SocketGuard/tor/control-port\"\n")
        );
        assert!(!t.contains("ControlSocket"));
        for forbidden in ["GeoIP", "ClientTransportPlugin", "ORPort", "User "] {
            assert!(!t.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_port_file_is_parsed() {
        assert_eq!(
            parse_port_file("PORT=127.0.0.1:41999\n").as_deref(),
            Some("127.0.0.1:41999")
        );
        assert_eq!(parse_port_file(""), None);
        assert_eq!(parse_port_file("PORT=\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_account_is_used_when_it_exists_and_the_daemon_is_root() {
        let a = FakeAccounts::present();
        assert_eq!(
            resolve_run_as(&a),
            RunAs::Account {
                name: "socketguard-net".into(),
                uid: 990,
                gid: 990
            }
        );
        assert_eq!(resolve_run_as(&a).describe(), "socketguard-net");

        let absent = resolve_run_as(&FakeAccounts::absent());
        assert_eq!(
            absent.describe(),
            "the daemon's account (socketguard-net does not exist)"
        );
        let user = FakeAccounts {
            root: false,
            daemon_uid: 1000,
            ..FakeAccounts::present()
        };
        assert!(resolve_run_as(&user)
            .describe()
            .contains("not running as root"));
    }

    /// A LocalService logon that fails means the daemon's own account runs Tor, and the
    /// directory, the expected owner of the cookie and the account shown all say so.
    #[test]
    fn when_the_logon_fails_the_daemons_account_is_used_for_acl_and_cookie_owner() {
        let works = FakeAccounts::present();
        assert_eq!(resolve_windows(&works, true), RunAs::LocalService);
        assert_eq!(
            cookie_owner(&RunAs::LocalService, Some("S-1-5-21-1".into())).as_deref(),
            Some("S-1-5-19")
        );

        let broken = FakeAccounts {
            local_service_error: Some("LogonUser: access denied".into()),
            ..FakeAccounts::present()
        };
        let run_as = resolve_windows(&broken, true);
        assert!(matches!(run_as, RunAs::Daemon { .. }));
        assert_eq!(
            run_as.describe(),
            "the daemon's account (could not log LocalService on: LogonUser: access denied)"
        );
        // ACL: no entry for LocalService; cookie: the daemon's own SID.
        assert_ne!(run_as, RunAs::LocalService);
        assert_eq!(
            cookie_owner(&run_as, Some("S-1-5-21-1".into())).as_deref(),
            Some("S-1-5-21-1")
        );
        // Not SYSTEM: not even asked.
        let not_system = resolve_windows(&works, false);
        assert!(not_system.describe().contains("not SYSTEM"));
    }

    fn ctx(dir: Option<PathBuf>, accounts: FakeAccounts) -> ManagedCtx {
        let third = std::env::temp_dir().join(format!("sg-tor3p-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(third.join("tor")).unwrap();
        let exe = if cfg!(windows) { "tor.exe" } else { "tor" };
        std::fs::write(third.join("tor").join(exe), b"x").unwrap();
        ManagedCtx::new(
            Arc::new(Bundled::from_dir(third)),
            dir,
            Arc::new(Supervisor::system()),
            Arc::new(accounts),
        )
    }

    fn state_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-tor-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn the_spec_has_the_command_line_environment_and_paths_of_the_adr() {
        let d = state_dir();
        let c = ctx(Some(d.clone()), FakeAccounts::present());
        let spec = ManagedTor::new("tor", &c).spec().unwrap();
        let torrc = d.join("tor").join("torrc").display().to_string();
        assert_eq!(
            spec.args,
            [
                "-f".to_string(),
                torrc,
                "--__OwningControllerProcess".into(),
                std::process::id().to_string()
            ]
        );
        assert_eq!(spec.data_dir, d.join("tor"));
        // The pid file is where only the daemon writes, not in the child's directory.
        assert_eq!(spec.pid_file, Some(d.join("run").join("tor.pid")));
        assert!(!spec.pid_file.as_ref().unwrap().starts_with(&spec.data_dir));
        assert_eq!(spec.quiet_patterns, ["New control connection opened"]);
        assert_eq!(spec.cwd.as_deref(), Some(d.join("tor").as_path()));
        if cfg!(target_os = "linux") {
            let third = c.bundled.dir().unwrap().join("tor");
            assert_eq!(
                spec.env,
                [("LD_LIBRARY_PATH".to_string(), third.display().to_string())]
            );
        }
        assert!(spec.health.is_some() && spec.before_start.is_some());
    }

    #[tokio::test]
    async fn without_files_or_a_state_directory_the_spec_says_why() {
        let none = ManagedCtx::inert();
        assert_eq!(
            ManagedTor::new("tor", &none).spec().unwrap_err(),
            socketguard_core::setup::NOT_INCLUDED
        );
        let c = ctx(None, FakeAccounts::present());
        assert!(ManagedTor::new("tor", &c)
            .spec()
            .unwrap_err()
            .contains("no state directory"));
    }

    #[tokio::test]
    async fn the_control_endpoint_comes_from_our_paths_and_the_cookie_is_pinned() {
        let d = state_dir();
        let c = ctx(Some(d.clone()), FakeAccounts::present());
        let t = ManagedTor::new("tor", &c);
        if cfg!(windows) {
            // Nothing written yet.
            assert!(t.connect_params().is_err());
            std::fs::create_dir_all(d.join("tor")).unwrap();
            std::fs::write(d.join("tor").join("control-port"), "PORT=127.0.0.1:9999\n").unwrap();
            let (e, o) = t.connect_params().unwrap();
            assert_eq!(e, Endpoint::Tcp("127.0.0.1:9999".into()));
            assert!(o.cookie_owner.is_some());
        } else {
            let (e, o) = t.connect_params().unwrap();
            assert_eq!(
                e,
                Endpoint::Unix(d.join("tor").join("control").display().to_string())
            );
            assert_eq!(o.expect_tor_uid.is_some(), cfg!(target_os = "linux"));
            if cfg!(target_os = "linux") {
                assert_eq!(o.expect_tor_uid, Some(990), "the account's uid");
            }
        }
        let (_, o) = t.connect_params().unwrap();
        assert_eq!(o.auth, TorAuth::Cookie);
        assert_eq!(
            o.cookie_path.as_deref(),
            Some(d.join("tor").join("control_auth_cookie").to_str().unwrap())
        );
        assert!(!o.allow_remote_control);
    }

    /// A daemon that is not SYSTEM runs Tor as itself: the directory is protected without
    /// an entry for LocalService, so the cookie Tor writes passes the vetting.
    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_a_daemon_that_is_not_system_vets_its_own_cookie() {
        let d = state_dir();
        let accounts = FakeAccounts {
            root: false,
            ..FakeAccounts::present()
        };
        let c = ctx(Some(d.clone()), accounts);
        let t = ManagedTor::new("tor", &c);
        let spec = t.spec().unwrap();
        assert!(matches!(spec.run_as, RunAs::Daemon { .. }));
        (spec.before_start.unwrap())().unwrap();
        // Tor writes these as the account it runs as: this process.
        let paths = TorPaths::new(&d);
        std::fs::write(&paths.cookie, [7u8; 32]).unwrap();
        std::fs::write(&paths.control_port_file, "PORT=127.0.0.1:1\n").unwrap();
        let (_, opts) = t.connect_params().unwrap();
        super::super::tor_control::read_cookie_file(&paths.cookie.display().to_string(), &opts)
            .unwrap();
    }

    /// The daemon is SYSTEM but the LocalService logon fails: the same happens as above, and
    /// the status says why.
    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_a_failed_localservice_logon_runs_tor_as_the_daemon_and_vets_that() {
        let d = state_dir();
        let accounts = FakeAccounts {
            local_service_error: Some("LogonUser: access denied".into()),
            ..FakeAccounts::present()
        };
        let c = ctx(Some(d.clone()), accounts);
        let t = ManagedTor::new("tor", &c);
        let spec = t.spec().unwrap();
        assert!(matches!(spec.run_as, RunAs::Daemon { .. }));
        assert!(spec
            .run_as
            .describe()
            .contains("could not log LocalService on: LogonUser: access denied"));
        (spec.before_start.unwrap())().unwrap();
        let paths = TorPaths::new(&d);
        std::fs::write(&paths.cookie, [7u8; 32]).unwrap();
        std::fs::write(&paths.control_port_file, "PORT=127.0.0.1:1\n").unwrap();
        let (_, opts) = t.connect_params().unwrap();
        assert_eq!(opts.cookie_owner, own_sid());
        super::super::tor_control::read_cookie_file(&paths.cookie.display().to_string(), &opts)
            .unwrap();
    }

    /// Portable mode has no installer and no account of its own: the daemon (an elevated user,
    /// not SYSTEM) is the account, and LocalService is not even asked.
    struct PortableAccounts;

    impl Accounts for PortableAccounts {
        fn lookup(&self, _name: &str) -> Option<account::Ids> {
            None
        }
        fn daemon(&self) -> (u32, bool) {
            (0, false)
        }
        fn local_service_logon(&self) -> Result<(), String> {
            panic!("portable mode never tries to log LocalService on");
        }
        fn portable(&self) -> bool {
            true
        }
    }

    #[test]
    fn portable_mode_runs_tor_as_the_daemons_account_without_trying_localservice() {
        let run_as = resolve_run_as(&PortableAccounts);
        if cfg!(windows) {
            assert_eq!(run_as, RunAs::Portable);
            assert_eq!(
                run_as.describe(),
                "the account running portable SocketGuard"
            );
            // The cookie is vetted against the daemon's own account, not LocalService's.
            assert_eq!(
                cookie_owner(&run_as, Some("S-1-5-21-1".into())).as_deref(),
                Some("S-1-5-21-1")
            );
        }
        // The same account on the other side of the flag still goes through the logon.
        let installed = FakeAccounts::present();
        assert!(!installed.portable);
        assert_ne!(
            resolve_run_as(&installed).describe(),
            "the account running portable SocketGuard"
        );
    }

    /// A managed Tor in portable mode: the directory under the data folder is protected
    /// (not inheriting the allowed user's read access), Tor's cookie is vetted as the
    /// daemon's own.
    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_portable_tor_has_a_protected_directory_and_vets_its_own_cookie() {
        use crate::state::winacl::tests::dacl_sddl;
        let d = state_dir();
        // Everyone (S-1-1-0) stands in for the account allowed to read `data\`.
        crate::state::protect_portable_dir(&d, Some("S-1-1-0")).unwrap();
        let accounts = FakeAccounts {
            portable: true,
            // Never consulted in portable mode.
            local_service_error: Some("must not be asked".into()),
            ..FakeAccounts::present()
        };
        let c = ctx(Some(d.clone()), accounts);
        let t = ManagedTor::new("tor", &c);
        let spec = t.spec().unwrap();
        assert_eq!(spec.run_as, RunAs::Portable);
        (spec.before_start.unwrap())().unwrap();
        let paths = TorPaths::new(&d);
        let sddl = dacl_sddl(&paths.dir);
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(
            !sddl.contains(";;;WD)") && !sddl.contains("FRFX") && !sddl.contains(";;;LS)"),
            "{sddl}"
        );
        std::fs::write(&paths.cookie, [7u8; 32]).unwrap();
        std::fs::write(&paths.control_port_file, "PORT=127.0.0.1:1\n").unwrap();
        let (_, opts) = t.connect_params().unwrap();
        assert_eq!(opts.cookie_owner, own_sid());
        super::super::tor_control::read_cookie_file(&paths.cookie.display().to_string(), &opts)
            .unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn the_reasons_follow_the_child() {
        let d = state_dir();
        let c = ctx(Some(d), FakeAccounts::present());
        let t = ManagedTor::new("tor", &c);
        assert_eq!(t.reason(true), "SocketGuard is turned off");
        assert!(!t.is_up());
        assert_eq!(t.info().state, ChildState::Stopped);
        assert_eq!(t.info().version, None);
    }

    /// The directory belongs to the account Tor runs as, which the daemon (root) does not
    /// trust: a `torrc` that is a link must not make it overwrite what the link points at.
    #[cfg(unix)]
    #[test]
    fn prepare_never_writes_through_a_planted_link() {
        let d = state_dir();
        let p = TorPaths::new(&d);
        std::fs::create_dir_all(&p.dir).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, &p.torrc).unwrap();
        std::os::unix::fs::symlink(&victim, &p.cookie).unwrap();
        prepare(&p, &RunAs::Daemon { note: None }).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        let meta = std::fs::symlink_metadata(&p.torrc).unwrap();
        assert!(meta.is_file(), "torrc is a regular file again");
        assert!(!p.cookie.exists());
        assert_eq!(std::fs::read_to_string(&p.torrc).unwrap(), torrc(&p, false));
    }

    #[test]
    fn prepare_makes_a_private_directory_a_fresh_torrc_and_no_leftovers() {
        let d = state_dir();
        let p = TorPaths::new(&d);
        std::fs::create_dir_all(&p.dir).unwrap();
        for f in [&p.control_socket, &p.control_port_file, &p.cookie] {
            std::fs::write(f, b"stale").unwrap();
        }
        std::fs::write(&p.torrc, b"old").unwrap();
        prepare(&p, &RunAs::Daemon { note: None }).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p.torrc).unwrap(),
            torrc(&p, cfg!(windows))
        );
        for f in [&p.control_socket, &p.control_port_file, &p.cookie] {
            assert!(!f.exists(), "{}", f.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p.dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // Twice is the same.
        prepare(&p, &RunAs::Daemon { note: None }).unwrap();
    }
}
