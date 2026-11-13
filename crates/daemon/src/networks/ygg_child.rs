//! The Yggdrasil node (ADR 0052): SocketGuard runs its own `yggdrasil` as a child
//! process. What is specific to it lives here: where its files are, the configuration file
//! it is started with, who it runs as, how to tell that it works, and the one-node-per-host
//! rule. The network around it is `ip::yggdrasil_child`; when it may start (after its
//! block is in force) is the engine's gate.
//!
//! The node's key is the daemon's (`ygg_key`): the address and the /64 are known before
//! anything runs, and the configuration file is rewritten from it at every start.

use super::child::ChildCtx;
use super::ip::ygg_admin::{self, AdminClient, PeerInfo};
use super::tor_child::write_fresh;
use super::ygg_key::YggKey;
use crate::account::{self, Accounts};
use crate::children::{
    ChildHealth, ChildSpec, ChildStatus, HealthCheck, OnExit, RunAs, StatusHandle,
};
use crate::iface::InterfaceManager;
use crate::ruleset::OverlayNode;
use socketguard_core::{ChildInfo, ChildState};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::warn;

/// The directory of the Yggdrasil under the state directory.
pub const DIR: &str = "yggdrasil";

/// The reason shown while another Yggdrasil node runs on the host (one node per host).
pub const OTHER_NODE: &str = "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it.";

/// A start that ends sooner than this counts as a failed start.
const QUICK_EXIT: Duration = Duration::from_secs(10);
/// A node that runs but has not answered on its admin socket this long after its start is
/// restarted without the admin socket (see [`AdminValve::engage`]).
pub const ADMIN_DEADLINE: Duration = Duration::from_secs(20);

/// What the card says while the node runs without an admin socket.
pub const PEERS_UNAVAILABLE: &str = "peer information unavailable: the admin socket does not work";

/// The longest admin socket path used; the system limit is 104 or 108 bytes.
const MAX_SOCKET_PATH: usize = 100;

/// The name SocketGuard gives the adapter of its node; None on macOS, where the system
/// names a `utunN` and the adapter is found by the address it holds.
pub fn adapter_name() -> Option<&'static str> {
    if cfg!(windows) {
        Some("SocketGuard")
    } else if cfg!(target_os = "macos") {
        None
    } else {
        Some("sgygg0")
    }
}

/// Where the Yggdrasil keeps its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YggPaths {
    /// Holds the configuration (with the key) and the pid file; the daemon's own.
    pub dir: PathBuf,
    pub conf: PathBuf,
    /// Belongs to the account Yggdrasil runs as: it removes its admin socket there when it
    /// ends, which the daemon's directory does not allow.
    pub run_dir: PathBuf,
    pub admin_socket: PathBuf,
}

impl YggPaths {
    pub fn new(state_dir: &Path) -> Self {
        let dir = state_dir.join(DIR);
        let run_dir = dir.join("run");
        Self {
            conf: dir.join("yggdrasil.conf"),
            admin_socket: run_dir.join("admin.sock"),
            run_dir,
            dir,
        }
    }

    /// The `AdminListen` value for the admin socket, or None when its path is too long for
    /// a Unix socket (the node then runs without admin).
    ///
    /// Windows: Yggdrasil takes the path from the URL, where a drive letter would end up
    /// in the host part, so the path is given without it and resolves on the current
    /// drive (the child's working directory is on the state directory's drive).
    pub fn admin_listen(&self) -> Option<String> {
        let mut path = self.admin_socket.display().to_string();
        if path.len() > MAX_SOCKET_PATH {
            return None;
        }
        if cfg!(windows) {
            path = path.replace('\\', "/");
            if path.as_bytes().get(1) == Some(&b':') {
                path = path[2..].to_string();
            }
        }
        Some(format!("unix://{path}"))
    }
}

/// Who the Yggdrasil runs as. Unix: it starts as the daemon's account (root, which
/// the tun needs) and drops to `socketguard-net` itself when that account exists and the
/// daemon may; else it stays the daemon's, saying why. Windows: the daemon's account, since
/// creating the adapter needs its rights.
pub fn resolve_run_as(accounts: &dyn Accounts) -> RunAs {
    if cfg!(windows) {
        if accounts.portable() {
            return RunAs::Portable;
        }
        return RunAs::Daemon {
            note: Some("creating the network adapter needs the daemon's rights".into()),
        };
    }
    let (_, root) = accounts.daemon();
    match accounts.lookup(account::NAME) {
        Some(_) if root => RunAs::DropsTo {
            name: account::NAME.into(),
        },
        Some(_) => RunAs::Daemon {
            note: Some(format!(
                "the daemon is not running as root, so it cannot drop Yggdrasil to {}",
                account::NAME
            )),
        },
        None => RunAs::Daemon {
            note: Some(format!("{} does not exist", account::NAME)),
        },
    }
}

/// The configuration file: only what SocketGuard decides. Everything else keeps Yggdrasil's
/// own default. `MulticastInterfaces` is `[]` unless `lan_discovery` is on: the node then
/// neither beacons nor opens a peering listener on the LAN (ADR 0060). On, the key is left
/// out and the built-in default applies (every interface, beacon and listen: nodes on the
/// LAN find each other). Checked against 0.5.15: `-useconffile <conf> -normaliseconf` prints
/// that default for a file without the key.
pub fn conf_text(
    key: &YggKey,
    peers: &[String],
    lan_discovery: bool,
    if_name: &str,
    admin_listen: Option<&str>,
) -> String {
    let mut conf = serde_json::json!({
        "PrivateKey": key.private_hex(),
        "IfName": if_name,
        "AdminListen": admin_listen.unwrap_or("none"),
        "Listen": [],
        "Peers": peers,
        "NodeInfoPrivacy": true,
    });
    if !lan_discovery {
        conf["MulticastInterfaces"] = serde_json::json!([]);
    }
    let mut text = serde_json::to_string_pretty(&conf).expect("a JSON value");
    text.push('\n');
    text
}

/// What stops Yggdrasil from starting because of its admin socket, and what the node does
/// then. Yggdrasil exits when it cannot open the admin socket, and Windows support for
/// Unix sockets in Go is the part least known to work: after two starts in a row that end
/// within [`QUICK_EXIT`] with a last line about the admin socket, the node is started
/// without one.
#[derive(Debug, Default)]
pub struct AdminValve {
    quick_failures: u32,
    off: bool,
}

impl AdminValve {
    pub fn admin_on(&self) -> bool {
        !self.off
    }

    /// The node was up but never answered on its admin socket in time: close the valve.
    /// Returns whether that changed anything (the next start differs).
    pub fn engage(&mut self) -> bool {
        !std::mem::replace(&mut self.off, true)
    }

    /// A process ended on its own after `ran_for`, last printing `last_line`.
    pub fn record_exit(&mut self, ran_for: Duration, last_line: Option<&str>) {
        let about_admin =
            last_line.is_some_and(|l| l.to_ascii_lowercase().contains("admin socket"));
        if ran_for < QUICK_EXIT && about_admin {
            self.quick_failures += 1;
            if self.quick_failures >= 2 {
                self.off = true;
            }
        } else {
            self.quick_failures = 0;
        }
    }
}

/// The admin valves of the Yggdrasil networks by network id.
pub type Valves = Arc<Mutex<HashMap<String, AdminValve>>>;

pub fn in_yggdrasil_range(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xfe00 == 0x0200
}

/// Whether an interface other than ours holds an address in `200::/7`: another Yggdrasil
/// node runs here. Ours is the adapter SocketGuard names, and (macOS) whichever interface
/// holds the node's own address.
pub fn another_node_running(
    ifaces: &dyn InterfaceManager,
    ours: &OverlayNode,
    adapter: Option<&str>,
) -> bool {
    let Ok(list) = ifaces.list_interfaces() else {
        return false;
    };
    list.iter().any(|i| {
        if Some(i.name.as_str()) == adapter {
            return false;
        }
        match ifaces.list_addresses(&i.name) {
            Ok(addrs) => !addrs.contains(&ours.address) && addrs.iter().any(in_yggdrasil_range),
            Err(_) => false,
        }
    })
}

/// The Yggdrasil of one network.
#[derive(Clone)]
pub struct YggChild {
    id: String,
    ctx: ChildCtx,
    ifaces: Arc<dyn InterfaceManager>,
    status: StatusHandle,
    paths: Result<YggPaths, String>,
}

impl YggChild {
    pub fn new(id: &str, ctx: &ChildCtx, ifaces: Arc<dyn InterfaceManager>) -> Self {
        Self {
            id: id.to_string(),
            status: ctx.children.handle(id),
            paths: ctx.state_dir().map(YggPaths::new),
            ifaces,
            ctx: ctx.clone(),
        }
    }

    pub fn key(&self) -> Option<YggKey> {
        self.ctx.keys.get(&self.id)
    }

    /// The node's addresses, from the key alone.
    pub fn node(&self) -> Option<OverlayNode> {
        self.key().map(|k| k.node())
    }

    pub fn child(&self) -> ChildStatus {
        self.status.get()
    }

    fn admin_on(&self) -> bool {
        self.ctx
            .valves
            .lock()
            .unwrap()
            .get(&self.id)
            .is_none_or(AdminValve::admin_on)
    }

    fn admin_client(&self) -> Option<AdminClient> {
        let paths = self.paths.as_ref().ok()?;
        // The callers are the status of the network and the health check: a node that
        // hangs must not hold them up for the 10 s the protocol allows.
        (self.admin_on() && paths.admin_listen().is_some())
            .then(|| AdminClient::new(&paths.admin_socket).with_deadline(Duration::from_secs(2)))
    }

    /// The interface of the node: the adapter SocketGuard names, else (macOS) the one that
    /// holds the node's address.
    pub fn interface(&self) -> Option<String> {
        if let Some(name) = adapter_name() {
            return Some(name.to_string());
        }
        let address = self.node()?.address;
        self.ifaces
            .list_interfaces()
            .ok()?
            .into_iter()
            .find_map(|i| {
                self.ifaces
                    .list_addresses(&i.name)
                    .ok()?
                    .contains(&address)
                    .then_some(i.name)
            })
    }

    /// Whether the node's adapter holds the node's address.
    fn adapter_has_address(&self) -> bool {
        let Some(node) = self.node() else {
            return false;
        };
        match adapter_name() {
            Some(name) => self
                .ifaces
                .list_addresses(name)
                .is_ok_and(|a| a.contains(&node.address)),
            None => self.interface().is_some(),
        }
    }

    /// Why the network is down while the child is not `Up`; empty when it is.
    pub fn reason(&self) -> String {
        let s = self.child();
        let or = |d: Option<String>, fallback: &str| d.unwrap_or_else(|| fallback.to_string());
        match s.state {
            ChildState::Up => String::new(),
            ChildState::Stopped => "SocketGuard is turned off".into(),
            ChildState::Waiting => or(s.detail, "waiting"),
            ChildState::Unavailable => or(s.detail, "Yggdrasil is not available"),
            // A detail here is what the health check could not do (see `children`).
            ChildState::Starting | ChildState::Bootstrapping => {
                or(s.detail, "Yggdrasil is starting")
            }
            ChildState::Exited => or(s.detail, "Yggdrasil exited"),
        }
    }

    /// The peerings and which are connected; None while the node does not answer or runs
    /// without an admin socket.
    pub fn peers(&self) -> Option<Vec<PeerInfo>> {
        if self.child().state != ChildState::Up {
            return None;
        }
        self.admin_client()?.get_peers().ok()
    }

    /// The start deadline passed: unless the node answers on its admin socket after all,
    /// close the valve so that the next start has none. Returns whether to restart.
    fn admin_deadline_passed(&self) -> bool {
        let Some(client) = self.admin_client() else {
            return false;
        };
        let ours = self.key().map(|k| k.public_hex());
        if matches!(client.get_self(), Ok(info) if Some(&info.key) == ours.as_ref()) {
            return false;
        }
        warn!("Yggdrasil does not answer on its admin socket; restarting it without");
        self.ctx
            .valves
            .lock()
            .unwrap()
            .entry(self.id.clone())
            .or_default()
            .engage()
    }

    /// The card of the network (the configured peers are added by the engine). Without a
    /// working admin socket there is nothing to count: it says so.
    pub fn info(&self, peers_connected: Option<u32>) -> ChildInfo {
        let s = self.child();
        let no_admin = !self.admin_on();
        ChildInfo {
            state: s.state,
            progress: None,
            detail: s
                .detail
                .or_else(|| no_admin.then(|| PEERS_UNAVAILABLE.to_string())),
            runs_as: s
                .runs_as
                .or_else(|| Some(resolve_run_as(self.ctx.accounts.as_ref()).describe())),
            version: self.ctx.bundled.version_of("yggdrasil"),
            address: self.node().map(|n| n.address.to_string()),
            peers: vec![],
            lan_discovery: false,
            peers_connected: if no_admin { None } else { peers_connected },
            bridges: vec![],
            bridges_unavailable: None,
        }
    }

    /// The child to run with `peers`, or why this build cannot run one.
    pub fn spec(&self, peers: &[String], lan_discovery: bool) -> Result<ChildSpec, String> {
        self.spec_with(peers, lan_discovery, cfg!(windows))
    }

    /// [`YggChild::spec`], with the admin valve armed or not (tests arm it everywhere).
    pub fn spec_with(
        &self,
        peers: &[String],
        lan_discovery: bool,
        valve_armed: bool,
    ) -> Result<ChildSpec, String> {
        let files = self.ctx.bundled.yggdrasil()?;
        let paths = self.paths.clone()?;
        let key = self
            .key()
            .ok_or_else(|| "the node's key is not available".to_string())?;
        let run_as = resolve_run_as(self.ctx.accounts.as_ref());
        let mut args = vec!["-useconffile".to_string(), paths.conf.display().to_string()];
        if let RunAs::DropsTo { name } = &run_as {
            args.push("-user".into());
            args.push(name.clone());
        }
        let owner = match &run_as {
            RunAs::DropsTo { name } => self.ctx.accounts.lookup(name).map(|ids| (ids.uid, ids.gid)),
            _ => None,
        };
        let prepare = Prepare {
            paths: paths.clone(),
            owner,
            key,
            peers: peers.to_vec(),
            lan_discovery,
            ygg: self.clone(),
        };
        let id = self.id.clone();
        let valves = self.ctx.valves.clone();
        let on_exit: Option<OnExit> = valve_armed.then(|| {
            Arc::new(move |ran_for: Duration, last: Option<&str>| {
                valves
                    .lock()
                    .unwrap()
                    .entry(id.clone())
                    .or_default()
                    .record_exit(ran_for, last);
            }) as OnExit
        });
        let ygg = self.clone();
        let state_dir = self.ctx.state_dir()?.to_path_buf();
        Ok(ChildSpec {
            name: "yggdrasil".into(),
            program: files.binary,
            args,
            env: vec![],
            // `-user` clears the parent-death signal: on Unix the child guard ends the node
            // when the daemon goes.
            guarded: cfg!(unix) && matches!(run_as, RunAs::DropsTo { .. }),
            pid_file: Some(crate::children::pid_file(&state_dir, &self.id)),
            quiet_patterns: vec![],
            start_deadline: Some(ADMIN_DEADLINE),
            on_deadline: Some(Arc::new(move || ygg.admin_deadline_passed())),
            stall_limit: None,
            // On the drive of the admin socket path (see `YggPaths::admin_listen`); the
            // DLL of the tun driver is found next to the executable, not here.
            cwd: Some(paths.dir.clone()),
            run_as,
            data_dir: paths.dir,
            health: Some(Arc::new(YggHealth(self.clone()))),
            before_start: Some(Arc::new(move || prepare.run())),
            on_exit,
            // What makes a launch different: a change restarts the node.
            config_tag: format!("{}\nlan_discovery={lan_discovery}", peers.join("\n")),
        })
    }
}

/// Up when the node answers on its admin socket (when it has one) as the node of our key
/// and its adapter holds the node's address.
struct YggHealth(YggChild);

impl HealthCheck for YggHealth {
    fn check(&self) -> ChildHealth {
        if let Some(client) = self.0.admin_client() {
            let ours = self.0.key().map(|k| k.public_hex());
            match client.get_self() {
                Ok(info) if Some(&info.key) == ours.as_ref() => {}
                Ok(_) => {
                    return ChildHealth::NotReady(
                        "the admin socket answers as another node than ours".into(),
                    )
                }
                Err(e) => {
                    return ChildHealth::NotReady(format!(
                        "cannot ask Yggdrasil over its admin socket: {e:#}"
                    ))
                }
            }
        }
        if self.0.adapter_has_address() {
            ChildHealth::Up
        } else {
            // Not an error: the node brings its adapter up a moment after it answers.
            ChildHealth::Starting
        }
    }
}

/// Everything `before_start` needs, owned by the closure.
struct Prepare {
    paths: YggPaths,
    /// Unix: the uid and gid Yggdrasil drops to, who gets the run directory.
    owner: Option<(u32, u32)>,
    key: YggKey,
    peers: Vec<String>,
    lan_discovery: bool,
    ygg: YggChild,
}

impl Prepare {
    fn run(&self) -> Result<(), String> {
        if cfg!(windows) {
            crate::wintun::record_before_first_start();
        }
        let admin = self
            .ygg
            .admin_on()
            .then(|| self.paths.admin_listen())
            .flatten();
        let text = conf_text(
            &self.key,
            &self.peers,
            self.lan_discovery,
            adapter_name().unwrap_or("auto"),
            admin.as_deref(),
        );
        prepare(&self.paths, self.owner, &text)
    }
}

/// Before each start: the directory exists and is private, the run directory belongs to
/// the account Yggdrasil drops to, no admin socket of an earlier run is left, and the
/// configuration file (with the key) is fresh and readable by the daemon only.
pub fn prepare(paths: &YggPaths, owner: Option<(u32, u32)>, conf: &str) -> Result<(), String> {
    let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");
    std::fs::create_dir_all(&paths.run_dir)
        .map_err(|e| fail(&format!("cannot create {}", paths.run_dir.display()), &e))?;
    crate::install::record_owned_directory_once(&paths.dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The account must be able to reach its run directory through this one, nothing
        // more: it cannot list it, and the configuration file is the daemon's (0600).
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o711))
            .map_err(|e| fail(&format!("cannot protect {}", paths.dir.display()), &e))?;
        std::fs::set_permissions(&paths.run_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| fail(&format!("cannot protect {}", paths.run_dir.display()), &e))?;
    }
    #[cfg(windows)]
    {
        crate::state::protect_service_dir(&paths.dir, false)
            .map_err(|e| fail(&format!("cannot protect {}", paths.dir.display()), &e))?;
    }
    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        super::tor_child::hand_over(&paths.run_dir, uid, gid)?;
        if let Some(parent) = paths.dir.parent() {
            super::tor_child::allow_traverse(parent)?;
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    // An admin socket left by an earlier run would make the new node refuse to start.
    match std::fs::remove_file(&paths.admin_socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(fail(
                &format!("cannot remove {}", paths.admin_socket.display()),
                &e,
            ))
        }
    }
    write_fresh(&paths.conf, conf, 0o600)
}

/// `peers` the node is connected to, for the card.
pub fn connected_count(peers: &[PeerInfo]) -> u32 {
    ygg_admin::connected(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::FakeAccounts;
    use crate::bundled::Bundled;
    use crate::children::Supervisor;
    use crate::test_support::MockInterfaceManager;

    const SEED: &str = "d20dbc4f35cf53079f03a6c61ab57ac17b2b7dd838bed20dea94fe30ed804566";
    const PUBLIC: &str = "58926089882365c29f6aaf27fc64955554ff9568c78a5e17d9d87dba8ed1c44d";

    pub(crate) fn key() -> YggKey {
        YggKey::from_private_hex(&format!("{SEED}{PUBLIC}")).unwrap()
    }

    fn state_dir() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sg-y-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ifaces() -> MockInterfaceManager {
        MockInterfaceManager::new(Default::default())
    }

    pub(crate) fn ctx(dir: Option<PathBuf>, accounts: FakeAccounts) -> ChildCtx {
        let third = std::env::temp_dir().join(format!("sg-ygg3p-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(third.join("yggdrasil")).unwrap();
        let exe = if cfg!(windows) {
            "yggdrasil.exe"
        } else {
            "yggdrasil"
        };
        std::fs::write(third.join("yggdrasil").join(exe), b"x").unwrap();
        std::fs::write(third.join("yggdrasil").join("wintun.dll"), b"x").unwrap();
        let ctx = ChildCtx::new(
            Arc::new(Bundled::from_dir(third)),
            dir,
            Arc::new(Supervisor::system()),
            Arc::new(accounts),
        );
        ctx.keys.insert("ygg", key());
        ctx
    }

    fn ygg(ctx: &ChildCtx, net: &MockInterfaceManager) -> YggChild {
        YggChild::new("ygg", ctx, Arc::new(net.clone()))
    }

    #[test]
    fn the_conf_has_what_socketguard_decides_and_nothing_else() {
        let text = conf_text(
            &key(),
            &[
                "tcp://192.0.2.1:9001".into(),
                "tls://example.org:443".into(),
            ],
            false,
            "sgygg0",
            Some("unix:///var/lib/socketguard/yggdrasil/run/admin.sock"),
        );
        let expected = format!(
            r#"{{
  "AdminListen": "unix:///var/lib/socketguard/yggdrasil/run/admin.sock",
  "IfName": "sgygg0",
  "Listen": [],
  "MulticastInterfaces": [],
  "NodeInfoPrivacy": true,
  "Peers": [
    "tcp://192.0.2.1:9001",
    "tls://example.org:443"
  ],
  "PrivateKey": "{SEED}{PUBLIC}"
}}
"#
        );
        assert_eq!(text, expected);
        // LAN discovery on: the key is left out and Yggdrasil's default applies.
        let on = conf_text(&key(), &[], true, "auto", None);
        assert!(!on.contains("Multicast"), "{on}");
        let none = conf_text(&key(), &[], false, "auto", None);
        assert!(none.contains(r#""AdminListen": "none""#) && none.contains(r#""IfName": "auto""#));
        assert!(none.contains(r#""Peers": []"#));
    }

    #[test]
    fn the_admin_socket_is_in_the_run_directory_and_a_long_path_means_no_admin() {
        let p = YggPaths::new(Path::new("/var/lib/socketguard"));
        assert_eq!(
            p.conf,
            Path::new("/var/lib/socketguard/yggdrasil/yggdrasil.conf")
        );
        if !cfg!(windows) {
            assert_eq!(
                p.admin_listen().as_deref(),
                Some("unix:///var/lib/socketguard/yggdrasil/run/admin.sock")
            );
        }
        let long = YggPaths::new(Path::new(&format!("/{}", "d".repeat(100))));
        assert_eq!(long.admin_listen(), None);
    }

    #[test]
    fn the_account_decides_who_it_runs_as() {
        let drops = resolve_run_as(&FakeAccounts::present());
        let absent = resolve_run_as(&FakeAccounts::absent()).describe();
        let not_root = resolve_run_as(&FakeAccounts {
            root: false,
            ..FakeAccounts::present()
        })
        .describe();
        if cfg!(windows) {
            assert!(matches!(drops, RunAs::Daemon { .. }));
            assert!(drops.describe().contains("daemon's account"));
        } else {
            assert_eq!(
                drops,
                RunAs::DropsTo {
                    name: "socketguard-net".into()
                }
            );
            assert_eq!(drops.describe(), "socketguard-net");
            assert_eq!(
                absent,
                "the daemon's account (socketguard-net does not exist)"
            );
            assert!(not_root.contains("not running as root"));
        }
    }

    #[test]
    fn portable_mode_runs_yggdrasil_as_the_account_running_it() {
        let portable = FakeAccounts {
            portable: true,
            ..FakeAccounts::present()
        };
        if cfg!(windows) {
            let run_as = resolve_run_as(&portable);
            assert_eq!(run_as, RunAs::Portable);
            assert_eq!(
                run_as.describe(),
                "the account running portable SocketGuard"
            );
        }
    }

    /// The node's key (`yggdrasil.conf`) in portable mode: the directory is protected, so the
    /// read access the allowed user has on `data\` does not reach it.
    #[cfg(windows)]
    #[tokio::test]
    async fn on_windows_portable_yggdrasil_keeps_its_key_from_the_allowed_user() {
        use crate::state::winacl::tests::dacl_sddl;
        let d = state_dir();
        // Everyone (S-1-1-0) stands in for the account allowed to read `data\`.
        crate::state::protect_portable_dir(&d, Some("S-1-1-0")).unwrap();
        let accounts = FakeAccounts {
            portable: true,
            ..FakeAccounts::present()
        };
        let c = ctx(Some(d.clone()), accounts);
        let spec = ygg(&c, &ifaces()).spec(&[], false).unwrap();
        assert_eq!(spec.run_as, RunAs::Portable);
        (spec.before_start.unwrap())().unwrap();
        let paths = YggPaths::new(&d);
        for p in [&paths.dir, &paths.conf, &paths.run_dir] {
            let sddl = dacl_sddl(p);
            assert!(
                !sddl.contains(";;;WD)") && !sddl.contains("FRFX"),
                "{}: {sddl}",
                p.display()
            );
        }
        assert!(dacl_sddl(&paths.dir).starts_with("D:P"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn the_spec_has_the_command_line_and_paths_of_the_adr() {
        let d = state_dir();
        let c = ctx(Some(d.clone()), FakeAccounts::present());
        let spec = ygg(&c, &ifaces())
            .spec(&["tcp://192.0.2.1:9001".to_string()], false)
            .unwrap();
        assert_eq!(spec.name, "yggdrasil");
        let conf = d
            .join("yggdrasil")
            .join("yggdrasil.conf")
            .display()
            .to_string();
        if cfg!(windows) {
            assert_eq!(spec.args, ["-useconffile".to_string(), conf]);
        } else {
            assert_eq!(
                spec.args,
                [
                    "-useconffile".to_string(),
                    conf,
                    "-user".into(),
                    "socketguard-net".into()
                ]
            );
        }
        assert_eq!(spec.data_dir, d.join("yggdrasil"));
        assert_eq!(spec.pid_file, Some(d.join("run").join("ygg.pid")));
        assert!(!spec.pid_file.as_ref().unwrap().starts_with(&spec.data_dir));
        assert_eq!(spec.guarded, cfg!(unix), "-user drops the death signal");
        assert_eq!(spec.start_deadline, Some(ADMIN_DEADLINE));
        assert_eq!(spec.cwd.as_deref(), Some(d.join("yggdrasil").as_path()));
        assert_eq!(spec.config_tag, "tcp://192.0.2.1:9001\nlan_discovery=false");
        assert!(spec.health.is_some() && spec.before_start.is_some());
        // A different peer list is a different launch; the same one is not.
        let other = ygg(&c, &ifaces()).spec(&[], false).unwrap();
        assert!(!spec.same_launch(&other));
        assert!(other.same_launch(&ygg(&c, &ifaces()).spec(&[], false).unwrap()));
        // So is turning LAN discovery on.
        assert!(!other.same_launch(&ygg(&c, &ifaces()).spec(&[], true).unwrap()));
    }

    #[tokio::test]
    async fn without_files_key_or_state_directory_the_spec_says_why() {
        let none = ChildCtx::inert();
        none.keys.insert("ygg", key());
        assert_eq!(
            YggChild::new("ygg", &none, Arc::new(ifaces()))
                .spec(&[], false)
                .unwrap_err(),
            socketguard_core::setup::NOT_INCLUDED
        );
        let c = ctx(None, FakeAccounts::present());
        assert!(ygg(&c, &ifaces())
            .spec(&[], false)
            .unwrap_err()
            .contains("no state directory"));
        let c = ctx(Some(state_dir()), FakeAccounts::present());
        c.keys.remove("ygg");
        assert_eq!(
            ygg(&c, &ifaces()).spec(&[], false).unwrap_err(),
            "the node's key is not available"
        );
    }

    #[test]
    fn prepare_writes_a_private_fresh_conf_and_clears_the_admin_socket() {
        let d = state_dir();
        let p = YggPaths::new(&d);
        std::fs::create_dir_all(&p.run_dir).unwrap();
        std::fs::write(&p.admin_socket, b"stale").unwrap();
        std::fs::write(&p.conf, b"old").unwrap();
        prepare(&p, None, "NEW\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p.conf).unwrap(), "NEW\n");
        assert!(!p.admin_socket.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |f: &Path| std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&p.conf), 0o600);
            assert_eq!(mode(&p.dir), 0o711);
            assert_eq!(mode(&p.run_dir), 0o700);
        }
        prepare(&p, None, "NEWER\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p.conf).unwrap(), "NEWER\n");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_never_writes_the_key_through_a_planted_link() {
        let d = state_dir();
        let p = YggPaths::new(&d);
        std::fs::create_dir_all(&p.run_dir).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, &p.conf).unwrap();
        std::os::unix::fs::symlink(&victim, &p.admin_socket).unwrap();
        prepare(&p, None, "KEY\n").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert!(std::fs::symlink_metadata(&p.conf).unwrap().is_file());
    }

    #[test]
    fn a_node_on_another_interface_is_found_and_ours_is_not() {
        let ours = key().node();
        let net = ifaces();
        net.add_interface("eth0");
        net.add_interface("sgygg0");
        net.add_interface("utun4");
        net.add_interface("ygg0");
        net.plant_address("eth0", "2001:db8::1".parse().unwrap());
        assert!(!another_node_running(&net, &ours, Some("sgygg0")));

        // Ours: the named adapter holds the node address and an app address (300::/7 too).
        net.plant_address("sgygg0", ours.address);
        net.plant_address("sgygg0", "301:9db6:7dd9:df72::5".parse().unwrap());
        assert!(!another_node_running(&net, &ours, Some("sgygg0")));
        // macOS: no known name, the interface holding our address is ours.
        net.plant_address("utun4", ours.address);
        net.drop_address("sgygg0", ours.address);
        net.drop_address("sgygg0", "301:9db6:7dd9:df72::5".parse().unwrap());
        assert!(!another_node_running(&net, &ours, None));

        // Another node: its own address on another interface.
        net.plant_address("ygg0", "200:1111:2222::1".parse().unwrap());
        assert!(another_node_running(&net, &ours, Some("sgygg0")));
        net.drop_address("ygg0", "200:1111:2222::1".parse().unwrap());
        assert!(!another_node_running(&net, &ours, Some("sgygg0")));
    }

    #[test]
    fn the_valve_closes_after_two_quick_exits_about_the_admin_socket() {
        let s = |n| Duration::from_secs(n);
        let admin = Some("2026/11/12 Admin socket failed to listen: bad path");
        let mut v = AdminValve::default();
        assert!(v.admin_on());
        v.record_exit(s(1), admin);
        assert!(v.admin_on(), "once is not twice");
        // A different failure, or a long run, starts the count over.
        v.record_exit(s(1), Some("panic: no tun"));
        v.record_exit(s(1), admin);
        assert!(v.admin_on());
        v.record_exit(s(60), admin);
        v.record_exit(s(1), admin);
        assert!(v.admin_on());
        v.record_exit(s(9), admin);
        assert!(!v.admin_on());
        // It stays off.
        v.record_exit(s(60), None);
        assert!(!v.admin_on());
    }

    #[tokio::test(start_paused = true)]
    async fn the_valve_works_through_the_supervisor_and_the_next_conf_has_no_admin() {
        use crate::children::fake::FakeSpawner;
        let d = state_dir();
        let fake = FakeSpawner::default();
        let mut c = ctx(Some(d.clone()), FakeAccounts::own());
        c.children = Arc::new(Supervisor::new(Arc::new(fake.clone())));
        let y = ygg(&c, &ifaces());
        let spec = y.spec_with(&[], false, true).unwrap();
        c.children.set("ygg", Some(spec));
        let conf = d.join("yggdrasil").join("yggdrasil.conf");
        let step = Duration::from_millis(5);
        tokio::time::sleep(step).await;
        let first = std::fs::read_to_string(&conf).unwrap();
        if !cfg!(windows) {
            assert!(first.contains(r#""AdminListen": "unix://"#), "{first}");
        }
        for round in 1..=2 {
            fake.last()
                .print("Admin socket failed to listen: no such file");
            fake.last().exit("exit code 1");
            // The pause before the restart doubles from one second.
            tokio::time::sleep(Duration::from_secs(3)).await;
            assert_eq!(fake.started(), round + 1, "restarted after round {round}");
        }
        let after = std::fs::read_to_string(&conf).unwrap();
        assert!(after.contains(r#""AdminListen": "none""#), "{after}");
        assert!(!y.admin_on());
        assert!(y.admin_client().is_none());
    }

    /// The node runs but never answers on its admin socket: after the deadline it is
    /// restarted without one, the adapter holding the address is then enough, and the card
    /// says that peer information is unavailable.
    #[tokio::test(start_paused = true)]
    async fn a_silent_admin_socket_means_a_restart_without_it_after_the_deadline() {
        use crate::children::fake::FakeSpawner;
        use socketguard_core::ChildState;
        let d = state_dir();
        let fake = FakeSpawner::default();
        let mut c = ctx(Some(d.clone()), FakeAccounts::own());
        c.children = Arc::new(Supervisor::new(Arc::new(fake.clone())));
        let net = ifaces();
        let y = ygg(&c, &net);
        let conf = d.join("yggdrasil").join("yggdrasil.conf");
        c.children.set("ygg", Some(y.spec(&[], false).unwrap()));
        tokio::time::sleep(Duration::from_millis(5)).await;
        if y.paths.as_ref().unwrap().admin_listen().is_none() {
            return;
        }
        assert!(std::fs::read_to_string(&conf).unwrap().contains("unix://"));

        // Alive, adapter up with its address, but no answer on the admin socket.
        let adapter = adapter_name().unwrap_or("utun7");
        net.add_interface(adapter);
        net.plant_address(adapter, key().node().address);
        tokio::time::sleep(ADMIN_DEADLINE - Duration::from_secs(2)).await;
        assert_eq!(fake.started(), 1, "not before the deadline");
        assert_ne!(y.child().state, ChildState::Up);
        assert!(y.admin_on());

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(
            fake.proc(0).signals(),
            ["term"],
            "the first node was stopped"
        );
        assert_eq!(fake.started(), 2, "restarted");
        assert!(!y.admin_on());
        let after = std::fs::read_to_string(&conf).unwrap();
        assert!(after.contains(r#""AdminListen": "none""#), "{after}");

        // Without the admin socket the adapter holding the address makes it up.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(y.child().state, ChildState::Up);
        let info = y.info(Some(2));
        assert_eq!(info.detail.as_deref(), Some(PEERS_UNAVAILABLE));
        assert_eq!(info.peers_connected, None);
        assert_eq!(y.peers(), None);
        // And it is not asked again.
        tokio::time::sleep(ADMIN_DEADLINE * 2).await;
        assert_eq!(fake.started(), 2);
    }

    #[tokio::test]
    async fn health_needs_the_adapter_to_hold_the_address_and_the_admin_to_answer() {
        let d = state_dir();
        let c = ctx(Some(d.clone()), FakeAccounts::present());
        let net = ifaces();
        let y = ygg(&c, &net);
        let health = YggHealth(y.clone());
        let adapter = adapter_name().unwrap_or("utun7");
        net.add_interface(adapter);
        // Admin answers (fake), the adapter has no address yet.
        let paths = YggPaths::new(&d);
        std::fs::create_dir_all(&paths.run_dir).unwrap();
        let own_self = format!(
            r#"{{"status":"success","response":{{"key":"{PUBLIC}","address":"{}","subnet":"{}"}}}}"#,
            key().node().address,
            key().node().subnet
        );
        let fake =
            ygg_admin::fake::FakeAdmin::start_at(&paths.admin_socket, vec![("getself", own_self)]);
        if paths.admin_listen().is_some() {
            assert_eq!(health.check(), ChildHealth::Starting);
        }
        net.plant_address(adapter, key().node().address);
        assert_eq!(health.check(), ChildHealth::Up);
        drop(fake);
    }

    #[tokio::test]
    async fn another_nodes_answer_does_not_make_ours_up() {
        let d = state_dir();
        let c = ctx(Some(d.clone()), FakeAccounts::present());
        let net = ifaces();
        net.add_interface(adapter_name().unwrap_or("utun7"));
        net.plant_address(adapter_name().unwrap_or("utun7"), key().node().address);
        let paths = YggPaths::new(&d);
        std::fs::create_dir_all(&paths.run_dir).unwrap();
        let theirs = r#"{"status":"success","response":{"key":"00","address":"200::1","subnet":"300::/64"}}"#;
        let _fake = ygg_admin::fake::FakeAdmin::start_at(
            &paths.admin_socket,
            vec![("getself", theirs.into())],
        );
        if paths.admin_listen().is_some() {
            assert!(matches!(
                YggHealth(ygg(&c, &net)).check(),
                ChildHealth::NotReady(_)
            ));
        }
    }
}
