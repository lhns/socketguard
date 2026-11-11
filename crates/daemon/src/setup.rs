//! Detecting what the host offers for each kind of network (ADR 0048): read-only. Every
//! look at the system goes through [`Probes`], so tests use a fake.

use crate::iface::HostInterface;
use crate::networks::ip::yggdrasil::{self, NodeInfo};
use crate::networks::tor_control::{self, ProtocolInfo};
use anyhow::{bail, Context, Result};
use socketguard_core::config::DEFAULT_TOR_CONTROL;
use socketguard_core::setup::{
    download_link, install_command, LanCandidate, NetworkSetup, SetupKind, SetupState, SetupStatus,
};
use socketguard_core::{Network, NetworkKind};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long one look at the system may take: this runs on every refresh of the screen.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `name` (with the platform's executable suffixes) in the directories of `PATH`.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(&path).find_map(|dir| {
        exts.iter().find_map(|ext| {
            let p = dir.join(format!("{name}{ext}"));
            p.is_file().then_some(p)
        })
    })
}

/// A system service, as far as it can be told cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Missing,
    Unknown,
}

/// Everything detection looks at.
pub trait Probes: Send + Sync {
    /// `std::env::consts::OS`.
    fn os(&self) -> &'static str;
    /// A program on PATH (package managers, `tor`).
    fn has_program(&self, name: &str) -> bool;
    /// Where `yggdrasilctl` is.
    fn yggdrasilctl(&self) -> Option<PathBuf>;
    /// `yggdrasilctl -json getSelf`.
    fn get_self(&self, ctl: &Path) -> Result<NodeInfo>;
    /// How many peers the node is connected to (`yggdrasilctl -json getPeers`).
    fn peers_up(&self, ctl: &Path) -> Result<usize>;
    fn service(&self, name: &str) -> ServiceState;
    /// PROTOCOLINFO of the Tor control port at `addr`; no authentication.
    fn tor_protocolinfo(&self, addr: &str) -> Result<ProtocolInfo>;
    /// Whether the daemon would accept the cookie file with the default Tor settings.
    fn cookie_accepted(&self, path: &str) -> Result<()>;
    fn interfaces(&self) -> Result<Vec<HostInterface>>;
    fn addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>>;
}

/// The probes of this machine.
pub struct SystemProbes {
    ifaces: Box<dyn crate::iface::InterfaceManager>,
}

impl Default for SystemProbes {
    fn default() -> Self {
        Self {
            ifaces: crate::iface::create(),
        }
    }
}

/// Run `cmd` for at most `PROBE_TIMEOUT`; its stdout.
fn run_limited(mut cmd: std::process::Command) -> Result<String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start the program")?;
    let mut stdout = child.stdout.take().context("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        bail!("failed with {status}");
    }
    Ok(out)
}

impl Probes for SystemProbes {
    fn os(&self) -> &'static str {
        std::env::consts::OS
    }

    fn has_program(&self, name: &str) -> bool {
        find_in_path(name).is_some()
    }

    fn yggdrasilctl(&self) -> Option<PathBuf> {
        yggdrasil::find_yggdrasilctl()
    }

    fn get_self(&self, ctl: &Path) -> Result<NodeInfo> {
        let mut cmd = std::process::Command::new(ctl);
        cmd.args(["-json", "getSelf"]);
        yggdrasil::parse_get_self(&run_limited(cmd)?)
    }

    fn peers_up(&self, ctl: &Path) -> Result<usize> {
        let mut cmd = std::process::Command::new(ctl);
        cmd.args(["-json", "getPeers"]);
        parse_peers_up(&run_limited(cmd)?)
    }

    #[cfg(windows)]
    fn service(&self, name: &str) -> ServiceState {
        let mut cmd = std::process::Command::new("sc.exe");
        cmd.args(["query", name]);
        match run_limited(cmd) {
            Ok(out) if out.contains("RUNNING") => ServiceState::Running,
            Ok(out) if out.contains("STOPPED") => ServiceState::Stopped,
            Ok(_) => ServiceState::Unknown,
            // `sc query` exits 1060 for a service that does not exist.
            Err(e) if e.to_string().contains("1060") => ServiceState::Missing,
            Err(_) => ServiceState::Unknown,
        }
    }

    #[cfg(unix)]
    fn service(&self, name: &str) -> ServiceState {
        if find_in_path("systemctl").is_none() {
            return ServiceState::Unknown;
        }
        let mut cmd = std::process::Command::new("systemctl");
        cmd.args(["is-active", name]);
        match run_limited(cmd) {
            Ok(_) => ServiceState::Running,
            Err(_) => ServiceState::Stopped,
        }
    }

    fn tor_protocolinfo(&self, addr: &str) -> Result<ProtocolInfo> {
        tor_control::probe_protocolinfo(addr, Duration::from_millis(800))
    }

    fn cookie_accepted(&self, path: &str) -> Result<()> {
        let opts = tor_control::AuthOptions::new(socketguard_core::config::TorAuth::Cookie);
        tor_control::read_cookie_file(path, &opts).map(|_| ())
    }

    fn interfaces(&self) -> Result<Vec<HostInterface>> {
        self.ifaces.describe_interfaces()
    }

    fn addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        self.ifaces.list_addresses(iface)
    }
}

/// The peers that are up in `yggdrasilctl -json getPeers`: `{"peers":[{"up":true,...}]}`.
pub fn parse_peers_up(json: &str) -> Result<usize> {
    let v: serde_json::Value = serde_json::from_str(json).context("invalid getPeers JSON")?;
    let peers = v["peers"].as_array().context("no peers list")?;
    Ok(peers
        .iter()
        .filter(|p| p["up"].as_bool() == Some(true))
        .count())
}

/// What the daemon has already: singleton kinds, and the interfaces of LAN networks.
#[derive(Debug, Clone, Default)]
pub struct Existing {
    pub local: bool,
    pub yggdrasil: bool,
    pub tor: bool,
    pub lan_interfaces: HashSet<String>,
}

impl Existing {
    pub fn from_networks(networks: &[Network]) -> Self {
        let mut e = Self::default();
        for n in networks {
            match n.kind {
                NetworkKind::Local => e.local = true,
                NetworkKind::Yggdrasil => e.yggdrasil = true,
                NetworkKind::Tor => e.tor = true,
                NetworkKind::Lan => {
                    e.lan_interfaces.extend(n.interface.clone());
                }
                NetworkKind::WireGuard => {}
            }
        }
        e
    }
}

/// The service names the status lines look at.
#[cfg(windows)]
const YGGDRASIL_SERVICE: &str = "Yggdrasil";
#[cfg(not(windows))]
const YGGDRASIL_SERVICE: &str = "yggdrasil";

/// Everything `GET /api/networks/setup` reports.
pub fn detect(p: &dyn Probes, existing: &Existing, config_path: Option<&Path>) -> NetworkSetup {
    let (yggdrasil, ygg_iface) = detect_yggdrasil(p, existing);
    NetworkSetup {
        lan: detect_lan(p, existing, ygg_iface.as_deref()),
        yggdrasil,
        tor: detect_tor(p, existing),
        local: detect_local(existing),
        // Absolute: the elevated `networks setup` has another working directory.
        config_path: config_path
            .map(|c| std::path::absolute(c).unwrap_or_else(|_| c.to_path_buf()))
            .map(|c| c.display().to_string()),
    }
}

fn detect_local(existing: &Existing) -> SetupState {
    SetupState::new(if existing.local {
        SetupStatus::Added
    } else {
        SetupStatus::Ready
    })
}

/// The LAN interfaces to offer: no loopback or tunnels, default route first.
fn detect_lan(p: &dyn Probes, existing: &Existing, skip: Option<&str>) -> Vec<LanCandidate> {
    let mut out: Vec<LanCandidate> = p
        .interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.loopback && !i.tunnel && Some(i.name.as_str()) != skip)
        .map(|i| LanCandidate {
            already_added: existing.lan_interfaces.contains(&i.name),
            interface: i.name,
            description: i.description,
            has_ipv6_prefix: i.has_ipv6_prefix,
            is_default_route: i.default_route,
            vlan_id: i.vlan_id,
        })
        .collect();
    out.sort_by(|a, b| {
        b.is_default_route
            .cmp(&a.is_default_route)
            .then_with(|| a.interface.cmp(&b.interface))
    });
    out
}

/// A state that says the software is missing: the package command where one is known to
/// exist, else the official download page.
fn not_installed(p: &dyn Probes, kind: SetupKind, missing: String) -> SetupState {
    let mut s = SetupState::new(SetupStatus::NotInstalled);
    s.missing = Some(missing);
    match install_command(kind, p.os(), &|m| p.has_program(m)) {
        Some(cmd) => s.install = Some(cmd.offer(Some(download_link(kind)))),
        None => s.download_link = Some(download_link(kind).to_string()),
    }
    s
}

/// The Yggdrasil state, and the interface that holds the node's address.
fn detect_yggdrasil(p: &dyn Probes, existing: &Existing) -> (SetupState, Option<String>) {
    let ctl = p.yggdrasilctl();
    let node = ctl.as_deref().map(|c| p.get_self(c));
    let iface = node
        .as_ref()
        .and_then(|n| n.as_ref().ok())
        .and_then(|info| {
            p.interfaces()
                .ok()?
                .into_iter()
                .find(|i| {
                    p.addresses(&i.name)
                        .is_ok_and(|a| a.contains(&info.address))
                })
                .map(|i| i.name)
        });
    if existing.yggdrasil {
        return (SetupState::new(SetupStatus::Added), iface);
    }
    let Some(ctl) = ctl else {
        let missing =
            if install_command(SetupKind::Yggdrasil, p.os(), &|m| p.has_program(m)).is_some() {
                "Yggdrasil is not installed."
            } else {
                "Yggdrasil is not installed; it has to be installed by hand."
            };
        return (
            not_installed(p, SetupKind::Yggdrasil, missing.to_string()),
            None,
        );
    };
    let mut state;
    let ctl_path = ctl.clone();
    match node.expect("ctl is set") {
        Ok(info) => {
            state = SetupState::new(SetupStatus::Ready);
            state
                .found
                .insert("address".into(), info.address.to_string());
            if let Ok(n) = p.peers_up(&ctl_path) {
                state.found.insert("peers".into(), n.to_string());
            }
            match &iface {
                Some(name) => {
                    state.found.insert("interface".into(), name.clone());
                }
                None => {
                    state.state = SetupStatus::NotConfigured;
                    state.missing = Some("the Yggdrasil adapter has no address yet".to_string());
                }
            }
        }
        Err(_) => {
            state = SetupState::new(SetupStatus::NotRunning);
            state.missing = Some(match p.service(YGGDRASIL_SERVICE) {
                ServiceState::Stopped => "The Yggdrasil service is stopped.".to_string(),
                _ => "Yggdrasil is installed, but the node is not running.".to_string(),
            });
        }
    }
    state
        .found
        .insert("yggdrasilctl".into(), ctl.display().to_string());
    (state, iface)
}

fn detect_tor(p: &dyn Probes, existing: &Existing) -> SetupState {
    if existing.tor {
        return SetupState::new(SetupStatus::Added);
    }
    match p.tor_protocolinfo(DEFAULT_TOR_CONTROL) {
        Ok(info) => {
            let mut s = SetupState::new(SetupStatus::Ready);
            s.found
                .insert("control".into(), DEFAULT_TOR_CONTROL.to_string());
            if let Some(v) = &info.version {
                s.found.insert("version".into(), v.clone());
            }
            if let Some(c) = &info.cookie_file {
                s.found.insert("cookie_path".into(), c.clone());
            }
            let cookie = info.methods.iter().any(|m| m == "SAFECOOKIE");
            match (&info.cookie_file, cookie) {
                (_, false) | (None, _) => {
                    s.state = SetupStatus::NotConfigured;
                    s.missing = Some("Tor's cookie authentication is off.".into());
                }
                // The API takes default Tor settings only, and those have no cookie_path:
                // fine on Unix if the daemon accepts the cookie file as it is.
                (Some(path), true) => {
                    let known = p.os() != "windows" && p.cookie_accepted(path).is_ok();
                    if !known {
                        s.state = SetupStatus::NotConfigured;
                        s.missing = Some("SocketGuard does not know Tor's cookie file yet.".into());
                    }
                }
            }
            s
        }
        // Debian's Tor offers a control socket with cookie authentication out of the box.
        // The API takes default settings only, so the socket goes into the config file.
        Err(_) if p.os() == "linux" && p.tor_protocolinfo(DEBIAN_CONTROL_SOCKET).is_ok() => {
            let mut s = SetupState::new(SetupStatus::NotConfigured);
            s.found
                .insert("control".into(), DEBIAN_CONTROL_SOCKET.to_string());
            s.missing = Some("SocketGuard does not know Tor's control socket yet.".into());
            s
        }
        Err(_) if p.has_program("tor") || tor_service_exists(p) => {
            let mut s = SetupState::new(SetupStatus::NotConfigured);
            s.missing = Some("Tor's control port is not enabled.".into());
            s
        }
        Err(_) => not_installed(p, SetupKind::Tor, tor_missing_sentence(p)),
    }
}

/// The control socket of Debian's Tor service (`tor-service-defaults-torrc`).
const DEBIAN_CONTROL_SOCKET: &str = "unix:/run/tor/control";

fn tor_service_exists(p: &dyn Probes) -> bool {
    matches!(
        p.service("tor"),
        ServiceState::Running | ServiceState::Stopped
    )
}

fn tor_missing_sentence(p: &dyn Probes) -> String {
    if install_command(SetupKind::Tor, p.os(), &|m| p.has_program(m)).is_some() {
        "Tor is not installed.".into()
    } else if p.os() == "windows" {
        "Tor is not installed. Windows has no package for it; download the Tor Expert Bundle."
            .into()
    } else {
        "Tor is not installed; install it from the Tor Project's download page.".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        os: &'static str,
        programs: Vec<&'static str>,
        ctl: Option<PathBuf>,
        node: Option<NodeInfo>,
        services: HashMap<&'static str, ServiceState>,
        tor: Option<ProtocolInfo>,
        cookie_ok: bool,
        ifaces: Vec<HostInterface>,
        addrs: HashMap<String, Vec<Ipv6Addr>>,
        peers: Option<usize>,
        tor_sockets: HashMap<&'static str, ProtocolInfo>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                os: "windows",
                programs: vec![],
                ctl: None,
                node: None,
                services: HashMap::new(),
                tor: None,
                cookie_ok: false,
                ifaces: vec![],
                addrs: HashMap::new(),
                peers: None,
                tor_sockets: HashMap::new(),
            }
        }
    }

    impl Probes for Fake {
        fn os(&self) -> &'static str {
            self.os
        }
        fn has_program(&self, name: &str) -> bool {
            self.programs.contains(&name)
        }
        fn yggdrasilctl(&self) -> Option<PathBuf> {
            self.ctl.clone()
        }
        fn get_self(&self, _: &Path) -> Result<NodeInfo> {
            self.node.clone().context("not running")
        }
        fn peers_up(&self, _: &Path) -> Result<usize> {
            self.peers.context("no peers")
        }
        fn service(&self, name: &str) -> ServiceState {
            self.services
                .get(name)
                .copied()
                .unwrap_or(ServiceState::Unknown)
        }
        fn tor_protocolinfo(&self, addr: &str) -> Result<ProtocolInfo> {
            if let Some(i) = self.tor_sockets.get(addr) {
                return Ok(i.clone());
            }
            self.tor
                .clone()
                .filter(|_| !addr.starts_with("unix:"))
                .context("refused")
        }
        fn cookie_accepted(&self, _: &str) -> Result<()> {
            if self.cookie_ok {
                Ok(())
            } else {
                bail!("not accepted")
            }
        }
        fn interfaces(&self) -> Result<Vec<HostInterface>> {
            Ok(self.ifaces.clone())
        }
        fn addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
            Ok(self.addrs.get(iface).cloned().unwrap_or_default())
        }
    }

    fn node() -> NodeInfo {
        yggdrasil::parse_get_self(
            r#"{"key":"ba83","address":"200:8af8:ba35:56ae:bef0:6284:981f:5972","subnet":"300:8af8:ba35:56ae::/64"}"#,
        )
        .unwrap()
    }

    fn iface(name: &str) -> HostInterface {
        HostInterface {
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn yggdrasil_is_not_installed_with_an_offer_on_windows_with_winget() {
        let p = Fake {
            programs: vec!["winget"],
            ..Default::default()
        };
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotInstalled);
        let offer = s.install.unwrap();
        assert_eq!(offer.manager, "winget");
        assert_eq!(
            offer.command,
            "winget install --id YggdrasilNetwork.Yggdrasil --source winget -e"
        );
        assert!(s.download_link.is_none());
    }

    #[test]
    fn yggdrasil_without_a_package_offers_the_download_page() {
        let p = Fake {
            os: "linux",
            programs: vec!["apt-get"],
            ..Default::default()
        };
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotInstalled);
        assert!(s.install.is_none());
        assert_eq!(
            s.download_link.as_deref(),
            Some(socketguard_core::setup::YGGDRASIL_DOWNLOAD)
        );
    }

    #[test]
    fn yggdrasil_not_running_when_get_self_fails() {
        let mut p = Fake {
            ctl: Some(PathBuf::from("C:/Program Files/Yggdrasil/yggdrasilctl.exe")),
            ..Default::default()
        };
        p.services.insert("Yggdrasil", ServiceState::Stopped);
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotRunning);
        assert_eq!(
            s.missing.as_deref(),
            Some("The Yggdrasil service is stopped.")
        );
        assert!(s.found["yggdrasilctl"].contains("yggdrasilctl"));
    }

    #[test]
    fn yggdrasil_ready_names_the_interface_that_holds_the_address() {
        let mut p = Fake {
            ctl: Some(PathBuf::from("yggdrasilctl")),
            node: Some(node()),
            ifaces: vec![iface("Ethernet"), iface("Yggdrasil")],
            ..Default::default()
        };
        p.addrs.insert("Yggdrasil".into(), vec![node().address]);
        let (s, found) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::Ready);
        assert_eq!(s.found["interface"], "Yggdrasil");
        assert_eq!(s.found["address"], node().address.to_string());
        assert_eq!(found.as_deref(), Some("Yggdrasil"));
        assert!(!s.found.contains_key("peers"));
    }

    #[test]
    fn peers_are_counted_from_get_peers() {
        let json = r#"{"peers":[{"remote":"tcp://a:1","up":true},{"remote":"tcp://b:1","up":false},{"address":"x","up":true}]}"#;
        assert_eq!(parse_peers_up(json).unwrap(), 2);
        assert_eq!(parse_peers_up(r#"{"peers":[]}"#).unwrap(), 0);
        assert!(parse_peers_up("{}").is_err());
        let mut p = Fake {
            ctl: Some(PathBuf::from("yggdrasilctl")),
            node: Some(node()),
            ifaces: vec![iface("Yggdrasil")],
            peers: Some(0),
            ..Default::default()
        };
        p.addrs.insert("Yggdrasil".into(), vec![node().address]);
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.found["peers"], "0");
    }

    #[test]
    fn yggdrasil_without_an_adapter_address_is_not_configured() {
        let p = Fake {
            ctl: Some(PathBuf::from("yggdrasilctl")),
            node: Some(node()),
            ifaces: vec![iface("Ethernet")],
            ..Default::default()
        };
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotConfigured);
        assert_eq!(
            s.missing.as_deref(),
            Some("the Yggdrasil adapter has no address yet")
        );
    }

    #[test]
    fn an_added_network_shows_as_added() {
        let existing = Existing {
            yggdrasil: true,
            tor: true,
            local: true,
            ..Default::default()
        };
        let s = detect(&Fake::default(), &existing, None);
        assert_eq!(s.yggdrasil.state, SetupStatus::Added);
        assert_eq!(s.tor.state, SetupStatus::Added);
        assert_eq!(s.local.state, SetupStatus::Added);
    }

    fn tor_info(methods: &[&str], cookie: Option<&str>) -> ProtocolInfo {
        ProtocolInfo {
            methods: methods.iter().map(|m| m.to_string()).collect(),
            cookie_file: cookie.map(str::to_string),
            version: Some("0.4.9.15".into()),
        }
    }

    #[test]
    fn tor_is_ready_on_unix_when_the_cookie_is_accepted() {
        let p = Fake {
            os: "linux",
            tor: Some(tor_info(&["COOKIE", "SAFECOOKIE"], Some("/run/tor/c"))),
            cookie_ok: true,
            ..Default::default()
        };
        let s = detect_tor(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::Ready);
        assert_eq!(s.found["control"], "127.0.0.1:9051");
        assert_eq!(s.found["version"], "0.4.9.15");
    }

    #[test]
    fn tor_needs_its_cookie_file_known_on_windows_and_for_untrusted_cookies() {
        let windows = Fake {
            tor: Some(tor_info(&["SAFECOOKIE"], Some("C:/tor/cookie"))),
            cookie_ok: true,
            ..Default::default()
        };
        let s = detect_tor(&windows, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotConfigured);
        assert_eq!(
            s.missing.as_deref(),
            Some("SocketGuard does not know Tor's cookie file yet.")
        );
        assert_eq!(s.found["cookie_path"], "C:/tor/cookie");
        let linux = Fake {
            os: "linux",
            tor: Some(tor_info(&["SAFECOOKIE"], Some("/run/tor/c"))),
            cookie_ok: false,
            ..Default::default()
        };
        assert_eq!(
            detect_tor(&linux, &Existing::default()).state,
            SetupStatus::NotConfigured
        );
    }

    #[test]
    fn a_control_socket_is_found_but_needs_the_config_file() {
        let mut p = Fake {
            os: "linux",
            ..Default::default()
        };
        p.tor_sockets.insert(
            "unix:/run/tor/control",
            tor_info(&["SAFECOOKIE"], Some("/run/tor/c")),
        );
        let s = detect_tor(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotConfigured);
        assert_eq!(s.found["control"], "unix:/run/tor/control");
        assert_eq!(
            s.missing.as_deref(),
            Some("SocketGuard does not know Tor's control socket yet.")
        );
    }

    #[test]
    fn tor_with_cookie_authentication_off() {
        let p = Fake {
            os: "linux",
            tor: Some(tor_info(&["NULL"], None)),
            ..Default::default()
        };
        let s = detect_tor(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotConfigured);
        assert_eq!(
            s.missing.as_deref(),
            Some("Tor's cookie authentication is off.")
        );
    }

    #[test]
    fn tor_installed_without_a_control_port_and_tor_missing() {
        let installed = Fake {
            os: "linux",
            programs: vec!["tor"],
            ..Default::default()
        };
        let s = detect_tor(&installed, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotConfigured);
        assert_eq!(
            s.missing.as_deref(),
            Some("Tor's control port is not enabled.")
        );

        let windows = Fake::default();
        let s = detect_tor(&windows, &Existing::default());
        assert_eq!(s.state, SetupStatus::NotInstalled);
        assert!(s.install.is_none());
        assert_eq!(
            s.download_link.as_deref(),
            Some("https://www.torproject.org/download/tor/")
        );
        assert!(s.missing.unwrap().contains("Windows has no package"));

        let debian = Fake {
            os: "linux",
            programs: vec!["apt-get"],
            ..Default::default()
        };
        let s = detect_tor(&debian, &Existing::default());
        assert_eq!(s.install.unwrap().command, "apt-get install -y tor");
    }

    #[test]
    fn lan_candidates_skip_tunnels_and_put_the_default_route_first() {
        let mk = |name: &str, default_route, tunnel, loopback| HostInterface {
            name: name.into(),
            default_route,
            tunnel,
            loopback,
            ..Default::default()
        };
        let p = Fake {
            ifaces: vec![
                mk("Ethernet 3", false, false, false),
                mk("Ethernet 2", true, false, false),
                mk("Loopback Pseudo-Interface 1", false, false, true),
                mk("Wintun", false, true, false),
                mk("Yggdrasil", false, false, false),
            ],
            ..Default::default()
        };
        let existing = Existing {
            lan_interfaces: HashSet::from(["Ethernet 3".to_string()]),
            ..Default::default()
        };
        let lan = detect_lan(&p, &existing, Some("Yggdrasil"));
        let names: Vec<_> = lan.iter().map(|l| l.interface.as_str()).collect();
        assert_eq!(names, ["Ethernet 2", "Ethernet 3"]);
        assert!(lan[0].is_default_route);
        assert!(!lan[0].already_added);
        assert!(lan[1].already_added);
    }
}
