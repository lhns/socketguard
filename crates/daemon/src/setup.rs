//! Detecting what the host offers for each kind of network (ADR 0048): read-only. Every
//! look at the system goes through [`Probes`], so tests use a fake.

use crate::bundled::Bundled;
use crate::iface::HostInterface;
use crate::networks::ip::yggdrasil::{self, NodeInfo};
use crate::networks::tor_control::{self, ProtocolInfo};
use anyhow::{bail, Context, Result};
use socketguard_core::config::DEFAULT_TOR_CONTROL;
use socketguard_core::setup::{
    KindSetup, LanCandidate, ManagedOffer, NetworkSetup, SetupState, SetupStatus,
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

/// Everything detection looks at.
pub trait Probes: Send + Sync {
    /// `std::env::consts::OS`.
    fn os(&self) -> &'static str;
    /// Where `yggdrasilctl` is.
    fn yggdrasilctl(&self) -> Option<PathBuf>;
    /// `yggdrasilctl -json getSelf`.
    fn get_self(&self, ctl: &Path) -> Result<NodeInfo>;
    /// How many peers the node is connected to (`yggdrasilctl -json getPeers`).
    fn peers_up(&self, ctl: &Path) -> Result<usize>;
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

/// Everything `GET /api/networks/setup` reports.
pub fn detect(
    p: &dyn Probes,
    existing: &Existing,
    config_path: Option<&Path>,
    bundled: &Bundled,
) -> NetworkSetup {
    let (ygg_existing, ygg_iface) = detect_yggdrasil(p, existing);
    NetworkSetup {
        lan: detect_lan(p, existing, ygg_iface.as_deref()),
        yggdrasil: KindSetup {
            managed: offer(bundled.yggdrasil().err(), bundled.version_of("yggdrasil")),
            existing: ygg_existing,
        },
        tor: KindSetup {
            managed: offer(bundled.tor().err(), bundled.version_of("tor")),
            existing: detect_tor(p, existing),
        },
        local: detect_local(existing),
        yggdrasil_block: None,
        // Absolute: the caller's working directory is not the daemon's.
        config_path: config_path
            .map(|c| std::path::absolute(c).unwrap_or_else(|_| c.to_path_buf()))
            .map(|c| c.display().to_string()),
    }
}

fn detect_local(existing: &Existing) -> SetupState {
    let mut s = SetupState::new(if existing.local {
        SetupStatus::Added
    } else {
        SetupStatus::Ready
    });
    s.found.insert(
        "interface".into(),
        socketguard_core::config::default_loopback(),
    );
    s
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

/// Whether SocketGuard can run its own copy: `reason` is why not.
fn offer(unavailable: Option<String>, version: Option<String>) -> ManagedOffer {
    ManagedOffer {
        available: unavailable.is_none(),
        reason: unavailable,
        version,
    }
}

/// What the card says about a running node that is not added to SocketGuard.
pub const EXPOSED_WARNING: &str = "Yggdrasil is running but not managed: programs on this PC that listen on all addresses are reachable over it until you add it here.";

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
        return (SetupState::new(SetupStatus::Absent), None);
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
                // The node answers but its adapter has no address: not usable yet.
                None => state.state = SetupStatus::Absent,
            }
        }
        Err(_) => state = SetupState::new(SetupStatus::Absent),
    }
    // A node answers but SocketGuard does not manage it (ADR 0051): programs listening on
    // all addresses are reachable over it.
    if state.found.contains_key("address") {
        state.exposed = true;
        state.warning = Some(EXPOSED_WARNING.to_string());
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
            // The API takes default Tor settings only, and those have no cookie_path:
            // fine on Unix if the daemon accepts the cookie file as it is.
            let usable = match &info.cookie_file {
                Some(path) if cookie => p.os() != "windows" && p.cookie_accepted(path).is_ok(),
                _ => false,
            };
            if !usable {
                s.state = SetupStatus::Absent;
            }
            s
        }
        Err(_) => SetupState::new(SetupStatus::Absent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        os: &'static str,
        ctl: Option<PathBuf>,
        node: Option<NodeInfo>,
        tor: Option<ProtocolInfo>,
        cookie_ok: bool,
        ifaces: Vec<HostInterface>,
        addrs: HashMap<String, Vec<Ipv6Addr>>,
        peers: Option<usize>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                os: "windows",
                ctl: None,
                node: None,
                tor: None,
                cookie_ok: false,
                ifaces: vec![],
                addrs: HashMap::new(),
                peers: None,
            }
        }
    }

    impl Probes for Fake {
        fn os(&self) -> &'static str {
            self.os
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
        fn tor_protocolinfo(&self, addr: &str) -> Result<ProtocolInfo> {
            let _ = addr;
            self.tor.clone().context("refused")
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
    fn yggdrasil_without_yggdrasilctl_is_absent() {
        let (s, iface) = detect_yggdrasil(&Fake::default(), &Existing::default());
        assert_eq!(s.state, SetupStatus::Absent);
        assert!(!s.exposed && s.warning.is_none() && iface.is_none());
    }

    #[test]
    fn yggdrasil_installed_but_not_running_is_absent() {
        let p = Fake {
            ctl: Some(PathBuf::from("C:/Program Files/Yggdrasil/yggdrasilctl.exe")),
            ..Default::default()
        };
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::Absent);
        assert!(s.found["yggdrasilctl"].contains("yggdrasilctl"));
        assert!(!s.exposed);
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
        assert!(s.exposed && s.warning.as_deref() == Some(EXPOSED_WARNING));
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
    fn yggdrasil_without_an_adapter_address_is_absent() {
        let p = Fake {
            ctl: Some(PathBuf::from("yggdrasilctl")),
            node: Some(node()),
            ifaces: vec![iface("Ethernet")],
            ..Default::default()
        };
        let (s, _) = detect_yggdrasil(&p, &Existing::default());
        assert_eq!(s.state, SetupStatus::Absent);
    }

    #[test]
    fn an_added_network_shows_as_added() {
        let existing = Existing {
            yggdrasil: true,
            tor: true,
            local: true,
            ..Default::default()
        };
        let s = detect(&Fake::default(), &existing, None, &Bundled::none());
        assert_eq!(s.yggdrasil.existing.state, SetupStatus::Added);
        assert_eq!(s.tor.existing.state, SetupStatus::Added);
        assert!(!s.tor.managed.available);
        assert_eq!(
            s.tor.managed.reason.as_deref(),
            Some(socketguard_core::setup::NOT_INCLUDED)
        );
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
    fn tor_is_absent_on_windows_and_for_untrusted_cookies_or_no_cookie_auth() {
        let windows = Fake {
            tor: Some(tor_info(&["SAFECOOKIE"], Some("C:/tor/cookie"))),
            cookie_ok: true,
            ..Default::default()
        };
        let s = detect_tor(&windows, &Existing::default());
        assert_eq!(s.state, SetupStatus::Absent);
        assert_eq!(s.found["cookie_path"], "C:/tor/cookie");
        let untrusted = Fake {
            os: "linux",
            tor: Some(tor_info(&["SAFECOOKIE"], Some("/run/tor/c"))),
            cookie_ok: false,
            ..Default::default()
        };
        assert_eq!(
            detect_tor(&untrusted, &Existing::default()).state,
            SetupStatus::Absent
        );
        let no_cookie = Fake {
            os: "linux",
            tor: Some(tor_info(&["NULL"], None)),
            ..Default::default()
        };
        assert_eq!(
            detect_tor(&no_cookie, &Existing::default()).state,
            SetupStatus::Absent
        );
    }

    #[test]
    fn tor_without_a_control_port_is_absent() {
        let s = detect_tor(&Fake::default(), &Existing::default());
        assert_eq!(s.state, SetupStatus::Absent);
        assert!(s.found.is_empty());
    }

    #[test]
    fn managed_offer_follows_the_bundled_files() {
        let d = std::env::temp_dir().join(format!("sg-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join("tor")).unwrap();
        std::fs::write(
            d.join("tor")
                .join(if cfg!(windows) { "tor.exe" } else { "tor" }),
            b"x",
        )
        .unwrap();
        std::fs::write(
            d.join("VERSIONS"),
            "tor 16.0.1
",
        )
        .unwrap();
        let s = detect(
            &Fake::default(),
            &Existing::default(),
            None,
            &Bundled::from_dir(&d),
        );
        assert!(s.tor.managed.available);
        assert_eq!(s.tor.managed.version.as_deref(), Some("16.0.1"));
        assert!(!s.yggdrasil.managed.available);
        assert!(s.yggdrasil.managed.reason.unwrap().contains("incomplete"));
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
