//! Detecting what the host offers for each kind of network (ADR 0048, ADR 0056): read-only.
//! Every look at the system goes through [`Probes`], so tests use a fake. Tor and Yggdrasil
//! are always SocketGuard's own, so what is detected is whether this build carries them and,
//! for Yggdrasil, whether another node already runs on the host.

use crate::bundled::Bundled;
use crate::iface::HostInterface;
use crate::networks::ygg_managed;
use anyhow::Result;
use socketguard_core::setup::{KindSetup, LanCandidate, NetworkSetup, SetupState, SetupStatus};
use socketguard_core::{Network, NetworkKind};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::Path;

/// Everything detection looks at.
pub trait Probes: Send + Sync {
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

impl Probes for SystemProbes {
    fn interfaces(&self) -> Result<Vec<HostInterface>> {
        self.ifaces.describe_interfaces()
    }

    fn addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
        self.ifaces.list_addresses(iface)
    }
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
    let mut yggdrasil = kind(
        existing.yggdrasil,
        bundled.yggdrasil().err(),
        bundled.version_of("yggdrasil"),
    );
    // Added, the network's own status says it waits; before, the card does.
    if !existing.yggdrasil && yggdrasil.available && another_node_running(p) {
        yggdrasil.reason = Some(ygg_managed::OTHER_NODE.to_string());
    }
    NetworkSetup {
        lan: detect_lan(p, existing),
        yggdrasil,
        tor: kind(existing.tor, bundled.tor().err(), bundled.version_of("tor")),
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
fn detect_lan(p: &dyn Probes, existing: &Existing) -> Vec<LanCandidate> {
    let mut out: Vec<LanCandidate> = p
        .interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.loopback && !i.tunnel)
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

/// SocketGuard's own copy of a kind: `unavailable` is why it cannot be added.
fn kind(added: bool, unavailable: Option<String>, version: Option<String>) -> KindSetup {
    KindSetup {
        available: unavailable.is_none(),
        reason: unavailable,
        version,
        added,
    }
}

/// Whether an adapter other than SocketGuard's own holds an address in Yggdrasil's range:
/// another node runs on this host.
fn another_node_running(p: &dyn Probes) -> bool {
    let ours = ygg_managed::adapter_name();
    p.interfaces().unwrap_or_default().iter().any(|i| {
        Some(i.name.as_str()) != ours
            && p.addresses(&i.name)
                .is_ok_and(|a| a.iter().any(ygg_managed::in_yggdrasil_range))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        ifaces: Vec<HostInterface>,
        addrs: HashMap<String, Vec<Ipv6Addr>>,
    }

    impl Probes for Fake {
        fn interfaces(&self) -> Result<Vec<HostInterface>> {
            Ok(self.ifaces.clone())
        }
        fn addresses(&self, iface: &str) -> Result<Vec<Ipv6Addr>> {
            Ok(self.addrs.get(iface).cloned().unwrap_or_default())
        }
    }

    fn iface(name: &str) -> HostInterface {
        HostInterface {
            name: name.into(),
            ..Default::default()
        }
    }

    fn with_files() -> (std::path::PathBuf, Bundled) {
        let d = std::env::temp_dir().join(format!("sg-setup-{}", uuid::Uuid::new_v4()));
        for (dir, exe) in [("tor", "tor"), ("yggdrasil", "yggdrasil")] {
            std::fs::create_dir_all(d.join(dir)).unwrap();
            let name = if cfg!(windows) {
                format!("{exe}.exe")
            } else {
                exe.to_string()
            };
            std::fs::write(d.join(dir).join(name), b"x").unwrap();
        }
        std::fs::write(d.join("yggdrasil").join("wintun.dll"), b"x").unwrap();
        std::fs::write(d.join("VERSIONS"), "tor 16.0.1\nyggdrasil v0.5.15\n").unwrap();
        let b = Bundled::from_dir(&d);
        (d, b)
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
        assert!(s.yggdrasil.added && s.tor.added);
        assert!(!s.tor.available);
        assert_eq!(
            s.tor.reason.as_deref(),
            Some(socketguard_core::setup::NOT_INCLUDED)
        );
        assert_eq!(s.local.state, SetupStatus::Added);
    }

    #[test]
    fn the_offer_follows_the_bundled_files() {
        let d = std::env::temp_dir().join(format!("sg-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join("tor")).unwrap();
        std::fs::write(
            d.join("tor")
                .join(if cfg!(windows) { "tor.exe" } else { "tor" }),
            b"x",
        )
        .unwrap();
        std::fs::write(d.join("VERSIONS"), "tor 16.0.1\n").unwrap();
        let s = detect(
            &Fake::default(),
            &Existing::default(),
            None,
            &Bundled::from_dir(&d),
        );
        assert!(s.tor.available && !s.tor.added);
        assert_eq!(s.tor.version.as_deref(), Some("16.0.1"));
        assert!(!s.yggdrasil.available);
        assert!(s.yggdrasil.reason.unwrap().contains("incomplete"));
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn another_yggdrasil_node_is_said_plainly_and_adding_stays_available() {
        let (d, bundled) = with_files();
        let mut p = Fake {
            ifaces: vec![iface("Ethernet"), iface("tun0")],
            ..Default::default()
        };
        let s = detect(&p, &Existing::default(), None, &bundled);
        assert!(s.yggdrasil.available && s.yggdrasil.reason.is_none());

        p.addrs
            .insert("tun0".into(), vec!["200:8af8::1".parse().unwrap()]);
        let s = detect(&p, &Existing::default(), None, &bundled);
        assert!(s.yggdrasil.available);
        assert_eq!(s.yggdrasil.reason.as_deref(), Some(ygg_managed::OTHER_NODE));
        assert_eq!(
            ygg_managed::OTHER_NODE,
            "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it."
        );
        // Our own adapter does not count, and once added the network speaks for itself.
        let own = ygg_managed::adapter_name().map(str::to_string);
        if let Some(own) = own {
            p.addrs.remove("tun0");
            p.ifaces.push(iface(&own));
            p.addrs.insert(own, vec!["200:8af8::1".parse().unwrap()]);
            let s = detect(&p, &Existing::default(), None, &bundled);
            assert!(s.yggdrasil.reason.is_none());
        }
        p.addrs
            .insert("tun0".into(), vec!["200:8af8::1".parse().unwrap()]);
        let added = Existing {
            yggdrasil: true,
            ..Default::default()
        };
        let s = detect(&p, &added, None, &bundled);
        assert!(s.yggdrasil.added && s.yggdrasil.reason.is_none());
        std::fs::remove_dir_all(d).ok();
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
            ],
            ..Default::default()
        };
        let existing = Existing {
            lan_interfaces: HashSet::from(["Ethernet 3".to_string()]),
            ..Default::default()
        };
        let lan = detect_lan(&p, &existing);
        let names: Vec<_> = lan.iter().map(|l| l.interface.as_str()).collect();
        assert_eq!(names, ["Ethernet 2", "Ethernet 3"]);
        assert!(lan[0].is_default_route);
        assert!(!lan[0].already_added);
        assert!(lan[1].already_added);
    }
}
