//! Pluggable networks (ADR 0037). A [`Network`] creates and removes the locators of its
//! addresses, enforces grants for the credential kinds it understands, and declares what
//! it can do ([`Capabilities`]). IP networks (Local, LAN, Yggdrasil) wrap an
//! [`Ipv6Backend`] and are enforced by the shared firewall ruleset (ADR 0029); Tor
//! enforces through its control port.
//!
//! The trait is blocking: IP allocation already runs commands, and the Tor client uses
//! plain sockets. The engine calls it from `spawn_blocking`.

pub mod tor;
pub mod tor_control;

use crate::backend::{self, Ipv6Backend, Prefix};
use crate::ruleset::{served_ports, subject_credentials, Snapshot};
use anyhow::Result;
use socketguard_core::config::BackendConfig;
use socketguard_core::{
    is_loopback_interface, Address, AddressId, AppId, Credential, CredentialKind, Locator,
    Network as NetworkInfo, NetworkKind, NetworkStatus, PortRef, PortSet, Subject,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

/// What a network can do. `reach()` in core stays the single source of truth for how
/// well a credential identifies a source; `verifies` is the list of kinds that give
/// `Reach::Verified` here, and a test keeps the two in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Locators are IPv6 addresses on an interface, enforced by the firewall ruleset.
    pub ip_locators: bool,
    /// Credential kinds this network verifies by key.
    pub verifies: &'static [CredentialKind],
    /// False for Local on loopback: this machine only, grants have no effect.
    pub grants_apply: bool,
    /// Whether UDP ports can be served.
    pub udp: bool,
}

/// An address to create a locator for.
#[derive(Debug, Clone)]
pub struct LocatorRequest {
    pub app_id: AppId,
    pub address_id: AddressId,
    pub ports: PortSet,
}

/// A new locator, with the secret (the onion service key) that must be stored with it.
#[derive(Debug, Clone)]
pub struct NewLocator {
    pub locator: Locator,
    pub secret: Option<String>,
}

/// What a network has to enforce: its addresses with their resolved grants.
#[derive(Debug, Clone, Default)]
pub struct NetworkEnforcement {
    pub addresses: Vec<EnforcedAddress>,
}

#[derive(Debug, Clone)]
pub struct EnforcedAddress {
    pub id: AddressId,
    pub locator: Locator,
    /// The ports this address serves that are listening now.
    pub ports: Vec<PortRef>,
    /// Where each port's listener is bound, when known.
    pub binds: BTreeMap<PortRef, IpAddr>,
    /// The stored secret of the locator (the onion service key).
    pub secret: Option<String>,
    /// The grants of the app that apply on this network.
    pub grants: Vec<EnforcedGrant>,
}

#[derive(Debug, Clone)]
pub struct EnforcedGrant {
    /// None = every port.
    pub port: Option<PortRef>,
    pub subject: EnforcedSubject,
}

#[derive(Debug, Clone)]
pub enum EnforcedSubject {
    Anyone,
    /// The credentials of the granted peers (all members of a group).
    Credentials(Vec<Credential>),
}

pub trait Network: Send + Sync {
    fn kind(&self) -> NetworkKind;
    fn capabilities(&self) -> Capabilities;
    /// Current status, and the /64 the network allocates from (IP networks with one).
    fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>);
    /// The /64 this network allocates from, for re-homing addresses; None if it has none.
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(None)
    }
    /// Create the locator of a new address.
    fn ensure_locator(&self, req: &LocatorRequest) -> Result<NewLocator>;
    /// Release the locator of an address that is going away.
    fn remove_locator(&self, address: &Address) -> Result<()>;
    /// Make the network match the grants. IP networks do nothing here: their rules are
    /// part of the shared firewall ruleset.
    fn enforce(&self, enforcement: &NetworkEnforcement) -> Result<()>;
    /// Take everything of ours off the network (the `disable` latch).
    fn disable(&self, addresses: &[Address]) -> Result<()>;
}

/// An IP network: allocation through an [`Ipv6Backend`].
pub struct IpNetwork {
    kind: NetworkKind,
    grants_apply: bool,
    backend: Box<dyn Ipv6Backend>,
}

impl IpNetwork {
    pub fn new(kind: NetworkKind, grants_apply: bool, backend: Box<dyn Ipv6Backend>) -> Self {
        Self {
            kind,
            grants_apply,
            backend,
        }
    }

    /// The network for `config` around an already built allocator. Local on loopback is
    /// this machine only; on another interface it takes grants like any IP network.
    pub fn for_config(config: &BackendConfig, backend: Box<dyn Ipv6Backend>) -> Self {
        let kind = NetworkKind::from(config.backend_type());
        let grants_apply =
            kind != NetworkKind::Local || !config.interface().is_some_and(is_loopback_interface);
        Self::new(kind, grants_apply, backend)
    }
}

impl Network for IpNetwork {
    fn kind(&self) -> NetworkKind {
        self.kind
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ip_locators: true,
            verifies: match self.kind {
                NetworkKind::Yggdrasil => &[CredentialKind::YggKey, CredentialKind::YggAddr],
                _ => &[],
            },
            grants_apply: self.grants_apply,
            udp: true,
        }
    }

    fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>) {
        match self.backend.current_prefix() {
            Ok(Some(p)) if p.len == 64 => (NetworkStatus::Up, Some(p.addr)),
            Ok(_) => (NetworkStatus::Up, None),
            Err(e) => (
                NetworkStatus::Down {
                    reason: e.to_string(),
                },
                None,
            ),
        }
    }

    fn current_prefix(&self) -> Result<Option<Prefix>> {
        self.backend.current_prefix()
    }

    fn ensure_locator(&self, _req: &LocatorRequest) -> Result<NewLocator> {
        let alloc = self.backend.allocate(None)?;
        Ok(NewLocator {
            locator: Locator::Ipv6 {
                addr: alloc.address,
            },
            secret: None,
        })
    }

    fn remove_locator(&self, address: &Address) -> Result<()> {
        match address.locator.ipv6() {
            Some(addr) => self.backend.release_address(&addr),
            None => Ok(()),
        }
    }

    fn enforce(&self, _enforcement: &NetworkEnforcement) -> Result<()> {
        Ok(())
    }

    fn disable(&self, _addresses: &[Address]) -> Result<()> {
        Ok(())
    }
}

/// Create the network for `config`.
/// `ula_global_id` is the installation's persisted ULA global ID.
pub fn create(config: &BackendConfig, ula_global_id: [u8; 5]) -> Result<Arc<dyn Network>> {
    match config {
        BackendConfig::Tor { control, auth } => Ok(Arc::new(tor::TorNetwork::new(
            control,
            auth.clone(),
            tor::CHECK_INTERVAL,
        ))),
        ip => Ok(Arc::new(IpNetwork::for_config(
            ip,
            backend::create_backend(ip, ula_global_id)?,
        ))),
    }
}

/// How specific a listener's bind address is, lower first: the Tor target prefers an
/// IPv4 listener, then an IPv6 wildcard, then a specific IPv6 address.
pub fn bind_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(a) if a.is_unspecified() => 1,
        IpAddr::V6(_) => 2,
    }
}

/// Resolve the grants that apply to the addresses of `network` in `snap`: the input of
/// [`Network::enforce`]. `secrets` are the stored locator secrets by address; `binds`
/// where the app's listeners are bound.
pub fn enforcement_for(
    network: &NetworkInfo,
    snap: &Snapshot,
    secrets: &HashMap<AddressId, String>,
    binds: &HashMap<(AppId, PortRef), IpAddr>,
) -> NetworkEnforcement {
    let peers: HashMap<&str, &socketguard_core::Peer> =
        snap.peers.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut addresses = Vec::new();
    for app in &snap.apps {
        let listening: Vec<PortRef> = app
            .ports
            .iter()
            .filter(|p| p.listening)
            .map(|p| PortRef {
                port: p.port,
                proto: p.proto,
            })
            .collect();
        for address in app.addresses.iter().filter(|a| a.network_id == network.id) {
            let ports: Vec<PortRef> = served_ports(app, address)
                .into_iter()
                .filter(|p| listening.contains(p))
                .collect();
            let grants = snap
                .grants
                .iter()
                .filter(|g| {
                    g.app_id == app.id && g.network_id.as_deref().is_none_or(|n| n == network.id)
                })
                .map(|g| EnforcedGrant {
                    port: g.port,
                    subject: match &g.subject {
                        Subject::Anyone => EnforcedSubject::Anyone,
                        s => EnforcedSubject::Credentials(
                            subject_credentials(snap, &peers, s)
                                .into_iter()
                                .cloned()
                                .collect(),
                        ),
                    },
                })
                .collect();
            addresses.push(EnforcedAddress {
                id: address.id.clone(),
                locator: address.locator.clone(),
                binds: ports
                    .iter()
                    .filter_map(|p| Some((*p, *binds.get(&(app.id.clone(), *p))?)))
                    .collect(),
                ports,
                secret: secrets.get(&address.id).cloned(),
                grants,
            });
        }
    }
    NetworkEnforcement { addresses }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockIpv6Backend;
    use socketguard_core::{reach, Reach};

    fn info(kind: NetworkKind) -> NetworkInfo {
        NetworkInfo {
            id: "n".into(),
            kind,
            name: "n".into(),
            interface: None,
            grants_apply: true,
            status: NetworkStatus::Up,
            prefix: None,
        }
    }

    /// Whatever a network declares as verified must be Verified in core's reach table.
    #[test]
    fn declared_verification_agrees_with_reach() {
        let tor = tor::TorNetwork::new("127.0.0.1:1", Default::default(), tor::CHECK_INTERVAL);
        let ygg = IpNetwork::new(
            NetworkKind::Yggdrasil,
            true,
            Box::new(MockIpv6Backend::new("300:1:2:3::", 128, "ygg0")),
        );
        let lan = IpNetwork::new(
            NetworkKind::Lan,
            true,
            Box::new(MockIpv6Backend::new("2001:db8::", 128, "eth0")),
        );
        let samples = [
            (
                CredentialKind::YggKey,
                "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b",
            ),
            (CredentialKind::YggAddr, "200:1::5"),
            (
                CredentialKind::TorClientKey,
                "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ",
            ),
            (CredentialKind::Ip, "fd00::5/128"),
        ];
        for net in [&tor as &dyn Network, &ygg, &lan] {
            let n = info(net.kind());
            for (kind, value) in samples {
                let c = Credential {
                    id: "c".into(),
                    kind,
                    value: value.into(),
                    label: None,
                };
                assert_eq!(
                    net.capabilities().verifies.contains(&kind),
                    reach(&c, &n) == Reach::Verified,
                    "{kind:?} on {:?}",
                    net.kind()
                );
            }
        }
        assert!(!tor.capabilities().ip_locators);
        assert!(!tor.capabilities().udp);
        assert!(lan.capabilities().ip_locators);
    }

    #[test]
    fn local_on_loopback_declares_no_grants() {
        let ula = |iface: &str| BackendConfig::Ula {
            interface: iface.into(),
        };
        let mock = || Box::new(MockIpv6Backend::new("fd00::", 128, "lo"));
        assert!(
            !IpNetwork::for_config(&ula("lo"), mock())
                .capabilities()
                .grants_apply
        );
        assert!(
            IpNetwork::for_config(&ula("eth0"), mock())
                .capabilities()
                .grants_apply
        );
    }
}
