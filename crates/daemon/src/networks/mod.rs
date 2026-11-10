//! Pluggable networks (ADR 0037). A [`Network`] creates and removes the locators of its
//! addresses, enforces grants for the credential kinds it understands, and declares what
//! it can do ([`Capabilities`]). IP networks (Local, LAN, Yggdrasil) wrap an
//! [`ip::Ipv6Backend`] and are enforced by the shared firewall ruleset (ADR 0029); Tor
//! enforces through its control port.
//!
//! The trait is blocking: IP allocation already runs commands, and the Tor client uses
//! plain sockets. The engine calls it from `spawn_blocking`.

pub mod ip;
pub mod ledger;
pub mod onion_key;
pub mod tor;
pub mod tor_client_key;
pub mod tor_control;

use crate::iface::InterfaceManager;
use crate::ruleset::{served_ports, subject_credentials, Snapshot};
use anyhow::Result;
use ip::{IpNetwork, Ipv6Backend, Prefix};
use socketguard_core::config::BackendConfig;
use socketguard_core::{
    Address, AddressId, AppId, Credential, CredentialKind, Locator, Network as NetworkInfo,
    NetworkKind, NetworkStatus, PortRef, PortSet, Subject,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    /// Service ids this daemon ever created on the network (persisted by the engine), so
    /// ones whose address is gone can still be swept. Never touch others.
    pub owned: BTreeSet<String>,
    /// Service ids that must be removed (their address was deleted); retried until the
    /// network confirms.
    pub tombstones: BTreeSet<String>,
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
    /// Whether a saved change is still waiting to take effect here (a service to publish,
    /// change or remove that the network has not confirmed). Mutations answer 202 only
    /// then, not merely because the network is down.
    fn pending(&self) -> bool {
        false
    }
}

/// Create the network for `config`.
/// `ula_global_id` is the installation's persisted ULA global ID.
///
/// Only an invalid configuration is an error. What depends on the system (a missing
/// prefix, no DHCPv6 server, Yggdrasil or Tor not running) is not: the network is
/// created, reports `Down` and recovers when the system does.
pub fn create(
    config: &BackendConfig,
    ula_global_id: [u8; 5],
    net: Arc<dyn InterfaceManager>,
) -> Result<Arc<dyn Network>> {
    match config {
        BackendConfig::Tor {
            control,
            auth,
            cookie_path,
            cookie_dir,
            expect_tor_uid,
            cookie_owner,
            allow_remote_control,
        } => {
            let opts = tor_control::AuthOptions {
                auth: auth.clone(),
                cookie_path: cookie_path.clone(),
                cookie_dir: cookie_dir.clone(),
                expect_tor_uid: *expect_tor_uid,
                cookie_owner: cookie_owner.clone(),
                allow_remote_control: *allow_remote_control,
            };
            tor_control::check_endpoint(&tor_control::Endpoint::parse(control), &opts)?;
            Ok(Arc::new(tor::TorNetwork::with_options(
                control,
                opts,
                tor::CHECK_INTERVAL,
            )))
        }
        BackendConfig::Ula { .. } => {
            Ok(ip_network(config, ip::ula::UlaBackend::new(ula_global_id)))
        }
        BackendConfig::Yggdrasil { admin_endpoint, .. } => Ok(ip_network(
            config,
            ip::yggdrasil::YggdrasilBackend::new(Box::new(ip::yggdrasil::YggdrasilctlNode::new(
                admin_endpoint.clone(),
            ))),
        )),
        BackendConfig::Slaac { interface, prefix } => Ok(ip_network(
            config,
            ip::slaac::SlaacBackend::new(interface, prefix.as_deref(), net)?,
        )),
        BackendConfig::Dhcpv6 { interface } => Ok(ip_network(
            config,
            ip::dhcpv6::Dhcpv6Backend::new(interface),
        )),
    }
}

fn ip_network(config: &BackendConfig, backend: impl Ipv6Backend + 'static) -> Arc<dyn Network> {
    Arc::new(IpNetwork::for_config(config, Box::new(backend)))
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
            .map(|p| p.port_ref())
            .collect();
        for address in app.addresses.iter().filter(|a| a.network_id == network.id) {
            let ports: Vec<PortRef> = served_ports(app, address)
                .into_iter()
                .filter(|p| listening.contains(p))
                .collect();
            let grants = socketguard_core::grants_for_app(&snap.grants, &snap.tags, &app.id)
                .iter()
                .filter(|g| g.network_id.as_deref().is_none_or(|n| n == network.id))
                .map(|g| EnforcedGrant {
                    port: g.port,
                    subject: match &g.subject {
                        Subject::Anyone => EnforcedSubject::Anyone,
                        s => EnforcedSubject::Credentials(
                            subject_credentials(&snap.groups, &peers, s)
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
    NetworkEnforcement {
        addresses,
        ..Default::default()
    }
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
            vlan_id: None,
        }
    }

    /// Whatever a network declares as verified must be Verified in core's reach table.
    #[test]
    fn declared_verification_agrees_with_reach() {
        let tor =
            tor::TorNetwork::with_options("127.0.0.1:1", Default::default(), tor::CHECK_INTERVAL);
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
}
