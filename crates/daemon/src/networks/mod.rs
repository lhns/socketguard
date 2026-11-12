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
pub mod managed;
pub mod onion_key;
pub mod tor;
pub mod tor_client_key;
pub mod tor_control;
pub mod tor_managed;
pub mod ygg_key;
pub mod ygg_managed;

pub use managed::ManagedCtx;

use crate::iface::InterfaceManager;
use crate::ruleset::{subject_credentials, Snapshot};
use anyhow::Result;
use ip::{IpNetwork, Ipv6Backend, Prefix};
use socketguard_core::config::BackendConfig;
use socketguard_core::{
    Address, AddressId, AppId, Credential, CredentialKind, Locator, Model, Network as NetworkInfo,
    NetworkKind, NetworkStatus, PortRangeSet, PortRef, Scope, Subject, Target,
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
    pub scope: Scope,
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
    /// The grants that cover this address on this network (see [`enforcement_for`]).
    pub grants: Vec<EnforcedGrant>,
}

#[derive(Debug, Clone)]
pub struct EnforcedGrant {
    /// The ports of the app the grant covers.
    pub ports: PortRangeSet,
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
    /// The interface found at runtime (Yggdrasil without a configured one). The engine
    /// uses it when the config names none; it is never written back to the config.
    fn interface(&self) -> Option<String> {
        None
    }
    /// The addresses of the node behind the network (Yggdrasil), the last known ones while
    /// it is down; None until it was seen.
    fn node(&self) -> Option<crate::ruleset::OverlayNode> {
        None
    }
    /// How the child process of a managed network stands (ADR 0052); None for networks
    /// that SocketGuard does not run itself.
    fn managed(&self) -> Option<socketguard_core::ManagedInfo> {
        None
    }
    /// The /64 this network allocates from, for re-homing addresses; None if it has none.
    fn current_prefix(&self) -> Result<Option<Prefix>> {
        Ok(None)
    }
    /// Create the locator of a new address.
    fn ensure_locator(&self, req: &LocatorRequest) -> Result<NewLocator>;
    /// Release the locator of an address that is going away.
    fn remove_locator(&self, address: &Address) -> Result<()>;
    /// Give back the lease behind `addr`, an IP address of this network that is being
    /// given up (retired, removed, disabled, uninstalled): DHCPv6 sends a Release to
    /// its server (RFC 8415 section 18.2.7). Best effort: it works from the address alone
    /// (also for leases of an earlier process), may block for a few seconds waiting for
    /// replies, and an unanswered release is not an error. Networks without leases do
    /// nothing.
    fn release_lease(&self, _addr: Ipv6Addr) -> Result<()> {
        Ok(())
    }
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
/// `id` is the network's id (the child process of a managed network is named after it),
/// `ula_global_id` the installation's persisted ULA global ID, `managed` what managed
/// networks need from the daemon.
///
/// Only an invalid configuration is an error. What depends on the system (a missing
/// prefix, no DHCPv6 server, Yggdrasil or Tor not running, a build without the files of a
/// managed network) is not: the network is created, reports `Down` and recovers when the
/// system does.
pub fn create(
    id: &str,
    config: &BackendConfig,
    ula_global_id: [u8; 5],
    net: Arc<dyn InterfaceManager>,
    managed: &ManagedCtx,
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
            managed: managed_tor,
            bridges: _,
        } => {
            if *managed_tor {
                return Ok(Arc::new(tor::TorNetwork::managed(
                    tor_managed::ManagedTor::new(id, managed),
                    tor::CHECK_INTERVAL,
                )));
            }
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
        BackendConfig::Ula { .. } => Ok(ip_network(
            config,
            ip::ula::UlaBackend::new(ula_global_id),
            net,
        )),
        BackendConfig::Yggdrasil {
            admin_endpoint,
            interface,
            managed: managed_ygg,
            peers: _,
        } => {
            if *managed_ygg {
                return Ok(ip_network(
                    config,
                    ip::yggdrasil_managed::ManagedYggBackend::new(ygg_managed::ManagedYgg::new(
                        id,
                        managed,
                        net.clone(),
                    )),
                    net,
                ));
            }
            // A Unix socket endpoint is spoken to directly; a TCP one, and a node without
            // an endpoint, go through `yggdrasilctl`.
            let node: Box<dyn ip::yggdrasil::YggdrasilNode> = match admin_endpoint
                .as_deref()
                .and_then(ip::ygg_admin::unix_endpoint)
            {
                Some(path) => Box::new(ip::ygg_admin::AdminNode::new(path)),
                None => Box::new(ip::yggdrasil::YggdrasilctlNode::new(admin_endpoint.clone())),
            };
            Ok(ip_network(
                config,
                ip::yggdrasil::YggdrasilBackend::new(node)
                    .with_host(net.clone(), interface.clone()),
                net,
            ))
        }
        BackendConfig::Slaac { interface, prefix } => Ok(ip_network(
            config,
            ip::slaac::SlaacBackend::new(interface, prefix.as_deref(), net.clone())?,
            net,
        )),
        BackendConfig::Dhcpv6 { interface } => Ok(ip_network(
            config,
            ip::dhcpv6::Dhcpv6Backend::new(interface),
            net,
        )),
    }
}

/// An IP network that also reports an interface which does not exist on `net` as down.
fn ip_network(
    config: &BackendConfig,
    backend: impl Ipv6Backend + 'static,
    net: Arc<dyn InterfaceManager>,
) -> Arc<dyn Network> {
    Arc::new(IpNetwork::for_config(config, Box::new(backend)).with_host(net))
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
///
/// An address that is not up is passed with no ports and no grants, so it stays
/// unpublished. A reservation's address on Tor takes only the grants that target the
/// reservation itself (ADR 0047): a grant on one bound row has no effect there. Its ports
/// are those the reservation serves for each bound app, and each grant covers the ports
/// that it covers on its own app.
pub fn enforcement_for(
    network: &NetworkInfo,
    snap: &Snapshot,
    model: &Model<'_>,
    info: &HashMap<AddressId, socketguard_core::AddressInfo>,
    secrets: &HashMap<AddressId, String>,
    binds: &HashMap<(AppId, PortRef), IpAddr>,
) -> NetworkEnforcement {
    let peers: HashMap<&str, &socketguard_core::Peer> =
        snap.peers.iter().map(|p| (p.id.as_str(), p)).collect();
    let apps: HashMap<&str, &socketguard_core::App> =
        snap.apps.iter().map(|a| (a.id.as_str(), a)).collect();
    let mut addresses = Vec::new();
    for address in snap.addresses.iter().filter(|a| a.network_id == network.id) {
        let mut out = EnforcedAddress {
            id: address.id.clone(),
            locator: address.locator.clone(),
            ports: vec![],
            binds: BTreeMap::new(),
            secret: secrets.get(&address.id).cloned(),
            grants: vec![],
        };
        let Some(state) = info.get(&address.id).filter(|s| s.up) else {
            addresses.push(out);
            continue;
        };
        let reservation = address.reservation_id.as_deref();
        let mut ports: BTreeSet<PortRef> = BTreeSet::new();
        for (app_id, served) in &state.served {
            let Some(app) = apps.get(app_id.as_str()) else {
                continue;
            };
            let listening = PortRangeSet::from_ports(
                app.ports
                    .iter()
                    .filter(|p| p.listening)
                    .map(|p| p.port_ref()),
            );
            let mine: Vec<PortRef> = served.total().intersect(&listening).ports().collect();
            for p in &mine {
                ports.insert(*p);
                if let Some(bind) = binds.get(&(app.id.clone(), *p)) {
                    out.binds.insert(*p, *bind);
                }
            }
            for g in model.app_grants(app).iter().filter(|g| {
                g.grant
                    .network_id
                    .as_deref()
                    .is_none_or(|n| n == network.id)
            }) {
                if let Some(rid) = reservation {
                    // Only grants on the reservation itself count for its onion address.
                    let on_it = snap
                        .grants
                        .iter()
                        .any(|x| x.id == g.grant.id && x.target == Target::Reservation(rid.into()));
                    if !on_it {
                        continue;
                    }
                }
                out.grants.push(EnforcedGrant {
                    ports: g.ports.total().intersect(&served.total()),
                    subject: match &g.grant.subject {
                        Subject::Anyone => EnforcedSubject::Anyone,
                        s => EnforcedSubject::Credentials(
                            subject_credentials(&snap.groups, &peers, s)
                                .into_iter()
                                .cloned()
                                .collect(),
                        ),
                    },
                });
            }
        }
        out.ports = ports.into_iter().collect();
        addresses.push(out);
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
            managed: None,
        }
    }

    /// An address of a port group publishes only the group's ports that listen now, even
    /// though the group's ranges are granted whole (ADR 0047).
    #[test]
    fn a_group_address_on_tor_publishes_only_listening_ports() {
        use chrono::Utc;
        use socketguard_core::{
            parse_ranges, App, AppPort, Grant, Locator, PortGroup, Protocol, Target,
        };
        let now = Utc::now();
        let port = |p: u16, listening| AppPort {
            port: p,
            proto: Protocol::Tcp,
            listening,
            last_seen: now,
            family: Default::default(),
        };
        let group = PortGroup {
            id: "sg".into(),
            label: "passive".into(),
            ports: parse_ranges(&["50000-50010/tcp"]).unwrap(),
            apps: vec!["a".into()],
            created_at: now,
        };
        let app = App {
            id: "a".into(),
            name: "ftpd".into(),
            process_name: "ftpd".into(),
            exe_path: None,
            interpreter_arg: None,
            identity_note: None,
            exe_missing: false,
            system: false,
            first_seen: now,
            last_seen: now,
            // 80 is outside the group; 50003 listens, 50004 was seen but is quiet.
            ports: vec![port(80, true), port(50003, true), port(50004, false)],
            addresses: vec![],
        };
        let address = Address {
            id: "ad".into(),
            ..Address::automatic(
                "a",
                Scope::group("sg"),
                "n",
                Locator::Onion {
                    hostname: "abc.onion".into(),
                },
            )
        };
        let snap = Snapshot {
            apps: vec![app],
            networks: vec![info(NetworkKind::Tor)],
            addresses: vec![address],
            port_groups: vec![group],
            grants: vec![Grant {
                id: "g".into(),
                target: Target::App("a".into()),
                // The grant names the group's row, which is what gives it an address.
                scope: Scope::group("sg"),
                network_id: None,
                subject: Subject::Anyone,
                created_at: now,
            }],
            ..Snapshot::default()
        };
        let secrets = HashMap::from([("ad".to_string(), "ED25519-V3:secret".to_string())]);
        let model = Model::new(snap.world());
        let enforcement = enforcement_for(
            &info(NetworkKind::Tor),
            &snap,
            &model,
            &model.address_info(),
            &secrets,
            &HashMap::new(),
        );
        let addr = &enforcement.addresses[0];
        let published: Vec<u16> = addr.ports.iter().map(|p| p.port).collect();
        assert_eq!(
            published,
            [50003],
            "the quiet port and the ones outside the group are not published"
        );
        let plan = tor::plan(addr);
        let spec = plan.spec.expect("published");
        assert_eq!(spec.ports.len(), 1);
        assert_eq!(spec.ports[0].0, 50003);
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
