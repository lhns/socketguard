//! The Tor network (ADR 0037): one onion service per address, published through the
//! control port. Tor cannot tell peers apart once a connection reaches the app over
//! loopback, so client authorization (`ClientAuthV3`) is the enforcement: an address with
//! no grant is not published at all, a grant to Anyone publishes it openly, and keyed
//! grants publish it for exactly those client keys.
//!
//! Services are `Detach`ed, so they survive control-connection drops and a daemon exit
//! (ADR 0026). The service key is stored with the address, so the `.onion` name is stable.

use super::onion_key;
use super::tor_control::{AuthOptions, Control, Endpoint, ServiceSpec};
use super::{
    Capabilities, EnforcedAddress, EnforcedSubject, LocatorRequest, Network, NetworkEnforcement,
    NewLocator,
};
use anyhow::{anyhow, bail, Result};
use socketguard_core::{
    Address, CredentialKind, Locator, NetworkKind, NetworkStatus, PortRef, Protocol,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How often an unchanged state is checked against Tor (it may have restarted and lost
/// its services).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// The service id (the name without `.onion`) of an onion locator.
pub fn service_id(locator: &Locator) -> Option<String> {
    match locator {
        Locator::Onion { hostname } => Some(hostname.trim_end_matches(".onion").to_string()),
        Locator::Ipv6 { .. } => None,
    }
}

/// The address Tor connects to for `port`: the listener's own bind address unless it is
/// a wildcard or loopback (IPv4 loopback for those, `[::1]` for an IPv6-only loopback
/// listener).
pub fn target(bind: Option<IpAddr>, port: u16) -> String {
    match bind {
        None => format!("127.0.0.1:{port}"),
        Some(IpAddr::V4(a)) if a.is_unspecified() || a.is_loopback() => {
            format!("127.0.0.1:{port}")
        }
        Some(IpAddr::V6(a)) if a.is_unspecified() => format!("127.0.0.1:{port}"),
        Some(IpAddr::V6(a)) if a == Ipv6Addr::LOCALHOST => format!("[::1]:{port}"),
        Some(IpAddr::V4(a)) => format!("{a}:{port}"),
        Some(IpAddr::V6(a)) => format!("[{a}]:{port}"),
    }
}

/// What to do with one address: the service to publish, or None to keep it unpublished,
/// plus notes for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub spec: Option<ServiceSpec>,
    pub notes: Vec<String>,
}

/// Decide the desired state of one address from its grants.
///
/// Tor authorizes per service, not per port, so every authorized party gets every
/// published port. The published ports are the union of the granted ports; a party whose
/// grants cover fewer ports than that is left out (and noted), which keeps the service
/// closed rather than over-granting. Give a port its own address (`split`) to grant it
/// separately.
pub fn plan(addr: &EnforcedAddress) -> Plan {
    let mut notes = Vec::new();
    let tcp: Vec<PortRef> = addr
        .ports
        .iter()
        .filter(|p| p.proto == Protocol::Tcp)
        .copied()
        .collect();
    if tcp.len() != addr.ports.len() {
        notes.push("UDP ports are not served over Tor".to_string());
    }
    let unpublished = |mut notes: Vec<String>, why: &str| {
        notes.push(why.to_string());
        Plan { spec: None, notes }
    };
    let Some(secret) = &addr.secret else {
        return unpublished(notes, "no service key is stored");
    };

    let mut anyone: BTreeSet<PortRef> = BTreeSet::new();
    let mut keys: BTreeMap<String, BTreeSet<PortRef>> = BTreeMap::new();
    for g in &addr.grants {
        let ports: BTreeSet<PortRef> = tcp
            .iter()
            .filter(|p| g.ports.contains(**p))
            .copied()
            .collect();
        if ports.is_empty() {
            continue;
        }
        match &g.subject {
            EnforcedSubject::Anyone => anyone.extend(ports),
            EnforcedSubject::Credentials(creds) => {
                for c in creds
                    .iter()
                    .filter(|c| c.kind == CredentialKind::TorClientKey)
                {
                    keys.entry(c.value.clone())
                        .or_default()
                        .extend(ports.iter().copied());
                }
            }
        }
    }
    let union: BTreeSet<PortRef> = anyone
        .iter()
        .chain(keys.values().flatten())
        .copied()
        .collect();
    if union.is_empty() {
        return unpublished(notes, "no grant applies");
    }

    let clients: Vec<String> = if anyone == union {
        Vec::new()
    } else {
        if !anyone.is_empty() {
            notes.push(
                "a grant to Anyone covers only some of the published ports; give those ports their own address"
                    .to_string(),
            );
        }
        let (full, partial): (Vec<_>, Vec<_>) = keys.iter().partition(|(_, p)| **p == union);
        for (k, _) in partial {
            notes.push(format!(
                "client key {k} is granted only some of the published ports and is left out; give those ports their own address"
            ));
        }
        if full.is_empty() {
            return unpublished(notes, "no client key covers the published ports");
        }
        full.into_iter().map(|(k, _)| k.clone()).collect()
    };

    Plan {
        spec: Some(ServiceSpec {
            key: Some(secret.clone()),
            ports: union
                .iter()
                .map(|p| (p.port, target(addr.binds.get(p).copied(), p.port)))
                .collect(),
            clients,
        }),
        notes,
    }
}

#[derive(Debug)]
struct State {
    /// Service id -> what we last published for it.
    applied: HashMap<String, ServiceSpec>,
    /// When Tor was last asked what it is running.
    checked: Option<Instant>,
    status: NetworkStatus,
    /// What the last enforcement wanted published, and the services it still had to remove
    /// (tombstones, ones whose address is gone) when it ended. They differ from `applied`
    /// or are non-empty exactly while a change is pending ([`Network::pending`]).
    desired: BTreeMap<String, ServiceSpec>,
    unremoved: BTreeSet<String>,
}

const NOT_CONNECTED: &str = "not connected to Tor yet";

/// Set the status, logging a change between up and down but not a repeated failure.
fn set_status(current: &mut NetworkStatus, new: NetworkStatus) {
    let was_down = matches!(current, NetworkStatus::Down { .. });
    let first = matches!(current, NetworkStatus::Down { reason } if reason == NOT_CONNECTED);
    match &new {
        NetworkStatus::Down { reason } if !was_down || first => {
            warn!("Tor network is down: {reason}")
        }
        NetworkStatus::Up if was_down => info!("Tor network is up"),
        _ => {}
    }
    *current = new;
}

/// Whether exactly the desired services are applied.
fn in_sync(
    desired: &BTreeMap<String, ServiceSpec>,
    applied: &HashMap<String, ServiceSpec>,
) -> bool {
    desired.len() == applied.len()
        && desired
            .iter()
            .all(|(id, spec)| applied.get(id) == Some(spec))
}

pub struct TorNetwork {
    endpoint: Endpoint,
    opts: AuthOptions,
    check_every: Duration,
    state: Mutex<State>,
    /// Serializes control-port work, without holding `state` across I/O.
    io: Mutex<()>,
}

impl TorNetwork {
    pub fn with_options(control: &str, opts: AuthOptions, check_every: Duration) -> Self {
        Self {
            endpoint: Endpoint::parse(control),
            opts,
            check_every,
            state: Mutex::new(State {
                applied: HashMap::new(),
                checked: None,
                status: NetworkStatus::Down {
                    reason: NOT_CONNECTED.to_string(),
                },
                desired: BTreeMap::new(),
                unremoved: BTreeSet::new(),
            }),
            io: Mutex::new(()),
        }
    }

    fn connect(&self) -> Result<Control> {
        match Control::connect(&self.endpoint, &self.opts) {
            Ok(c) => Ok(c),
            Err(e) => {
                set_status(
                    &mut self.state.lock().unwrap().status,
                    NetworkStatus::Down {
                        reason: format!("{e:#}"),
                    },
                );
                Err(e)
            }
        }
    }
}

impl Network for TorNetwork {
    fn kind(&self) -> NetworkKind {
        NetworkKind::Tor
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ip_locators: false,
            verifies: &[CredentialKind::TorClientKey],
            grants_apply: true,
            udp: false,
        }
    }

    fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>) {
        (self.state.lock().unwrap().status.clone(), None)
    }

    /// Generate the service key and name here. Nothing reaches Tor until the first grant
    /// publishes the service.
    fn ensure_locator(&self, _req: &LocatorRequest) -> Result<NewLocator> {
        let key = onion_key::generate();
        Ok(NewLocator {
            locator: Locator::Onion {
                hostname: format!("{}.onion", key.service_id),
            },
            secret: Some(key.secret),
        })
    }

    fn remove_locator(&self, address: &Address) -> Result<()> {
        let Some(id) = service_id(&address.locator) else {
            return Ok(());
        };
        let _io = self.io.lock().unwrap();
        // Forget the service only once Tor confirmed it is gone: if Tor is down it is
        // still published, and the caller tombstones it for a retry.
        self.connect()?.del_onion(&id)?;
        self.state.lock().unwrap().applied.remove(&id);
        Ok(())
    }

    fn enforce(&self, enforcement: &NetworkEnforcement) -> Result<()> {
        let mut desired: BTreeMap<String, ServiceSpec> = BTreeMap::new();
        let mut ours: BTreeSet<String> = BTreeSet::new();
        let mut notes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for a in &enforcement.addresses {
            let Some(id) = service_id(&a.locator) else {
                continue;
            };
            ours.insert(id.clone());
            let p = plan(a);
            notes.insert(id.clone(), p.notes);
            if let Some(spec) = p.spec {
                desired.insert(id, spec);
            }
        }

        // Services to take down even though no address wants them: tombstones, and ones
        // we created whose address is gone.
        let stale: BTreeSet<String> = enforcement
            .tombstones
            .iter()
            .chain(enforcement.owned.difference(&ours))
            .cloned()
            .collect();

        let _io = self.io.lock().unwrap();
        let (applied, due) = {
            let mut st = self.state.lock().unwrap();
            st.desired = desired.clone();
            st.unremoved = stale.clone();
            let due = st.checked.is_none_or(|t| t.elapsed() >= self.check_every)
                || !matches!(st.status, NetworkStatus::Up);
            (st.applied.clone(), due)
        };
        if in_sync(&desired, &applied) && !due && stale.is_empty() {
            return Ok(());
        }

        let mut c = self.connect()?;
        let live: BTreeSet<String> = c.detached()?.into_iter().collect();
        let mut now_applied = applied.clone();
        let mut errors: Vec<String> = Vec::new();
        let mut removed: BTreeSet<String> = BTreeSet::new();

        // Closed first: anything of ours that should not be published goes.
        let closing: BTreeSet<&String> = ours.iter().chain(applied.keys()).chain(&stale).collect();
        for id in closing {
            if desired.contains_key(id) || !(live.contains(id) || applied.contains_key(id)) {
                continue;
            }
            match c.del_onion(id) {
                Ok(()) => {
                    now_applied.remove(id);
                    removed.insert(id.clone());
                    info!("Onion service {id} unpublished");
                }
                Err(e) => errors.push(format!("{e:#}")),
            }
        }
        for (id, spec) in &desired {
            let is_live = live.contains(id);
            if is_live && applied.get(id) == Some(spec) {
                continue;
            }
            if is_live {
                if let Err(e) = c.del_onion(id) {
                    errors.push(format!("{e:#}"));
                    continue;
                }
            }
            match c.add_onion(spec) {
                Ok(added) if added.service_id == *id => {
                    for n in notes.get(id).into_iter().flatten() {
                        info!("Onion service {id}: {n}");
                    }
                    info!(
                        "Onion service {id} published ({} port(s), {})",
                        spec.ports.len(),
                        if spec.clients.is_empty() {
                            "open".to_string()
                        } else {
                            format!("{} authorized client(s)", spec.clients.len())
                        }
                    );
                    now_applied.insert(id.clone(), spec.clone());
                }
                Ok(added) => {
                    let _ = c.del_onion(&added.service_id);
                    now_applied.remove(id);
                    errors.push(format!(
                        "Tor derived {} from the stored key of {id}",
                        added.service_id
                    ));
                }
                Err(e) => {
                    now_applied.remove(id);
                    errors.push(format!("{id}: {e:#}"));
                }
            }
        }
        for (id, n) in &notes {
            if !desired.contains_key(id) && !n.is_empty() {
                debug!("Onion service {id} stays unpublished: {}", n.join("; "));
            }
        }

        let mut st = self.state.lock().unwrap();
        st.applied = now_applied;
        // Stale services that are not live are gone already.
        st.unremoved
            .retain(|id| live.contains(id) && !removed.contains(id));
        st.checked = Some(Instant::now());
        set_status(&mut st.status, NetworkStatus::Up);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errors.join("; ")))
        }
    }

    fn pending(&self) -> bool {
        let st = self.state.lock().unwrap();
        !in_sync(&st.desired, &st.applied) || !st.unremoved.is_empty()
    }

    fn disable(&self, addresses: &[Address]) -> Result<()> {
        let _io = self.io.lock().unwrap();
        let mut ids: BTreeSet<String> = addresses
            .iter()
            .filter_map(|a| service_id(&a.locator))
            .collect();
        ids.extend(self.state.lock().unwrap().applied.keys().cloned());
        let mut c = self.connect()?;
        let mut failed = Vec::new();
        let mut removed = Vec::new();
        for id in ids {
            match c.del_onion(&id) {
                Ok(()) => removed.push(id),
                Err(e) => failed.push(format!("{e:#}")),
            }
        }
        {
            let mut st = self.state.lock().unwrap();
            for id in &removed {
                st.applied.remove(id);
            }
            st.checked = None;
        }
        if failed.is_empty() {
            Ok(())
        } else {
            bail!("{}", failed.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::EnforcedGrant;
    use crate::test_support::MockTorControl;
    use socketguard_core::{Credential, PortRangeSet};

    const KEY_A: &str = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";
    const KEY_B: &str = "FDBSRGWHBKODXLW6IWZZSNGD5AXYI3X4SRXHPQ3GIGJO7OGEDMJQ";

    fn port(p: u16) -> PortRef {
        PortRef {
            port: p,
            proto: Protocol::Tcp,
        }
    }

    fn creds(keys: &[&str]) -> EnforcedSubject {
        EnforcedSubject::Credentials(
            keys.iter()
                .enumerate()
                .map(|(i, k)| Credential {
                    id: format!("c{i}"),
                    kind: CredentialKind::TorClientKey,
                    value: k.to_string(),
                    label: None,
                })
                .collect(),
        )
    }

    fn address(ports: &[u16], grants: Vec<EnforcedGrant>) -> EnforcedAddress {
        EnforcedAddress {
            id: "addr1".into(),
            locator: Locator::Onion {
                hostname: "svc1.onion".into(),
            },
            ports: ports.iter().map(|p| port(*p)).collect(),
            binds: BTreeMap::new(),
            secret: Some("ED25519-V3:svc1".into()),
            grants,
        }
    }

    fn grant(p: Option<u16>, subject: EnforcedSubject) -> EnforcedGrant {
        EnforcedGrant {
            ports: match p {
                Some(p) => PortRangeSet::from_ports([port(p)]),
                None => PortRangeSet::everything(),
            },
            subject,
        }
    }

    #[test]
    fn no_grants_means_unpublished() {
        let p = plan(&address(&[80], vec![]));
        assert_eq!(p.spec, None);
        // A grant for a port the address does not serve does not count either.
        let p = plan(&address(&[80], vec![grant(Some(81), creds(&[KEY_A]))]));
        assert_eq!(p.spec, None);
        // Nor does a grant of a peer without a Tor key.
        let p = plan(&address(&[80], vec![grant(None, creds(&[]))]));
        assert_eq!(p.spec, None);
    }

    #[test]
    fn anyone_publishes_without_client_auth() {
        let p = plan(&address(
            &[80, 8080],
            vec![
                grant(None, EnforcedSubject::Anyone),
                grant(None, creds(&[KEY_A])),
            ],
        ));
        let spec = p.spec.unwrap();
        assert!(spec.clients.is_empty());
        assert_eq!(spec.key.as_deref(), Some("ED25519-V3:svc1"));
        assert_eq!(
            spec.ports,
            [
                (80, "127.0.0.1:80".to_string()),
                (8080, "127.0.0.1:8080".to_string())
            ]
        );
    }

    #[test]
    fn keys_mean_client_auth() {
        let p = plan(&address(
            &[8080],
            vec![
                grant(Some(8080), creds(&[KEY_B])),
                grant(None, creds(&[KEY_A, KEY_B])),
            ],
        ));
        let spec = p.spec.unwrap();
        assert_eq!(spec.clients, [KEY_B, KEY_A]); // sorted
        assert_eq!(spec.ports, [(8080, "127.0.0.1:8080".to_string())]);
    }

    #[test]
    fn udp_is_skipped_with_a_note() {
        let mut a = address(&[80], vec![grant(None, creds(&[KEY_A]))]);
        a.ports.push(PortRef {
            port: 53,
            proto: Protocol::Udp,
        });
        let p = plan(&a);
        assert_eq!(p.spec.unwrap().ports.len(), 1);
        assert!(p.notes.iter().any(|n| n.contains("UDP")));
    }

    #[test]
    fn a_key_with_fewer_ports_than_the_service_is_left_out() {
        // KEY_A may reach 80 only, KEY_B both: published ports are 80+8080, so A would
        // over-reach and is dropped.
        let p = plan(&address(
            &[80, 8080],
            vec![
                grant(Some(80), creds(&[KEY_A])),
                grant(None, creds(&[KEY_B])),
            ],
        ));
        let spec = p.spec.unwrap();
        assert_eq!(spec.clients, [KEY_B]);
        assert!(p.notes.iter().any(|n| n.contains(KEY_A)));
        // Only partial keys: closed.
        let p = plan(&address(
            &[80, 8080],
            vec![
                grant(Some(80), creds(&[KEY_A])),
                grant(Some(8080), creds(&[KEY_B])),
            ],
        ));
        assert_eq!(p.spec, None);
    }

    #[test]
    fn missing_secret_is_unpublished() {
        let mut a = address(&[80], vec![grant(None, EnforcedSubject::Anyone)]);
        a.secret = None;
        assert_eq!(plan(&a).spec, None);
    }

    #[test]
    fn targets() {
        let v4: IpAddr = "192.168.1.5".parse().unwrap();
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(target(None, 80), "127.0.0.1:80");
        assert_eq!(target(Some("0.0.0.0".parse().unwrap()), 80), "127.0.0.1:80");
        assert_eq!(
            target(Some("127.0.0.1".parse().unwrap()), 80),
            "127.0.0.1:80"
        );
        assert_eq!(target(Some("::".parse().unwrap()), 80), "127.0.0.1:80");
        assert_eq!(target(Some("::1".parse().unwrap()), 80), "[::1]:80");
        assert_eq!(target(Some(v4), 80), "192.168.1.5:80");
        assert_eq!(target(Some(v6), 80), "[2001:db8::5]:80");
    }

    fn enforcement(addrs: Vec<EnforcedAddress>) -> NetworkEnforcement {
        NetworkEnforcement {
            addresses: addrs,
            ..Default::default()
        }
    }

    fn net(mock: &MockTorControl, every: Duration) -> TorNetwork {
        TorNetwork::with_options(&mock.addr(), mock.auth_options(), every)
    }

    #[test]
    fn new_locator_is_generated_locally_without_touching_tor() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let req = LocatorRequest {
            app_id: "app".into(),
            address_id: "a".into(),
            scope: socketguard_core::Scope::All,
        };
        let loc = n.ensure_locator(&req).unwrap();
        let Locator::Onion { hostname } = &loc.locator else {
            panic!("not an onion locator");
        };
        let secret = loc.secret.unwrap();
        assert_eq!(
            hostname,
            &format!(
                "{}.onion",
                onion_key::service_id_of_secret(&secret).unwrap()
            )
        );
        assert!(mock.commands().is_empty(), "no control-port call");
        // It works with Tor down too.
        mock.set_down(true);
        n.ensure_locator(&req).unwrap();
    }

    #[test]
    fn the_stored_key_publishes_under_the_local_name() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let req = LocatorRequest {
            app_id: "app".into(),
            address_id: "a".into(),
            scope: socketguard_core::Scope::All,
        };
        let loc = n.ensure_locator(&req).unwrap();
        let mut addr = address(&[8080], vec![grant(None, EnforcedSubject::Anyone)]);
        addr.locator = loc.locator.clone();
        addr.secret = loc.secret;
        n.enforce(&enforcement(vec![addr])).unwrap();
        assert_eq!(mock.detached(), [service_id(&loc.locator).unwrap()]);
    }

    #[test]
    fn pending_only_while_something_is_unconfirmed() {
        let mock = MockTorControl::start();
        let n = net(&mock, Duration::ZERO);
        assert!(!n.pending());

        // Down with nothing to do: not pending.
        mock.set_down(true);
        assert!(n
            .enforce(&enforcement(vec![address(&[8080], vec![])]))
            .is_err());
        assert!(!n.pending());

        // Down with a service to publish: pending until Tor confirms.
        let open = enforcement(vec![address(
            &[8080],
            vec![grant(None, EnforcedSubject::Anyone)],
        )]);
        assert!(n.enforce(&open).is_err());
        assert!(n.pending());
        mock.set_down(false);
        n.enforce(&open).unwrap();
        assert!(!n.pending());

        // A removal Tor has not confirmed, and a tombstone.
        mock.set_down(true);
        assert!(n
            .enforce(&enforcement(vec![address(&[8080], vec![])]))
            .is_err());
        assert!(n.pending());
        mock.set_down(false);
        n.enforce(&enforcement(vec![address(&[8080], vec![])]))
            .unwrap();
        assert!(!n.pending());
        mock.inject_service("gone1");
        mock.set_down(true);
        assert!(n.enforce(&stale(&[], &["gone1"], vec![])).is_err());
        assert!(n.pending());
        mock.set_down(false);
        n.enforce(&stale(&[], &["gone1"], vec![])).unwrap();
        assert!(!n.pending());
    }

    #[test]
    fn enforce_publishes_changes_and_removes() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let open = address(&[8080], vec![grant(None, EnforcedSubject::Anyone)]);
        let id = "svc1".to_string();

        // No grants: nothing published, and no ADD_ONION at all.
        n.enforce(&enforcement(vec![address(&[8080], vec![])]))
            .unwrap();
        assert!(mock.add_commands().is_empty());

        // A grant publishes with a client key.
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        n.enforce(&enforcement(vec![keyed.clone()])).unwrap();
        assert_eq!(mock.detached(), [id.as_str()]);
        assert_eq!(mock.add_commands().len(), 1);
        assert!(mock.add_commands()[0].contains(&format!("ClientAuthV3={KEY_A}")));

        // Unchanged: no more commands (not even a check, within the interval).
        let before = mock.commands().len();
        n.enforce(&enforcement(vec![keyed.clone()])).unwrap();
        assert_eq!(mock.commands().len(), before);

        // A changed grant re-adds exactly this service.
        let both = address(&[8080], vec![grant(None, creds(&[KEY_A, KEY_B]))]);
        n.enforce(&enforcement(vec![both])).unwrap();
        assert_eq!(mock.add_commands().len(), 2);
        assert!(mock
            .commands()
            .iter()
            .any(|c| c == &format!("DEL_ONION {id}")));
        assert_eq!(mock.detached(), [id.as_str()]);

        // Anyone replaces the keys.
        n.enforce(&enforcement(vec![open])).unwrap();
        assert!(!mock.add_commands().last().unwrap().contains("ClientAuthV3"));

        // Revoked: removed.
        n.enforce(&enforcement(vec![address(&[8080], vec![])]))
            .unwrap();
        assert!(mock.detached().is_empty());
    }

    #[test]
    fn a_revoked_service_is_deleted_once() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        n.enforce(&enforcement(vec![keyed])).unwrap();

        // The id is in the address list, applied and owned: still one DEL_ONION.
        let mut revoked = enforcement(vec![address(&[8080], vec![])]);
        revoked.owned = ["svc1".to_string()].into();
        n.enforce(&revoked).unwrap();
        let dels = mock
            .commands()
            .iter()
            .filter(|c| c.starts_with("DEL_ONION"))
            .count();
        assert_eq!(dels, 1);
    }

    #[test]
    fn enforce_readds_after_tor_loses_services_and_on_restart() {
        let mock = MockTorControl::start();
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        let n = net(&mock, Duration::ZERO);
        n.enforce(&enforcement(vec![keyed.clone()])).unwrap();
        assert_eq!(mock.detached().len(), 1);

        // Tor restarted: the service is gone, the next check puts it back.
        mock.forget_services();
        n.enforce(&enforcement(vec![keyed.clone()])).unwrap();
        assert_eq!(mock.detached().len(), 1);

        // A new daemon (empty memory) over a Tor that still runs the service re-adds it.
        let n2 = net(&mock, CHECK_INTERVAL);
        let adds = mock.add_commands().len();
        n2.enforce(&enforcement(vec![keyed])).unwrap();
        assert_eq!(mock.add_commands().len(), adds + 1);
        assert_eq!(mock.detached().len(), 1);

        // ... and one with nothing granted removes a stray service of ours.
        let n3 = net(&mock, CHECK_INTERVAL);
        n3.enforce(&enforcement(vec![address(&[8080], vec![])]))
            .unwrap();
        assert!(mock.detached().is_empty());
    }

    #[test]
    fn tor_down_is_a_status_not_a_crash() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        mock.set_down(true);
        let a = address(&[8080], vec![grant(None, EnforcedSubject::Anyone)]);
        assert!(n.enforce(&enforcement(vec![a.clone()])).is_err());
        assert!(matches!(n.status().0, NetworkStatus::Down { .. }));
        mock.set_down(false);
        n.enforce(&enforcement(vec![a])).unwrap();
        assert_eq!(n.status().0, NetworkStatus::Up);
        assert_eq!(mock.detached().len(), 1);
    }

    #[test]
    fn disable_removes_everything_of_ours() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let a = address(&[8080], vec![grant(None, EnforcedSubject::Anyone)]);
        n.enforce(&enforcement(vec![a])).unwrap();
        assert_eq!(mock.detached().len(), 1);
        n.disable(&[]).unwrap();
        assert!(mock.detached().is_empty());
    }

    // ── Revocation must not fail open ──

    fn stale(
        owned: &[&str],
        tombstones: &[&str],
        addrs: Vec<EnforcedAddress>,
    ) -> NetworkEnforcement {
        NetworkEnforcement {
            addresses: addrs,
            owned: owned.iter().map(|s| s.to_string()).collect(),
            tombstones: tombstones.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_revocation_during_an_outage_is_retried_until_tor_confirms() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        n.enforce(&enforcement(vec![keyed])).unwrap();
        assert_eq!(mock.detached(), ["svc1"]);

        let revoked = address(&[8080], vec![]);
        mock.set_down(true);
        assert!(n.enforce(&enforcement(vec![revoked.clone()])).is_err());
        assert_eq!(
            mock.detached(),
            ["svc1"],
            "still published while Tor is away"
        );
        // Forgotten from `applied` only after a confirmed removal.
        assert!(n.state.lock().unwrap().applied.contains_key("svc1"));

        mock.set_down(false);
        n.enforce(&enforcement(vec![revoked])).unwrap();
        assert!(mock.detached().is_empty());
        assert!(n.state.lock().unwrap().applied.is_empty());
    }

    #[test]
    fn remove_locator_keeps_the_service_in_memory_until_it_is_gone() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        n.enforce(&enforcement(vec![keyed])).unwrap();
        let gone = Address {
            id: "addr1".into(),
            app_id: "app".into(),
            network_id: "tor".into(),
            locator: Locator::Onion {
                hostname: "svc1.onion".into(),
            },
            scope: socketguard_core::Scope::All,
            created_at: chrono::Utc::now(),
        };
        mock.set_down(true);
        assert!(n.remove_locator(&gone).is_err());
        assert!(n.state.lock().unwrap().applied.contains_key("svc1"));
        mock.set_down(false);
        n.remove_locator(&gone).unwrap();
        assert!(mock.detached().is_empty());
        assert!(n.state.lock().unwrap().applied.is_empty());
    }

    #[test]
    fn tombstones_are_retried_even_when_nothing_else_changed() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        n.enforce(&enforcement(vec![address(&[8080], vec![])]))
            .unwrap();
        mock.inject_service("gone1");
        let before = mock.commands().len();
        // Within the check interval and with nothing wanted, but a tombstone: Tor is asked.
        mock.set_down(true);
        assert!(n.enforce(&stale(&[], &["gone1"], vec![])).is_err());
        assert_eq!(mock.detached(), ["gone1"]);
        mock.set_down(false);
        n.enforce(&stale(&[], &["gone1"], vec![])).unwrap();
        assert!(mock.commands().len() > before);
        assert!(mock.detached().is_empty());
        // A tombstone for a service Tor no longer runs is just done.
        n.enforce(&stale(&[], &["gone1"], vec![])).unwrap();
    }

    #[test]
    fn owned_services_without_an_address_are_swept_and_others_are_left() {
        let mock = MockTorControl::start();
        let n = net(&mock, CHECK_INTERVAL);
        mock.inject_service("ours-but-gone");
        mock.inject_service("foreign");
        let keyed = address(&[8080], vec![grant(None, creds(&[KEY_A]))]);
        n.enforce(&stale(&["ours-but-gone", "svc1"], &[], vec![keyed]))
            .unwrap();
        assert_eq!(mock.detached(), ["foreign", "svc1"]);
    }
}
