//! Engine scenarios against the model of ADR 0027: discovery, address layouts, grants and
//! the ruleset they produce, with mock firewall, interfaces, monitor and networks.

use socketguard_core::config::{
    BackendConfig, BackendInstanceConfig, DaemonConfig, FilterMode, ProcessFilter,
};
use socketguard_core::ListeningSocket;
use socketguard_core::{
    ActivityKind, ActivityQuery, App, CredentialKind, NetworkStatus, NewCredential, NewGrant,
    PortRef, Protocol, Reach, Scope, Subject, Target,
};
use socketguard_daemon::api::DaemonEvent;
use socketguard_daemon::engine::{Engine, EngineError, GrantFilter, ProtectHostError};
use socketguard_daemon::firewall::{DropEvent, Dst, ScopeMatch, Sources};
use socketguard_daemon::iface::InterfaceManager as _;
use socketguard_daemon::networks::ip::{ula::UlaBackend, Ipv6Backend as _};
use socketguard_daemon::test_support::*;
use socketguard_daemon::AppState;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, RwLockReadGuard};

const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";
/// The node address that KEY derives.
const KEY_ADDR: &str = "200:8af8:ba35:56ae:bef0:6284:981f:5972/128";

// ─── Harness ─────────────────────────────────────────────────────────────────

struct Harness {
    state: Arc<AppState>,
    fw: Arc<MockFirewall>,
    fw_calls: Arc<Mutex<Vec<FirewallCall>>>,
    net: MockInterfaceManager,
    net_calls: Arc<Mutex<Vec<NetworkCall>>>,
    sockets: Arc<Mutex<Vec<ListeningSocket>>>,
    nets: HashMap<&'static str, MockIpv6Backend>,
}

impl Harness {
    async fn new(nets: Vec<Net>, sockets: Vec<ListeningSocket>) -> Self {
        Self::with_filter(nets, sockets, ProcessFilter::default()).await
    }

    async fn with_filter(
        nets: Vec<Net>,
        sockets: Vec<ListeningSocket>,
        process_filter: ProcessFilter,
    ) -> Self {
        let d = daemon_with(
            nets,
            sockets,
            DaemonConfig {
                process_filter,
                ..DaemonConfig::default()
            },
            None,
        )
        .await;
        Self {
            state: d.state,
            fw: d.fw,
            fw_calls: d.fw_calls,
            net: d.net,
            net_calls: d.net_calls,
            sockets: d.sockets,
            nets: d.nets,
        }
    }

    async fn reconcile(&self) {
        let engine = self.state.engine.read().await;
        engine.reconcile(&self.state).await.unwrap();
    }

    async fn engine(&self) -> RwLockReadGuard<'_, Engine> {
        self.state.engine.read().await
    }

    fn set_sockets(&self, sockets: Vec<ListeningSocket>) {
        *self.sockets.lock().unwrap() = sockets;
    }

    fn clear_calls(&self) {
        self.fw_calls.lock().unwrap().clear();
        self.net_calls.lock().unwrap().clear();
    }

    async fn apps(&self) -> Vec<App> {
        self.engine()
            .await
            .list_apps(&self.state, false)
            .await
            .unwrap()
    }

    /// The only app.
    async fn app(&self) -> App {
        let apps = self.apps().await;
        assert_eq!(apps.len(), 1, "expected exactly one app: {apps:?}");
        apps.into_iter().next().unwrap()
    }

    /// The address of the only app on `network` (the only one there).
    async fn addr_on(&self, network: &str) -> Ipv6Addr {
        let app = self.app().await;
        let found: Vec<_> = app
            .addresses
            .iter()
            .filter(|a| a.network_id == network)
            .collect();
        assert_eq!(found.len(), 1, "one address on {network}: {found:?}");
        found[0].locator.ipv6().unwrap()
    }

    /// Open the only app to Anyone, which gives it an address on every network that takes
    /// grants (an address exists only once a grant names the row).
    async fn open(&self) -> socketguard_core::GrantView {
        let app = self.app().await;
        self.grant(&app.id, Subject::Anyone).await
    }

    /// The last ruleset applied to the firewall.
    fn last_ruleset(&self) -> socketguard_daemon::firewall::DesiredRuleset {
        applied(&self.fw_calls)
            .pop()
            .expect("a ruleset was applied")
    }

    async fn peer(&self, label: &str, kind: CredentialKind, value: &str) -> String {
        self.engine()
            .await
            .create_peer(
                &self.state,
                label,
                &[NewCredential {
                    kind,
                    value: value.into(),
                    label: None,
                }],
            )
            .await
            .unwrap()
            .id
    }

    async fn grant(&self, app_id: &str, subject: Subject) -> socketguard_core::GrantView {
        self.engine()
            .await
            .create_grant(
                &self.state,
                &NewGrant {
                    target: Target::App(app_id.into()),
                    scope: Scope::All,
                    network_id: None,
                    subject,
                    confirm_open: true,
                },
            )
            .await
            .unwrap()
    }

    async fn activity(&self, kind: ActivityKind) -> Vec<socketguard_core::ActivityRecord> {
        self.state
            .db
            .list_activity(&ActivityQuery {
                kind: Some(kind),
                limit: Some(100),
                ..Default::default()
            })
            .await
            .unwrap()
    }
}

fn listener(name: &str, port: u16, protocol: Protocol) -> ListeningSocket {
    ListeningSocket {
        pid: 1000,
        process_name: name.to_string(),
        port,
        protocol,
        bind_address: IpAddr::V6("::".parse().unwrap()),
        exe_path: Some(format!("/usr/bin/{name}")),
        cmdline: Some(vec![name.to_string()]),
        uid: Some("1000".into()),
        foreign_mntns: false,
        cwd: None,
        unidentified: false,
        in_service_unit: false,
    }
}

fn script(interpreter: &str, script: &str, port: u16) -> ListeningSocket {
    ListeningSocket {
        pid: 2000 + port as u32,
        process_name: interpreter.to_string(),
        port,
        protocol: Protocol::Tcp,
        bind_address: IpAddr::V6("::".parse().unwrap()),
        exe_path: Some(format!("/usr/bin/{interpreter}")),
        cmdline: Some(vec![
            interpreter.to_string(),
            script.to_string(),
            "--serve".into(),
        ]),
        uid: Some("1000".into()),
        foreign_mntns: false,
        cwd: None,
        unidentified: false,
        in_service_unit: false,
    }
}

fn tcp(port: u16) -> PortRef {
    PortRef {
        port,
        proto: Protocol::Tcp,
    }
}

fn drain(rx: &mut broadcast::Receiver<DaemonEvent>) -> Vec<DaemonEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn net_adds(h: &Harness) -> Vec<(String, Ipv6Addr)> {
    h.net_calls
        .lock()
        .unwrap()
        .iter()
        .filter_map(|c| match c {
            NetworkCall::AddAddress {
                iface,
                addr,
                prefix,
            } => {
                assert_eq!(*prefix, 128);
                Some((iface.clone(), *addr))
            }
            _ => None,
        })
        .collect()
}

// ─── Discovery ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn discovery_creates_a_pending_app_with_an_address_on_every_network() {
    let h = Harness::new(
        vec![local_net(), lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    let mut events = h.state.events.subscribe();
    h.reconcile().await;

    let app = h.app().await;
    assert_eq!(app.name, "nginx");
    assert!(!app.reviewed, "a new app is pending");
    assert_eq!(app.ports.len(), 1);
    assert!((app.ports[0].port, app.ports[0].listening) == (80, true));
    // Nothing is granted: only Local on loopback has an address.
    assert_eq!(app.addresses.len(), 1);
    assert_eq!(app.addresses[0].network_id, "local");
    h.open().await;
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 3);
    assert!(app.addresses.iter().all(|a| a.scope == Scope::All));
    let nets: Vec<_> = app
        .addresses
        .iter()
        .map(|a| a.network_id.as_str())
        .collect();
    assert!(["local", "lan", "ygg"].iter().all(|n| nets.contains(n)));

    // Addresses are on their interfaces, each from its network's prefix.
    let adds = net_adds(&h);
    assert_eq!(adds.len(), 3);
    let ygg_addr = h.addr_on("ygg").await;
    assert!(adds.contains(&("ygg0".to_string(), ygg_addr)));
    assert!(ygg_addr.to_string().starts_with("300:1:2:3:"));
    assert!(h
        .addr_on("lan")
        .await
        .to_string()
        .starts_with("2001:db8:1:2:"));

    // The last ruleset denies every address by the managed scope and the Yggdrasil
    // interface has its overlay scope.
    let fw = applied(&h.fw_calls);
    let fw = [fw.last().unwrap().clone()];
    let scope_ids: Vec<_> = fw[0].scopes.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(scope_ids, ["managed", "overlay:ygg0"]);
    let ScopeMatch::Destinations(dsts) = &fw[0].scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts.len(), 3);
    assert!(dsts.contains(&IpAddr::V6(ygg_addr)));

    // Activity and events tell the frontends.
    let found = h.activity(ActivityKind::AppDiscovered).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].app_id.as_deref(), Some(app.id.as_str()));
    let evs = drain(&mut events);
    assert!(evs.contains(&DaemonEvent::AppDiscovered(app.id.clone())));
    assert!(evs.contains(&DaemonEvent::AppsChanged));
    assert!(evs.contains(&DaemonEvent::Activity));
}

#[tokio::test]
async fn reconcile_is_idempotent() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    h.open().await;
    h.clear_calls();
    h.reconcile().await;
    assert!(
        applied(&h.fw_calls).is_empty(),
        "an unchanged ruleset is not re-sent"
    );
    assert!(h.net_calls.lock().unwrap().is_empty());
    assert_eq!(h.app().await.addresses.len(), 2);
    assert_eq!(h.activity(ActivityKind::AppDiscovered).await.len(), 1);
}

#[tokio::test]
async fn a_vanished_firewall_state_is_reapplied_on_the_next_pass() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    h.clear_calls();
    h.fw.simulate_drift();
    h.reconcile().await;
    assert_eq!(applied(&h.fw_calls).len(), 1, "drift triggers a re-apply");
    h.clear_calls();
    h.reconcile().await;
    assert!(applied(&h.fw_calls).is_empty());
}

#[tokio::test]
async fn verify_runs_on_a_cadence_and_after_a_failed_apply() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    let clock = ManualClock::new();
    {
        let mut engine = h.state.engine.write().await;
        engine.set_verify_interval(Duration::from_secs(5));
        engine.set_clock(clock.clone());
    }
    h.reconcile().await; // applies; counts as verified
    let base = h.fw.verify_count();
    for _ in 0..5 {
        h.reconcile().await;
    }
    assert_eq!(h.fw.verify_count(), base, "no verify within the interval");

    clock.advance(Duration::from_secs(6));
    h.reconcile().await;
    assert_eq!(
        h.fw.verify_count(),
        base + 1,
        "verify once the interval passed"
    );
    h.reconcile().await;
    assert_eq!(h.fw.verify_count(), base + 1);

    // Drift is only noticed on a verify pass.
    h.fw.simulate_drift();
    h.clear_calls();
    h.reconcile().await;
    assert!(applied(&h.fw_calls).is_empty());
    clock.advance(Duration::from_secs(6));
    h.reconcile().await;
    assert_eq!(applied(&h.fw_calls).len(), 1, "drift re-applied when due");
}

#[tokio::test]
async fn a_revoked_grant_cuts_its_established_connections() {
    let h = Harness::new(
        vec![lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let peer = h.peer("friend", CredentialKind::Ip, "2001:db8::7").await;
    let g = h.grant(&app.id, Subject::Peer(peer)).await;
    h.reconcile().await;
    assert!(h.fw.revoked().is_empty(), "granting revokes nothing");
    h.engine()
        .await
        .delete_grant(&h.state, &g.grant.id)
        .await
        .unwrap();
    h.reconcile().await;
    let revoked = h.fw.revoked();
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0].ports.start, 80);
    assert_eq!(revoked[0].src, Some("2001:db8::7/128".parse().unwrap()));
}

#[tokio::test]
async fn interpreter_apps_are_split_by_script() {
    let h = Harness::new(
        vec![local_net()],
        vec![
            script("python3", "/srv/a/server.py", 8000),
            script("python3", "/srv/b/worker.py", 8001),
            // The same script on a second port is the same app.
            script("python3", "/srv/a/server.py", 8002),
            listener("nginx", 80, Protocol::Tcp),
        ],
    )
    .await;
    h.reconcile().await;

    let apps = h.apps().await;
    assert_eq!(apps.len(), 3);
    let server = apps.iter().find(|a| a.name == "server.py").unwrap();
    let ports: Vec<u16> = server.ports.iter().map(|p| p.port).collect();
    assert_eq!(ports, [8000, 8002]);
    assert_eq!(server.interpreter_arg.as_deref(), Some("/srv/a/server.py"));
    assert!(apps
        .iter()
        .any(|a| a.name == "worker.py" && a.ports.len() == 1));
    assert!(apps.iter().any(|a| a.name == "nginx"));
    // Each app has its own address.
    let all: std::collections::HashSet<_> = apps
        .iter()
        .flat_map(|a| a.addresses.iter().map(|x| x.locator.ipv6().unwrap()))
        .collect();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn process_filter_ignores_non_matching() {
    let h = Harness::with_filter(
        vec![local_net()],
        vec![
            listener("nginx", 80, Protocol::Tcp),
            listener("svchost", 135, Protocol::Tcp),
        ],
        ProcessFilter {
            mode: FilterMode::Denylist,
            patterns: vec!["svchost*".into()],
        },
    )
    .await;
    h.reconcile().await;
    assert_eq!(h.app().await.name, "nginx");
}

#[tokio::test]
async fn a_returning_app_keeps_its_identity_across_pids_and_restarts() {
    let h = Harness::new(
        vec![local_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let first = h.app().await;

    let mut moved = listener("nginx", 80, Protocol::Tcp);
    moved.pid = 4242;
    h.set_sockets(vec![moved]);
    h.reconcile().await;
    assert_eq!(h.app().await.id, first.id);

    // It stops: the record, its address and its grants stay (ADR 0027).
    h.set_sockets(vec![]);
    h.reconcile().await;
    let stopped = h.app().await;
    assert!(!stopped.ports[0].listening);
    assert_eq!(stopped.addresses, first.addresses);
    h.set_sockets(vec![listener("nginx", 80, Protocol::Tcp)]);
    h.reconcile().await;
    assert!(h.app().await.ports[0].listening);
    assert_eq!(h.activity(ActivityKind::AppDiscovered).await.len(), 1);
}

#[tokio::test]
async fn an_upgraded_binary_is_still_the_same_app() {
    let h = Harness::new(
        vec![local_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let mut upgraded = listener("nginx", 80, Protocol::Tcp);
    // The monitor strips " (deleted)" before the engine sees the path.
    upgraded.exe_path = Some("/usr/bin/nginx".into());
    h.set_sockets(vec![upgraded]);
    h.reconcile().await;
    assert_eq!(h.apps().await.len(), 1);
}

#[tokio::test]
async fn allocation_is_retried_until_it_succeeds() {
    let ygg = ygg_net();
    let h = Harness::new(
        vec![local_net(), ygg],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.nets["ygg"].set_failing(true);
    h.reconcile().await;
    h.open().await;

    // The app exists and has the addresses that worked.
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 1);
    assert_eq!(app.addresses[0].network_id, "local");

    h.nets["ygg"].set_failing(false);
    h.reconcile().await;
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 2);
    let ygg_addr = h.addr_on("ygg").await;
    assert!(h.net.addresses("ygg0").contains(&ygg_addr));
    assert!(applied(&h.fw_calls).last().unwrap().scopes.iter().any(
        |s| matches!(&s.matcher, ScopeMatch::Destinations(d) if d.contains(&IpAddr::V6(ygg_addr)))
    ));
}

// ─── Grants and rules ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_grant_to_a_yggdrasil_key_peer_gives_a_rule_with_iif() {
    let h = Harness::new(
        vec![local_net(), lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let peer = h
        .peer("b", CredentialKind::YggKey, &KEY.to_uppercase())
        .await;
    let view = h.grant(&app.id, Subject::Peer(peer)).await;

    // Verified on Yggdrasil, not reachable on the LAN; Local takes no grants.
    let reach: HashMap<_, _> = view
        .reach
        .iter()
        .map(|r| (r.network_id.as_str(), r.reach))
        .collect();
    assert_eq!(reach.len(), 2);
    assert_eq!(reach["ygg"], Reach::Verified);
    assert_eq!(reach["lan"], Reach::NotReachable);

    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    let r = &rs.rules[0];
    assert_eq!(r.iif.as_deref(), Some("ygg0"));
    assert_eq!(r.dst, IpAddr::V6(h.addr_on("ygg").await));
    assert_eq!(r.ports.start, 80);
    assert_eq!(r.sources, Sources::Nets(vec![KEY_ADDR.parse().unwrap()]));
    let app = h.app().await;
    assert!(r.id.starts_with(&format!(
        "a:{}:80:tcp:{}",
        app.addresses
            .iter()
            .find(|a| a.network_id == "ygg")
            .unwrap()
            .id,
        view.grant.id
    )));

    // The grant is visible through the queries, with reach.
    let detail = h.engine().await.get_app(&h.state, &app.id).await.unwrap();
    assert_eq!(detail.grants.len(), 1);
    assert_eq!(detail.grants[0].reach, view.reach);
    let by_peer = h
        .engine()
        .await
        .list_grants(
            &h.state,
            GrantFilter {
                peer_id: Some(match &view.grant.subject {
                    Subject::Peer(p) => p.clone(),
                    _ => unreachable!(),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(by_peer.len(), 1);
    assert_eq!(h.activity(ActivityKind::GrantAdded).await.len(), 1);
}

#[tokio::test]
async fn an_ip_suffix_peer_follows_a_prefix_change() {
    let h = Harness::new(
        vec![local_net(), lan_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let peer = h.peer("nas", CredentialKind::IpSuffix, "::a:b/64").await;
    h.grant(&app.id, Subject::Peer(peer)).await;

    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(
        rs.rules[0].iif.as_deref(),
        Some("eth0"),
        "IP-only credentials are bound to the network's interface"
    );
    assert_eq!(
        rs.rules[0].sources,
        Sources::Nets(vec!["2001:db8:1:2::a:b/128".parse().unwrap()])
    );
    let old = h.addr_on("lan").await;

    // The router hands out a new /64.
    h.nets["lan"].set_prefix("2001:db8:9:9::");
    h.reconcile().await;

    let new = h.addr_on("lan").await;
    assert_ne!(new, old);
    assert!(new.to_string().starts_with("2001:db8:9:9:"));
    assert_eq!(
        socketguard_daemon::networks::ip::iid_of(new),
        socketguard_daemon::networks::ip::iid_of(old),
        "same interface ID, new prefix"
    );
    assert!(h.net.addresses("eth0").contains(&new));
    assert!(!h.net.addresses("eth0").contains(&old));
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].dst, IpAddr::V6(new));
    assert_eq!(
        rs.rules[0].sources,
        Sources::Nets(vec!["2001:db8:9:9::a:b/128".parse().unwrap()])
    );
}

#[tokio::test]
async fn a_key_peer_with_no_yggdrasil_network_is_not_reachable() {
    let h = Harness::new(vec![lan_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    let app = h.app().await;
    let peer = h.peer("b", CredentialKind::YggKey, KEY).await;
    let view = h.grant(&app.id, Subject::Peer(peer)).await;
    assert_eq!(view.reach.len(), 1);
    assert_eq!(view.reach[0].network_id, "lan");
    assert_eq!(view.reach[0].reach, Reach::NotReachable);
    assert!(h.last_ruleset().rules.is_empty());
}

#[tokio::test]
async fn a_grant_to_anyone_needs_confirmation_and_local_grants_are_rejected() {
    let h = Harness::new(
        vec![local_net(), lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let grant = |subject, network: Option<&str>, confirm| NewGrant {
        target: Target::App(app.id.clone()),
        scope: Scope::All,
        network_id: network.map(str::to_string),
        subject,
        confirm_open: confirm,
    };

    let e = h
        .engine()
        .await
        .create_grant(&h.state, &grant(Subject::Anyone, None, false))
        .await;
    assert!(matches!(e, Err(EngineError::ConfirmationRequired)), "{e:?}");
    assert!(h.state.db.list_grants().await.unwrap().is_empty());

    let e = h
        .engine()
        .await
        .create_grant(&h.state, &grant(Subject::Anyone, Some("local"), true))
        .await;
    assert!(matches!(e, Err(EngineError::LocalNetwork)), "{e:?}");
    assert_eq!(
        EngineError::LocalNetwork.to_string(),
        "Local is this machine only"
    );

    let view = h
        .engine()
        .await
        .create_grant(&h.state, &grant(Subject::Anyone, None, true))
        .await
        .unwrap();
    assert!(view.reach.iter().all(|r| r.reach == Reach::Open));
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 2, "lan and ygg, not local");
    assert!(rs
        .rules
        .iter()
        .all(|r| r.sources == Sources::Any && r.iif.is_some()));

    // Duplicates and unknown references are refused.
    let e = h
        .engine()
        .await
        .create_grant(&h.state, &grant(Subject::Anyone, None, true))
        .await;
    assert!(matches!(e, Err(EngineError::Conflict(_))));
    let e = h
        .engine()
        .await
        .create_grant(&h.state, &grant(Subject::Peer("nobody".into()), None, true))
        .await;
    assert!(matches!(e, Err(EngineError::NotFound(_))));
    let e = h
        .engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                scope: Scope::port(tcp(9)),
                ..grant(Subject::Anyone, None, true)
            },
        )
        .await;
    assert!(matches!(e, Err(EngineError::Invalid(_))));
}

#[tokio::test]
async fn deleting_a_peer_removes_its_rules() {
    let h = Harness::new(
        vec![lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let a = h.peer("a", CredentialKind::YggKey, KEY).await;
    let b = h.peer("b", CredentialKind::Ip, "fd00:5a::2").await;
    h.grant(&app.id, Subject::Peer(a.clone())).await;
    h.grant(&app.id, Subject::Peer(b)).await;
    assert_eq!(h.last_ruleset().rules.len(), 2);

    let mut events = h.state.events.subscribe();
    h.engine().await.delete_peer(&h.state, &a).await.unwrap();
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1, "only the other peer's rule remains");
    assert_eq!(rs.rules[0].iif.as_deref(), Some("eth0"));
    assert_eq!(h.state.db.list_grants().await.unwrap().len(), 1);
    let evs = drain(&mut events);
    assert!(evs.contains(&DaemonEvent::PeersChanged) && evs.contains(&DaemonEvent::GrantsChanged));
    assert_eq!(h.activity(ActivityKind::PeerRemoved).await.len(), 1);
    let e = h.engine().await.delete_peer(&h.state, &a).await;
    assert!(matches!(e, Err(EngineError::NotFound(_))));
}

#[tokio::test]
async fn groups_grant_to_all_members_and_deleting_one_removes_the_rules() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    let app = h.app().await;
    let a = h.peer("a", CredentialKind::YggKey, KEY).await;
    let b = h.peer("b", CredentialKind::YggAddr, "200:1::5").await;
    let engine = h.engine().await;
    let group = engine
        .create_group(&h.state, "family", std::slice::from_ref(&a))
        .await
        .unwrap();
    drop(engine);
    h.grant(&app.id, Subject::Group(group.id.clone())).await;
    assert_eq!(
        h.last_ruleset().rules[0].sources,
        Sources::Nets(vec![KEY_ADDR.parse().unwrap()])
    );

    h.engine()
        .await
        .set_group_members(&h.state, &group.id, &[a.clone(), b.clone()])
        .await
        .unwrap();
    assert_eq!(
        h.last_ruleset().rules[0].sources,
        Sources::Nets(vec![
            "200:1::5/128".parse().unwrap(),
            KEY_ADDR.parse().unwrap()
        ])
    );
    let peer = h.engine().await.get_peer(&h.state, &b).await.unwrap();
    assert_eq!(peer.groups, vec![group.id.clone()]);

    h.engine()
        .await
        .set_group_members(&h.state, &group.id, std::slice::from_ref(&a))
        .await
        .unwrap();
    assert_eq!(
        h.last_ruleset().rules[0].sources,
        Sources::Nets(vec![KEY_ADDR.parse().unwrap()])
    );

    h.engine()
        .await
        .delete_group(&h.state, &group.id)
        .await
        .unwrap();
    assert!(h.last_ruleset().rules.is_empty());
    assert!(h.state.db.list_grants().await.unwrap().is_empty());
    assert!(
        h.engine().await.get_peer(&h.state, &a).await.is_ok(),
        "members stay"
    );
}

#[tokio::test]
async fn peers_validate_and_stay_unique() {
    let h = Harness::new(vec![ygg_net()], vec![]).await;
    let engine = h.engine().await;
    let cred = |kind, value: &str| NewCredential {
        kind,
        value: value.into(),
        label: None,
    };
    let e = engine
        .create_peer(&h.state, "all", &[cred(CredentialKind::Ip, "0.0.0.0/0")])
        .await;
    assert!(
        matches!(&e, Err(EngineError::Invalid(m)) if m.contains("grant to Anyone")),
        "{e:?}"
    );
    let e = engine
        .create_peer(&h.state, "base", &[cred(CredentialKind::Ip, "200::")])
        .await;
    assert!(matches!(&e, Err(EngineError::Invalid(_))), "{e:?}");
    let e = engine.create_peer(&h.state, "  ", &[]).await;
    assert!(matches!(e, Err(EngineError::Invalid(_))));
    let e = engine
        .create_peer(
            &h.state,
            "dup",
            &[
                cred(CredentialKind::YggKey, KEY),
                cred(CredentialKind::YggKey, &KEY.to_uppercase()),
            ],
        )
        .await;
    assert!(matches!(e, Err(EngineError::Invalid(_))), "{e:?}");

    // 200::/7 in an Ip credential is normalized.
    let p = engine
        .create_peer(&h.state, "n", &[cred(CredentialKind::Ip, "300:1:2:3::5")])
        .await
        .unwrap();
    assert_eq!(p.credentials[0].kind, CredentialKind::YggAddr);

    // Credentials and labels are unique across peers.
    let e = engine
        .create_peer(
            &h.state,
            "other",
            &[cred(CredentialKind::YggAddr, "300:1:2:3::5")],
        )
        .await;
    assert!(
        matches!(&e, Err(EngineError::Conflict(m)) if m.contains("already belongs to peer n")),
        "{e:?}"
    );
    let e = engine.create_peer(&h.state, "n", &[]).await;
    assert!(matches!(e, Err(EngineError::Conflict(_))));
    assert!(engine.list_peers(&h.state).await.unwrap().len() == 1);

    // Add, rename, remove.
    let c = engine
        .add_credential(&h.state, &p.id, &cred(CredentialKind::YggKey, KEY))
        .await
        .unwrap();
    let renamed = engine
        .update_peer_label(&h.state, &p.id, "laptop")
        .await
        .unwrap();
    assert_eq!(
        (renamed.label.as_str(), renamed.credentials.len()),
        ("laptop", 2)
    );
    engine
        .remove_credential(&h.state, &p.id, &c.id)
        .await
        .unwrap();
    let e = engine.remove_credential(&h.state, &p.id, &c.id).await;
    assert!(matches!(e, Err(EngineError::NotFound(_))));
    assert_eq!(
        engine
            .get_peer(&h.state, &p.id)
            .await
            .unwrap()
            .credentials
            .len(),
        1
    );
}

#[tokio::test]
async fn review_and_delete_app() {
    let h = Harness::new(
        vec![lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    assert_eq!(
        h.engine()
            .await
            .list_apps(&h.state, true)
            .await
            .unwrap()
            .len(),
        1
    );
    h.engine()
        .await
        .review_app(&h.state, &app.id, true)
        .await
        .unwrap();
    assert!(h
        .engine()
        .await
        .list_apps(&h.state, true)
        .await
        .unwrap()
        .is_empty());
    assert!(h.app().await.reviewed);
    let e = h.engine().await.review_app(&h.state, "nope", true).await;
    assert!(matches!(e, Err(EngineError::NotFound(_))));

    h.grant(&app.id, Subject::Anyone).await;
    h.clear_calls();
    h.engine()
        .await
        .delete_app(&h.state, &app.id)
        .await
        .unwrap();
    assert!(h.apps().await.is_empty());
    assert!(h.state.db.list_grants().await.unwrap().is_empty());
    assert!(h.net.addresses("eth0").is_empty() && h.net.addresses("ygg0").is_empty());
    // The addresses left the interfaces before the ruleset stopped covering them.
    let net = h.net_calls.lock().unwrap().len();
    assert_eq!(net, 2);
    let rs = h.last_ruleset();
    assert!(rs.rules.is_empty());
    assert!(!rs.scopes.iter().any(|s| s.id == "managed"));
    assert_eq!(h.activity(ActivityKind::AppRemoved).await.len(), 1);

    // It reappears as pending when it listens again.
    h.reconcile().await;
    let again = h.app().await;
    assert!(!again.reviewed);
    assert_eq!(again.id, app.id);
}

// ─── Observability ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_drop_event_produces_blocked_activity() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.engine().await.startup_reconcile(&h.state).await;
    h.reconcile().await;
    h.open().await;
    let app = h.app().await;
    let dst = h.addr_on("ygg").await;

    let src: IpAddr = "200:5a::77".parse().unwrap();
    let long_ago = SystemTime::now() - Duration::from_secs(300);
    let drop_event = |at, src| DropEvent {
        at,
        src,
        dst: IpAddr::V6(dst),
        port: Some(80),
        proto: Some(Protocol::Tcp),
        iif: Some("ygg0".into()),
        scope_id: Some("managed".into()),
    };
    for _ in 0..3 {
        assert!(h.fw.emit_drop(drop_event(long_ago, src)));
    }
    h.fw.emit_drop(drop_event(long_ago, "200:5a::88".parse().unwrap()));
    let mut events = h.state.events.subscribe();
    h.reconcile().await;

    let blocked = h.activity(ActivityKind::Blocked).await;
    assert_eq!(blocked.len(), 2, "aggregated per source: {blocked:?}");
    let rec = blocked.iter().find(|r| r.src == Some(src)).unwrap();
    assert_eq!(rec.count, 3);
    assert_eq!(rec.app_id.as_deref(), Some(app.id.as_str()));
    assert_eq!(rec.network_id.as_deref(), Some("ygg"));
    assert_eq!((rec.port, rec.proto), (Some(80), Some(Protocol::Tcp)));
    assert!(drain(&mut events).contains(&DaemonEvent::Activity));

    // Flushed once: nothing is written twice.
    h.reconcile().await;
    assert_eq!(h.activity(ActivityKind::Blocked).await.len(), 2);
}

// ─── Lifecycle: freeze, disable, restore ─────────────────────────────────────

#[tokio::test]
async fn disable_removes_rules_and_addresses() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    h.open().await;
    assert_eq!(
        h.net.addresses("lo").len() + h.net.addresses("ygg0").len(),
        2
    );
    h.clear_calls();

    h.engine().await.disable(&h.state).await.unwrap();

    assert!(h.net.addresses("lo").is_empty() && h.net.addresses("ygg0").is_empty());
    let calls = h.fw_calls.lock().unwrap().clone();
    assert_eq!(calls, vec![FirewallCall::Disable]);
    // The model stays: re-enabling is a daemon start away.
    assert_eq!(h.app().await.addresses.len(), 2);
}

#[tokio::test]
async fn disabled_stays_off_across_reconciles_and_startup_until_enabled() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    h.engine().await.disable(&h.state).await.unwrap();
    assert!(h.state.db.disabled().await);
    h.clear_calls();

    // New apps are still tracked, but nothing is applied or added.
    h.set_sockets(vec![
        listener("nginx", 80, Protocol::Tcp),
        listener("redis", 6379, Protocol::Tcp),
    ]);
    h.nets["ygg"].set_prefix("300:9:9:9::");
    h.reconcile().await;
    h.engine().await.startup_reconcile(&h.state).await;
    assert_eq!(h.apps().await.len(), 2);
    assert!(h.fw_calls.lock().unwrap().is_empty(), "no Apply");
    assert!(net_adds(&h).is_empty());

    h.engine().await.enable(&h.state).await.unwrap();
    assert!(!h.state.db.disabled().await);
    assert_eq!(applied(&h.fw_calls).len(), 1);
    assert_eq!(net_adds(&h).len(), 1, "only the opened app has an address");
}

#[tokio::test]
async fn startup_reapplies_the_ruleset_and_restores_missing_addresses() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let a = h.addr_on("ygg").await;
    h.net.drop_address("ygg0", a);
    h.clear_calls();

    h.engine().await.startup_reconcile(&h.state).await;

    let fw = applied(&h.fw_calls);
    assert_eq!(fw.len(), 1, "the ruleset is replaced, never flushed");
    assert_eq!(fw[0].rules.len(), 1);
    assert!(h.net.addresses("ygg0").contains(&a));
}

#[tokio::test]
async fn failed_apply_keeps_addresses_off_interfaces() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.fw.set_failing(true);
    let app = h.app().await;
    // The grant is saved although the apply fails (and the address is created).
    let _ = h
        .engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::App(app.id),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await;
    h.reconcile().await;
    assert!(net_adds(&h).is_empty(), "nothing would deny the address");
    assert_eq!(h.app().await.addresses.len(), 1, "but it is recorded");

    h.fw.set_failing(false);
    h.reconcile().await;
    assert_eq!(net_adds(&h).len(), 1);
}

#[tokio::test]
async fn missing_address_is_re_added() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let a = h.addr_on("ygg").await;
    h.net.drop_address("ygg0", a);
    h.reconcile().await;
    assert!(
        h.net.addresses("ygg0").contains(&a),
        "closed address is restored"
    );
}

#[tokio::test]
async fn missing_interface_is_skipped_then_recovers() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let a = h.addr_on("ygg").await;

    // Yggdrasil is down: the tun is gone. Reconcile must not fail.
    h.net.set_interface_missing("ygg0", true);
    h.reconcile().await;
    assert!(h.net.addresses("ygg0").is_empty());

    h.net.set_interface_missing("ygg0", false);
    h.reconcile().await;
    assert!(h.net.addresses("ygg0").contains(&a));
}

#[tokio::test]
async fn prefix_change_rehomes_keeping_the_interface_id() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let old = h.addr_on("ygg").await;
    assert_eq!(old, "300:1:2:3::1".parse::<Ipv6Addr>().unwrap());

    h.nets["ygg"].set_prefix("300:9:9:9::");
    h.reconcile().await;

    let new = h.addr_on("ygg").await;
    assert_eq!(new, "300:9:9:9::1".parse::<Ipv6Addr>().unwrap());
    assert!(h.net.addresses("ygg0").contains(&new));
    assert!(!h.net.addresses("ygg0").contains(&old));
    // The ruleset follows the address.
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].dst, IpAddr::V6(new));
    let ScopeMatch::Destinations(dsts) = &rs.scopes[0].matcher else {
        panic!("managed scope matches destinations");
    };
    assert_eq!(dsts, &vec![IpAddr::V6(new)]);
}

// ─── Networks ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn networks_report_kind_status_and_prefix() {
    let h = Harness::new(vec![local_net(), lan_net(), ygg_net()], vec![]).await;
    let nets = h.engine().await.networks();
    let by_id: HashMap<_, _> = nets.iter().map(|n| (n.id.as_str(), n)).collect();
    assert_eq!(by_id["local"].kind, socketguard_core::NetworkKind::Local);
    assert!(!by_id["local"].grants_apply);
    assert!(by_id["lan"].grants_apply && by_id["ygg"].grants_apply);
    assert_eq!(by_id["ygg"].interface.as_deref(), Some("ygg0"));
    assert_eq!(by_id["ygg"].prefix, Some("300:1:2:3::".parse().unwrap()));
    assert_eq!(by_id["local"].prefix, None);
    assert!(nets.iter().all(|n| n.status == NetworkStatus::Up));
}

#[tokio::test]
async fn adding_and_removing_a_network() {
    let h = Harness::new(
        vec![local_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    // A grant on every network names the row on a network that is added later too.
    h.open().await;
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 1);

    let inst = BackendInstanceConfig {
        id: "ygg".into(),
        backend: BackendConfig::Yggdrasil {
            interface: "ygg0".into(),
            admin_endpoint: None,
        },
    };
    // The new network brings its own allocator (a mock stands in for yggdrasilctl).
    {
        let mut engine = h.state.engine.write().await;
        let mock = ygg_net().mock;
        add_ip_network(&mut engine, &h.state, &inst, Box::new(mock)).await;
    }
    let app = h.app().await;
    assert_eq!(app.addresses.len(), 2);
    let ygg_addr = h.addr_on("ygg").await;
    assert!(h.net.addresses("ygg0").contains(&ygg_addr));
    assert!(h
        .last_ruleset()
        .scopes
        .iter()
        .any(|s| s.id == "overlay:ygg0"));

    // A grant tied to that network goes with it.
    h.engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::App(app.id.clone()),
                scope: Scope::All,
                network_id: Some("ygg".into()),
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await
        .unwrap();
    {
        let mut engine = h.state.engine.write().await;
        engine.remove_backend_instance(&h.state, "ygg").await;
    }
    assert!(h.net.addresses("ygg0").is_empty());
    assert_eq!(h.app().await.addresses.len(), 1);
    assert_eq!(
        h.state.db.list_grants().await.unwrap().len(),
        1,
        "only the grant on every network is left"
    );
    assert!(!h
        .last_ruleset()
        .scopes
        .iter()
        .any(|s| s.id == "overlay:ygg0"));
}

// ─── Persistence and whole-host protection ───────────────────────────────────

#[tokio::test]
async fn ula_global_id_survives_restart() {
    let path = std::env::temp_dir().join(format!("sg-ula-{}.db", uuid::Uuid::new_v4()));
    let path_str = path.to_str().unwrap();
    let first = {
        let db = socketguard_daemon::state::Database::new(path_str)
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let id = db.ula_global_id().await.unwrap();
        let b = UlaBackend::new(id);
        (id, b.allocate(None).unwrap().address.octets())
    };

    // "Restart": reopen the same DB and rebuild the backend.
    let db = socketguard_daemon::state::Database::new(path_str)
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let id = db.ula_global_id().await.unwrap();
    assert_eq!(id, first.0);
    let b = UlaBackend::new(id);
    assert_eq!(
        b.allocate(None).unwrap().address.octets()[..6],
        first.1[..6]
    );

    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn protect_host_is_refused_when_it_would_lock_out_sshd() {
    let h = Harness::new(vec![lan_net()], vec![listener("sshd", 22, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.clear_calls();

    // sshd has no grant: refused, nothing stored, nothing applied.
    let err = h
        .engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], false)
        .await
        .unwrap_err();
    assert!(matches!(&err, ProtectHostError::Lockout(r) if r.len() == 1 && r[0].port == 22));
    assert!(h
        .state
        .db
        .get_setting("protect_host_interfaces")
        .await
        .unwrap()
        .is_none());
    assert!(h.fw_calls.lock().unwrap().is_empty());

    // Force overrides, reports the risk, stores the setting and applies the scope.
    let risks = h
        .engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], true)
        .await
        .unwrap();
    assert_eq!(risks.len(), 1);
    assert_eq!(
        h.state
            .db
            .get_setting("protect_host_interfaces")
            .await
            .unwrap()
            .as_deref(),
        Some(r#"["eth0"]"#)
    );
    assert!(h.last_ruleset().scopes.iter().any(|s| s.id == "host:eth0"));
    assert_eq!(
        h.engine()
            .await
            .settings(&h.state)
            .await
            .unwrap()
            .protect_host_interfaces,
        ["eth0"]
    );
    assert_eq!(h.activity(ActivityKind::ProtectHostChanged).await.len(), 1);

    // An empty list switches it off again, without any check.
    h.engine()
        .await
        .set_protect_host(&h.state, vec![], false)
        .await
        .unwrap();
    assert!(!h.last_ruleset().scopes.iter().any(|s| s.id == "host:eth0"));
}

#[tokio::test]
async fn protect_host_is_allowed_once_sshd_is_granted() {
    let h = Harness::new(vec![lan_net()], vec![listener("sshd", 22, Protocol::Tcp)]).await;
    h.reconcile().await;
    let app = h.app().await;

    // A peer that is not identified on a LAN (a key) does not clear the risk ...
    let key_peer = h.peer("k", CredentialKind::YggKey, KEY).await;
    h.grant(&app.id, Subject::Peer(key_peer)).await;
    let r = h
        .engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], false)
        .await;
    assert!(matches!(r, Err(ProtectHostError::Lockout(_))));

    // ... an IP-identified peer does.
    let admin = h.peer("admin", CredentialKind::Ip, "fd00:5a::2").await;
    h.grant(&app.id, Subject::Peer(admin)).await;
    let risks = h
        .engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], false)
        .await
        .unwrap();
    assert!(risks.is_empty());
}

#[tokio::test]
async fn protect_host_is_allowed_by_a_grant_to_anyone() {
    let h = Harness::new(vec![lan_net()], vec![listener("sshd", 22, Protocol::Tcp)]).await;
    h.reconcile().await;
    let app = h.app().await;
    h.grant(&app.id, Subject::Anyone).await;
    assert!(h
        .engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], false)
        .await
        .is_ok());
}

// ─── Local on a real interface (ADR 0027) ────────────────────────────────────

#[tokio::test]
async fn local_on_a_non_loopback_interface_takes_grants_like_a_lan() {
    let dummy = Net {
        id: "local",
        config: BackendConfig::Ula {
            interface: "dummy0".into(),
        },
        mock: {
            let m = MockIpv6Backend::new("fd00:1:2:3::", 128, "dummy0");
            m.set_prefix("fd00:1:2:3::");
            m
        },
    };
    let h = Harness::new(vec![dummy], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    let app = h.app().await;
    let net = h.engine().await.networks().remove(0);
    assert!(net.grants_apply, "{net:?}");

    let peer = h.peer("laptop", CredentialKind::Ip, "fd00::5").await;
    let view = h.grant(&app.id, Subject::Peer(peer)).await;
    assert_eq!(view.reach.len(), 1);
    assert_eq!(view.reach[0].reach, Reach::IpOnly);
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].iif.as_deref(), Some("dummy0"));
    assert_eq!(
        rs.rules[0].sources,
        Sources::Nets(vec!["fd00::5/128".parse().unwrap()])
    );

    // A grant naming the network is accepted, too.
    let e = h
        .engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::App(app.id.clone()),
                scope: Scope::All,
                network_id: Some("local".into()),
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await;
    assert!(e.is_ok(), "{e:?}");
}

// ─── Remote administration inside a protected scope ──────────────────────────

#[tokio::test]
async fn remote_admin_inside_a_protected_scope_is_reported_once() {
    let h = Harness::new(
        vec![lan_net(), ygg_net()],
        vec![listener("sshd", 22, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let sshd = h.app().await;

    // sshd listens on a wildcard, the Yggdrasil overlay is protected, no grant reaches it.
    let exposed = h.activity(ActivityKind::RemoteAdminExposed).await;
    assert_eq!(exposed.len(), 1, "{exposed:?}");
    assert_eq!(exposed[0].app_id.as_deref(), Some(sshd.id.as_str()));
    assert_eq!(exposed[0].network_id.as_deref(), Some("ygg"));
    assert_eq!(exposed[0].port, Some(22));

    // Passes that change nothing do not repeat it.
    h.reconcile().await;
    h.reconcile().await;
    assert_eq!(h.activity(ActivityKind::RemoteAdminExposed).await.len(), 1);

    // A protected host interface is a second scope, reported once more.
    h.engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], true)
        .await
        .unwrap();
    h.reconcile().await;
    h.reconcile().await;
    let exposed = h.activity(ActivityKind::RemoteAdminExposed).await;
    assert_eq!(exposed.len(), 2, "{exposed:?}");
    assert!(exposed
        .iter()
        .any(|r| r.network_id.as_deref() == Some("lan")));

    // Once a grant reaches sshd on both, the situation clears; losing it reports again.
    let peer = h.peer("admin", CredentialKind::YggKey, KEY).await;
    let ip_peer = h.peer("admin-lan", CredentialKind::Ip, "2001:db8::7").await;
    let g1 = h.grant(&sshd.id, Subject::Peer(peer)).await;
    h.grant(&sshd.id, Subject::Peer(ip_peer)).await;
    h.reconcile().await;
    assert_eq!(h.activity(ActivityKind::RemoteAdminExposed).await.len(), 2);
    h.engine()
        .await
        .delete_grant(&h.state, &g1.grant.id)
        .await
        .unwrap();
    h.reconcile().await;
    assert_eq!(
        h.activity(ActivityKind::RemoteAdminExposed).await.len(),
        3,
        "reported again after the grant was lost"
    );
}

#[tokio::test]
async fn ordinary_apps_in_a_protected_scope_are_not_remote_admin() {
    let h = Harness::new(
        vec![lan_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    assert!(h
        .activity(ActivityKind::RemoteAdminExposed)
        .await
        .is_empty());
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_export_gauges_and_firewall_counters_without_source_addresses() {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();

    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.engine()
        .await
        .register_metrics(&provider.meter("socketguard-test"));
    h.reconcile().await;
    let app = h.app().await;
    let peer = h.peer("alice", CredentialKind::YggKey, KEY).await;
    h.grant(&app.id, Subject::Peer(peer)).await;

    // The firewall reports counters for the rule of the grant and for a scope.
    let rs = h.last_ruleset();
    h.fw.set_counters(vec![
        socketguard_daemon::firewall::Counter {
            id: rs.rules[0].id.clone(),
            packets: 7,
            bytes: 700,
        },
        socketguard_daemon::firewall::Counter {
            id: "overlay:ygg0".into(),
            packets: 3,
            bytes: 300,
        },
        socketguard_daemon::firewall::Counter {
            id: "not-in-the-ruleset".into(),
            packets: 1,
            bytes: 1,
        },
    ]);
    h.reconcile().await;
    provider.force_flush().unwrap();

    type Points = Vec<(Vec<(String, String)>, u64)>;
    let finished = exporter.get_finished_metrics().unwrap();
    let last = finished.last().expect("a collection");
    let mut seen: HashMap<String, Points> = HashMap::new();
    for scope in last.scope_metrics() {
        for m in scope.metrics() {
            let points: Points = match m.data() {
                AggregatedMetrics::U64(MetricData::Gauge(g)) => {
                    g.data_points().map(|p| (Vec::new(), p.value())).collect()
                }
                AggregatedMetrics::U64(MetricData::Sum(s)) => s
                    .data_points()
                    .map(|p| {
                        let mut a: Vec<_> = p
                            .attributes()
                            .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                            .collect();
                        a.sort();
                        (a, p.value())
                    })
                    .collect(),
                _ => continue,
            };
            seen.insert(m.name().to_string(), points);
        }
    }
    assert_eq!(seen["socketguard.apps"][0].1, 1);
    assert_eq!(seen["socketguard.addresses"][0].1, 2);
    assert_eq!(seen["socketguard.peers"][0].1, 1);
    assert_eq!(seen["socketguard.grants"][0].1, 1);

    let attrs = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut v: Vec<_> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        v.sort();
        v
    };
    let mut packets = seen["socketguard.firewall.packets"].clone();
    packets.sort();
    let mut want = vec![
        (
            attrs(&[("app", "nginx"), ("network", "ygg"), ("subject", "alice")]),
            7,
        ),
        (attrs(&[("scope", "overlay:ygg0")]), 3),
    ];
    want.sort();
    assert_eq!(packets, want);
    assert_eq!(
        seen["socketguard.firewall.bytes"]
            .iter()
            .map(|(_, v)| *v)
            .sum::<u64>(),
        1000
    );
    // Bounded cardinality: only app, network, subject and scope ever appear as attributes.
    for points in seen.values() {
        for (a, _) in points {
            assert!(a
                .iter()
                .all(|(k, _)| ["app", "network", "subject", "scope"].contains(&k.as_str())));
        }
    }

    // The same totals are on the app detail.
    let detail = h.engine().await.get_app(&h.state, &app.id).await.unwrap();
    assert_eq!(detail.counters.len(), 1);
    assert_eq!(
        (detail.counters[0].packets, detail.counters[0].bytes),
        (7, 700)
    );
}

#[tokio::test]
async fn a_network_that_cannot_initialise_is_down_not_fatal() {
    // SLAAC on an interface with no usable prefix; the daemon must still start.
    let cfg = DaemonConfig {
        backends: vec![BackendInstanceConfig {
            id: "lan".into(),
            backend: BackendConfig::Slaac {
                interface: "eth0".into(),
                prefix: None,
            },
        }],
        ..DaemonConfig::default()
    };
    let net = MockInterfaceManager::new(Default::default());
    let fw = Arc::new(MockFirewall::new(Default::default()));
    let monitor = MockSocketMonitor::new(vec![listener("nginx", 80, Protocol::Tcp)]);
    let engine = Engine::new_with_deps(
        &cfg,
        [1, 2, 3, 4, 5],
        Box::new(monitor),
        fw,
        Arc::new(net.clone()),
    )
    .expect("a missing prefix is not a startup error");
    let state = test_app_state(engine, cfg).await;

    let status = || async {
        let nets = state.engine.read().await.networks();
        nets.into_iter().next().unwrap().status
    };
    state.engine.write().await.reconcile(&state).await.unwrap();
    // A grant names the row, so the app wants an address there.
    let app_id = state.db.list_apps().await.unwrap()[0].id.clone();
    state
        .engine
        .read()
        .await
        .create_grant(
            &state,
            &NewGrant {
                target: Target::App(app_id),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await
        .unwrap();
    state.engine.write().await.reconcile(&state).await.unwrap();
    match status().await {
        NetworkStatus::Down { reason } => assert!(reason.contains("no global or unique-local")),
        s => panic!("expected down, got {s:?}"),
    }
    assert!(state.db.list_addresses().await.unwrap().is_empty());

    // The router advertises a prefix; the next reconcile recovers (discovery cache is
    // not cleared by failures).
    net.add_address("eth0", "fd3e:1eec:520:582e::1".parse().unwrap(), 64)
        .unwrap();
    state.engine.write().await.reconcile(&state).await.unwrap();
    assert_eq!(status().await, NetworkStatus::Up);
    let addr = state.db.list_addresses().await.unwrap()[0]
        .locator
        .ipv6()
        .unwrap();
    assert!(socketguard_daemon::networks::ip::same_prefix64(
        addr,
        "fd3e:1eec:520:582e::".parse().unwrap()
    ));
}

// ─── Address lifecycle: owned addresses are denied until really gone ─────────

/// Whether the managed scope of the last applied ruleset denies `addr`.
fn denied(h: &Harness, addr: Ipv6Addr) -> bool {
    h.last_ruleset()
        .scopes
        .iter()
        .any(|s| matches!(&s.matcher, ScopeMatch::Destinations(d) if d.contains(&IpAddr::V6(addr))))
}

#[tokio::test]
async fn failed_removal_keeps_the_address_denied_and_is_retried() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let app = h.app().await;
    let a = h.addr_on("ygg").await;
    assert!(h.net.addresses("ygg0").contains(&a));
    assert!(denied(&h, a));

    h.set_sockets(vec![]);
    h.net.set_remove_failing(true);
    h.engine()
        .await
        .delete_app(&h.state, &app.id)
        .await
        .unwrap();
    // The app and its row are gone, but the address is still on the interface...
    assert!(h.apps().await.is_empty());
    assert!(h.net.addresses("ygg0").contains(&a));
    let owned = h.state.db.list_owned_addresses().await.unwrap();
    assert_eq!(owned.len(), 1);
    assert!(owned[0].retiring);
    // ...and still denied.
    assert!(denied(&h, a));

    h.reconcile().await;
    assert!(h.net.addresses("ygg0").contains(&a));
    assert!(
        denied(&h, a),
        "still denied while the removal keeps failing"
    );

    h.net.set_remove_failing(false);
    h.reconcile().await;
    assert!(!h.net.addresses("ygg0").contains(&a));
    assert!(h.state.db.list_owned_addresses().await.unwrap().is_empty());
    h.reconcile().await;
    assert!(!denied(&h, a), "the scope drops it once it is gone");
}

#[tokio::test]
async fn crash_leftover_retiring_address_is_removed_at_startup() {
    let h = Harness::new(vec![ygg_net()], vec![]).await;
    // The previous run marked the address retiring and died before removing it.
    let ghost: Ipv6Addr = "300:1:2:3::dead".parse().unwrap();
    h.net.plant_address("ygg0", ghost);
    h.state
        .db
        .retire_address(ghost, "ygg0", Some("ygg"))
        .await
        .unwrap();

    h.engine().await.startup_reconcile(&h.state).await;

    let first = applied(&h.fw_calls).remove(0);
    assert!(
        first.scopes.iter().any(|s| matches!(
            &s.matcher,
            ScopeMatch::Destinations(d) if d.contains(&IpAddr::V6(ghost))
        )),
        "denied by the first ruleset, before it is removed"
    );
    assert!(!h.net.addresses("ygg0").contains(&ghost));
    assert!(h.state.db.list_owned_addresses().await.unwrap().is_empty());
}

#[tokio::test]
async fn orphaned_owned_address_is_swept() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    // An address we own that no app has any more (e.g. a crash between the DB update and
    // the removal).
    let orphan: Ipv6Addr = "300:1:2:3::beef".parse().unwrap();
    h.net.plant_address("ygg0", orphan);
    h.state
        .db
        .claim_address(orphan, "ygg0", Some("ygg"))
        .await
        .unwrap();
    let kept = h.addr_on("ygg").await;

    h.reconcile().await;
    assert!(!h.net.addresses("ygg0").contains(&orphan));
    assert!(
        h.net.addresses("ygg0").contains(&kept),
        "apps' addresses stay"
    );
    let owned = h.state.db.list_owned_addresses().await.unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].addr, kept);
    assert!(!owned[0].retiring);
}

#[tokio::test]
async fn address_outside_the_applied_ruleset_is_never_added() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let first = h.addr_on("ygg").await;

    // A second app appears, but the ruleset that would cover it cannot be applied.
    h.fw.set_failing(true);
    let mut sockets = vec![listener("nginx", 80, Protocol::Tcp)];
    sockets.push(listener("redis", 6379, Protocol::Tcp));
    h.set_sockets(sockets);
    h.reconcile().await;
    assert_eq!(h.apps().await.len(), 2);
    let redis = h
        .apps()
        .await
        .into_iter()
        .find(|a| a.name == "redis")
        .unwrap();
    let _ = h
        .engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::App(redis.id),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await;
    h.reconcile().await;
    assert_eq!(
        h.net.addresses("ygg0"),
        [first].into_iter().collect(),
        "only the covered address is on the interface"
    );
    assert_eq!(
        h.state.db.list_owned_addresses().await.unwrap().len(),
        1,
        "and nothing else was recorded as owned"
    );

    h.fw.set_failing(false);
    h.reconcile().await;
    assert_eq!(h.net.addresses("ygg0").len(), 2);
}

#[tokio::test]
async fn disable_removes_owned_addresses_and_keeps_rows_until_confirmed() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await;
    h.open().await;
    let a = h.addr_on("ygg").await;

    h.net.set_remove_failing(true);
    h.clear_calls();
    let err = h.engine().await.disable(&h.state).await.unwrap_err();
    assert!(err.to_string().contains(&a.to_string()), "{err}");
    assert!(h.net.addresses("ygg0").contains(&a));
    let owned = h.state.db.list_owned_addresses().await.unwrap();
    assert_eq!(owned.len(), 1);
    assert!(owned[0].retiring);
    // The address is still on its interface, so it stays denied: the rules stay.
    assert!(h.state.db.disabled().await, "the latch stays set");
    assert!(
        !h.fw_calls.lock().unwrap().contains(&FirewallCall::Disable),
        "rules must stay while an address does"
    );

    // The disabled daemon keeps retrying the removal, then removes the rules.
    h.net.set_remove_failing(false);
    h.reconcile().await;
    assert!(!h.net.addresses("ygg0").contains(&a));
    assert!(h.state.db.list_owned_addresses().await.unwrap().is_empty());
    assert_eq!(
        h.fw_calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == FirewallCall::Disable)
            .count(),
        1
    );
}

// ─── A fresh database next to an existing ruleset (second security review) ───

#[tokio::test]
async fn fresh_database_does_not_replace_an_existing_ruleset_until_enabled() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.fw.set_installed(true); // a ruleset from before the database was lost
    h.engine().await.startup_reconcile(&h.state).await;
    assert!(h.state.db.unadopted().await.unwrap());

    // Reconciles track apps but apply nothing and add no address.
    h.reconcile().await;
    h.engine().await.startup_reconcile(&h.state).await;
    assert!(
        h.fw_calls.lock().unwrap().is_empty(),
        "no Apply, no Disable"
    );
    assert!(net_adds(&h).is_empty());
    assert_eq!(h.apps().await.len(), 1);

    // `enable` adopts the new state: the ruleset is replaced and the latch cleared.
    h.open().await;
    h.engine().await.enable(&h.state).await.unwrap();
    assert!(!h.state.db.unadopted().await.unwrap());
    assert_eq!(applied(&h.fw_calls).len(), 1);
    assert_eq!(net_adds(&h).len(), 1);
    h.reconcile().await;
    assert_eq!(applied(&h.fw_calls).len(), 1, "and it stays adopted");
}

#[tokio::test]
async fn fresh_database_without_a_ruleset_applies_normally() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.engine().await.startup_reconcile(&h.state).await;
    assert!(!h.state.db.unadopted().await.unwrap());
    assert_eq!(applied(&h.fw_calls).len(), 1);
}

#[tokio::test]
async fn existing_database_keeps_the_ruleset_flow_after_restart() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.reconcile().await; // the first apply consumes the fresh-database mark
    h.engine().await.startup_reconcile(&h.state).await;
    assert!(!h.state.db.unadopted().await.unwrap());
}

#[tokio::test]
async fn disable_removes_an_unadopted_ruleset() {
    let h = Harness::new(vec![ygg_net()], vec![listener("nginx", 80, Protocol::Tcp)]).await;
    h.fw.set_installed(true);
    h.engine().await.startup_reconcile(&h.state).await;
    assert!(h.state.db.unadopted().await.unwrap());
    h.engine().await.disable(&h.state).await.unwrap();
    assert!(!h.state.db.unadopted().await.unwrap());
    assert!(h.fw_calls.lock().unwrap().contains(&FirewallCall::Disable));
}

// ─── App identity (ADR 0027 amendment) ───────────────────────────────────────

#[tokio::test]
async fn identity_is_per_user_and_never_shared_with_forgeries() {
    let mut other_user = listener("nginx", 8080, Protocol::Tcp);
    other_user.uid = Some("1001".into());
    let mut foreign = listener("nginx", 8081, Protocol::Tcp);
    foreign.foreign_mntns = true;
    let mut no_exe = listener("nginx", 8082, Protocol::Tcp);
    no_exe.exe_path = None;
    let mut inline = script("node", "/srv/trusted/app.js", 8083);
    inline.cmdline = Some(
        ["node", "--eval=1", "/srv/trusted/app.js"]
            .map(String::from)
            .to_vec(),
    );
    let h = Harness::new(
        vec![local_net()],
        vec![
            listener("nginx", 80, Protocol::Tcp),
            other_user,
            foreign,
            no_exe,
            script("node", "/srv/trusted/app.js", 3000),
            inline,
        ],
    )
    .await;
    h.reconcile().await;

    let apps = h.apps().await;
    assert_eq!(apps.len(), 6, "{apps:?}");
    let notes: Vec<_> = apps
        .iter()
        .filter_map(|a| a.identity_note.clone())
        .collect();
    assert!(notes.contains(&"foreign mount namespace".to_string()));
    assert!(notes.contains(&"no executable path".to_string()));
    assert!(notes.contains(&"inline code".to_string()));
    let trusted = apps
        .iter()
        .find(|a| a.interpreter_arg.as_deref() == Some("/srv/trusted/app.js"))
        .unwrap();
    assert_eq!(trusted.ports.len(), 1, "the inline process did not join it");
}

#[tokio::test]
async fn identical_requests_racing_create_one_grant_peer_and_group() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let e = h.engine().await;
    let s = &h.state;

    let (a, b) = tokio::join!(
        e.create_peer(s, "laptop", &[]),
        e.create_peer(s, "laptop", &[])
    );
    assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
    let loser = a.err().or(b.err()).unwrap();
    assert!(matches!(loser, EngineError::Conflict(_)), "{loser:?}");

    let (a, b) = tokio::join!(
        e.create_group(s, "family", &[]),
        e.create_group(s, "family", &[])
    );
    assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
    let loser = a.err().or(b.err()).unwrap();
    assert!(matches!(loser, EngineError::Conflict(_)), "{loser:?}");

    let req = NewGrant {
        target: Target::App(app.id.clone()),
        scope: Scope::All,
        network_id: None,
        subject: Subject::Anyone,
        confirm_open: true,
    };
    let (a, b) = tokio::join!(e.create_grant(s, &req), e.create_grant(s, &req));
    assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
    let loser = a.err().or(b.err()).unwrap();
    assert!(matches!(loser, EngineError::Conflict(_)), "{loser:?}");
    assert_eq!(s.db.list_grants().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_apply_still_records_the_change_and_announces_it() {
    let h = Harness::new(
        vec![local_net(), ygg_net()],
        vec![listener("nginx", 80, Protocol::Tcp)],
    )
    .await;
    h.reconcile().await;
    let app = h.app().await;
    let e = h.engine().await;
    let s = &h.state;
    let mut events = s.events.subscribe();
    h.fw.set_failing(true);

    let err = e
        .create_grant(
            s,
            &NewGrant {
                target: Target::App(app.id.clone()),
                scope: Scope::All,
                network_id: None,
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::Internal(_)), "{err:?}");
    assert_eq!(h.activity(ActivityKind::GrantAdded).await.len(), 1);
    let mut seen = Vec::new();
    while let Ok(ev) = events.try_recv() {
        seen.push(ev);
    }
    assert!(seen.contains(&DaemonEvent::GrantsChanged), "{seen:?}");
    assert!(seen.contains(&DaemonEvent::Activity), "{seen:?}");
}

#[tokio::test]
async fn groups_are_recorded_in_the_activity_log() {
    let h = Harness::new(vec![local_net()], vec![]).await;
    let e = h.engine().await;
    let s = &h.state;
    let peer = e.create_peer(s, "laptop", &[]).await.unwrap();
    let group = e.create_group(s, "family", &[]).await.unwrap();
    e.rename_group(s, &group.id, "household").await.unwrap();
    e.set_group_members(s, &group.id, std::slice::from_ref(&peer.id))
        .await
        .unwrap();
    e.delete_group(s, &group.id).await.unwrap();

    assert_eq!(h.activity(ActivityKind::GroupAdded).await.len(), 1);
    assert_eq!(h.activity(ActivityKind::GroupChanged).await.len(), 2);
    let removed = h.activity(ActivityKind::GroupRemoved).await;
    assert_eq!(removed.len(), 1);
    assert!(removed[0].message.contains("household"), "{removed:?}");
}

// ─── IPv4 and segments (ADR 0044) ────────────────────────────────────────────

fn socket_on(name: &str, port: u16, bind: &str) -> ListeningSocket {
    ListeningSocket {
        bind_address: bind.parse().unwrap(),
        ..listener(name, port, Protocol::Tcp)
    }
}

async fn reach_of(h: &Harness, grant_id: &str) -> Reach {
    let views = h
        .engine()
        .await
        .list_grants(&h.state, GrantFilter::default())
        .await
        .unwrap();
    let view = views.iter().find(|v| v.grant.id == grant_id).unwrap();
    assert_eq!(view.reach.len(), 1, "{view:?}");
    view.reach[0].reach
}

#[tokio::test]
async fn ipv4_peer_reach_follows_the_listener_and_protect_host() {
    use socketguard_core::AddrFamily;
    let h = Harness::new(vec![lan_net()], vec![socket_on("nginx", 80, "0.0.0.0")]).await;
    h.net.set_ipv4_subnets("eth0", &["192.168.1.0/24"]);
    h.reconcile().await;
    let app = h.app().await;
    assert_eq!(app.ports[0].family, AddrFamily::V4);
    let peer = h.peer("laptop", CredentialKind::Ip, "192.168.1.5").await;
    let gid = h.grant(&app.id, Subject::Peer(peer)).await.grant.id;

    // Nothing filters IPv4 yet: the peer's grant lets everyone in.
    assert_eq!(reach_of(&h, &gid).await, Reach::Unfiltered);
    assert!(h.last_ruleset().rules.iter().all(|r| r.dst != Dst::HostV4));

    h.engine()
        .await
        .set_protect_host(&h.state, vec!["eth0".into()], false)
        .await
        .unwrap();
    assert_eq!(reach_of(&h, &gid).await, Reach::IpOnly);
    let rs = h.last_ruleset();
    let v4: Vec<_> = rs.rules.iter().filter(|r| r.dst == Dst::HostV4).collect();
    assert_eq!(v4.len(), 1);
    assert_eq!(v4[0].ports.start, 80);
    assert_eq!(v4[0].iif.as_deref(), Some("eth0"));
    assert_eq!(
        v4[0].sources,
        Sources::Nets(vec!["192.168.1.5/32".parse().unwrap()])
    );

    // The service moves to IPv6 only: the IPv4 credential reaches nothing.
    h.set_sockets(vec![socket_on("nginx", 80, "fd00::1")]);
    h.reconcile().await;
    assert_eq!(h.app().await.ports[0].family, AddrFamily::V6);
    assert_eq!(reach_of(&h, &gid).await, Reach::NotReachable);
    assert!(h.last_ruleset().rules.iter().all(|r| r.dst != Dst::HostV4));
}

#[tokio::test]
async fn a_segment_grant_is_limited_to_the_networks_prefix() {
    let h = Harness::new(vec![lan_net()], vec![socket_on("nginx", 80, "::")]).await;
    h.reconcile().await;
    let app = h.app().await;
    let view = h
        .engine()
        .await
        .create_grant(
            &h.state,
            &NewGrant {
                target: Target::App(app.id.clone()),
                scope: Scope::All,
                network_id: Some("lan".into()),
                subject: Subject::Anyone,
                confirm_open: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(view.reach[0].reach, Reach::Open);
    let rs = h.last_ruleset();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(
        rs.rules[0].sources,
        Sources::Nets(vec![
            "fe80::/10".parse().unwrap(),
            "2001:db8:1:2::/64".parse().unwrap()
        ])
    );
}

#[tokio::test]
async fn vlan_interfaces_report_their_id() {
    let vlan = Net {
        id: "mgmt",
        config: BackendConfig::Slaac {
            interface: "eth0.20".into(),
            prefix: None,
        },
        mock: {
            let m = MockIpv6Backend::new("2001:db8:20::", 128, "eth0.20");
            m.set_prefix("2001:db8:20::");
            m
        },
    };
    let h = Harness::new(vec![vlan], vec![]).await;
    h.net.set_vlan("eth0.20", 20);
    let nets = h.engine().await.networks_described();
    assert_eq!(nets[0].vlan_id, Some(20));
    assert_eq!(h.engine().await.networks()[0].vlan_id, None);
}
