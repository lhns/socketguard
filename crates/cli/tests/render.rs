//! Snapshots of the human output (review with `cargo insta review`).

use chrono::{DateTime, Utc};
use socketguard_cli::commands::find_grants;
use socketguard_cli::document::{parse as parse_document, text as document_text};
use socketguard_cli::render::{self, Names};
use socketguard_core::api_types::*;
use socketguard_core::*;
use std::path::Path;

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn tcp(port: u16) -> PortRef {
    PortRef {
        port,
        proto: Protocol::Tcp,
    }
}

fn address(id: &str, net: &str, addr: &str, scope: Scope) -> Address {
    Address {
        id: id.into(),
        app_id: Some("5c0d1f2a99887766".into()),
        network_id: net.into(),
        scope,
        reservation_id: None,
        up: net == "ygg",
        excluded: vec![],
        notes: vec![],
        locator: Locator::Ipv6 {
            addr: addr.parse().unwrap(),
        },
        created_at: t("2026-11-09T12:00:00Z"),
    }
}

fn nginx() -> App {
    App {
        id: "5c0d1f2a99887766".into(),
        name: "nginx".into(),
        process_name: "nginx".into(),
        exe_path: Some("/usr/sbin/nginx".into()),
        interpreter_arg: None,
        identity_note: None,
        exe_missing: false,
        system: false,
        first_seen: t("2026-11-01T08:00:00Z"),
        last_seen: t("2026-11-09T12:30:00Z"),
        ports: vec![
            AppPort {
                port: 80,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: t("2026-11-09T12:30:00Z"),
                family: Default::default(),
            },
            AppPort {
                port: 443,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: t("2026-11-09T12:30:00Z"),
                family: Default::default(),
            },
            AppPort {
                port: 8125,
                proto: Protocol::Udp,
                listening: false,
                last_seen: t("2026-11-08T12:30:00Z"),
                family: Default::default(),
            },
        ],
        addresses: vec![
            address("a1b2c3d4e5f6", "ygg", "300:1:2:3::1", Scope::port(tcp(443))),
            address("b2c3d4e5f6a1", "ygg", "300:1:2:3::2", Scope::All),
            address("c3d4e5f6a1b2", "lan", "2001:db8:1:2::5", Scope::All),
        ],
    }
}

fn redis() -> App {
    App {
        id: "9e8d7c6b00112233".into(),
        name: "redis-server".into(),
        process_name: "redis-server".into(),
        exe_path: None,
        interpreter_arg: None,
        identity_note: None,
        exe_missing: false,
        system: false,
        first_seen: t("2026-11-09T09:00:00Z"),
        last_seen: t("2026-11-09T12:30:00Z"),
        ports: vec![AppPort {
            port: 6379,
            proto: Protocol::Tcp,
            listening: true,
            last_seen: t("2026-11-09T12:30:00Z"),
            family: Default::default(),
        }],
        addresses: vec![],
    }
}

fn peer(id: &str, label: &str, groups: &[&str]) -> Peer {
    Peer {
        id: id.into(),
        label: label.into(),
        credentials: vec![Credential {
            id: format!("cred{id}"),
            kind: CredentialKind::YggKey,
            value: "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b".into(),
            label: Some("laptop".into()),
        }],
        groups: groups.iter().map(|g| g.to_string()).collect(),
        created_at: t("2026-11-02T10:00:00Z"),
    }
}

fn names() -> Names {
    Names::new(
        &[nginx(), redis()],
        &[peer("peer-alice-1", "alice", &["group-team-1"])],
        &[group()],
    )
}

fn group() -> PeerGroup {
    PeerGroup {
        id: "group-team-1".into(),
        label: "team".into(),
        members: vec!["peer-alice-1".into()],
        created_at: t("2026-11-02T10:00:00Z"),
    }
}

fn grant(
    id: &str,
    port: Option<u16>,
    net: Option<&str>,
    subject: Subject,
    reach: &[(&str, Reach)],
) -> GrantView {
    GrantView {
        grant: Grant {
            id: id.into(),
            target: Target::App("5c0d1f2a99887766".into()),
            scope: port.map_or(Scope::All, |p| Scope::port(tcp(p))),
            network_id: net.map(Into::into),
            subject,
            created_at: t("2026-11-05T10:00:00Z"),
        },
        reach: reach
            .iter()
            .map(|(n, r)| GrantReach {
                network_id: n.to_string(),
                reach: *r,
                note: None,
            })
            .collect(),
    }
}

fn grants() -> Vec<GrantView> {
    vec![
        grant(
            "g1111111aaaa",
            Some(80),
            Some("ygg"),
            Subject::Peer("peer-alice-1".into()),
            &[("ygg", Reach::Verified)],
        ),
        grant(
            "g2222222bbbb",
            None,
            None,
            Subject::Group("group-team-1".into()),
            &[("ygg", Reach::WholeSubnet), ("lan", Reach::IpOnly)],
        ),
        grant(
            "g3333333cccc",
            Some(443),
            None,
            Subject::Anyone,
            &[("ygg", Reach::Open), ("local", Reach::NotReachable)],
        ),
    ]
}

fn networks() -> Vec<Network> {
    vec![
        Network {
            id: "local".into(),
            kind: NetworkKind::Local,
            name: "Local".into(),
            interface: Some("lo".into()),
            grants_apply: false,
            status: NetworkStatus::Up,
            prefix: None,
            vlan_id: None,
            managed: None,
        },
        Network {
            id: "ygg".into(),
            kind: NetworkKind::Yggdrasil,
            name: "Yggdrasil".into(),
            interface: Some("ygg0".into()),
            grants_apply: true,
            status: NetworkStatus::Up,
            prefix: None,
            vlan_id: None,
            managed: None,
        },
        Network {
            id: "lan".into(),
            kind: NetworkKind::Lan,
            name: "LAN".into(),
            interface: Some("eth0".into()),
            grants_apply: true,
            status: NetworkStatus::Down {
                reason: "no prefix".into(),
            },
            prefix: None,
            vlan_id: None,
            managed: None,
        },
    ]
}

#[test]
fn status() {
    let mut s = StatusResponse {
        version: "0.1.0".into(),
        networks: networks(),
        protect_host_interfaces: vec!["eth0".into()],
        disabled: false,
        unadopted: false,
        counts: Counts {
            apps: 2,
            addresses: 3,
            peers: 1,
            groups: 1,
            grants: 3,
        },
        config_path: None,
        db_path: None,
        socket: None,
        service_installed: None,
        bundled: Default::default(),
    };
    insta::assert_snapshot!("status", render::status(&s));
    s.disabled = true;
    s.protect_host_interfaces.clear();
    s.networks.clear();
    insta::assert_snapshot!("status_disabled", render::status(&s));
    s.disabled = false;
    s.unadopted = true;
    insta::assert_snapshot!("status_unadopted", render::status(&s));
    s.unadopted = false;
    s.config_path = Some("/etc/socketguard/socketguard.json".into());
    s.db_path = Some("/var/lib/socketguard/socketguard.db".into());
    s.socket = Some("/run/socketguard/socketguard.sock".into());
    s.service_installed = Some(false);
    insta::assert_snapshot!("status_host", render::status(&s));
    s.config_path = None;
    s.service_installed = None;
    assert!(!render::status(&s).contains("config"));
    assert!(!render::status(&s).contains("service"));
    // What the build ships, or that it ships nothing.
    assert!(render::status(&s).contains("bundled       none (managed networks not included"));
    s.bundled = socketguard_core::setup::BundledInfo {
        dir: Some("/opt/socketguard/third_party".into()),
        versions: socketguard_core::setup::BundledInfo::parse_versions(
            "tor 16.0.1\nyggdrasil v0.5.15 abc\n",
        ),
    };
    assert!(render::status(&s).contains("bundled       tor 16.0.1, yggdrasil v0.5.15"));
}

#[test]
fn managed_networks_in_the_table() {
    use socketguard_core::{ChildState, ManagedInfo};
    let info = |state, progress, peers_connected, address: Option<&str>| ManagedInfo {
        state,
        progress,
        detail: None,
        runs_as: None,
        version: None,
        address: address.map(str::to_string),
        peers: vec![],
        peers_connected,
    };
    let net = |id: &str, kind, managed| Network {
        id: id.into(),
        kind,
        name: id.into(),
        interface: None,
        grants_apply: true,
        status: NetworkStatus::Up,
        prefix: None,
        vlan_id: None,
        managed,
    };
    let out = render::networks(&[
        net(
            "tor",
            NetworkKind::Tor,
            Some(info(ChildState::Bootstrapping, Some(40), None, None)),
        ),
        net(
            "yggdrasil",
            NetworkKind::Yggdrasil,
            Some(info(ChildState::Up, None, Some(2), Some("200:1::5"))),
        ),
        net("tor2", NetworkKind::Tor, None),
    ]);
    assert!(out.contains("tor (managed)"), "{out}");
    assert!(out.contains("bootstrapping 40%"), "{out}");
    assert!(out.contains("up  2 peers"), "{out}");
    assert!(out.contains("200:1::5"), "{out}");
    assert!(out.contains("tor (your own)"), "{out}");
    assert_eq!(
        render::network_peers("yggdrasil", &["tls://a.example:1".into()]),
        "peers of yggdrasil:\ntls://a.example:1"
    );
    assert_eq!(
        render::network_peers("yggdrasil", &[]),
        "yggdrasil has no peers"
    );
}

#[test]
fn network_setup_shows_both_forms() {
    use socketguard_core::setup::*;
    let kind = |available, reason: Option<&str>, state| KindSetup {
        managed: ManagedOffer {
            available,
            reason: reason.map(str::to_string),
            version: available.then(|| "16.0.1".to_string()),
        },
        existing: SetupState::new(state),
    };
    let s = NetworkSetup {
        lan: vec![],
        yggdrasil: kind(false, Some(NOT_INCLUDED), SetupStatus::Absent),
        tor: kind(true, None, SetupStatus::Ready),
        local: SetupState::new(SetupStatus::Ready),
        yggdrasil_block: None,
        config_path: None,
    };
    let out = render::network_setup(&s);
    assert!(
        out.contains("managed: not available (Not included in this build)"),
        "{out}"
    );
    assert!(out.contains("managed: available (version 16.0.1)"), "{out}");
    assert!(out.contains("your own: ready to add"), "{out}");
    assert!(out.contains("your own: none found"), "{out}");
}

#[test]
fn apps_table() {
    insta::assert_snapshot!(render::apps(&[nginx(), redis()]));
    assert_eq!(render::apps(&[]), "no apps");
}

#[test]
fn app_detail() {
    let d = AppDetail {
        app: nginx(),
        grants: grants(),
        counters: vec![AppCounter {
            network_id: "ygg".into(),
            subject: "alice".into(),
            packets: 1234,
            bytes: 567890,
        }],
        access: vec![],
        tags: vec![],
        port_groups: vec![],
    };
    insta::assert_snapshot!(render::app_detail(&d, &names()));
}

#[test]
fn closed_app_detail() {
    let d = AppDetail {
        app: redis(),
        grants: vec![],
        counters: vec![],
        access: vec![],
        tags: vec![],
        port_groups: vec![],
    };
    insta::assert_snapshot!(render::app_detail(&d, &names()));
}

#[test]
fn grants_table() {
    insta::assert_snapshot!(render::grants(&grants(), &names(), true));
}

#[test]
fn peers_and_groups() {
    let p = peer("peer-alice-1", "alice", &["group-team-1"]);
    let n = names();
    insta::assert_snapshot!("peers", render::peers(std::slice::from_ref(&p), &n));
    insta::assert_snapshot!("peer_detail", render::peer_detail(&p, &n, &grants()[..2]));
    insta::assert_snapshot!("groups", render::groups(&[group()], &n));
}

#[test]
fn networks_table() {
    insta::assert_snapshot!(render::networks(&networks()));
}

#[test]
fn activity_lines() {
    let rec = |id, kind, port, src: Option<&str>, count, msg: &str| ActivityRecord {
        id,
        at: t("2026-11-09T12:00:01Z"),
        kind,
        app_id: Some("5c0d1f2a99887766".into()),
        peer_id: None,
        network_id: Some("ygg".into()),
        src: src.map(|s| s.parse().unwrap()),
        port,
        proto: port.map(|_| Protocol::Tcp),
        count,
        message: msg.into(),
    };
    let records = vec![
        rec(
            1,
            ActivityKind::AppDiscovered,
            None,
            None,
            1,
            "New app nginx is listening",
        ),
        rec(
            2,
            ActivityKind::Blocked,
            Some(80),
            Some("300:9::1"),
            3,
            "blocked",
        ),
    ];
    insta::assert_snapshot!(render::activity(&records, &names()));
    insta::assert_snapshot!(
        "events",
        [
            render::event_line(
                t("2026-11-09T12:00:02Z"),
                &socketguard_client::ApiEvent::GrantsChanged
            ),
            render::event_line(
                t("2026-11-09T12:00:03Z"),
                &socketguard_client::ApiEvent::AppDiscovered("9e8d7c6b".into())
            ),
        ]
        .join("\n")
    );
}

#[test]
fn share_connection_strings() {
    let lines = render::share_lines(&nginx(), Some("ygg"));
    insta::assert_snapshot!(lines.join("\n"));
    // Addresses overlap: 443 has its own address and the other one serves it too.
    assert!(render::share_lines(&nginx(), Some("nope")).is_empty());
}

#[test]
fn share_onion_addresses() {
    let mut app = nginx();
    app.ports.push(AppPort {
        port: 8080,
        proto: Protocol::Tcp,
        listening: true,
        last_seen: t("2026-11-09T12:30:00Z"),
        family: Default::default(),
    });
    app.ports.push(AppPort {
        port: 22,
        proto: Protocol::Tcp,
        listening: true,
        last_seen: t("2026-11-09T12:30:00Z"),
        family: Default::default(),
    });
    let mut onion = address("d4e5f6a1b2c3", "tor", "::1", Scope::All);
    onion.locator = Locator::Onion {
        hostname: "abcdefghijklmnop.onion".into(),
    };
    onion.up = true;
    app.addresses = vec![onion];
    assert_eq!(
        render::share_lines(&app, Some("tor")),
        [
            "abcdefghijklmnop.onion:22",
            "http://abcdefghijklmnop.onion",
            "https://abcdefghijklmnop.onion",
            "http://abcdefghijklmnop.onion:8080",
        ]
    );
}

#[test]
fn tor_network_config_from_flags() {
    use socketguard_core::config::{BackendConfig, TorAuth};
    assert_eq!(
        socketguard_cli::commands::tor_config(None, None),
        BackendConfig::Tor {
            control: "127.0.0.1:9051".into(),
            auth: TorAuth::Cookie,
            cookie_path: None,
            cookie_dir: None,
            expect_tor_uid: None,
            cookie_owner: None,
            allow_remote_control: false,
            managed: false
        }
    );
    assert_eq!(
        socketguard_cli::commands::tor_config(Some("unix:/run/tor/c".into()), Some("pw".into())),
        BackendConfig::Tor {
            control: "unix:/run/tor/c".into(),
            auth: TorAuth::Password("pw".into()),
            cookie_path: None,
            cookie_dir: None,
            expect_tor_uid: None,
            cookie_owner: None,
            allow_remote_control: false,
            managed: false
        }
    );
}

#[test]
fn diff_and_risks() {
    let r = ApplyResponse {
        dry_run: true,
        changes: vec![
            Change {
                kind: ChangeKind::Create,
                item: ChangeItem::Peer,
                name: "carol".into(),
                detail: Some("1 credentials".into()),
                opens_to_anyone: false,
            },
            Change {
                kind: ChangeKind::Update,
                item: ChangeItem::Setting,
                name: "protect_host_interfaces".into(),
                detail: None,
                opens_to_anyone: false,
            },
            Change {
                kind: ChangeKind::Create,
                item: ChangeItem::Grant,
                name: "nginx 80/tcp on ygg to Anyone".into(),
                detail: None,
                opens_to_anyone: true,
            },
        ],
    };
    insta::assert_snapshot!("diff", render::changes(&r));
    assert_eq!(
        render::changes(&ApplyResponse {
            dry_run: false,
            changes: vec![]
        }),
        "no changes"
    );
    let risks = [LockoutRiskInfo {
        process_name: "sshd".into(),
        port: 22,
        protocol: Protocol::Tcp,
        bind_address: "::".into(),
        message: "sshd on :::22/tcp has no grant".into(),
    }];
    insta::assert_snapshot!("lockout", render::lockout_risks(&risks));
}

#[test]
fn finding_the_grant_to_revoke() {
    let g = grants();
    let alice = Subject::Peer("peer-alice-1".into());
    let found = find_grants(&g, "5c0d1f2a99887766", &Scope::port(tcp(80)), &alice, None);
    assert_eq!(found.len(), 1);
    assert!(find_grants(
        &g,
        "5c0d1f2a99887766",
        &Scope::port(tcp(80)),
        &alice,
        Some("lan")
    )
    .is_empty());
    assert_eq!(
        find_grants(
            &g,
            "5c0d1f2a99887766",
            &Scope::port(tcp(80)),
            &alice,
            Some("ygg")
        )
        .len(),
        1
    );
    assert!(find_grants(&g, "5c0d1f2a99887766", &Scope::All, &alice, None).is_empty());
    assert_eq!(
        find_grants(
            &g,
            "5c0d1f2a99887766",
            &Scope::port(tcp(443)),
            &Subject::Anyone,
            None
        )
        .len(),
        1
    );
}

#[test]
fn documents_round_trip_through_toml_and_json() {
    let doc = ExportDocument {
        version: EXPORT_VERSION,
        settings: Settings {
            protect_host_interfaces: vec!["eth0".into()],
        },
        peers: vec![ExportPeer {
            label: "alice".into(),
            credentials: vec![ExportCredential {
                kind: CredentialKind::YggKey,
                value: "ba83".into(),
                label: None,
            }],
        }],
        groups: vec![ExportGroup {
            label: "team".into(),
            members: vec!["alice".into()],
        }],
        port_groups: vec![],
        grants: vec![
            ExportGrant {
                app: ExportAppRef {
                    id: "5c0d".into(),
                    name: "nginx".into(),
                },
                scope: ExportScope::Port {
                    port: 80,
                    proto: Protocol::Tcp,
                },
                network: Some("ygg".into()),
                subject: ExportSubject::Peer("alice".into()),
            },
            ExportGrant {
                app: ExportAppRef {
                    id: "5c0d".into(),
                    name: "nginx".into(),
                },
                scope: ExportScope::All,
                network: None,
                subject: ExportSubject::Anyone,
            },
        ],
        reservations: vec![ExportReservation {
            label: "web".into(),
            bindings: vec![ExportBinding::App {
                app: ExportAppRef {
                    id: "5c0d".into(),
                    name: "nginx".into(),
                },
                scope: ExportScope::All,
            }],
            grants: vec![ExportReservationGrant {
                network: None,
                subject: ExportSubject::Peer("alice".into()),
            }],
        }],
    };
    let toml_text = document_text(&doc, false).unwrap();
    insta::assert_snapshot!("export_toml", toml_text);
    assert_eq!(
        parse_document(&toml_text, Path::new("a.toml")).unwrap(),
        doc
    );
    assert_eq!(parse_document(&toml_text, Path::new("noext")).unwrap(), doc);
    let json_text = document_text(&doc, true).unwrap();
    assert_eq!(
        parse_document(&json_text, Path::new("a.json")).unwrap(),
        doc
    );
    assert_eq!(parse_document(&json_text, Path::new("noext")).unwrap(), doc);
    assert!(parse_document("nonsense {", Path::new("x.json")).is_err());
}

fn web_reservation() -> ReservationView {
    let binding = |id: &str, app: &str, port: u16| Binding {
        id: id.into(),
        reservation_id: "r1111111aaaa".into(),
        target: BindingTarget::App {
            app_id: app.into(),
            scope: Scope::port(tcp(port)),
        },
    };
    let mut ygg = address("e5f6a1b2c3d4", "ygg", "300:1:2:3::9", Scope::All);
    ygg.app_id = None;
    ygg.reservation_id = Some("r1111111aaaa".into());
    ygg.excluded = vec!["6000-6010/tcp".parse().unwrap()];
    let mut tor = ygg.clone();
    tor.id = "f6a1b2c3d4e5".into();
    tor.network_id = "tor".into();
    tor.up = false;
    tor.excluded = vec![];
    tor.notes = vec!["port 80 is bound to two apps".into()];
    ReservationView {
        reservation: Reservation {
            id: "r1111111aaaa".into(),
            label: "web".into(),
            bindings: vec![
                binding("b1", "5c0d1f2a99887766", 80),
                binding("b2", "9e8d7c6b00112233", 80),
            ],
            created_at: t("2026-11-09T12:00:00Z"),
        },
        addresses: vec![ygg, tor],
        conflicts: vec![PortConflict {
            ports: "80/tcp".parse().unwrap(),
            bindings: vec!["b1".into(), "b2".into()],
            served_app: Some("5c0d1f2a99887766".into()),
        }],
        grants: vec![],
    }
}

#[test]
fn reservations_and_addresses() {
    let r = web_reservation();
    let n = names().with_reservations(std::slice::from_ref(&r));
    insta::assert_snapshot!(
        "reservations",
        render::reservations(std::slice::from_ref(&r), &n)
    );
    assert_eq!(render::reservations(&[], &n), "no reservations");
    insta::assert_snapshot!("addresses", render::addresses(&r.addresses, &n));
    assert!(render::addresses(&[], &n).contains("when a grant names it"));
}

#[test]
fn grant_notes_and_reservation_access_are_shown() {
    let mut g = grants();
    g[0].reach[0].note = Some("bound to reservation web: grant the reservation".into());
    let n = names().with_reservations(&[web_reservation()]);
    let text = render::grants(&g, &n, true);
    assert!(
        text.contains("note (g1111111 on ygg): bound to reservation web"),
        "{text}"
    );
    let mut d = AppDetail {
        app: nginx(),
        grants: vec![],
        counters: vec![],
        access: vec![EffectiveAccess {
            grant_id: "g9".into(),
            scope: Scope::All,
            ports: vec![],
            network_id: None,
            subject: Subject::Anyone,
            origin: AccessOrigin::Reservation {
                reservation_id: "r1111111aaaa".into(),
            },
        }],
        tags: vec![],
        port_groups: vec![],
    };
    d.app.addresses[0].reservation_id = Some("r1111111aaaa".into());
    let text = render::app_detail(&d, &n);
    assert!(
        text.contains("Through reservations") && text.contains("reservation web"),
        "{text}"
    );
    assert!(text.contains("up") && text.contains("closed"), "{text}");
}
