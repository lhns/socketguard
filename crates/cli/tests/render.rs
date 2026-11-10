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

fn address(id: &str, net: &str, addr: &str, ports: PortSet) -> Address {
    Address {
        id: id.into(),
        app_id: "5c0d1f2a99887766".into(),
        network_id: net.into(),
        ports,
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
        reviewed: true,
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
            address(
                "a1b2c3d4e5f6",
                "ygg",
                "300:1:2:3::1",
                PortSet::Only(vec![tcp(443)]),
            ),
            address("b2c3d4e5f6a1", "ygg", "300:1:2:3::2", PortSet::All),
            address("c3d4e5f6a1b2", "lan", "2001:db8:1:2::5", PortSet::All),
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
        reviewed: false,
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
            app_id: "5c0d1f2a99887766".into(),
            port: port.map(tcp),
            network_id: net.map(Into::into),
            subject,
            created_at: t("2026-11-05T10:00:00Z"),
        },
        reach: reach
            .iter()
            .map(|(n, r)| GrantReach {
                network_id: n.to_string(),
                reach: *r,
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
            pending_apps: 1,
            addresses: 3,
            peers: 1,
            groups: 1,
            grants: 3,
        },
    };
    insta::assert_snapshot!("status", render::status(&s));
    s.disabled = true;
    s.protect_host_interfaces.clear();
    s.networks.clear();
    insta::assert_snapshot!("status_disabled", render::status(&s));
    s.disabled = false;
    s.unadopted = true;
    insta::assert_snapshot!("status_unadopted", render::status(&s));
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
    };
    insta::assert_snapshot!(render::app_detail(&d, &names()));
}

#[test]
fn closed_app_detail() {
    let d = AppDetail {
        app: redis(),
        grants: vec![],
        counters: vec![],
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
    // 443 has its own address; the other address serves the remaining TCP port.
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
    let mut onion = address("d4e5f6a1b2c3", "tor", "::1", PortSet::All);
    onion.locator = Locator::Onion {
        hostname: "abcdefghijklmnop.onion".into(),
    };
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
            allow_remote_control: false
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
            allow_remote_control: false
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
                name: "address_mode".into(),
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
    let found = find_grants(&g, "5c0d1f2a99887766", Some(tcp(80)), &alice, None);
    assert_eq!(found.len(), 1);
    assert!(find_grants(&g, "5c0d1f2a99887766", Some(tcp(80)), &alice, Some("lan")).is_empty());
    assert_eq!(
        find_grants(&g, "5c0d1f2a99887766", Some(tcp(80)), &alice, Some("ygg")).len(),
        1
    );
    assert!(find_grants(&g, "5c0d1f2a99887766", None, &alice, None).is_empty());
    assert_eq!(
        find_grants(
            &g,
            "5c0d1f2a99887766",
            Some(tcp(443)),
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
            address_mode: AddressMode::PerPort,
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
        grants: vec![
            ExportGrant {
                app: ExportAppRef {
                    id: "5c0d".into(),
                    name: "nginx".into(),
                },
                port: Some(tcp(80)),
                network: Some("ygg".into()),
                subject: ExportSubject::Peer("alice".into()),
            },
            ExportGrant {
                app: ExportAppRef {
                    id: "5c0d".into(),
                    name: "nginx".into(),
                },
                port: None,
                network: None,
                subject: ExportSubject::Anyone,
            },
        ],
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
