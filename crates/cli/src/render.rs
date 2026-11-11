//! Human-readable output: pure functions from API types to strings, snapshot tested.
//! Nothing here talks to the daemon or the terminal.

use crate::resolve::short;
use chrono::{DateTime, Utc};
use comfy_table::{presets, Table};
use socketguard_core::api_types::{
    ApplyResponse, BatchChange, Change, ChangeItem, ChangeKind, ChangesResponse, LockoutRiskInfo,
    ShareResponse, StatusResponse, TorKeyResponse,
};
use socketguard_core::{
    ranges_text, AccessOrigin, ActivityRecord, Address, App, AppDetail, BindingTarget, Credential,
    GrantView, Locator, Network, NetworkKind, NetworkStatus, ParsedCredential, Peer, PeerGroup,
    PortGroup, Reach, ReservationView, Scope, Settings, Subject, Tag, Target,
};
use std::collections::HashMap;

/// Labels for ids, for output that mentions apps, peers and groups by id.
#[derive(Debug, Default, Clone)]
pub struct Names {
    pub apps: HashMap<String, String>,
    pub peers: HashMap<String, String>,
    pub groups: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    pub port_groups: HashMap<String, String>,
    pub reservations: HashMap<String, String>,
}

impl Names {
    pub fn new(apps: &[App], peers: &[Peer], groups: &[PeerGroup]) -> Self {
        Self {
            tags: HashMap::new(),
            port_groups: HashMap::new(),
            reservations: HashMap::new(),
            apps: apps
                .iter()
                .map(|a| (a.id.clone(), a.name.clone()))
                .collect(),
            peers: peers
                .iter()
                .map(|p| (p.id.clone(), p.label.clone()))
                .collect(),
            groups: groups
                .iter()
                .map(|g| (g.id.clone(), g.label.clone()))
                .collect(),
        }
    }

    /// The names of `tags` too.
    pub fn with_tags(mut self, tags: &[Tag]) -> Self {
        self.tags = tags
            .iter()
            .map(|t| (t.id.clone(), t.label.clone()))
            .collect();
        self
    }

    /// The names of `reservations` too.
    pub fn with_reservations(mut self, reservations: &[ReservationView]) -> Self {
        self.reservations = reservations
            .iter()
            .map(|r| (r.reservation.id.clone(), r.reservation.label.clone()))
            .collect();
        self
    }

    /// The names of `groups` (port groups) too.
    pub fn with_port_groups(mut self, groups: &[PortGroup]) -> Self {
        self.port_groups = groups
            .iter()
            .map(|g| (g.id.clone(), g.label.clone()))
            .collect();
        self
    }

    pub fn app(&self, id: &str) -> String {
        label(&self.apps, id)
    }

    /// A scope for people: `All ports`, `80/tcp`, `group <label>`.
    pub fn scope(&self, s: &Scope) -> String {
        match s {
            Scope::Group { id } => format!("group {}", label(&self.port_groups, id)),
            other => other.describe(&[]),
        }
    }

    pub fn tag(&self, id: &str) -> String {
        label(&self.tags, id)
    }

    pub fn reservation(&self, id: &str) -> String {
        label(&self.reservations, id)
    }

    /// What a grant covers: an app's name, `tag:<label>` or `reservation:<label>`.
    pub fn target(&self, t: &Target) -> String {
        match t {
            Target::App(id) => self.app(id),
            Target::Tag(id) => format!("tag:{}", self.tag(id)),
            Target::Reservation(id) => format!("reservation:{}", self.reservation(id)),
        }
    }

    /// An app row as typed in commands: `app`, `app:80/tcp`, `app:port-group=<label>`.
    pub fn row(&self, app_id: &str, scope: &Scope) -> String {
        match scope {
            Scope::All => self.app(app_id),
            Scope::Group { id } => format!(
                "{}:port-group={}",
                self.app(app_id),
                label(&self.port_groups, id)
            ),
            Scope::Port { port, proto } => format!("{}:{port}/{proto}", self.app(app_id)),
        }
    }

    /// A binding as typed in commands: a row, or `tag:<label>`.
    pub fn binding(&self, t: &BindingTarget) -> String {
        match t {
            BindingTarget::App { app_id, scope } => self.row(app_id, scope),
            BindingTarget::Tag { tag_id } => format!("tag:{}", self.tag(tag_id)),
        }
    }

    pub fn peer(&self, id: &str) -> String {
        label(&self.peers, id)
    }

    pub fn group(&self, id: &str) -> String {
        label(&self.groups, id)
    }

    /// Who a grant is for. Anyone scoped to a network is "everyone on <network>", a segment.
    pub fn grantee(&self, g: &socketguard_core::Grant) -> String {
        match (&g.subject, &g.network_id) {
            (Subject::Anyone, Some(n)) => format!("everyone on {n} (segment)"),
            (s, _) => self.subject(s),
        }
    }

    pub fn subject(&self, s: &Subject) -> String {
        match s {
            Subject::Peer(id) => self.peer(id),
            Subject::Group(id) => format!("group:{}", self.group(id)),
            Subject::Anyone => "anyone".to_string(),
        }
    }
}

/// The name of `id`, or its short form when it is not known.
fn label(names: &HashMap<String, String>, id: &str) -> String {
    names
        .get(id)
        .cloned()
        .unwrap_or_else(|| short(id).to_string())
}

// ─── Building blocks ─────────────────────────────────────────────────────────

/// A borderless table with two spaces between columns and no trailing blanks.
fn table(header: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut t = Table::new();
    t.load_preset(presets::NOTHING);
    t.set_header(header.iter().map(|h| h.to_string()));
    for r in rows {
        t.add_row(r);
    }
    for col in t.column_iter_mut() {
        col.set_padding((0, 2));
    }
    t.to_string()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn section(title: &str, body: String) -> String {
    format!("{title}\n{}", indent(&body))
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("  {l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The confirmation question for opening an app to Anyone (ADR 0027, 0044).
pub fn open_question(app: &str, network: Option<&str>) -> String {
    match network {
        Some(n) => format!("Open {app} to everyone on {n}?"),
        None => format!("Open {app} to anyone who can reach it?"),
    }
}

pub fn time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn reach_label(r: Reach) -> &'static str {
    match r {
        Reach::Verified => "verified",
        Reach::WholeSubnet => "whole subnet",
        Reach::IpOnly => "IP only",
        Reach::Open => "open",
        Reach::Unfiltered => "open to everyone over IPv4",
        Reach::NotReachable => "not reachable",
    }
}

fn kind_label(k: NetworkKind) -> &'static str {
    match k {
        NetworkKind::Local => "local",
        NetworkKind::Lan => "lan",
        NetworkKind::Yggdrasil => "yggdrasil",
        NetworkKind::WireGuard => "wireguard",
        NetworkKind::Tor => "tor",
    }
}

pub fn locator(l: &Locator) -> String {
    match l {
        Locator::Ipv6 { addr } => addr.to_string(),
        Locator::Onion { hostname } => hostname.clone(),
    }
}

fn app_ports(app: &App) -> String {
    let ports: Vec<String> = app
        .ports
        .iter()
        .map(|p| {
            let s = p.port_ref().to_string();
            if p.listening {
                s
            } else {
                format!("{s}*")
            }
        })
        .collect();
    if ports.is_empty() {
        "-".to_string()
    } else {
        ports.join(", ")
    }
}

/// Why a reach is what it is, one line per note, below a table of grants.
fn reach_notes(grants: &[GrantView]) -> Vec<String> {
    grants
        .iter()
        .flat_map(|g| {
            g.reach.iter().filter_map(move |r| {
                r.note
                    .as_ref()
                    .map(|n| format!("note ({} on {}): {n}", short(&g.grant.id), r.network_id))
            })
        })
        .collect()
}

fn reach_summary(g: &GrantView) -> String {
    if g.reach.is_empty() {
        return "-".to_string();
    }
    g.reach
        .iter()
        .map(|r| format!("{}: {}", r.network_id, reach_label(r.reach)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn grant_scope(g: &GrantView, names: &Names) -> (String, String) {
    (
        names.scope(&g.grant.scope),
        g.grant
            .network_id
            .clone()
            .unwrap_or_else(|| "all".to_string()),
    )
}

// ─── Status, networks, settings ──────────────────────────────────────────────

/// The interfaces under whole-host protection, or "off".
fn protect_host(interfaces: &[String]) -> String {
    if interfaces.is_empty() {
        "off".to_string()
    } else {
        interfaces.join(", ")
    }
}

/// Where the daemon keeps its state and whether it is a service, one line (with a leading
/// newline) each; what it did not report is left out.
fn host_lines(s: &StatusResponse) -> String {
    let service = s
        .service_installed
        .map(|i| if i { "installed" } else { "not installed" });
    [
        ("config", s.config_path.as_deref()),
        ("database", s.db_path.as_deref()),
        ("socket", s.socket.as_deref()),
        ("service", service),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|v| format!("\n{k:<13} {v}")))
    .collect()
}

pub fn status(s: &StatusResponse) -> String {
    let c = &s.counts;
    let protect = protect_host(&s.protect_host_interfaces);
    let enforcement = if s.disabled {
        "DISABLED (no rules, no addresses; `socketguard enable` to restore)"
    } else if s.unadopted {
        "UNADOPTED (an existing ruleset was found with an empty database and is left alone; \
         `socketguard enable` adopts the new state and replaces it, `socketguard disable` removes it)"
    } else {
        "on"
    };
    format!(
        "socketguard daemon {}\n\
         enforcement   {enforcement}\n\
         protect-host  {protect}\n\
         apps          {}, {} addresses\n\
         peers         {}, groups {}, grants {}{}\n\n{}",
        s.version,
        c.apps,
        c.addresses,
        c.peers,
        c.groups,
        c.grants,
        host_lines(s),
        section("Networks", networks(&s.networks)),
    )
}

/// `networks detect`: what each kind of network needs.
pub fn network_setup(s: &socketguard_core::setup::NetworkSetup) -> String {
    use socketguard_core::setup::{SetupState, SetupStatus};
    let state = |name: &str, st: &SetupState| {
        let label = match st.state {
            SetupStatus::Ready => "ready to add",
            SetupStatus::NotConfigured => "needs setup",
            SetupStatus::NotRunning => "not running",
            SetupStatus::NotInstalled => "not installed",
            SetupStatus::Added => "added",
        };
        let mut out = format!("{name}: {label}");
        if let Some(m) = &st.missing {
            out.push_str(&format!(" ({m})"));
        }
        for (k, v) in &st.found {
            out.push_str(&format!("\n  {k}: {v}"));
        }
        if let Some(i) = &st.install {
            out.push_str(&format!("\n  install: {}", i.command));
        }
        if let Some(l) = &st.download_link {
            out.push_str(&format!("\n  download: {l}"));
        }
        if let Some(w) = &st.warning {
            out.push_str(&format!("\n  warning: {w}"));
        }
        out
    };
    let mut out = String::from("LAN interfaces:");
    if s.lan.is_empty() {
        out.push_str(" none found");
    }
    for l in &s.lan {
        out.push_str(&format!(
            "\n  {}{}{}{}{}",
            l.interface,
            l.description
                .as_ref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default(),
            if l.is_default_route {
                ", default route"
            } else {
                ""
            },
            if l.has_ipv6_prefix {
                ""
            } else {
                ", no IPv6 prefix announced"
            },
            if l.already_added { ", added" } else { "" },
        ));
    }
    format!(
        "{out}\n\n{}\n\n{}\n\n{}",
        state("Yggdrasil", &s.yggdrasil),
        state("Tor", &s.tor),
        state("Local", &s.local)
    )
}

/// What stays reachable when a block goes (ADR 0051): one paragraph per network whose node
/// keeps running; empty when nothing does.
pub fn exposure(e: &socketguard_core::api_types::ExposureResponse) -> String {
    e.sentences().join("\n")
}

pub fn networks(nets: &[Network]) -> String {
    if nets.is_empty() {
        return "no networks".to_string();
    }
    table(
        &["ID", "KIND", "INTERFACE", "STATUS", "NOTE"],
        nets.iter()
            .map(|n| {
                let status = match &n.status {
                    NetworkStatus::Up => "up".to_string(),
                    NetworkStatus::Down { reason } => format!("down: {reason}"),
                };
                let note = if n.grants_apply {
                    String::new()
                } else {
                    "this machine only, grants do not apply".to_string()
                };
                vec![
                    n.id.clone(),
                    kind_label(n.kind).to_string(),
                    n.interface.clone().unwrap_or_else(|| "-".into()),
                    status,
                    note,
                ]
            })
            .collect(),
    )
}

pub fn settings(s: &Settings) -> String {
    format!(
        "protect-host   {}",
        protect_host(&s.protect_host_interfaces)
    )
}

// ─── Apps ────────────────────────────────────────────────────────────────────

pub fn apps(apps: &[App]) -> String {
    if apps.is_empty() {
        return "no apps".to_string();
    }
    let mut out = table(
        &["ID", "NAME", "PORTS", "KIND", "ADDRESSES"],
        apps.iter()
            .map(|a| {
                vec![
                    short(&a.id).to_string(),
                    a.name.clone(),
                    app_ports(a),
                    if a.system { "system" } else { "app" }.to_string(),
                    a.addresses.len().to_string(),
                ]
            })
            .collect(),
    );
    if apps.iter().any(|a| a.ports.iter().any(|p| !p.listening)) {
        out.push_str("\n\n* not listening now");
    }
    out
}

/// `up` when the address is on its interface (or published), else `closed`: nothing grants
/// the row it serves, or the network is down.
fn up_label(up: bool) -> &'static str {
    if up {
        "up"
    } else {
        "closed"
    }
}

/// What an address serves: its ports, or the reservation it belongs to.
fn address_serves(a: &Address, groups: &[PortGroup], names: &Names) -> String {
    match &a.reservation_id {
        Some(r) => format!("reservation {}", names.reservation(r)),
        None => a.scope.describe(groups),
    }
}

/// Lines under an address table: ports left out, and why a Tor service is not as expected.
fn address_notes(addrs: &[Address]) -> Vec<String> {
    let mut out = Vec::new();
    for a in addrs {
        if !a.excluded.is_empty() {
            out.push(format!(
                "{}: leaves out {} (another app listens there)",
                short(&a.id),
                ranges_text(&a.excluded)
            ));
        }
        for n in &a.notes {
            out.push(format!("{}: {n}", short(&a.id)));
        }
    }
    out
}

fn with_lines(mut body: String, lines: Vec<String>) -> String {
    if !lines.is_empty() {
        body.push_str("\n\n");
        body.push_str(&lines.join("\n"));
    }
    body
}

fn addresses_table(addrs: &[Address], groups: &[PortGroup], names: &Names) -> String {
    with_lines(
        table(
            &["ID", "NETWORK", "ADDRESS", "PORTS", "STATE"],
            addrs
                .iter()
                .map(|a| {
                    vec![
                        short(&a.id).to_string(),
                        a.network_id.clone(),
                        locator(&a.locator),
                        address_serves(a, groups, names),
                        up_label(a.up).to_string(),
                    ]
                })
                .collect(),
        ),
        address_notes(addrs),
    )
}

/// Every address of the host (`addresses list`): whose it is, what it serves, its state.
pub fn addresses(addrs: &[Address], names: &Names) -> String {
    if addrs.is_empty() {
        return "no addresses yet: an app row gets one when a grant names it".to_string();
    }
    with_lines(
        table(
            &["ID", "NETWORK", "ADDRESS", "OWNER", "PORTS", "STATE"],
            addrs
                .iter()
                .map(|a| {
                    let (owner, ports) = match (&a.reservation_id, &a.app_id) {
                        (Some(r), _) => (
                            format!("reservation {}", names.reservation(r)),
                            Scope::All.describe(&[]),
                        ),
                        (None, Some(app)) => (names.app(app), names.scope(&a.scope)),
                        (None, None) => ("-".to_string(), names.scope(&a.scope)),
                    };
                    vec![
                        short(&a.id).to_string(),
                        a.network_id.clone(),
                        locator(&a.locator),
                        owner,
                        ports,
                        up_label(a.up).to_string(),
                    ]
                })
                .collect(),
        ),
        address_notes(addrs),
    )
}

fn port_groups_table(groups: &[PortGroup]) -> String {
    table(
        &["ID", "LABEL", "PORTS", "APPS"],
        groups
            .iter()
            .map(|g| {
                vec![
                    short(&g.id).to_string(),
                    g.label.clone(),
                    socketguard_core::ranges_text(&g.ports),
                    g.apps.len().to_string(),
                ]
            })
            .collect(),
    )
}

/// The port groups as a table.
pub fn port_groups(groups: &[PortGroup], names: &Names) -> String {
    if groups.is_empty() {
        return "no port groups".to_string();
    }
    table(
        &["ID", "LABEL", "PORTS", "APPS"],
        groups
            .iter()
            .map(|g| {
                vec![
                    short(&g.id).to_string(),
                    g.label.clone(),
                    socketguard_core::ranges_text(&g.ports),
                    if g.apps.is_empty() {
                        "-".to_string()
                    } else {
                        g.apps
                            .iter()
                            .map(|a| names.app(a))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                ]
            })
            .collect(),
    )
}

pub fn grants(grants: &[GrantView], names: &Names, with_app: bool) -> String {
    if grants.is_empty() {
        return "no grants".to_string();
    }
    let mut header = vec!["ID"];
    if with_app {
        header.push("APP");
    }
    header.extend(["PORT", "NETWORK", "WHO", "REACH"]);
    let t = table(
        &header,
        grants
            .iter()
            .map(|g| {
                let (port, net) = grant_scope(g, names);
                let mut row = vec![short(&g.grant.id).to_string()];
                if with_app {
                    row.push(names.target(&g.grant.target));
                }
                row.extend([port, net, names.grantee(&g.grant), reach_summary(g)]);
                row
            })
            .collect(),
    );
    with_lines(t, reach_notes(grants))
}

/// Which kind of access `app_detail` lists in a section of its own.
#[derive(Clone, Copy)]
enum Origin {
    Tag,
    Reservation,
}

pub fn app_detail(d: &AppDetail, names: &Names) -> String {
    let app = &d.app;
    let mut head = format!("{}  ({})", app.name, app.id);
    if let Some(exe) = &app.exe_path {
        head.push_str(&format!("\n  executable  {exe}"));
    }
    if let Some(arg) = &app.interpreter_arg {
        head.push_str(&format!("\n  script      {arg}"));
    }
    if let Some(note) = &app.identity_note {
        head.push_str(&format!(
            "\n  identity    {note} (not shared with other apps)"
        ));
    }
    if app.system {
        head.push_str("\n  kind        system component");
    }
    if !d.tags.is_empty() {
        let labels: Vec<String> = d.tags.iter().map(|t| names.tag(t)).collect();
        head.push_str(&format!("\n  tags        {}", labels.join(", ")));
    }
    head.push_str(&format!(
        "\n  first seen  {}\n  last seen   {}",
        time(app.first_seen),
        time(app.last_seen)
    ));

    let ports = if app.ports.is_empty() {
        "none".to_string()
    } else {
        table(
            &["PORT", "LISTENING"],
            app.ports
                .iter()
                .map(|p| {
                    vec![
                        p.port_ref().to_string(),
                        if p.listening { "yes" } else { "no" }.to_string(),
                    ]
                })
                .collect(),
        )
    };
    let addrs = if app.addresses.is_empty() {
        "none yet: a row gets an address when a grant names it".to_string()
    } else {
        addresses_table(&app.addresses, &d.port_groups, names)
    };
    let mut parts = vec![head, section("Ports", ports), section("Addresses", addrs)];
    if !d.port_groups.is_empty() {
        parts.push(section("Port groups", port_groups_table(&d.port_groups)));
    }
    parts.push(section(
        "Who can reach it",
        if d.grants.is_empty() {
            "nobody (closed)".to_string()
        } else {
            grants(&d.grants, names, false)
        },
    ));
    for (title, first, which) in [
        ("Through tags", "TAG", Origin::Tag),
        ("Through reservations", "RESERVATION", Origin::Reservation),
    ] {
        let via: Vec<_> = d
            .access
            .iter()
            .filter_map(|a| match (&a.origin, which) {
                (AccessOrigin::Tag { tag_id }, Origin::Tag) => Some((names.tag(tag_id), a)),
                (AccessOrigin::Reservation { reservation_id }, Origin::Reservation) => {
                    Some((names.reservation(reservation_id), a))
                }
                _ => None,
            })
            .collect();
        if via.is_empty() {
            continue;
        }
        parts.push(section(
            title,
            table(
                &[first, "PORT", "NETWORK", "WHO"],
                via.into_iter()
                    .map(|(label, a)| {
                        vec![
                            label,
                            names.scope(&a.scope),
                            a.network_id.clone().unwrap_or_else(|| "all".to_string()),
                            match (&a.subject, &a.network_id) {
                                (Subject::Anyone, Some(n)) => format!("everyone on {n} (segment)"),
                                (s, _) => names.subject(s),
                            },
                        ]
                    })
                    .collect(),
            ),
        ));
    }
    if !d.counters.is_empty() {
        parts.push(section(
            "Allowed traffic",
            table(
                &["NETWORK", "WHO", "PACKETS", "BYTES"],
                d.counters
                    .iter()
                    .map(|c| {
                        vec![
                            c.network_id.clone(),
                            c.subject.clone(),
                            c.packets.to_string(),
                            c.bytes.to_string(),
                        ]
                    })
                    .collect(),
            ),
        ));
    }
    parts.join("\n\n")
}

/// Connection strings per TCP port of the app (for its addresses that are up), optionally limited to one network: first
/// `[addr]:port`, then a URL for the well-known web ports.
pub fn share_lines(app: &App, network: Option<&str>) -> Vec<String> {
    let mut plain = Vec::new();
    let mut urls = Vec::new();
    for a in &app.addresses {
        // A closed address (no grant names its row now) does not accept connections.
        if !a.up || network.is_some_and(|n| n != a.network_id) {
            continue;
        }
        // The ports the address serves among the app's detected ones; a port group's
        // ranges are not known here.
        let ports: Vec<u16> = socketguard_core::scope_ports(
            app,
            &a.scope,
            &[],
            &socketguard_core::PortRangeSet::new(),
        )
        .total()
        .ports()
        .filter(|p| p.proto == socketguard_core::Protocol::Tcp)
        .map(|p| p.port)
        .collect();
        let host = match &a.locator {
            Locator::Ipv6 { addr } => format!("[{addr}]"),
            Locator::Onion { hostname } => {
                // Onion services take no URL port for the default web ports, and a URL
                // replaces the plain form.
                for port in ports {
                    match port {
                        80 => urls.push(format!("http://{hostname}")),
                        443 => urls.push(format!("https://{hostname}")),
                        8080 => urls.push(format!("http://{hostname}:8080")),
                        _ => plain.push(format!("{hostname}:{port}")),
                    }
                }
                continue;
            }
        };
        for port in ports {
            plain.push(format!("{host}:{port}"));
            match port {
                80 | 8080 => urls.push(format!("http://{host}:{port}")),
                443 => urls.push(format!("https://{host}:{port}")),
                _ => {}
            }
        }
    }
    plain.extend(urls);
    plain
}

// ─── Peers and groups ────────────────────────────────────────────────────────

fn credential_rows(creds: &[Credential]) -> Vec<Vec<String>> {
    creds
        .iter()
        .map(|c| {
            vec![
                short(&c.id).to_string(),
                c.kind.to_string(),
                c.value.clone(),
                c.label.clone().unwrap_or_default(),
            ]
        })
        .collect()
}

pub fn peers(peers: &[Peer], names: &Names) -> String {
    if peers.is_empty() {
        return "no peers".to_string();
    }
    table(
        &["ID", "LABEL", "CREDENTIALS", "GROUPS"],
        peers
            .iter()
            .map(|p| {
                vec![
                    short(&p.id).to_string(),
                    p.label.clone(),
                    p.credentials
                        .iter()
                        .map(|c| c.kind.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    p.groups
                        .iter()
                        .map(|g| names.group(g))
                        .collect::<Vec<_>>()
                        .join(", "),
                ]
            })
            .collect(),
    )
}

/// What `peers parse` found: one line per value.
pub fn parsed_credentials(parsed: &[ParsedCredential]) -> String {
    table(
        &["VALUE", "KIND", "STORED AS", "WORKS ON"],
        parsed
            .iter()
            .map(|p| {
                let works = match &p.error {
                    Some(e) => format!("error: {e}"),
                    None => p
                        .reach
                        .iter()
                        .map(|r| {
                            format!("{} ({})", kind_label(r.network_kind), reach_label(r.reach))
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                };
                vec![
                    p.input.clone(),
                    p.kind.map(|k| k.to_string()).unwrap_or_default(),
                    p.normalized.clone().unwrap_or_default(),
                    works,
                ]
            })
            .collect(),
    )
}

pub fn peer_detail(p: &Peer, names: &Names, grants_of: &[GrantView]) -> String {
    let groups = if p.groups.is_empty() {
        "none".to_string()
    } else {
        p.groups
            .iter()
            .map(|g| names.group(g))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let creds = if p.credentials.is_empty() {
        "none".to_string()
    } else {
        table(
            &["ID", "KIND", "VALUE", "LABEL"],
            credential_rows(&p.credentials),
        )
    };
    format!(
        "{}  ({})\n  groups      {groups}\n  created     {}\n\n{}\n\n{}",
        p.label,
        p.id,
        time(p.created_at),
        section("Credentials", creds),
        section(
            "Grants (own and through groups)",
            grants(grants_of, names, true)
        ),
    )
}

pub fn groups(groups: &[PeerGroup], names: &Names) -> String {
    if groups.is_empty() {
        return "no groups".to_string();
    }
    table(
        &["ID", "LABEL", "MEMBERS"],
        groups
            .iter()
            .map(|g| vec![short(&g.id).to_string(), g.label.clone(), members(g, names)])
            .collect(),
    )
}

pub fn members(g: &PeerGroup, names: &Names) -> String {
    g.members
        .iter()
        .map(|m| names.peer(m))
        .collect::<Vec<_>>()
        .join(", ")
}

// ─── Activity, events, diffs, risks ──────────────────────────────────────────

pub fn activity_line(r: &ActivityRecord, names: &Names) -> String {
    let mut line = format!("{}  {:<20}", time(r.at), r.kind.as_str());
    if let Some(app) = &r.app_id {
        line.push_str(&format!("  {}", names.app(app)));
    }
    if let Some(port) = r.port {
        let proto = r.proto.map_or(String::new(), |p| format!("/{p}"));
        line.push_str(&format!("  :{port}{proto}"));
    }
    if let Some(src) = r.src {
        line.push_str(&format!("  from {src}"));
    }
    if r.count > 1 {
        line.push_str(&format!("  x{}", r.count));
    }
    line.push_str(&format!("  {}", r.message));
    line
}

pub fn activity(records: &[ActivityRecord], names: &Names) -> String {
    if records.is_empty() {
        return "no activity".to_string();
    }
    records
        .iter()
        .map(|r| activity_line(r, names))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn event_line(at: DateTime<Utc>, event: &socketguard_client::ApiEvent) -> String {
    use socketguard_client::ApiEvent;
    match event {
        ApiEvent::AppDiscovered(id) => format!("{}  {}  {id}", time(at), event.name()),
        ApiEvent::Unknown { name, data } => format!("{}  {name}  {data}", time(at)),
        _ => format!("{}  {}", time(at), event.name()),
    }
}

pub fn changes(r: &ApplyResponse) -> String {
    if r.changes.is_empty() {
        return "no changes".to_string();
    }
    let mut lines: Vec<String> = r.changes.iter().map(change_line).collect();
    lines.push(String::new());
    lines.push(format!(
        "{} change(s){}",
        r.changes.len(),
        if r.dry_run { " (dry run)" } else { "" }
    ));
    lines.join("\n")
}

fn change_line(c: &Change) -> String {
    let sign = match c.kind {
        ChangeKind::Create => "+",
        ChangeKind::Update => "~",
        ChangeKind::Delete => "-",
    };
    let item = match c.item {
        ChangeItem::Setting => "setting",
        ChangeItem::Peer => "peer",
        ChangeItem::Group => "group",
        ChangeItem::Grant => "grant",
        ChangeItem::Tag => "tag",
        ChangeItem::TagMember => "tag member",
        ChangeItem::PortGroup => "port group",
        ChangeItem::App => "app",
        ChangeItem::Reservation => "reservation",
        ChangeItem::Binding => "binding",
    };
    let mut line = format!("{sign} {item} {}", c.name);
    if let Some(d) = &c.detail {
        line.push_str(&format!(" ({d})"));
    }
    if c.opens_to_anyone {
        line.push_str("  [opens to anyone]");
    }
    line
}

/// The diff of a batch (`grant` and `revoke` with several targets), one line per change
/// and, for a grant, how well its subject is identified per network.
pub fn batch(r: &ChangesResponse) -> String {
    if r.changes.is_empty() {
        return "no changes".to_string();
    }
    r.changes
        .iter()
        .map(|b: &BatchChange| {
            let mut line = change_line(&b.change);
            if !b.reach.is_empty() {
                let reach: Vec<String> = b
                    .reach
                    .iter()
                    .map(|g| match &g.note {
                        Some(n) => format!("{}: {} - {n}", g.network_id, reach_label(g.reach)),
                        None => format!("{}: {}", g.network_id, reach_label(g.reach)),
                    })
                    .collect();
                line.push_str(&format!("  [{}]", reach.join(", ")));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── Tags ────────────────────────────────────────────────────────────────────

/// The members of a tag, as `app` or `app:port/proto`.
fn tag_members(t: &Tag, names: &Names) -> String {
    if t.members.is_empty() {
        return "none".to_string();
    }
    t.members
        .iter()
        .map(|m| names.row(&m.app_id, &m.scope))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn tags(tags: &[Tag], names: &Names) -> String {
    if tags.is_empty() {
        return "no tags".to_string();
    }
    table(
        &["ID", "LABEL", "PATTERNS", "MEMBERS"],
        tags.iter()
            .map(|t| {
                vec![
                    short(&t.id).to_string(),
                    t.label.clone(),
                    if t.patterns.is_empty() {
                        "-".to_string()
                    } else {
                        t.patterns.join(", ")
                    },
                    tag_members(t, names),
                ]
            })
            .collect(),
    )
}

pub fn tag_detail(t: &Tag, names: &Names, grants_on_tag: &[GrantView]) -> String {
    let mut head = format!("{}  ({})", t.label, t.id);
    head.push_str(&format!(
        "\n  patterns    {}",
        if t.patterns.is_empty() {
            "none".to_string()
        } else {
            t.patterns.join(", ")
        }
    ));
    head.push_str(&format!("\n  members     {}", tag_members(t, names)));
    if !t.excluded.is_empty() {
        let out: Vec<String> = t.excluded.iter().map(|a| names.app(a)).collect();
        head.push_str(&format!(
            "\n  kept out    {} (removed by hand although a pattern matches)",
            out.join(", ")
        ));
    }
    let grants = if grants_on_tag.is_empty() {
        "none".to_string()
    } else {
        grants(grants_on_tag, names, true)
    };
    format!("{head}\n\n{}", section("Grants on this tag", grants))
}

// ─── Reservations ────────────────────────────────────────────────────────────

/// A reservation: its bindings, its address on each network, what it cannot serve, and the
/// grants on it.
pub fn reservation_detail(r: &ReservationView, names: &Names) -> String {
    let res = &r.reservation;
    let mut out = format!("{}  ({})", res.label, res.id);
    let bindings: Vec<String> = res
        .bindings
        .iter()
        .map(|b| names.binding(&b.target))
        .collect();
    out.push_str(&format!(
        "\n  bindings   {}",
        if bindings.is_empty() {
            "none".to_string()
        } else {
            bindings.join(", ")
        }
    ));
    if r.addresses.is_empty() {
        out.push_str("\n  addresses  none yet: it gets one when a grant names it");
    }
    for (i, a) in r.addresses.iter().enumerate() {
        out.push_str(&format!(
            "\n  {}  {}  {}  {}",
            if i == 0 { "addresses" } else { "         " },
            a.network_id,
            locator(&a.locator),
            up_label(a.up)
        ));
        if !a.excluded.is_empty() {
            out.push_str(&format!(
                "\n             {}: leaves out {} (another app listens there)",
                a.network_id,
                ranges_text(&a.excluded)
            ));
        }
        for n in &a.notes {
            out.push_str(&format!("\n             {}: {n}", a.network_id));
        }
    }
    for c in &r.conflicts {
        let claimed: Vec<String> = c
            .bindings
            .iter()
            .filter_map(|id| res.bindings.iter().find(|b| &b.id == id))
            .map(|b| names.binding(&b.target))
            .collect();
        let outcome = match &c.served_app {
            Some(app) => format!("served for {}", names.app(app)),
            None => "closed".to_string(),
        };
        out.push_str(&format!(
            "\n  conflict   {} claimed by {}: {outcome}",
            c.ports,
            claimed.join(", ")
        ));
    }
    if !r.grants.is_empty() {
        out.push_str(&format!(
            "\n\n{}",
            section("Grants", grants(&r.grants, names, false))
        ));
    }
    out
}

/// The reservations, one block each.
pub fn reservations(rs: &[ReservationView], names: &Names) -> String {
    if rs.is_empty() {
        return "no reservations".to_string();
    }
    rs.iter()
        .map(|r| reservation_detail(r, names))
        .collect::<Vec<_>>()
        .join("\n\n")
}

// ─── Tor keys and sharing ────────────────────────────────────────────────────

/// The result of generating a Tor client key: the private key is shown here and by `share`.
pub fn tor_key(peer: &str, k: &TorKeyResponse) -> String {
    format!(
        "generated a Tor client key for {peer}\n  public key   {}\n  private key  {}\n\n\
         The public key is now one of the peer's credentials. Keep the private key secret: \
         it is what the peer puts into its ClientOnionAuthDir. `socketguard share <app>` \
         prints the finished line for each onion service the peer is granted.",
        k.credential.value, k.private_key
    )
}

/// The client authorization lines for the app's onion services.
pub fn tor_share(s: &ShareResponse) -> Vec<String> {
    s.tor
        .iter()
        .flat_map(|t| {
            [
                format!(
                    "tor client access for {} to {}: save as {}.auth_private in its ClientOnionAuthDir",
                    t.peer_label,
                    t.hostname,
                    t.hostname.strip_suffix(".onion").unwrap_or(&t.hostname)
                ),
                t.auth_private.clone(),
            ]
        })
        .collect()
}

pub fn lockout_risks(risks: &[LockoutRiskInfo]) -> String {
    let mut lines = vec!["whole-host protection would cut off remote administration:".to_string()];
    for r in risks {
        lines.push(format!("  {}", r.message));
    }
    lines.push(String::new());
    lines.push(
        "Grant each of them to a peer first (socketguard grant <app>:<port> <peer>), \
         or repeat with --force to accept the lockout."
            .to_string(),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reach_badges() {
        let all = [
            Reach::Verified,
            Reach::WholeSubnet,
            Reach::IpOnly,
            Reach::Open,
            Reach::Unfiltered,
            Reach::NotReachable,
        ];
        let labels: Vec<_> = all.into_iter().map(reach_label).collect();
        assert_eq!(
            labels,
            [
                "verified",
                "whole subnet",
                "IP only",
                "open",
                "open to everyone over IPv4",
                "not reachable"
            ]
        );
    }
}
