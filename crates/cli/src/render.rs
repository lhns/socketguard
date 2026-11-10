//! Human-readable output: pure functions from API types to strings, snapshot tested.
//! Nothing here talks to the daemon or the terminal.

use crate::resolve::short;
use chrono::{DateTime, Utc};
use comfy_table::{presets, Table};
use socketguard_core::api_types::{
    ApplyResponse, Change, ChangeItem, ChangeKind, LockoutRiskInfo, StatusResponse,
};
use socketguard_core::{
    ActivityRecord, Address, App, AppDetail, Credential, GrantView, Locator, Network, NetworkKind,
    NetworkStatus, ParsedCredential, Peer, PeerGroup, PortSet, Reach, Settings, Subject,
};
use std::collections::HashMap;

/// Labels for ids, for output that mentions apps, peers and groups by id.
#[derive(Debug, Default, Clone)]
pub struct Names {
    pub apps: HashMap<String, String>,
    pub peers: HashMap<String, String>,
    pub groups: HashMap<String, String>,
}

impl Names {
    pub fn new(apps: &[App], peers: &[Peer], groups: &[PeerGroup]) -> Self {
        Self {
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

    pub fn app(&self, id: &str) -> String {
        label(&self.apps, id)
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

fn port_set(p: &PortSet) -> String {
    match p {
        PortSet::All => "all".to_string(),
        PortSet::Only(ports) => ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", "),
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

fn grant_scope(g: &GrantView) -> (String, String) {
    (
        g.grant
            .port
            .map_or("all ports".to_string(), |p| p.to_string()),
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
         apps          {} ({} pending), {} addresses\n\
         peers         {}, groups {}, grants {}\n\n{}",
        s.version,
        c.apps,
        c.pending_apps,
        c.addresses,
        c.peers,
        c.groups,
        c.grants,
        section("Networks", networks(&s.networks)),
    )
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
        "address-mode   {}\nprotect-host   {}",
        s.address_mode,
        protect_host(&s.protect_host_interfaces)
    )
}

// ─── Apps ────────────────────────────────────────────────────────────────────

pub fn apps(apps: &[App]) -> String {
    if apps.is_empty() {
        return "no apps".to_string();
    }
    let mut out = table(
        &["ID", "NAME", "PORTS", "STATE", "ADDRESSES"],
        apps.iter()
            .map(|a| {
                vec![
                    short(&a.id).to_string(),
                    a.name.clone(),
                    app_ports(a),
                    if a.reviewed { "reviewed" } else { "pending" }.to_string(),
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

fn addresses_table(addrs: &[Address]) -> String {
    table(
        &["ID", "NETWORK", "ADDRESS", "PORTS"],
        addrs
            .iter()
            .map(|a| {
                vec![
                    short(&a.id).to_string(),
                    a.network_id.clone(),
                    locator(&a.locator),
                    port_set(&a.ports),
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
    table(
        &header,
        grants
            .iter()
            .map(|g| {
                let (port, net) = grant_scope(g);
                let mut row = vec![short(&g.grant.id).to_string()];
                if with_app {
                    row.push(names.app(&g.grant.app_id));
                }
                row.extend([port, net, names.grantee(&g.grant), reach_summary(g)]);
                row
            })
            .collect(),
    )
}

pub fn app_detail(d: &AppDetail, names: &Names) -> String {
    let app = &d.app;
    let state = if app.reviewed {
        "reviewed"
    } else {
        "pending (closed until granted)"
    };
    let mut head = format!("{}  ({})\n  state       {state}", app.name, app.id);
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
        "none".to_string()
    } else {
        addresses_table(&app.addresses)
    };
    let mut parts = vec![
        head,
        section("Ports", ports),
        section("Addresses", addrs),
        section(
            "Who can reach it",
            if d.grants.is_empty() {
                "nobody (closed)".to_string()
            } else {
                grants(&d.grants, names, false)
            },
        ),
    ];
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

/// Connection strings per TCP port of the app, optionally limited to one network: first
/// `[addr]:port`, then a URL for the well-known web ports.
pub fn share_lines(app: &App, network: Option<&str>) -> Vec<String> {
    let mut plain = Vec::new();
    let mut urls = Vec::new();
    for a in &app.addresses {
        if network.is_some_and(|n| n != a.network_id) {
            continue;
        }
        let ports: Vec<u16> = match &a.ports {
            PortSet::All => {
                // Ports that another address of the same network claims are not here.
                let claimed: Vec<_> = app
                    .addresses
                    .iter()
                    .filter(|o| o.network_id == a.network_id)
                    .filter_map(|o| match &o.ports {
                        PortSet::Only(p) => Some(p.clone()),
                        PortSet::All => None,
                    })
                    .flatten()
                    .collect();
                app.ports
                    .iter()
                    .filter(|p| {
                        !claimed
                            .iter()
                            .any(|c| c.port == p.port && c.proto == p.proto)
                    })
                    .filter(|p| p.proto == socketguard_core::Protocol::Tcp)
                    .map(|p| p.port)
                    .collect()
            }
            PortSet::Only(ps) => ps
                .iter()
                .filter(|p| p.proto == socketguard_core::Protocol::Tcp)
                .map(|p| p.port)
                .collect(),
        };
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
