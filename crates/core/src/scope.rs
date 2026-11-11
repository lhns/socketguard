//! Scopes and socket groups (ADR 0047): which sockets of an app a grant, a tag member or
//! an address means, the port sets that follow from it, and the sets themselves.
//!
//! [`PortRangeSet`] is the arithmetic (union, intersection, subtraction) on ports and port
//! ranges per protocol. [`ScopePorts`] is a set of ports in two parts: `fixed`, the ports
//! the app listens on or a scope names explicitly, and `ranged`, ports that only a socket
//! group's range contributes. The firewall renders `fixed` ports one by one and `ranged`
//! ones as ranges, and the exclusion rule of ADR 0047 only touches `ranged`.

use crate::model::{App, AppId, PortRef};
use crate::types::Protocol;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub type SocketGroupId = String;

// ─── Port ranges ─────────────────────────────────────────────────────────────

/// A range of ports of one protocol, both ends included. `80/tcp` is the range `80-80`.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
    pub proto: Protocol,
}

impl PortRange {
    /// A validated range: ports from 1, `start <= end`.
    pub fn new(start: u16, end: u16, proto: Protocol) -> Result<Self, String> {
        let r = PortRange { start, end, proto };
        r.validate()?;
        Ok(r)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.start == 0 {
            return Err("port 0 is not a port".to_string());
        }
        if self.start > self.end {
            return Err(format!(
                "port range {}-{} ends before it starts",
                self.start, self.end
            ));
        }
        Ok(())
    }

    pub fn single(p: PortRef) -> Self {
        PortRange {
            start: p.port,
            end: p.port,
            proto: p.proto,
        }
    }

    pub fn contains(&self, p: PortRef) -> bool {
        p.proto == self.proto && (self.start..=self.end).contains(&p.port)
    }

    pub fn is_single(&self) -> bool {
        self.start == self.end
    }

    /// The ports as written in rule ids and rules: `80` or `50000-51000`.
    pub fn port_text(&self) -> String {
        if self.is_single() {
            self.start.to_string()
        } else {
            format!("{}-{}", self.start, self.end)
        }
    }
}

/// `80/tcp` or `50000-51000/tcp`.
impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.port_text(), self.proto)
    }
}

impl FromStr for PortRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (ports, proto) = s
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("invalid port range {s:?}: write 80/tcp or 50000-51000/udp"))?;
        let proto: Protocol = proto.trim().parse()?;
        let num = |t: &str| {
            t.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {s:?}"))
        };
        let (start, end) = match ports.split_once('-') {
            Some((a, b)) => (num(a)?, num(b)?),
            None => {
                let p = num(ports)?;
                (p, p)
            }
        };
        PortRange::new(start, end, proto)
    }
}

/// A set of ports per protocol, kept as sorted, non-overlapping, non-adjacent ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortRangeSet {
    tcp: Vec<(u16, u16)>,
    udp: Vec<(u16, u16)>,
}

/// Sort and merge ranges that overlap or touch.
fn normalize(mut v: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    v.retain(|(s, e)| s <= e);
    v.sort_unstable();
    let mut out: Vec<(u16, u16)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if u32::from(s) <= u32::from(last.1) + 1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn intersect_side(a: &[(u16, u16)], b: &[(u16, u16)]) -> Vec<(u16, u16)> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        let (s, e) = (a[i].0.max(b[j].0), a[i].1.min(b[j].1));
        if s <= e {
            out.push((s, e));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn subtract_side(a: &[(u16, u16)], b: &[(u16, u16)]) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    for &(s, e) in a {
        // The part of (s, e) not covered by any range of b, working in u32 so that the
        // ends of the port space need no special case.
        let mut from = u32::from(s);
        let end = u32::from(e);
        for &(bs, be) in b {
            let (bs, be) = (u32::from(bs), u32::from(be));
            if be < from || bs > end {
                continue;
            }
            if bs > from {
                out.push((from as u16, (bs - 1) as u16));
            }
            from = from.max(be + 1);
            if from > end {
                break;
            }
        }
        if from <= end {
            out.push((from as u16, e));
        }
    }
    out
}

impl PortRangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every port 0-65535 of both protocols.
    pub fn everything() -> Self {
        PortRangeSet {
            tcp: vec![(0, u16::MAX)],
            udp: vec![(0, u16::MAX)],
        }
    }

    pub fn from_ranges(ranges: impl IntoIterator<Item = PortRange>) -> Self {
        let mut s = Self::new();
        for r in ranges {
            s.insert(r.start, r.end, r.proto);
        }
        s
    }

    pub fn from_ports(ports: impl IntoIterator<Item = PortRef>) -> Self {
        Self::from_ranges(ports.into_iter().map(PortRange::single))
    }

    fn side(&self, proto: Protocol) -> &Vec<(u16, u16)> {
        match proto {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        }
    }

    fn side_mut(&mut self, proto: Protocol) -> &mut Vec<(u16, u16)> {
        match proto {
            Protocol::Tcp => &mut self.tcp,
            Protocol::Udp => &mut self.udp,
        }
    }

    pub fn insert(&mut self, start: u16, end: u16, proto: Protocol) {
        let side = self.side_mut(proto);
        side.push((start, end));
        *side = normalize(std::mem::take(side));
    }

    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    pub fn contains(&self, p: PortRef) -> bool {
        self.side(p.proto)
            .binary_search_by(|&(s, e)| {
                if p.port < s {
                    std::cmp::Ordering::Greater
                } else if p.port > e {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn union(&self, other: &Self) -> Self {
        PortRangeSet {
            tcp: normalize([self.tcp.as_slice(), other.tcp.as_slice()].concat()),
            udp: normalize([self.udp.as_slice(), other.udp.as_slice()].concat()),
        }
    }

    pub fn intersect(&self, other: &Self) -> Self {
        PortRangeSet {
            tcp: intersect_side(&self.tcp, &other.tcp),
            udp: intersect_side(&self.udp, &other.udp),
        }
    }

    pub fn subtract(&self, other: &Self) -> Self {
        PortRangeSet {
            tcp: subtract_side(&self.tcp, &other.tcp),
            udp: subtract_side(&self.udp, &other.udp),
        }
    }

    /// The ranges, TCP first, each protocol in port order.
    pub fn ranges(&self) -> Vec<PortRange> {
        let side = |v: &Vec<(u16, u16)>, proto| {
            v.iter()
                .map(move |&(start, end)| PortRange { start, end, proto })
                .collect::<Vec<_>>()
        };
        let mut out = side(&self.tcp, Protocol::Tcp);
        out.extend(side(&self.udp, Protocol::Udp));
        out
    }

    /// Every single port, for sets known to be small (detected or explicit ports).
    pub fn ports(&self) -> impl Iterator<Item = PortRef> + '_ {
        self.ranges().into_iter().flat_map(|r| {
            (r.start..=r.end).map(move |port| PortRef {
                port,
                proto: r.proto,
            })
        })
    }
}

/// Normalize a list of ranges: sorted, overlapping and adjacent ones merged.
pub fn normalize_ranges(ranges: &[PortRange]) -> Vec<PortRange> {
    PortRangeSet::from_ranges(ranges.iter().copied()).ranges()
}

/// Parse and normalize ranges written as `80/tcp`, `50000-51000/tcp`.
pub fn parse_ranges<S: AsRef<str>>(items: &[S]) -> Result<Vec<PortRange>, String> {
    let ranges = items
        .iter()
        .map(|s| s.as_ref().parse::<PortRange>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(normalize_ranges(&ranges))
}

/// `80/tcp, 50000-51000/tcp`
pub fn ranges_text(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ─── Scope and socket groups ─────────────────────────────────────────────────

/// Which sockets of an app a grant, a tag member or an address means.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    /// Every socket of the app: its detected ports and its attached socket groups.
    #[default]
    All,
    Port {
        port: u16,
        proto: Protocol,
    },
    /// A socket group attached to the app.
    Group {
        id: SocketGroupId,
    },
}

impl Scope {
    pub fn port(p: PortRef) -> Scope {
        Scope::Port {
            port: p.port,
            proto: p.proto,
        }
    }

    pub fn group(id: impl Into<SocketGroupId>) -> Scope {
        Scope::Group { id: id.into() }
    }

    pub fn is_all(&self) -> bool {
        matches!(self, Scope::All)
    }

    pub fn as_port(&self) -> Option<PortRef> {
        match self {
            Scope::Port { port, proto } => Some(PortRef {
                port: *port,
                proto: *proto,
            }),
            _ => None,
        }
    }

    pub fn group_id(&self) -> Option<&str> {
        match self {
            Scope::Group { id } => Some(id),
            _ => None,
        }
    }

    /// For people: `all ports`, `80/tcp`, `group <label>` (the id if the group is unknown).
    pub fn describe(&self, groups: &[SocketGroup]) -> String {
        match self {
            Scope::All => "all ports".to_string(),
            Scope::Port { port, proto } => format!("{port}/{proto}"),
            Scope::Group { id } => format!(
                "group {}",
                groups
                    .iter()
                    .find(|g| &g.id == id)
                    .map_or(id.as_str(), |g| g.label.as_str())
            ),
        }
    }
}

/// A named set of ports and port ranges that belong together (FTP's control port and its
/// passive range). It is attached to the apps it applies to and is then usable in each as
/// a scope; its ports need not be detected.
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketGroup {
    pub id: SocketGroupId,
    pub label: String,
    /// Non-empty, normalized: sorted, merged.
    pub ports: Vec<PortRange>,
    /// The apps it is attached to.
    pub apps: Vec<AppId>,
    pub created_at: DateTime<Utc>,
}

impl SocketGroup {
    pub fn is_attached_to(&self, app_id: &str) -> bool {
        self.apps.iter().any(|a| a == app_id)
    }

    pub fn port_set(&self) -> PortRangeSet {
        PortRangeSet::from_ranges(self.ports.iter().copied())
    }
}

pub fn find_group<'a>(groups: &'a [SocketGroup], id: &str) -> Option<&'a SocketGroup> {
    groups.iter().find(|g| g.id == id)
}

// ─── Ports of a scope ────────────────────────────────────────────────────────

/// A set of ports in two parts, see the module documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopePorts {
    /// Detected and explicitly named ports.
    pub fixed: PortRangeSet,
    /// Ports that only a socket group's range contributes; disjoint from `fixed`.
    pub ranged: PortRangeSet,
}

impl ScopePorts {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn total(&self) -> PortRangeSet {
        self.fixed.union(&self.ranged)
    }

    pub fn is_empty(&self) -> bool {
        self.fixed.is_empty() && self.ranged.is_empty()
    }

    pub fn contains(&self, p: PortRef) -> bool {
        self.fixed.contains(p) || self.ranged.contains(p)
    }

    pub fn union(&self, other: &Self) -> Self {
        let fixed = self.fixed.union(&other.fixed);
        let ranged = self.ranged.union(&other.ranged).subtract(&fixed);
        ScopePorts { fixed, ranged }
    }

    /// The ports in both. A port stays `fixed` when either side has it fixed.
    pub fn intersect(&self, other: &Self) -> Self {
        let total = self.total().intersect(&other.total());
        let fixed = total.intersect(&self.fixed.union(&other.fixed));
        let ranged = total.subtract(&fixed);
        ScopePorts { fixed, ranged }
    }

    /// The ports of the set as ranges, for display.
    pub fn ranges(&self) -> Vec<PortRange> {
        self.total().ranges()
    }
}

/// Every port that an app other than `app_id` listens on now. A listener on a wildcard
/// address answers on every local address, so these ports are not the app's to grant by
/// range (ADR 0047).
pub fn foreign_listening(apps: &[App], app_id: &str) -> PortRangeSet {
    PortRangeSet::from_ports(
        apps.iter()
            .filter(|a| a.id != app_id)
            .flat_map(|a| a.ports.iter())
            .filter(|p| p.listening)
            .map(|p| p.port_ref()),
    )
}

/// The ports the app has detected, listening or not.
pub fn detected_ports(app: &App) -> PortRangeSet {
    PortRangeSet::from_ports(app.ports.iter().map(|p| p.port_ref()))
}

/// The ports `scope` means on `app` (ADR 0047):
///
/// - `All`: the detected ports and the ranges of every attached socket group,
/// - `Port`: that port, detected or not,
/// - `Group`: the group's ranges if it is attached to the app, else nothing.
///
/// Ranges that come from a group leave out `foreign` ports (see [`foreign_listening`]) unless
/// the app has the port itself. Pass an empty set to get the plain semantics.
pub fn scope_ports(
    app: &App,
    scope: &Scope,
    groups: &[SocketGroup],
    foreign: &PortRangeSet,
) -> ScopePorts {
    let detected = detected_ports(app);
    let excluded = foreign.subtract(&detected);
    match scope {
        Scope::All => {
            let attached = groups
                .iter()
                .filter(|g| g.is_attached_to(&app.id))
                .fold(PortRangeSet::new(), |acc, g| acc.union(&g.port_set()));
            ScopePorts {
                ranged: attached.subtract(&detected).subtract(&excluded),
                fixed: detected,
            }
        }
        Scope::Port { port, proto } => ScopePorts {
            fixed: PortRangeSet::from_ports([PortRef {
                port: *port,
                proto: *proto,
            }]),
            ranged: PortRangeSet::new(),
        },
        Scope::Group { id } => match find_group(groups, id) {
            Some(g) if g.is_attached_to(&app.id) => ScopePorts {
                ranged: g.port_set().subtract(&excluded),
                fixed: PortRangeSet::new(),
            },
            _ => ScopePorts::empty(),
        },
    }
}

/// The ports `scope` names by itself, as a tag grant's own scope does: no attachment
/// needed, `All` is everything.
pub fn raw_scope_ports(scope: &Scope, groups: &[SocketGroup]) -> ScopePorts {
    match scope {
        Scope::All => ScopePorts {
            fixed: PortRangeSet::new(),
            ranged: PortRangeSet::everything(),
        },
        Scope::Port { port, proto } => ScopePorts {
            fixed: PortRangeSet::from_ports([PortRef {
                port: *port,
                proto: *proto,
            }]),
            ranged: PortRangeSet::new(),
        },
        Scope::Group { id } => ScopePorts {
            ranged: find_group(groups, id).map_or_else(PortRangeSet::new, SocketGroup::port_set),
            fixed: PortRangeSet::new(),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::AppPort;

    fn tcp(port: u16) -> PortRef {
        PortRef {
            port,
            proto: Protocol::Tcp,
        }
    }

    fn set(ranges: &[&str]) -> PortRangeSet {
        PortRangeSet::from_ranges(ranges.iter().map(|r| r.parse::<PortRange>().unwrap()))
    }

    fn texts(s: &PortRangeSet) -> Vec<String> {
        s.ranges().iter().map(|r| r.to_string()).collect()
    }

    #[test]
    fn ranges_parse_print_and_validate() {
        let r: PortRange = "80/tcp".parse().unwrap();
        assert_eq!((r.start, r.end, r.proto), (80, 80, Protocol::Tcp));
        assert_eq!(r.to_string(), "80/tcp");
        let r: PortRange = "50000-51000/udp".parse().unwrap();
        assert_eq!(r.to_string(), "50000-51000/udp");
        assert_eq!(
            " 7 - 9 /tcp".parse::<PortRange>().unwrap().to_string(),
            "7-9/tcp"
        );
        for bad in [
            "80",
            "80/icmp",
            "9-5/tcp",
            "0/tcp",
            "70000/tcp",
            "a-b/tcp",
            "",
        ] {
            assert!(bad.parse::<PortRange>().is_err(), "{bad:?}");
        }
        assert!(PortRange::new(2, 1, Protocol::Tcp).is_err());
        assert_eq!(
            ranges_text(&parse_ranges(&["443/tcp", "80/tcp"]).unwrap()),
            "80/tcp, 443/tcp"
        );
    }

    #[test]
    fn sets_normalize_and_merge() {
        let s = set(&["80/tcp", "81/tcp", "90-95/tcp", "93-100/tcp", "53/udp"]);
        assert_eq!(texts(&s), ["80-81/tcp", "90-100/tcp", "53/udp"]);
        assert!(s.contains(tcp(81)) && s.contains(tcp(100)) && !s.contains(tcp(82)));
        assert!(!s.contains(PortRef {
            port: 53,
            proto: Protocol::Tcp
        }));
        // Adjacent ranges merge, also at the top of the port space.
        let top = set(&["65530-65534/tcp", "65535/tcp"]);
        assert_eq!(texts(&top), ["65530-65535/tcp"]);
        assert!(PortRangeSet::new().is_empty());
    }

    #[test]
    fn union_intersection_and_subtraction() {
        let a = set(&["10-20/tcp", "30-40/tcp", "5/udp"]);
        let b = set(&["15-35/tcp", "5/udp", "6/udp"]);
        assert_eq!(texts(&a.union(&b)), ["10-40/tcp", "5-6/udp"]);
        assert_eq!(texts(&a.intersect(&b)), ["15-20/tcp", "30-35/tcp", "5/udp"]);
        assert_eq!(texts(&a.subtract(&b)), ["10-14/tcp", "36-40/tcp"]);
        assert_eq!(texts(&b.subtract(&a)), ["21-29/tcp", "6/udp"]);
        // A hole in the middle of a range.
        let hole = set(&["1-100/tcp"]).subtract(&set(&["50/tcp"]));
        assert_eq!(texts(&hole), ["1-49/tcp", "51-100/tcp"]);
        // The protocols do not mix.
        assert!(set(&["80/tcp"]).intersect(&set(&["80/udp"])).is_empty());
        assert!(a.subtract(&a).is_empty());
    }

    #[test]
    fn subtraction_at_the_ends_of_the_port_space() {
        let all = PortRangeSet::everything();
        let rest = all.subtract(&PortRangeSet::from_ports([tcp(0), tcp(65535)]));
        assert_eq!(texts(&rest), ["1-65534/tcp", "0-65535/udp"]);
        assert!(all.subtract(&all).is_empty());
        let top = set(&["65535/tcp"]);
        assert!(top.subtract(&top).is_empty());
        assert_eq!(texts(&top.union(&set(&["65534/tcp"]))), ["65534-65535/tcp"]);
        assert_eq!(
            texts(&set(&["1-3/tcp"]).subtract(&set(&["1/tcp"]))),
            ["2-3/tcp"]
        );
        assert!(all.contains(tcp(0)) && all.contains(tcp(65535)));
    }

    #[test]
    fn ports_enumerates_small_sets() {
        let s = set(&["80-82/tcp", "53/udp"]);
        assert_eq!(s.ports().count(), 4);
    }

    #[test]
    fn scope_serde_shape() {
        use serde_json::json;
        assert_eq!(
            serde_json::to_value(Scope::All).unwrap(),
            json!({"kind":"all"})
        );
        assert_eq!(
            serde_json::to_value(Scope::port(tcp(80))).unwrap(),
            json!({"kind":"port","port":80,"proto":"tcp"})
        );
        assert_eq!(
            serde_json::to_value(Scope::group("g1")).unwrap(),
            json!({"kind":"group","id":"g1"})
        );
        for s in [Scope::All, Scope::port(tcp(80)), Scope::group("g1")] {
            let back: Scope = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
            assert_eq!(back, s);
        }
        assert_eq!(Scope::default(), Scope::All);
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default)]
            scope: Scope,
        }
        assert_eq!(
            serde_json::from_value::<Holder>(json!({})).unwrap().scope,
            Scope::All
        );
        assert!(serde_json::from_value::<Scope>(json!({"kind":"port"})).is_err());
    }

    pub(crate) fn app_with(id: &str, ports: &[(u16, bool)]) -> App {
        let now = Utc::now();
        App {
            id: id.into(),
            name: id.into(),
            process_name: id.into(),
            exe_path: None,
            interpreter_arg: None,
            identity_note: None,
            reviewed: true,
            system: false,
            first_seen: now,
            last_seen: now,
            ports: ports
                .iter()
                .map(|&(port, listening)| AppPort {
                    port,
                    proto: Protocol::Tcp,
                    listening,
                    last_seen: now,
                    family: Default::default(),
                })
                .collect(),
            addresses: vec![],
        }
    }

    pub(crate) fn group(id: &str, ranges: &[&str], apps: &[&str]) -> SocketGroup {
        SocketGroup {
            id: id.into(),
            label: id.into(),
            ports: parse_ranges(ranges).unwrap(),
            apps: apps.iter().map(|a| a.to_string()).collect(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn scope_semantics_per_app() {
        let app = app_with("a", &[(21, true), (8080, false)]);
        let groups = [
            group("passive", &["50000-50010/tcp"], &["a"]),
            group("other", &["60000/tcp"], &[]),
        ];
        let none = PortRangeSet::new();
        // All: detected (listening or not) and the attached group's ranges.
        let all = scope_ports(&app, &Scope::All, &groups, &none);
        assert_eq!(texts(&all.fixed), ["21/tcp", "8080/tcp"]);
        assert_eq!(texts(&all.ranged), ["50000-50010/tcp"]);
        // Port: that port, detected or not.
        let p = scope_ports(&app, &Scope::port(tcp(9999)), &groups, &none);
        assert_eq!(texts(&p.total()), ["9999/tcp"]);
        // Group: attached gives its ranges, a detached group nothing.
        let g = scope_ports(&app, &Scope::group("passive"), &groups, &none);
        assert_eq!(texts(&g.total()), ["50000-50010/tcp"]);
        assert!(scope_ports(&app, &Scope::group("other"), &groups, &none).is_empty());
        assert!(scope_ports(&app, &Scope::group("missing"), &groups, &none).is_empty());
    }

    #[test]
    fn group_ranges_leave_out_ports_another_app_listens_on() {
        let a = app_with("a", &[(50005, true)]);
        let b = app_with("b", &[(50003, true), (50004, false)]);
        let groups = [group("passive", &["50000-50010/tcp"], &["a"])];
        let foreign = foreign_listening(&[a.clone(), b], "a");
        assert_eq!(
            texts(&foreign),
            ["50003/tcp"],
            "only listening ports of others"
        );
        let all = scope_ports(&a, &Scope::All, &groups, &foreign);
        // 50003 is b's; 50005 is a's own and stays (as a fixed port).
        assert_eq!(texts(&all.fixed), ["50005/tcp"]);
        assert_eq!(
            texts(&all.ranged),
            ["50000-50002/tcp", "50004/tcp", "50006-50010/tcp"]
        );
        let g = scope_ports(&a, &Scope::group("passive"), &groups, &foreign);
        assert_eq!(
            texts(&g.total()),
            ["50000-50002/tcp", "50004-50010/tcp"],
            "a's own 50005 is inside the range"
        );
        // An explicit port and a detected port are not affected.
        let c = app_with("c", &[(50003, true)]);
        let groups_c = [group("passive", &["50000-50010/tcp"], &["c"])];
        let foreign_c = foreign_listening(&[a.clone(), c.clone()], "c");
        assert!(foreign_c.contains(tcp(50005)));
        let explicit = scope_ports(&c, &Scope::port(tcp(50005)), &groups_c, &foreign_c);
        assert!(explicit.contains(tcp(50005)));
        let all_c = scope_ports(&c, &Scope::All, &groups_c, &foreign_c);
        assert!(all_c.contains(tcp(50003)) && !all_c.contains(tcp(50005)));
    }

    #[test]
    fn raw_scopes_need_no_attachment() {
        let groups = [group("g", &["1000-1010/tcp"], &[])];
        assert!(raw_scope_ports(&Scope::All, &groups).contains(tcp(1)));
        assert_eq!(
            texts(&raw_scope_ports(&Scope::group("g"), &groups).total()),
            ["1000-1010/tcp"]
        );
        assert_eq!(
            texts(&raw_scope_ports(&Scope::port(tcp(7)), &groups).total()),
            ["7/tcp"]
        );
        assert!(raw_scope_ports(&Scope::group("nope"), &groups).is_empty());
    }

    #[test]
    fn scope_ports_keep_detected_ports_fixed_through_unions_and_intersections() {
        let fixed = ScopePorts {
            fixed: set(&["80/tcp", "81/tcp"]),
            ranged: set(&["1000-2000/tcp"]),
        };
        let raw = ScopePorts {
            fixed: PortRangeSet::new(),
            ranged: PortRangeSet::everything(),
        };
        let both = fixed.intersect(&raw);
        assert_eq!(both, fixed);
        let narrowed = fixed.intersect(&ScopePorts {
            fixed: PortRangeSet::new(),
            ranged: set(&["81-1500/tcp"]),
        });
        assert_eq!(texts(&narrowed.fixed), ["81/tcp"]);
        assert_eq!(texts(&narrowed.ranged), ["1000-1500/tcp"]);
        let u = fixed.union(&ScopePorts {
            fixed: set(&["1500/tcp"]),
            ranged: set(&["80/tcp"]),
        });
        assert_eq!(texts(&u.fixed), ["80-81/tcp", "1500/tcp"]);
        assert!(!u.ranged.contains(tcp(1500)) && u.ranged.contains(tcp(1000)));
    }
}
