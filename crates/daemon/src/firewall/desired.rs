//! The desired firewall state (ADR 0029): a platform-independent description that the
//! engine produces as a pure function of its state, and each platform backend applies
//! atomically as a whole.
//!
//! Semantics, evaluated per inbound packet:
//! 1. Always allowed: established/related, loopback, the ICMPv6 types needed for NDP,
//!    MLD and PMTU (echo rate-limited), and DHCPv6 client replies (udp 547 -> 546).
//!    Backends that only see new connections (WFP ALE) get most of this for free.
//! 2. A matching [`Rule`] allows the packet.
//! 3. Otherwise, a packet that falls inside any [`Scope`] is dropped (and counted/logged).
//! 4. Anything outside every scope is left alone.
//!
//! Link-local destinations are NOT exempt: inside a scope they are denied like any other.

use ipnet::IpNet;
use socketguard_core::Protocol;
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredRuleset {
    pub scopes: Vec<Scope>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Stable identifier, used for counters and drop attribution (e.g. "managed",
    /// "overlay:ygg0", "host:eth0"). Must be unique within a ruleset.
    pub id: String,
    pub kind: ScopeKind,
    pub matcher: ScopeMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// SocketGuard-allocated addresses, all ports.
    ManagedAddresses,
    /// An overlay interface protected by default (Yggdrasil).
    Overlay,
    /// Opt-in whole-host protection of an interface.
    WholeHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeMatch {
    /// Inbound packets whose destination is one of these addresses (any port, any interface).
    Destinations(Vec<IpAddr>),
    /// All inbound packets arriving on this interface, for the given families. Matching by
    /// interface covers every prefix on it, including rotating privacy and link-local addresses.
    Interface { name: String, families: Families },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Families {
    V6,
    V4,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Stable identifier, used for counters (e.g. derived from grant or socket+backend).
    /// Must be unique within a ruleset.
    pub id: String,
    /// When set, the packet must arrive on this interface. Required for sources whose
    /// identity is only guaranteed by that interface (Yggdrasil `200::/7`, WireGuard).
    pub iif: Option<String>,
    pub dst: IpAddr,
    pub port: u16,
    pub proto: Protocol,
    pub sources: Sources,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sources {
    Any,
    /// Non-empty list of allowed source networks (single hosts as /128 or /32).
    Nets(Vec<IpNet>),
}

/// Packet/byte counter for a rule or scope, keyed by its `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    pub id: String,
    pub packets: u64,
    pub bytes: u64,
}

/// A dropped inbound connection attempt reported by the platform (NFLOG, WFP net events).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    pub at: SystemTime,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
    pub iif: Option<String>,
    /// The scope that dropped it, when the platform can tell.
    pub scope_id: Option<String>,
}

pub type DropSink = Box<dyn Fn(DropEvent) + Send + Sync>;
