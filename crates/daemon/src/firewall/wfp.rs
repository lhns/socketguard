//! Windows Filtering Platform backend (ADR 0030, 0029, 0026).
//!
//! Everything lives under SocketGuard's own persistent provider and a persistent sublayer
//! of maximum weight, so the state survives daemon exit and reboot (frozen state) and is
//! removed only by [`Firewall::disable`], never touching other filters.
//!
//! Layers: `ALE_AUTH_RECV_ACCEPT_V4/V6` see only *new* inbound flows. Established traffic
//! is therefore never re-evaluated, which covers "established/related" for free.
//! ICMPv6 NDP/MLD/PMTU messages are not classified at ALE recv-accept, so they need no
//! permit and cannot be blocked by us. ICMP echo requests are classified there and are
//! denied inside a scope unless a rule matches (conservative; not exempted).
//!
//! Per-ruleset layout inside the sublayer (higher weight is evaluated first):
//! - weight 15: hard permits: loopback (by remote address) and DHCP client replies (v6
//!   only from `fe80::/10`; not on the overlay interface);
//! - weight 10: hard permits: one per (rule, source net);
//! - weight 4: blocks: one per scope destination address / scope interface family.
//!
//! Interfaces: rules and scopes match `FWPM_CONDITION_IP_ARRIVAL_INTERFACE`, the interface
//! the packet came in on (ADR 0029's `iif`), not the local interface of the destination
//! address. Aliases are resolved to LUIDs when applying; the resolved map is remembered
//! so [`Firewall::interfaces_changed`] can tell when an adapter was recreated. A BLOCK scope
//! whose interface does not resolve fails the whole apply (the previous filters stay),
//! because skipping it would silently leave the interface open; permits for an
//! unresolvable interface are skipped. Established flows are never re-evaluated by ALE,
//! so a revoked grant lets them live until they close ([`Firewall::revoke`] does nothing
//! here, ADR 0030).
//!
//! Not used: `FWPM_FILTER_FLAG_BOOTTIME`. Boot-time filters are a separate table enforced
//! before BFE starts and cannot be combined with PERSISTENT, so adding them would mean a
//! second, parallel filter set. Persistent filters are applied as soon as BFE starts; the
//! gap before that is accepted for now.

use super::{DesiredRuleset, DropEvent, DropSink, Families, Firewall, ScopeMatch, Sources};
use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use socketguard_core::Protocol;
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const AUTHN_DEFAULT: u32 = 0xFFFF_FFFF; // RPC_C_AUTHN_DEFAULT
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;

/// "SOCKGUARD" in ASCII, so the objects are recognisable in `netsh wfp show state`.
const PROVIDER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_000000000001);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_000000000002);
/// Distinct keys for the integration test, so it never touches production objects.
const TEST_PROVIDER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_0000000000f1);
const TEST_SUBLAYER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_0000000000f2);

const W_ALWAYS: u8 = 15;
const W_RULE: u8 = 10;
const W_BLOCK: u8 = 4;

const NAME_PREFIX: &str = "SocketGuard";
const SCOPE_NAME_PREFIX: &str = "SocketGuard scope:";

/// Drop events per second handed to the sink; the rest are discarded.
const MAX_EVENTS_PER_SEC: u32 = 50;

// ---------------------------------------------------------------------------
// Planning: DesiredRuleset -> filter specs (pure, unit-tested)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    V4,
    V6,
}

impl Layer {
    fn key(self) -> GUID {
        match self {
            Layer::V4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Layer::V6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }
    fn of(ip: &IpAddr) -> Self {
        if ip.is_ipv4() {
            Layer::V4
        } else {
            Layer::V6
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Hard permit (clear-action-right): later sublayers cannot veto it.
    Permit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cond {
    LocalAddr(IpAddr),
    LocalPort(u16),
    RemotePort(u16),
    Proto(u8),
    /// A host (full prefix) matches by address, anything else by address+mask.
    Remote(IpNet),
    /// The same for the local (destination) address.
    LocalNet(IpNet),
    /// Arrival interface alias; resolved to a LUID when applying.
    ArrivalIf(String),
    /// Any arrival interface but this one (no condition when the alias does not exist).
    NotArrivalIf(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub conds: Vec<Cond>,
    /// Set on scope blocks: the scope that a drop by this filter is attributed to.
    pub scope_id: Option<String>,
}

fn proto_number(p: Protocol) -> u8 {
    match p {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    }
}

fn host_net(ip: IpAddr) -> IpNet {
    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).expect("full prefix is valid")
}

/// Drop the specs that name an interface alias that does not resolve (`luids` holds the
/// ones that do). An absent adapter receives no traffic, so skipping its block scope
/// leaves nothing open: managed addresses stay covered by the destination blocks, and the
/// engine re-applies when `interfaces_changed` reports the adapter back. Failing the whole
/// apply instead (the earlier choice) left revoked grants in force while an adapter was
/// missing. A `NotArrivalIf` for an absent adapter excludes nothing and is just dropped.
pub(crate) fn drop_unresolved(
    specs: Vec<FilterSpec>,
    luids: &HashMap<String, u64>,
) -> Vec<FilterSpec> {
    let missing = |n: &String| !luids.contains_key(n);
    specs
        .into_iter()
        .filter(|s| {
            !s.conds
                .iter()
                .any(|c| matches!(c, Cond::ArrivalIf(n) if missing(n)))
        })
        .map(|mut s| {
            s.conds
                .retain(|c| !matches!(c, Cond::NotArrivalIf(n) if missing(n)));
            s
        })
        .collect()
}

/// Translate the desired state into filter specs. See the module docs for the layout.
pub(crate) fn plan(desired: &DesiredRuleset) -> Vec<FilterSpec> {
    let mut out = Vec::new();

    if !desired.scopes.is_empty() {
        // Always allowed: loopback (by remote address, independent of WFP's loopback
        // flag) and DHCP client replies (unicast replies are new inbound UDP flows).
        for (layer, net) in [
            (Layer::V6, host_net(Ipv6Addr::LOCALHOST.into())),
            (
                Layer::V4,
                IpNet::new(Ipv4Addr::new(127, 0, 0, 0).into(), 8).unwrap(),
            ),
        ] {
            out.push(FilterSpec {
                name: format!("{NAME_PREFIX} loopback"),
                layer,
                action: Action::Permit,
                weight: W_ALWAYS,
                conds: vec![Cond::Remote(net)],
                scope_id: None,
            });
        }
        // Same-field conditions are ORed, so only one overlay can be excluded; SocketGuard
        // allows a single Yggdrasil network.
        let overlay = desired.overlay_interfaces().first().map(|i| i.to_string());
        for (layer, local, remote, name) in [
            (Layer::V6, 546, 547, "dhcpv6 reply"),
            (Layer::V4, 68, 67, "dhcpv4 reply"),
        ] {
            let mut conds = vec![
                Cond::Proto(17),
                Cond::LocalPort(local),
                Cond::RemotePort(remote),
            ];
            if layer == Layer::V6 {
                // Replies come from a link-local server to our link-local address.
                let link_local: IpNet = "fe80::/10".parse().expect("valid net");
                conds.push(Cond::Remote(link_local));
                conds.push(Cond::LocalNet(link_local));
            }
            conds.extend(overlay.clone().map(Cond::NotArrivalIf));
            out.push(FilterSpec {
                name: format!("{NAME_PREFIX} {name}"),
                layer,
                action: Action::Permit,
                weight: W_ALWAYS,
                conds,
                scope_id: None,
            });
        }
    }

    for rule in &desired.rules {
        let layer = Layer::of(&rule.dst);
        let mut base = vec![
            Cond::LocalAddr(rule.dst),
            Cond::LocalPort(rule.port),
            Cond::Proto(proto_number(rule.proto)),
        ];
        if let Some(iif) = &rule.iif {
            base.push(Cond::ArrivalIf(iif.clone()));
        }
        let name = format!("{NAME_PREFIX} {}", rule.id);
        let spec = |conds| FilterSpec {
            name: name.clone(),
            layer,
            action: Action::Permit,
            weight: W_RULE,
            conds,
            scope_id: None,
        };
        match &rule.sources {
            Sources::Any => out.push(spec(base)),
            Sources::Nets(nets) => {
                for net in nets {
                    if Layer::of(&net.addr()) != layer {
                        tracing::warn!(rule = %rule.id, %net, "source family differs from destination; skipped");
                        continue;
                    }
                    let mut conds = base.clone();
                    conds.push(Cond::Remote(*net));
                    out.push(spec(conds));
                }
            }
        }
    }

    for scope in &desired.scopes {
        let name = format!("{SCOPE_NAME_PREFIX}{}", scope.id);
        let block = |layer, conds| FilterSpec {
            name: name.clone(),
            layer,
            action: Action::Block,
            weight: W_BLOCK,
            conds,
            scope_id: Some(scope.id.clone()),
        };
        match &scope.matcher {
            ScopeMatch::Destinations(addrs) => {
                for a in addrs {
                    out.push(block(Layer::of(a), vec![Cond::LocalAddr(*a)]));
                }
            }
            ScopeMatch::Interface {
                name: iif,
                families,
            } => {
                let layers: &[Layer] = match families {
                    Families::V6 => &[Layer::V6],
                    Families::V4 => &[Layer::V4],
                    Families::Both => &[Layer::V6, Layer::V4],
                };
                for l in layers {
                    out.push(block(*l, vec![Cond::ArrivalIf(iif.clone())]));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Thin RAII wrappers over the raw API
// ---------------------------------------------------------------------------

fn check(what: &str, rc: u32) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "{what} failed: 0x{rc:08X}{}",
            if rc == 5 {
                " (access denied, run elevated)"
            } else {
                ""
            }
        ))
    }
}

/// Like [`check`] but also accepts the given codes.
fn check_or(what: &str, rc: u32, tolerated: &[u32]) -> Result<()> {
    if tolerated.contains(&rc) {
        Ok(())
    } else {
        check(what, rc)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct Engine(HANDLE);

// The engine handle is an RPC handle usable from any thread.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        check("FwpmEngineOpen0", unsafe {
            FwpmEngineOpen0(PCWSTR::null(), AUTHN_DEFAULT, None, None, &mut h)
        })?;
        Ok(Engine(h))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// A transaction that aborts unless committed.
struct Txn<'a> {
    engine: &'a Engine,
    done: bool,
}

impl<'a> Txn<'a> {
    fn begin(engine: &'a Engine) -> Result<Self> {
        check("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(engine.0, 0)
        })?;
        Ok(Txn {
            engine,
            done: false,
        })
    }
    fn commit(mut self) -> Result<()> {
        self.done = true;
        check("FwpmTransactionCommit0", unsafe {
            FwpmTransactionCommit0(self.engine.0)
        })
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.done {
            unsafe { FwpmTransactionAbort0(self.engine.0) };
        }
    }
}

/// Condition values referenced by pointer from `FWPM_FILTER_CONDITION0`. Boxed so the
/// addresses stay stable while the Vecs grow; must outlive the `FwpmFilterAdd0` call.
#[derive(Default)]
#[allow(clippy::vec_box)] // the Box is what keeps the pointed-to values from moving
struct CondStore {
    v6: Vec<Box<FWP_BYTE_ARRAY16>>,
    v6_mask: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    v4_mask: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    luids: Vec<Box<u64>>,
}

fn raw_cond(
    store: &mut CondStore,
    c: &Cond,
    luids: &HashMap<String, u64>,
) -> Result<FWPM_FILTER_CONDITION0> {
    let mut r: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
    r.matchType = FWP_MATCH_EQUAL;
    match c {
        Cond::LocalAddr(ip) => {
            r.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
            match ip {
                IpAddr::V6(a) => {
                    let mut b = Box::new(FWP_BYTE_ARRAY16 {
                        byteArray16: a.octets(),
                    });
                    r.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    r.conditionValue.Anonymous.byteArray16 = &mut *b;
                    store.v6.push(b);
                }
                IpAddr::V4(a) => {
                    r.conditionValue.r#type = FWP_UINT32;
                    r.conditionValue.Anonymous.uint32 = u32::from(*a); // host order
                }
            }
        }
        Cond::LocalPort(p) => {
            r.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            r.conditionValue.r#type = FWP_UINT16;
            r.conditionValue.Anonymous.uint16 = *p;
        }
        Cond::RemotePort(p) => {
            r.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            r.conditionValue.r#type = FWP_UINT16;
            r.conditionValue.Anonymous.uint16 = *p;
        }
        Cond::Proto(p) => {
            r.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            r.conditionValue.r#type = FWP_UINT8;
            r.conditionValue.Anonymous.uint8 = *p;
        }
        Cond::Remote(net) | Cond::LocalNet(net) => {
            r.fieldKey = if matches!(c, Cond::LocalNet(_)) {
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            } else {
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            };
            match net {
                IpNet::V6(n) if n.prefix_len() == 128 => {
                    let mut b = Box::new(FWP_BYTE_ARRAY16 {
                        byteArray16: n.addr().octets(),
                    });
                    r.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    r.conditionValue.Anonymous.byteArray16 = &mut *b;
                    store.v6.push(b);
                }
                IpNet::V6(n) => {
                    let mut b = Box::new(FWP_V6_ADDR_AND_MASK {
                        addr: n.network().octets(),
                        prefixLength: n.prefix_len(),
                    });
                    r.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    r.conditionValue.Anonymous.v6AddrMask = &mut *b;
                    store.v6_mask.push(b);
                }
                IpNet::V4(n) if n.prefix_len() == 32 => {
                    r.conditionValue.r#type = FWP_UINT32;
                    r.conditionValue.Anonymous.uint32 = u32::from(n.addr());
                }
                IpNet::V4(n) => {
                    let mut b = Box::new(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from(n.network()),
                        mask: u32::from(n.netmask()),
                    });
                    r.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    r.conditionValue.Anonymous.v4AddrMask = &mut *b;
                    store.v4_mask.push(b);
                }
            }
        }
        Cond::ArrivalIf(name) | Cond::NotArrivalIf(name) => {
            let luid = *luids
                .get(name)
                .ok_or_else(|| anyhow!("interface {name} not resolved"))?;
            let mut b = Box::new(luid);
            if matches!(c, Cond::NotArrivalIf(_)) {
                r.matchType = FWP_MATCH_NOT_EQUAL;
            }
            r.fieldKey = FWPM_CONDITION_IP_ARRIVAL_INTERFACE;
            r.conditionValue.r#type = FWP_UINT64;
            r.conditionValue.Anonymous.uint64 = &mut *b;
            store.luids.push(b);
        }
    }
    Ok(r)
}

fn resolve_luid(alias: &str) -> Option<u64> {
    let w = wide(alias);
    let mut luid = NET_LUID_LH::default();
    let rc = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(w.as_ptr()), &mut luid) };
    if rc.0 == 0 {
        Some(unsafe { luid.Value })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

struct Keys {
    provider: GUID,
    sublayer: GUID,
}

struct CallbackCtx {
    sink: DropSink,
    /// filter id -> scope id, for our block filters. Rebuilt after each apply.
    filters: Arc<Mutex<HashMap<u64, Option<String>>>>,
    window: Mutex<(Instant, u32)>,
}

struct DropSubscription {
    engine: Engine,
    handle: HANDLE,
    ctx: *mut CallbackCtx,
}

unsafe impl Send for DropSubscription {}

impl Drop for DropSubscription {
    fn drop(&mut self) {
        unsafe {
            // Unsubscribing waits for in-flight callbacks, so freeing ctx afterwards is safe.
            FwpmNetEventUnsubscribe0(self.engine.0, self.handle);
            drop(Box::from_raw(self.ctx));
        }
    }
}

pub struct WfpFirewall {
    keys: Keys,
    /// Alias to LUID (None: did not resolve) as of the last successful apply.
    applied_luids: Mutex<HashMap<String, Option<u64>>>,
    filters: Arc<Mutex<HashMap<u64, Option<String>>>>,
    sub: Mutex<Option<DropSubscription>>,
}

impl WfpFirewall {
    pub fn new() -> Self {
        Self::with_keys(Keys {
            provider: PROVIDER_KEY,
            sublayer: SUBLAYER_KEY,
        })
    }

    /// Uses provider/sublayer keys distinct from production, for integration tests.
    #[allow(dead_code)]
    pub fn new_for_test() -> Self {
        Self::with_keys(Keys {
            provider: TEST_PROVIDER_KEY,
            sublayer: TEST_SUBLAYER_KEY,
        })
    }

    fn with_keys(keys: Keys) -> Self {
        WfpFirewall {
            keys,
            applied_luids: Mutex::default(),
            filters: Arc::default(),
            sub: Mutex::new(None),
        }
    }

    fn provider_ptr(&self) -> *mut GUID {
        &self.keys.provider as *const GUID as *mut GUID
    }

    fn ensure_provider_and_sublayer(&self, e: &Engine) -> Result<()> {
        let mut pn = wide("SocketGuard");
        let mut p: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        p.providerKey = self.keys.provider;
        p.displayData.name = PWSTR(pn.as_mut_ptr());
        p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        check_or(
            "FwpmProviderAdd0",
            unsafe { FwpmProviderAdd0(e.0, &p, None) },
            &[FWP_E_ALREADY_EXISTS],
        )?;

        let mut sn = wide("SocketGuard sublayer");
        let mut s: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        s.subLayerKey = self.keys.sublayer;
        s.displayData.name = PWSTR(sn.as_mut_ptr());
        s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        s.providerKey = self.provider_ptr();
        s.weight = 0xFFFF; // evaluated before every other sublayer
        check_or(
            "FwpmSubLayerAdd0",
            unsafe { FwpmSubLayerAdd0(e.0, &s, None) },
            &[FWP_E_ALREADY_EXISTS],
        )
    }

    /// All filters of our provider (at the two layers we use) as (id, display name).
    fn enum_filters(&self, e: &Engine) -> Result<Vec<(u64, String)>> {
        let mut out = Vec::new();
        for layer in [Layer::V4, Layer::V6] {
            let mut t: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
            t.providerKey = self.provider_ptr();
            t.layerKey = layer.key();
            t.enumType = FWP_FILTER_ENUM_OVERLAPPING;
            t.actionMask = 0xFFFF_FFFF; // must be set, or nothing matches
            let mut h = HANDLE::default();
            check("FwpmFilterCreateEnumHandle0", unsafe {
                FwpmFilterCreateEnumHandle0(e.0, Some(&t), &mut h)
            })?;
            let res = (|| -> Result<()> {
                loop {
                    let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                    let mut n = 0u32;
                    check("FwpmFilterEnum0", unsafe {
                        FwpmFilterEnum0(e.0, h, 100, &mut entries, &mut n)
                    })?;
                    for i in 0..n as usize {
                        let f = unsafe { &**entries.add(i) };
                        let name = unsafe { f.displayData.name.to_string() }.unwrap_or_default();
                        out.push((f.filterId, name));
                    }
                    unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
                    if n < 100 {
                        return Ok(());
                    }
                }
            })();
            unsafe { FwpmFilterDestroyEnumHandle0(e.0, h) };
            res?;
        }
        Ok(out)
    }

    fn add_filter(
        &self,
        e: &Engine,
        spec: &FilterSpec,
        luids: &HashMap<String, u64>,
    ) -> Result<()> {
        let mut store = CondStore::default();
        let mut conds = spec
            .conds
            .iter()
            .map(|c| raw_cond(&mut store, c, luids))
            .collect::<Result<Vec<_>>>()?;
        let mut name = wide(&spec.name);
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.displayData.name = PWSTR(name.as_mut_ptr());
        f.layerKey = spec.layer.key();
        f.subLayerKey = self.keys.sublayer;
        f.providerKey = self.provider_ptr();
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = spec.weight;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = conds.as_mut_ptr();
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        match spec.action {
            Action::Permit => {
                f.action.r#type = FWP_ACTION_PERMIT;
                f.flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            }
            Action::Block => f.action.r#type = FWP_ACTION_BLOCK,
        }
        // `store`, `conds` and `name` are alive until after this call.
        let rc = unsafe { FwpmFilterAdd0(e.0, &f, None, None) };
        drop(store);
        check(&format!("FwpmFilterAdd0({})", spec.name), rc)
    }

    fn delete_our_filters(&self, e: &Engine) -> Result<()> {
        for (id, _) in self.enum_filters(e)? {
            check_or(
                "FwpmFilterDeleteById0",
                unsafe { FwpmFilterDeleteById0(e.0, id) },
                &[FWP_E_FILTER_NOT_FOUND],
            )?;
        }
        Ok(())
    }

    /// Rebuild the filter id -> scope id map used to attribute drop events.
    fn refresh_filter_map(&self, e: &Engine) -> Result<()> {
        let map = self
            .enum_filters(e)?
            .into_iter()
            .map(|(id, name)| (id, name.strip_prefix(SCOPE_NAME_PREFIX).map(str::to_owned)))
            .collect();
        *self.filters.lock().unwrap() = map;
        Ok(())
    }

    /// Test helper: (our filter count, sublayer exists, provider exists).
    #[allow(dead_code)]
    pub fn state(&self) -> Result<(usize, bool, bool)> {
        let e = Engine::open()?;
        let n = self.enum_filters(&e)?.len();
        let mut sl: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmSubLayerGetByKey0(e.0, &self.keys.sublayer, &mut sl) };
        let sublayer = rc == 0;
        if sublayer {
            unsafe { FwpmFreeMemory0(&mut sl as *mut _ as *mut *mut c_void) };
        } else {
            check_or("FwpmSubLayerGetByKey0", rc, &[FWP_E_SUBLAYER_NOT_FOUND])?;
        }
        let mut pr: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmProviderGetByKey0(e.0, &self.keys.provider, &mut pr) };
        let provider = rc == 0;
        if provider {
            unsafe { FwpmFreeMemory0(&mut pr as *mut _ as *mut *mut c_void) };
        } else {
            check_or("FwpmProviderGetByKey0", rc, &[FWP_E_PROVIDER_NOT_FOUND])?;
        }
        Ok((n, sublayer, provider))
    }
}

impl Default for WfpFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl Firewall for WfpFirewall {
    fn apply(&self, desired: &DesiredRuleset) -> Result<()> {
        let specs = plan(desired);

        // Resolve interface aliases up front.
        let mut resolved: HashMap<String, Option<u64>> = HashMap::new();
        for c in specs.iter().flat_map(|s| &s.conds) {
            if let Cond::ArrivalIf(n) | Cond::NotArrivalIf(n) = c {
                resolved.entry(n.clone()).or_insert_with(|| resolve_luid(n));
            }
        }
        let luids: HashMap<String, u64> = resolved
            .iter()
            .filter_map(|(n, l)| l.map(|l| (n.clone(), l)))
            .collect();
        for n in resolved.iter().filter(|(_, l)| l.is_none()).map(|(n, _)| n) {
            tracing::warn!(interface = %n, "interface not found; filters for it skipped until it returns");
        }
        let specs = drop_unresolved(specs, &luids);

        let e = Engine::open()?;
        {
            let txn = Txn::begin(&e)?;
            self.ensure_provider_and_sublayer(&e)?;
            self.delete_our_filters(&e)?;
            for s in &specs {
                self.add_filter(&e, s, &luids)?;
            }
            txn.commit()?; // any early return above aborts via Txn::drop
        }
        *self.applied_luids.lock().unwrap() = resolved;
        if let Err(err) = self.refresh_filter_map(&e) {
            tracing::warn!("could not refresh drop attribution map: {err:#}");
        }
        Ok(())
    }

    fn verify(&self) -> Result<bool> {
        // `apply` always creates the provider and `disable` removes it, so its presence is
        // the sign that SocketGuard's state is installed (an empty ruleset has no filters).
        let e = Engine::open()?;
        let mut pr: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmProviderGetByKey0(e.0, &self.keys.provider, &mut pr) };
        if rc == 0 {
            unsafe { FwpmFreeMemory0(&mut pr as *mut _ as *mut *mut c_void) };
            return Ok(true);
        }
        check_or("FwpmProviderGetByKey0", rc, &[FWP_E_PROVIDER_NOT_FOUND])?;
        Ok(false)
    }

    fn interfaces_changed(&self) -> bool {
        self.applied_luids
            .lock()
            .unwrap()
            .iter()
            .any(|(alias, luid)| resolve_luid(alias) != *luid)
    }

    fn disable(&self) -> Result<()> {
        let e = Engine::open()?;
        let txn = Txn::begin(&e)?;
        self.delete_our_filters(&e)?;
        check_or(
            "FwpmSubLayerDeleteByKey0",
            unsafe { FwpmSubLayerDeleteByKey0(e.0, &self.keys.sublayer) },
            &[FWP_E_SUBLAYER_NOT_FOUND],
        )?;
        check_or(
            "FwpmProviderDeleteByKey0",
            unsafe { FwpmProviderDeleteByKey0(e.0, &self.keys.provider) },
            &[FWP_E_PROVIDER_NOT_FOUND],
        )?;
        txn.commit()?;
        self.filters.lock().unwrap().clear();
        self.applied_luids.lock().unwrap().clear();
        Ok(())
    }

    // counters(): WFP exposes no cheap per-filter packet counters; the trait default
    // (empty) is used. Drops are reported through subscribe_drops instead.

    fn subscribe_drops(&self, sink: DropSink) -> Result<()> {
        let mut slot = self.sub.lock().unwrap();
        if slot.is_some() {
            bail!("drop events already subscribed");
        }
        // Dedicated handle, kept for the lifetime of the subscription.
        let engine = Engine::open()?;
        let one = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: 1 },
        };
        check("FwpmEngineSetOption0", unsafe {
            FwpmEngineSetOption0(engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &one)
        })?;
        if let Err(err) = self.refresh_filter_map(&engine) {
            tracing::warn!("could not load drop attribution map: {err:#}");
        }
        let ctx = Box::into_raw(Box::new(CallbackCtx {
            sink,
            filters: self.filters.clone(),
            window: Mutex::new((Instant::now(), 0)),
        }));
        let sub: FWPM_NET_EVENT_SUBSCRIPTION0 = unsafe { std::mem::zeroed() };
        let mut handle = HANDLE::default();
        let rc = unsafe {
            FwpmNetEventSubscribe0(
                engine.0,
                &sub,
                Some(on_event),
                Some(ctx as *const c_void),
                &mut handle,
            )
        };
        if let Err(err) = check("FwpmNetEventSubscribe0", rc) {
            drop(unsafe { Box::from_raw(ctx) });
            return Err(err);
        }
        *slot = Some(DropSubscription {
            engine,
            handle,
            ctx,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drop events
// ---------------------------------------------------------------------------

fn filetime_to_system_time(ft: &windows::Win32::Foundation::FILETIME) -> SystemTime {
    const UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let t = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    match t.checked_sub(UNIX_EPOCH_100NS) {
        Some(d) => UNIX_EPOCH + Duration::from_nanos(d * 100),
        None => SystemTime::now(),
    }
}

unsafe extern "system" fn on_event(context: *mut c_void, event: *const FWPM_NET_EVENT1) {
    if context.is_null() || event.is_null() {
        return;
    }
    // Never unwind across the FFI boundary.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        handle_event(&*(context as *const CallbackCtx), &*event)
    }));
}

fn handle_event(ctx: &CallbackCtx, ev: &FWPM_NET_EVENT1) {
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    let drop_info = unsafe { ev.Anonymous.classifyDrop };
    if drop_info.is_null() {
        return;
    }
    // Only drops by our own filters; the map holds exactly our filter ids.
    let filter_id = unsafe { (*drop_info).filterId };
    let scope_id = match ctx.filters.lock().unwrap().get(&filter_id) {
        Some(s) => s.clone(),
        None => return,
    };

    let h = &ev.header;
    let (src, dst) = unsafe {
        if h.ipVersion == FWP_IP_VERSION_V6 {
            (
                IpAddr::V6(Ipv6Addr::from(h.Anonymous2.remoteAddrV6.byteArray16)),
                IpAddr::V6(Ipv6Addr::from(h.Anonymous1.localAddrV6.byteArray16)),
            )
        } else if h.ipVersion == FWP_IP_VERSION_V4 {
            (
                IpAddr::V4(Ipv4Addr::from(h.Anonymous2.remoteAddrV4)),
                IpAddr::V4(Ipv4Addr::from(h.Anonymous1.localAddrV4)),
            )
        } else {
            return;
        }
    };

    {
        let mut w = ctx.window.lock().unwrap();
        if w.0.elapsed() >= Duration::from_secs(1) {
            *w = (Instant::now(), 0);
        }
        if w.1 >= MAX_EVENTS_PER_SEC {
            return;
        }
        w.1 += 1;
    }

    (ctx.sink)(DropEvent {
        at: filetime_to_system_time(&h.timeStamp),
        src,
        dst,
        port: Some(h.localPort),
        proto: match h.ipProtocol {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            _ => None,
        },
        iif: None, // not carried by classify-drop events
        scope_id,
    });
}

impl Drop for WfpFirewall {
    fn drop(&mut self) {
        // Filters stay (frozen state); only the event subscription and its handle go.
        self.sub.lock().ok().and_then(|mut s| s.take());
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Rule, Scope, ScopeKind};
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn scope(id: &str, m: ScopeMatch) -> Scope {
        Scope {
            id: id.into(),
            kind: ScopeKind::ManagedAddresses,
            matcher: m,
        }
    }
    fn rule(id: &str, dst: &str, iif: Option<&str>, sources: Sources) -> Rule {
        Rule {
            id: id.into(),
            iif: iif.map(Into::into),
            dst: ip(dst),
            port: 8080,
            proto: Protocol::Tcp,
            sources,
        }
    }
    fn with_name<'a>(v: &'a [FilterSpec], n: &str) -> Vec<&'a FilterSpec> {
        v.iter().filter(|s| s.name == n).collect()
    }

    #[test]
    fn empty_ruleset_plans_nothing() {
        assert!(plan(&DesiredRuleset::default()).is_empty());
    }

    #[test]
    fn always_allowed_present_when_scoped() {
        let d = DesiredRuleset {
            scopes: vec![scope("s", ScopeMatch::Destinations(vec![ip("fd00::1")]))],
            rules: vec![],
        };
        let p = plan(&d);
        let permits: Vec<_> = p.iter().filter(|s| s.weight == W_ALWAYS).collect();
        assert_eq!(permits.len(), 4);
        assert!(permits.iter().all(|s| s.action == Action::Permit));
        assert!(permits
            .iter()
            .any(|s| s.layer == Layer::V6 && s.conds == vec![Cond::Remote(net("::1/128"))]));
        assert!(permits
            .iter()
            .any(|s| s.layer == Layer::V4 && s.conds == vec![Cond::Remote(net("127.0.0.0/8"))]));
        assert!(permits
            .iter()
            .any(|s| s.conds.contains(&Cond::LocalPort(546))
                && s.conds.contains(&Cond::RemotePort(547))
                && s.conds.contains(&Cond::Remote(net("fe80::/10")))));
        // DHCPv4 has no link-local source to require.
        assert!(permits.iter().any(|s| s.layer == Layer::V4
            && s.conds.contains(&Cond::RemotePort(67))
            && !s.conds.iter().any(|c| matches!(c, Cond::Remote(_)))));
    }

    #[test]
    fn dhcp_permits_exclude_the_overlay_interface() {
        let d = DesiredRuleset {
            scopes: vec![Scope {
                id: "overlay:ygg0".into(),
                kind: ScopeKind::Overlay,
                matcher: ScopeMatch::Interface {
                    name: "ygg0".into(),
                    families: Families::Both,
                },
            }],
            rules: vec![],
        };
        let p = plan(&d);
        let dhcp: Vec<_> = p.iter().filter(|s| s.name.contains("dhcp")).collect();
        assert_eq!(dhcp.len(), 2);
        assert!(dhcp
            .iter()
            .all(|s| s.conds.contains(&Cond::NotArrivalIf("ygg0".into()))));
    }

    #[test]
    fn dhcpv6_reply_is_link_local_to_link_local() {
        let d = DesiredRuleset {
            scopes: vec![scope(
                "managed",
                ScopeMatch::Destinations(vec![ip("fd00::1")]),
            )],
            rules: vec![],
        };
        let p = plan(&d);
        let v6 = p
            .iter()
            .find(|s| s.name.ends_with("dhcpv6 reply"))
            .expect("dhcpv6 permit");
        assert!(v6.conds.contains(&Cond::Remote(net("fe80::/10"))));
        assert!(v6.conds.contains(&Cond::LocalNet(net("fe80::/10"))));
    }

    #[test]
    fn unresolved_interface_scope_is_skipped_not_fatal() {
        let d = DesiredRuleset {
            scopes: vec![
                scope(
                    "managed",
                    ScopeMatch::Destinations(vec![ip("fd00::1"), ip("301::1")]),
                ),
                Scope {
                    id: "overlay:ygg0".into(),
                    kind: ScopeKind::Overlay,
                    matcher: ScopeMatch::Interface {
                        name: "ygg0".into(),
                        families: Families::Both,
                    },
                },
                scope(
                    "host:Ethernet",
                    ScopeMatch::Interface {
                        name: "Ethernet".into(),
                        families: Families::V6,
                    },
                ),
            ],
            rules: vec![rule(
                "r",
                "fd00::1",
                Some("Ethernet"),
                Sources::Nets(vec![net("fd00::2/128")]),
            )],
        };
        let all = plan(&d);
        let only_ethernet = HashMap::from([("Ethernet".to_string(), 7u64)]);
        let kept = drop_unresolved(all.clone(), &only_ethernet);
        // The absent adapter's block (V6 and V4) is gone, everything else stays: the
        // managed-address blocks, the Ethernet block and the Ethernet permit.
        assert_eq!(all.len() - kept.len(), 2);
        assert!(kept
            .iter()
            .all(|s| !s.conds.contains(&Cond::ArrivalIf("ygg0".into()))));
        assert_eq!(
            kept.iter()
                .filter(|s| s.action == Action::Block && s.scope_id.as_deref() == Some("managed"))
                .count(),
            2
        );
        assert!(kept
            .iter()
            .any(|s| s.conds.contains(&Cond::ArrivalIf("Ethernet".into()))
                && s.action == Action::Permit));
        // The overlay exclusion of the DHCP permits disappears with the adapter.
        assert!(all
            .iter()
            .any(|s| s.conds.contains(&Cond::NotArrivalIf("ygg0".into()))));
        assert!(kept
            .iter()
            .filter(|s| s.name.contains("dhcp"))
            .all(|s| !s.conds.iter().any(|c| matches!(c, Cond::NotArrivalIf(_)))));
        // With every interface present nothing is dropped.
        let both = HashMap::from([("Ethernet".to_string(), 7u64), ("ygg0".to_string(), 8u64)]);
        assert_eq!(drop_unresolved(all.clone(), &both), all);
    }

    #[test]
    fn destination_scope_blocks_per_address_and_family() {
        let d = DesiredRuleset {
            scopes: vec![scope(
                "managed",
                ScopeMatch::Destinations(vec![ip("fd00::1"), ip("10.0.0.1")]),
            )],
            rules: vec![],
        };
        let p = plan(&d);
        let b = with_name(&p, "SocketGuard scope:managed");
        assert_eq!(b.len(), 2);
        assert!(b.iter().all(|s| s.action == Action::Block
            && s.weight == W_BLOCK
            && s.scope_id.as_deref() == Some("managed")));
        assert!(b
            .iter()
            .any(|s| s.layer == Layer::V6 && s.conds == vec![Cond::LocalAddr(ip("fd00::1"))]));
        assert!(b
            .iter()
            .any(|s| s.layer == Layer::V4 && s.conds == vec![Cond::LocalAddr(ip("10.0.0.1"))]));
    }

    #[test]
    fn interface_scope_families() {
        let mk = |f| DesiredRuleset {
            scopes: vec![scope(
                "ygg",
                ScopeMatch::Interface {
                    name: "ygg0".into(),
                    families: f,
                },
            )],
            rules: vec![],
        };
        let blocks = |f| -> Vec<Layer> {
            plan(&mk(f))
                .iter()
                .filter(|s| s.action == Action::Block)
                .map(|s| s.layer)
                .collect()
        };
        assert_eq!(blocks(Families::V6), vec![Layer::V6]);
        assert_eq!(blocks(Families::V4), vec![Layer::V4]);
        assert_eq!(blocks(Families::Both), vec![Layer::V6, Layer::V4]);
        let p = plan(&mk(Families::V6));
        let b = p.iter().find(|s| s.action == Action::Block).unwrap();
        assert_eq!(b.conds, vec![Cond::ArrivalIf("ygg0".into())]);
    }

    #[test]
    fn rule_with_nets_makes_one_permit_per_net_with_iif() {
        let d = DesiredRuleset {
            scopes: vec![],
            rules: vec![rule(
                "r1",
                "fd00::1",
                Some("ygg0"),
                Sources::Nets(vec![net("200::/7"), net("fd00::5/128")]),
            )],
        };
        let p = plan(&d);
        assert_eq!(p.len(), 2);
        for s in &p {
            assert_eq!(s.action, Action::Permit);
            assert_eq!(s.layer, Layer::V6);
            assert_eq!(s.weight, W_RULE);
            assert!(s.conds.contains(&Cond::LocalAddr(ip("fd00::1"))));
            assert!(s.conds.contains(&Cond::LocalPort(8080)));
            assert!(s.conds.contains(&Cond::Proto(6)));
            assert!(s.conds.contains(&Cond::ArrivalIf("ygg0".into())));
        }
        assert!(p[0].conds.contains(&Cond::Remote(net("200::/7"))));
        assert!(p[1].conds.contains(&Cond::Remote(net("fd00::5/128"))));
    }

    #[test]
    fn rule_any_source_v4_udp_has_no_remote_condition() {
        let mut r = rule("r2", "10.0.0.1", None, Sources::Any);
        r.proto = Protocol::Udp;
        let p = plan(&DesiredRuleset {
            scopes: vec![],
            rules: vec![r],
        });
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].layer, Layer::V4);
        assert!(p[0].conds.contains(&Cond::Proto(17)));
        assert!(!p[0]
            .conds
            .iter()
            .any(|c| matches!(c, Cond::Remote(_) | Cond::ArrivalIf(_))));
    }

    #[test]
    fn mismatched_source_family_is_skipped() {
        let d = DesiredRuleset {
            scopes: vec![],
            rules: vec![rule(
                "r3",
                "fd00::1",
                None,
                Sources::Nets(vec![net("10.0.0.0/8"), net("fd00::/8")]),
            )],
        };
        let p = plan(&d);
        assert_eq!(p.len(), 1);
        assert!(p[0].conds.contains(&Cond::Remote(net("fd00::/8"))));
    }

    #[test]
    fn permits_outweigh_blocks() {
        const { assert!(W_ALWAYS > W_RULE && W_RULE > W_BLOCK) };
        const { assert!(W_ALWAYS <= 15) }; // FWP_UINT8 weights are 0..=15
    }

    #[test]
    fn raw_conditions_for_masks_and_hosts() {
        let mut store = CondStore::default();
        let luids = HashMap::from([("ygg0".to_string(), 42u64)]);
        let c = raw_cond(&mut store, &Cond::Remote(net("200::/7")), &luids).unwrap();
        assert_eq!(c.conditionValue.r#type, FWP_V6_ADDR_MASK);
        assert_eq!(
            unsafe { (*c.conditionValue.Anonymous.v6AddrMask).prefixLength },
            7
        );
        let c = raw_cond(&mut store, &Cond::Remote(net("10.1.0.0/16")), &luids).unwrap();
        assert_eq!(c.conditionValue.r#type, FWP_V4_ADDR_MASK);
        assert_eq!(
            unsafe { (*c.conditionValue.Anonymous.v4AddrMask).mask },
            0xFFFF_0000
        );
        let c = raw_cond(&mut store, &Cond::Remote(net("10.1.2.3/32")), &luids).unwrap();
        assert_eq!(c.conditionValue.r#type, FWP_UINT32);
        assert_eq!(unsafe { c.conditionValue.Anonymous.uint32 }, 0x0A01_0203);
        let c = raw_cond(&mut store, &Cond::ArrivalIf("ygg0".into()), &luids).unwrap();
        assert_eq!(c.conditionValue.r#type, FWP_UINT64);
        assert_eq!(c.fieldKey, FWPM_CONDITION_IP_ARRIVAL_INTERFACE);
        assert_eq!(c.matchType, FWP_MATCH_EQUAL);
        assert_eq!(unsafe { *c.conditionValue.Anonymous.uint64 }, 42);
        let c = raw_cond(&mut store, &Cond::NotArrivalIf("ygg0".into()), &luids).unwrap();
        assert_eq!(c.matchType, FWP_MATCH_NOT_EQUAL);
        assert!(raw_cond(&mut store, &Cond::ArrivalIf("nope".into()), &luids).is_err());
    }
}
