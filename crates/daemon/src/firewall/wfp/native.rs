use super::plan::{self, Action, Cond, FilterSpec, Layer, SCOPE_NAME_PREFIX};
use crate::firewall::{DesiredRuleset, DropEvent, DropSink, Firewall};
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
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const AUTHN_DEFAULT: u32 = 0xFFFF_FFFF; // RPC_C_AUTHN_DEFAULT
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;

/// "SOCKGUARD" in ASCII, so the objects are recognisable in `netsh wfp show state`.
const PROVIDER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_000000000001);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x534f434b_4755_4152_4400_000000000002);

/// Drop events per second handed to the sink; the rest are discarded.
const MAX_EVENTS_PER_SEC: u32 = 50;

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::V4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::V6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
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
    ranges: Vec<Box<FWP_RANGE0>>,
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
        Cond::LocalPortRange(low, high) => {
            r.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            r.matchType = FWP_MATCH_RANGE;
            let mut range: Box<FWP_RANGE0> = Box::new(unsafe { std::mem::zeroed() });
            range.valueLow.r#type = FWP_UINT16;
            range.valueLow.Anonymous.uint16 = *low;
            range.valueHigh.r#type = FWP_UINT16;
            range.valueHigh.Anonymous.uint16 = *high;
            r.conditionValue.r#type = FWP_RANGE_TYPE;
            r.conditionValue.Anonymous.rangeValue = &mut *range;
            store.ranges.push(range);
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
    crate::iface::alias_to_luid(alias).map(|luid| unsafe { luid.Value })
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
            t.layerKey = layer_key(layer);
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
        f.layerKey = layer_key(spec.layer);
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
    fn blocks_absent_interfaces(&self) -> bool {
        false
    }

    fn apply(&self, desired: &DesiredRuleset) -> Result<()> {
        let specs = plan::plan(desired);

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
        let specs = plan::drop_unresolved(specs, &luids);

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
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
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

    #[test]
    fn a_port_range_is_a_range_condition_that_outlives_the_call() {
        let mut store = CondStore::default();
        let luids = HashMap::new();
        let c = raw_cond(&mut store, &Cond::LocalPortRange(50000, 51000), &luids).unwrap();
        assert_eq!(c.fieldKey, FWPM_CONDITION_IP_LOCAL_PORT);
        assert_eq!(c.matchType, FWP_MATCH_RANGE);
        assert_eq!(c.conditionValue.r#type, FWP_RANGE_TYPE);
        // The condition points into the store, which keeps the range alive and in place.
        let range = unsafe { &*c.conditionValue.Anonymous.rangeValue };
        assert_eq!(unsafe { range.valueLow.Anonymous.uint16 }, 50000);
        assert_eq!(unsafe { range.valueHigh.Anonymous.uint16 }, 51000);
        assert_eq!(range.valueLow.r#type, FWP_UINT16);
        assert_eq!(store.ranges.len(), 1);
    }
}
