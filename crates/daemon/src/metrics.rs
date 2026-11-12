//! OpenTelemetry metrics (ADR 0034): gauges for what the daemon manages, counters for what
//! the firewall allowed and dropped. The engine feeds a shared [`Metrics`] on every
//! reconcile pass; the instruments read it when the SDK collects. With no meter provider
//! installed the instruments are no-ops.
//!
//! Attributes are app name, network id and grant subject label for rules, and the scope id
//! for scopes. Source addresses never become attributes (bounded cardinality).

use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use socketguard_core::AppCounter;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// What a firewall counter measures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CounterKey {
    /// Traffic allowed by the rules of one grant subject to one app on one network.
    Rule {
        app_id: String,
        app: String,
        network: String,
        subject: String,
    },
    /// Traffic dropped by a scope.
    Scope { scope: String },
}

impl CounterKey {
    fn attributes(&self) -> Vec<KeyValue> {
        match self {
            CounterKey::Rule {
                app,
                network,
                subject,
                ..
            } => vec![
                KeyValue::new("app", app.clone()),
                KeyValue::new("network", network.clone()),
                KeyValue::new("subject", subject.clone()),
            ],
            CounterKey::Scope { scope } => vec![KeyValue::new("scope", scope.clone())],
        }
    }
}

type AttrKey = Vec<(String, String)>;
/// Attributes, packets, bytes.
type Observation = (Vec<KeyValue>, u64, u64);

#[derive(Default)]
struct Data {
    apps: u64,
    addresses: u64,
    peers: u64,
    grants: u64,
    /// Cumulative packets and bytes per key, surviving rule re-applies (which reset the
    /// firewall's own counters).
    totals: HashMap<CounterKey, (u64, u64)>,
    /// The last raw reading per counter id, to turn readings into deltas.
    last: HashMap<String, (u64, u64)>,
}

/// Shared between the engine (writer) and the instruments (readers).
#[derive(Clone, Default)]
pub struct Metrics {
    data: Arc<Mutex<Data>>,
}

impl Metrics {
    pub fn set_counts(&self, apps: usize, addresses: usize, peers: usize, grants: usize) {
        let mut d = self.data.lock().unwrap();
        d.apps = apps as u64;
        d.addresses = addresses as u64;
        d.peers = peers as u64;
        d.grants = grants as u64;
    }

    /// Fold a counter reading into the totals. A reading below the previous one means the
    /// firewall restarted the counter (the table is replaced on every apply), so the new
    /// value counts in full.
    pub fn record(&self, readings: impl IntoIterator<Item = (String, CounterKey, u64, u64)>) {
        let mut d = self.data.lock().unwrap();
        let mut seen = HashSet::new();
        for (id, key, packets, bytes) in readings {
            let (lp, lb) = d.last.get(&id).copied().unwrap_or((0, 0));
            let delta = |now: u64, last: u64| if now >= last { now - last } else { now };
            let (dp, db) = (delta(packets, lp), delta(bytes, lb));
            let t = d.totals.entry(key).or_default();
            t.0 += dp;
            t.1 += db;
            d.last.insert(id.clone(), (packets, bytes));
            seen.insert(id);
        }
        // Counters that no longer exist start from zero if they come back.
        d.last.retain(|id, _| seen.contains(id));
    }

    /// Forget the series of rules and scopes that are not in `live` (the keys of the ruleset
    /// that was just applied), so removed apps and grants do not accumulate forever.
    pub fn retain_series<'a>(&self, live: impl IntoIterator<Item = &'a CounterKey>) {
        let live: HashSet<&CounterKey> = live.into_iter().collect();
        self.data
            .lock()
            .unwrap()
            .totals
            .retain(|k, _| live.contains(k));
    }

    /// The firewall's counters start over: call after a ruleset was applied, so the next
    /// readings count in full.
    pub fn counters_reset(&self) {
        self.data.lock().unwrap().last.clear();
    }

    /// Allowed traffic of one app, per network and grant subject.
    pub fn app_counters(&self, app_id: &str) -> Vec<AppCounter> {
        let d = self.data.lock().unwrap();
        let mut out: Vec<AppCounter> = d
            .totals
            .iter()
            .filter_map(|(k, (p, b))| match k {
                CounterKey::Rule {
                    app_id: a,
                    network,
                    subject,
                    ..
                } if a == app_id => Some(AppCounter {
                    network_id: network.clone(),
                    subject: subject.clone(),
                    packets: *p,
                    bytes: *b,
                }),
                _ => None,
            })
            .collect();
        out.sort_by(|a, b| (&a.network_id, &a.subject).cmp(&(&b.network_id, &b.subject)));
        out
    }

    /// Totals summed per attribute set (several apps' rules can share one).
    fn observations(&self) -> Vec<Observation> {
        let d = self.data.lock().unwrap();
        let mut by_attrs: HashMap<AttrKey, Observation> = HashMap::new();
        for (k, (p, b)) in &d.totals {
            let attrs = k.attributes();
            let id: AttrKey = attrs
                .iter()
                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                .collect();
            let e = by_attrs.entry(id).or_insert((attrs, 0, 0));
            e.1 += p;
            e.2 += b;
        }
        by_attrs.into_values().collect()
    }

    /// Create the instruments on `meter`. Call once.
    pub fn register(&self, meter: &Meter) {
        for (name, description, get) in [
            (
                "socketguard.apps",
                "Apps SocketGuard knows about",
                (|d: &Data| d.apps) as fn(&Data) -> u64,
            ),
            (
                "socketguard.addresses",
                "Addresses allocated to apps",
                |d| d.addresses,
            ),
            ("socketguard.peers", "Peers", |d| d.peers),
            ("socketguard.grants", "Grants", |d| d.grants),
        ] {
            let m = self.clone();
            meter
                .u64_observable_gauge(name)
                .with_description(description)
                .with_callback(move |o| o.observe(get(&m.data.lock().unwrap()), &[]))
                .build();
        }
        let m = self.clone();
        meter
            .u64_observable_counter("socketguard.firewall.packets")
            .with_description("Packets the firewall allowed (per app, network and subject) or dropped (per scope)")
            .with_callback(move |o| {
                for (attrs, packets, _) in m.observations() {
                    o.observe(packets, &attrs);
                }
            })
            .build();
        let m = self.clone();
        meter
            .u64_observable_counter("socketguard.firewall.bytes")
            .with_unit("By")
            .with_description(
                "Bytes the firewall allowed (per app, network and subject) or dropped (per scope)",
            )
            .with_callback(move |o| {
                for (attrs, _, bytes) in m.observations() {
                    o.observe(bytes, &attrs);
                }
            })
            .build();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(app: &str) -> CounterKey {
        CounterKey::Rule {
            app_id: app.into(),
            app: app.into(),
            network: "ygg".into(),
            subject: "alice".into(),
        }
    }

    #[test]
    fn readings_become_totals_and_survive_resets() {
        let m = Metrics::default();
        m.record([("r1".into(), rule("a"), 10, 100)]);
        m.record([("r1".into(), rule("a"), 15, 150)]);
        assert_eq!(m.app_counters("a")[0].packets, 15);
        // The firewall table was replaced: the reading starts over.
        m.record([("r1".into(), rule("a"), 2, 20)]);
        let c = &m.app_counters("a")[0];
        assert_eq!((c.packets, c.bytes), (17, 170));
        assert!(m.app_counters("b").is_empty());
    }

    #[test]
    fn series_of_removed_rules_are_forgotten() {
        let m = Metrics::default();
        m.record([
            ("r1".into(), rule("a"), 1, 10),
            ("r2".into(), rule("b"), 2, 20),
        ]);
        m.retain_series([&rule("a")]);
        assert_eq!(m.app_counters("a")[0].packets, 1);
        assert!(m.app_counters("b").is_empty());
        assert_eq!(m.observations().len(), 1);
    }

    #[test]
    fn rules_of_one_attribute_set_are_summed() {
        let m = Metrics::default();
        m.record([
            ("r1".into(), rule("a"), 1, 10),
            ("r2".into(), rule("a"), 2, 20),
        ]);
        let obs = m.observations();
        assert_eq!(obs.len(), 1);
        assert_eq!((obs[0].1, obs[0].2), (3, 30));
    }
}
