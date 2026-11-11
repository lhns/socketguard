//! Taking SocketGuard off a host: the firewall rules, the addresses on interfaces and the
//! onion services (ADR 0026, 0038, 0050). Used by `--disable`, `uninstall` and the API's
//! `disable`. It never stops at the first failure and reports per item what was removed,
//! what was already absent and what is LEFT; a partial failure keeps the rules (fail closed).

use crate::engine::ADDRESS_PREFIX_LEN;
use crate::firewall::Firewall;
use crate::iface::InterfaceManager;
use crate::networks::{self, ledger, Network};
use crate::report::Report;
use crate::state::Database;
use socketguard_core::{Address, Locator};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// A configured network, or why it could not be built.
pub struct NetworkSlot {
    pub id: String,
    /// A Tor network (the only kind outside the firewall: it holds onion services).
    pub is_tor: bool,
    pub network: Result<Arc<dyn Network>, String>,
}

pub struct DisableInput<'a> {
    pub db: &'a Database,
    /// Network id to interface name.
    pub interfaces: &'a HashMap<String, String>,
    pub networks: Vec<NetworkSlot>,
    pub firewall: Arc<dyn Firewall>,
    pub ifaces: Arc<dyn InterfaceManager>,
    /// What stays reachable over Yggdrasil once the rules are gone (ADR 0051); None when
    /// the caller cannot tell. Reported as notes, so every frontend of the report shows it.
    pub exposure: Option<socketguard_core::api_types::ExposureResponse>,
}

/// Remove everything the database knows about, then the rules.
pub async fn disable_with_db(input: DisableInput<'_>) -> Report {
    let DisableInput {
        db,
        interfaces,
        networks,
        firewall,
        ifaces,
        exposure,
    } = input;
    let mut report = Report::default();
    for sentence in exposure.iter().flat_map(|e| e.sentences()) {
        report.note(sentence);
    }

    // The latch first: nothing puts the rules or addresses back while we remove them.
    if let Err(e) = db.set_disabled(true).await {
        report.left("the disabled latch", format!("could not be stored: {e:#}"));
        return report;
    }
    // Removing the rules answers the unadopted question too.
    let _ = db.set_unadopted(false).await;

    // Addresses from before ownership was recorded are adopted so they are removed too.
    match db.list_addresses().await {
        Ok(list) => {
            for a in list {
                let Some(ip) = a.locator.ipv6() else { continue };
                if let Some(iface) = interfaces.get(&a.network_id) {
                    if let Err(e) = db.retire_address(ip, iface, Some(&a.network_id)).await {
                        warn!("Cannot record {ip} as retiring: {e}");
                    }
                }
            }
        }
        Err(e) => report.left("the address list", format!("cannot be read: {e:#}")),
    }

    // Addresses first: removing the rules first would briefly expose them.
    let mut addresses_left = 0;
    match db.list_owned_addresses().await {
        Ok(owned) => {
            for o in owned {
                if !o.retiring {
                    let _ = db
                        .retire_address(o.addr, &o.interface, o.network_id.as_deref())
                        .await;
                }
                // A DHCPv6 lease is given back before the address goes (best effort).
                if let Some(net) = o
                    .network_id
                    .as_ref()
                    .and_then(|id| networks.iter().find(|s| &s.id == id))
                    .and_then(|s| s.network.as_ref().ok().cloned())
                {
                    let addr = o.addr;
                    if let Ok(Err(e)) =
                        tokio::task::spawn_blocking(move || net.release_lease(addr)).await
                    {
                        warn!("Could not release the lease of {addr}: {e:#}");
                    }
                }
                let what = format!("address {} on {}", o.addr, o.interface);
                let net = ifaces.clone();
                let (iface, addr) = (o.interface.clone(), o.addr);
                let outcome =
                    tokio::task::spawn_blocking(move || remove_confirmed(&*net, &iface, addr))
                        .await;
                match outcome {
                    Ok(Ok(was_there)) => match db.forget_address(o.addr).await {
                        Ok(()) if was_there => report.removed(what),
                        Ok(()) => report.absent(what),
                        Err(e) => {
                            addresses_left += 1;
                            report.left(
                                what,
                                format!("removed, but its record was not deleted: {e:#}"),
                            )
                        }
                    },
                    Ok(Err(e)) => {
                        addresses_left += 1;
                        report.left(what, format!("{e:#}"))
                    }
                    Err(e) => {
                        addresses_left += 1;
                        report.left(what, format!("{e}"))
                    }
                }
            }
        }
        Err(e) => {
            addresses_left += 1;
            report.left("the owned addresses", format!("cannot be read: {e:#}"));
        }
    }

    // Onion services: the ones of the addresses, the ledger and the tombstones.
    report.extend(disable_non_ip(db, &networks).await);

    // The rules stay while any address does: it remains denied.
    if addresses_left > 0 {
        report.left(
            "firewall rules",
            format!(
                "kept on purpose: {addresses_left} address(es) are still on interfaces and stay denied (fail closed); the disabled daemon retries the removal"
            ),
        );
    } else {
        report.extend(disable_firewall_by_name(firewall).await);
    }
    report
}

/// Remove `addr` from `iface` and confirm. Ok(true): it was there and is gone; Ok(false):
/// it was not there.
fn remove_confirmed(
    net: &dyn InterfaceManager,
    iface: &str,
    addr: std::net::Ipv6Addr,
) -> anyhow::Result<bool> {
    let present = net.list_addresses(iface).map(|l| l.contains(&addr));
    if let Ok(false) = present {
        return Ok(false);
    }
    let removed = net.remove_address(iface, addr, ADDRESS_PREFIX_LEN);
    match net.list_addresses(iface) {
        Ok(l) if l.contains(&addr) => Err(removed
            .err()
            .unwrap_or_else(|| anyhow::anyhow!("still on the interface after removal"))),
        Ok(_) => Ok(true),
        // Cannot look: believe the command's own answer.
        Err(_) => removed.map(|()| true),
    }
}

/// The firewall rules by name, without the database. `disable` always runs (it tolerates
/// absence on every backend, and also removes the legacy `ip6` table); the checks before
/// and after only decide the label.
pub async fn disable_firewall_by_name(firewall: Arc<dyn Firewall>) -> Report {
    let mut r = Report::default();
    let what = "firewall rules";
    let fw = firewall.clone();
    let before = tokio::task::spawn_blocking(move || fw.verify())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(|x| x);
    let fw = firewall.clone();
    match tokio::task::spawn_blocking(move || fw.disable()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            r.left(what, format!("{e:#}"));
            return r;
        }
        Err(e) => {
            r.left(what, format!("{e}"));
            return r;
        }
    }
    let fw = firewall;
    match tokio::task::spawn_blocking(move || fw.verify()).await {
        Ok(Ok(false)) if matches!(before, Ok(false)) => r.absent(what),
        Ok(Ok(false)) => r.removed(what),
        Ok(Ok(true)) => r.left(what, "still present after removal"),
        Ok(Err(e)) => {
            r.removed(what);
            r.items.last_mut().unwrap().note = Some(format!("removal not re-verified: {e:#}"));
        }
        Err(e) => r.left(what, format!("{e}")),
    }
    r
}

/// Onion services: those of the addresses, the ledger and the tombstones. An unreachable
/// Tor, an invalid Tor network or ledger ids with no Tor network at all leave them and say
/// which.
async fn disable_non_ip(db: &Database, slots: &[NetworkSlot]) -> Report {
    let mut r = Report::default();
    let addresses = match db.list_addresses().await {
        Ok(a) => a,
        Err(e) => {
            r.left(
                "onion services",
                format!("the address list cannot be read: {e:#}"),
            );
            return r;
        }
    };
    let ledger_ids = match ledger::load(db).await {
        Ok(l) => l
            .owned
            .union(&l.tombstones)
            .cloned()
            .collect::<BTreeSet<_>>(),
        Err(e) => {
            r.left(
                "onion services",
                format!("the Tor ledger cannot be read: {e:#}"),
            );
            return r;
        }
    };
    let list_of = |ids: &BTreeSet<String>| {
        ids.iter()
            .map(|i| format!("{i}.onion"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let tor_slots: Vec<&NetworkSlot> = slots.iter().filter(|s| s.is_tor).collect();
    if tor_slots.is_empty() {
        let mut ids = ledger_ids.clone();
        ids.extend(
            addresses
                .iter()
                .filter_map(|a| networks::tor::service_id(&a.locator)),
        );
        if !ids.is_empty() {
            r.left(
                "onion services",
                format!(
                    "no Tor network is configured, so these were not checked or removed: {}",
                    list_of(&ids)
                ),
            );
        }
        return r;
    }
    for slot in tor_slots {
        let mine: Vec<Address> = addresses
            .iter()
            .filter(|a| a.network_id == slot.id)
            .cloned()
            .collect();
        let mut ids: BTreeSet<String> = mine
            .iter()
            .filter_map(|a| networks::tor::service_id(&a.locator))
            .collect();
        ids.extend(ledger_ids.iter().cloned());
        let what = format!("onion services of network '{}'", slot.id);
        let list = list_of(&ids);
        let net = match &slot.network {
            Ok(n) => n.clone(),
            Err(why) => {
                if ids.is_empty() {
                    r.absent(what);
                } else {
                    r.left(what, format!("the network cannot be used ({why}), so these were not checked or removed: {list}"));
                }
                continue;
            }
        };
        // Called even without ids: Tor's own list of what it published is removed too.
        // The ledger ids have no address row: hand them over as addresses of this network.
        let have: BTreeSet<String> = mine
            .iter()
            .filter_map(|a| networks::tor::service_id(&a.locator))
            .collect();
        let mut all = mine;
        for id in ledger_ids.iter().filter(|i| !have.contains(*i)) {
            all.push(Address::of_reservation(
                "ledger",
                &slot.id,
                Locator::Onion {
                    hostname: format!("{id}.onion"),
                },
            ));
        }
        match tokio::task::spawn_blocking(move || net.disable(&all)).await {
            Ok(Ok(())) => {
                let ids_vec: Vec<String> = ids.iter().cloned().collect();
                if let Err(e) = ledger::forget(db, &ids_vec).await {
                    warn!("Could not update the Tor ledger: {e:#}");
                }
                if ids.is_empty() {
                    r.absent(what);
                } else {
                    r.removed(format!("{what} ({list})"));
                }
            }
            Ok(Err(e)) => r.left(
                what,
                format!("Tor did not confirm the removal ({e:#}); left: {list}"),
            ),
            Err(e) => r.left(what, format!("{e}; left: {list}")),
        }
    }
    r
}

/// What `--disable` and `uninstall` say when a Yggdrasil network was configured (ADR 0051).
pub const YGGDRASIL_LEFT_RUNNING: &str = "The Yggdrasil block is removed with the rest: if a Yggdrasil node still runs, programs on this PC that listen on all addresses are reachable over it. Stop its service yourself to close it.";

/// Whether the config file lists a Yggdrasil network.
pub fn config_has_yggdrasil(config: &Path) -> bool {
    std::fs::read_to_string(config)
        .ok()
        .and_then(|t| {
            serde_json::from_str::<serde_json::Value>(t.strip_prefix('\u{feff}').unwrap_or(&t)).ok()
        })
        .and_then(|d| d.get("backends").and_then(|b| b.as_array().cloned()))
        .is_some_and(|b| b.iter().any(|n| n["type"] == "yggdrasil"))
}

/// Where `--disable` and `uninstall` looked.
pub struct Target<'a> {
    pub config: &'a Path,
    pub config_found: bool,
    pub db: &'a Path,
}

/// The decision of `--disable [--force]` and of the disable step of `uninstall`: refuse
/// (changing nothing) when the database is missing, unless the rules are asked to be removed
/// by name. `uninstall` (`absent_ok`) also accepts a missing database when no rules exist.
pub async fn disable_command(
    target: &Target<'_>,
    force: bool,
    absent_ok: bool,
    firewall: Arc<dyn Firewall>,
    ifaces: Arc<dyn InterfaceManager>,
    interfaces: &HashMap<String, String>,
    make_slots: &dyn Fn([u8; 5]) -> Vec<NetworkSlot>,
) -> Result<Report, String> {
    if target.db.is_file() {
        let path = target.db.to_string_lossy().into_owned();
        let db = Database::open_existing(&path)
            .await
            .map_err(|e| format!("{e:#}"))?;
        db.migrate().await.map_err(|e| format!("{e:#}"))?;
        let ula = db.ula_global_id().await.map_err(|e| format!("{e:#}"))?;
        let mut report = disable_with_db(DisableInput {
            db: &db,
            interfaces,
            networks: make_slots(ula),
            firewall,
            ifaces,
            exposure: None,
        })
        .await;
        // No daemon is running to ask what listens: say what the block's going means.
        if config_has_yggdrasil(target.config) {
            report.note(YGGDRASIL_LEFT_RUNNING);
        }
        return Ok(report);
    }
    let looked = format!(
        "config {} ({}), database {}",
        target.config.display(),
        if target.config_found {
            "found"
        } else {
            "not found"
        },
        target.db.display()
    );
    if absent_ok && !force {
        let fw = firewall.clone();
        if let Ok(Ok(false)) = tokio::task::spawn_blocking(move || fw.verify()).await {
            let mut r = Report::default();
            r.absent("firewall rules");
            r.note(format!(
                "There is no database ({looked}): addresses on interfaces could not be checked."
            ));
            return Ok(r);
        }
    }
    if !force {
        return Err(format!(
            "there is no database to work from; looked at: {looked}. Nothing was changed. \
             Point SOCKETGUARD_CONFIG at the right config file, or use --force to remove the \
             firewall rules by name (addresses on interfaces cannot be checked without the database)."
        ));
    }
    Ok(disable_without_database(firewall, &[target.config, target.db]).await)
}

/// `--disable --force` without a database: the rules by name; says what it could not check.
pub async fn disable_without_database(firewall: Arc<dyn Firewall>, looked_at: &[&Path]) -> Report {
    let mut r = disable_firewall_by_name(firewall).await;
    r.note(format!(
        "No database was read ({}): addresses on interfaces and onion services could NOT be checked or removed. Any SocketGuard address that is still on an interface is no longer denied.",
        looked_at.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    ));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

    async fn db() -> Database {
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    fn mock_fw() -> Arc<MockFirewall> {
        Arc::new(MockFirewall::new(Arc::new(Mutex::new(vec![]))))
    }

    #[tokio::test]
    async fn an_address_that_cannot_be_removed_keeps_the_rules_and_is_named() {
        let db = db().await;
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        db.claim_address(addr, "lo", Some("local")).await.unwrap();
        let net = MockInterfaceManager::new(Arc::new(Mutex::new(vec![])));
        net.plant_address("lo", addr);
        net.set_remove_failing(true);
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::from([("local".to_string(), "lo".to_string())]),
            networks: vec![],
            firewall: mock_fw(),
            ifaces: Arc::new(net),
        })
        .await;
        let text = r.render();
        assert!(!r.complete(), "{text}");
        assert!(
            text.contains("LEFT            address fd00::1 on lo"),
            "{text}"
        );
        assert!(text.contains("firewall rules: kept on purpose"), "{text}");
    }

    #[tokio::test]
    async fn removed_and_already_absent_addresses_are_told_apart() {
        let db = db().await;
        let (a, b): (Ipv6Addr, Ipv6Addr) = ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap());
        db.claim_address(a, "lo", Some("local")).await.unwrap();
        db.claim_address(b, "lo", Some("local")).await.unwrap();
        let net = MockInterfaceManager::new(Arc::new(Mutex::new(vec![])));
        net.plant_address("lo", a); // b is not on the interface
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::from([("local".to_string(), "lo".to_string())]),
            networks: vec![],
            firewall: mock_fw(),
            ifaces: Arc::new(net),
        })
        .await;
        let text = r.render();
        assert!(r.complete(), "{text}");
        assert!(text.contains("removed         address fd00::1"), "{text}");
        assert!(text.contains("already absent  address fd00::2"), "{text}");
        assert!(db.list_owned_addresses().await.unwrap().is_empty());
    }

    // ── the commands' decisions ──

    use crate::networks::{Capabilities, LocatorRequest, NetworkEnforcement, NewLocator};
    use socketguard_core::{NetworkKind, NetworkStatus};

    /// A Tor that remembers what it was told to remove, or is unreachable.
    struct FakeTor {
        removed: Mutex<Vec<String>>,
        reachable: bool,
    }

    impl Network for FakeTor {
        fn kind(&self) -> NetworkKind {
            NetworkKind::Tor
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                ip_locators: false,
                verifies: &[],
                grants_apply: true,
                udp: false,
            }
        }
        fn status(&self) -> (NetworkStatus, Option<Ipv6Addr>) {
            (NetworkStatus::Up, None)
        }
        fn ensure_locator(&self, _: &LocatorRequest) -> anyhow::Result<NewLocator> {
            unimplemented!()
        }
        fn remove_locator(&self, _: &Address) -> anyhow::Result<()> {
            Ok(())
        }
        fn enforce(&self, _: &NetworkEnforcement) -> anyhow::Result<()> {
            Ok(())
        }
        fn disable(&self, addresses: &[Address]) -> anyhow::Result<()> {
            anyhow::ensure!(self.reachable, "cannot connect to the Tor control port");
            for a in addresses {
                if let Some(id) = networks::tor::service_id(&a.locator) {
                    self.removed.lock().unwrap().push(id);
                }
            }
            Ok(())
        }
    }

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sg-dis-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn no_slots(_: [u8; 5]) -> Vec<NetworkSlot> {
        vec![]
    }

    #[tokio::test]
    async fn without_a_database_it_refuses_names_the_paths_and_creates_nothing() {
        let d = tmp();
        let (cfg, dbp) = (d.join("socketguard.json"), d.join("socketguard.db"));
        let calls = Arc::new(Mutex::new(vec![]));
        let fw = Arc::new(MockFirewall::new(calls.clone()));
        let err = disable_command(
            &Target {
                config: &cfg,
                config_found: false,
                db: &dbp,
            },
            false,
            false,
            fw,
            Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
            &HashMap::new(),
            &no_slots,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains(&dbp.display().to_string()) && err.contains(&cfg.display().to_string()),
            "{err}"
        );
        assert!(calls.lock().unwrap().is_empty(), "no firewall call");
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "no file appeared"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn force_removes_the_rules_by_name_and_says_what_it_could_not_check() {
        let d = tmp();
        let (cfg, dbp) = (d.join("socketguard.json"), d.join("socketguard.db"));
        let calls = Arc::new(Mutex::new(vec![]));
        let fw = Arc::new(MockFirewall::new(calls.clone()));
        let rep = disable_command(
            &Target {
                config: &cfg,
                config_found: false,
                db: &dbp,
            },
            true,
            false,
            fw,
            Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
            &HashMap::new(),
            &no_slots,
        )
        .await
        .unwrap();
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| matches!(c, FirewallCall::Disable)));
        let text = rep.render();
        assert!(
            text.contains("addresses on interfaces and onion services could NOT be checked"),
            "{text}"
        );
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "no database was created"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn an_invalid_tor_network_does_not_stop_the_others_and_is_reported() {
        let db = db().await;
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        db.claim_address(addr, "lo", Some("local")).await.unwrap();
        ledger::add_owned(&db, &BTreeSet::from(["abcdefghijklmnop".to_string()]))
            .await
            .unwrap();
        let net = Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![]))));
        net.plant_address("lo", addr);
        let calls = Arc::new(Mutex::new(vec![]));
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::from([("local".to_string(), "lo".to_string())]),
            networks: vec![NetworkSlot {
                id: "tor".into(),
                is_tor: true,
                network: Err("invalid control endpoint \"nonsense\"".into()),
            }],
            firewall: Arc::new(MockFirewall::new(calls.clone())),
            ifaces: net,
        })
        .await;
        let text = r.render();
        assert!(text.contains("removed         address fd00::1"), "{text}");
        assert!(
            text.contains("firewall rules") && !text.contains("LEFT            firewall"),
            "{text}"
        );
        assert!(
            text.contains("LEFT            onion services of network 'tor'"),
            "{text}"
        );
        assert!(
            text.contains("abcdefghijklmnop.onion") && text.contains("invalid control endpoint"),
            "{text}"
        );
        assert!(!r.complete());
    }

    #[tokio::test]
    async fn ledger_only_onion_services_are_removed_and_forgotten() {
        let db = db().await;
        ledger::add_owned(
            &db,
            &BTreeSet::from(["aaaa".to_string(), "bbbb".to_string()]),
        )
        .await
        .unwrap();
        ledger::add_tombstones(&db, &["cccc".to_string()])
            .await
            .unwrap();
        let tor = Arc::new(FakeTor {
            removed: Mutex::new(vec![]),
            reachable: true,
        });
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::new(),
            networks: vec![NetworkSlot {
                id: "tor".into(),
                is_tor: true,
                network: Ok(tor.clone()),
            }],
            firewall: mock_fw(),
            ifaces: Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        })
        .await;
        assert!(r.complete(), "{}", r.render());
        let mut got = tor.removed.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, ["aaaa", "bbbb", "cccc"]);
        let l = ledger::load(&db).await.unwrap();
        assert!(l.owned.is_empty() && l.tombstones.is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_tor_leaves_the_services_listed_and_the_ledger_intact() {
        let db = db().await;
        ledger::add_owned(&db, &BTreeSet::from(["aaaa".to_string()]))
            .await
            .unwrap();
        let tor = Arc::new(FakeTor {
            removed: Mutex::new(vec![]),
            reachable: false,
        });
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::new(),
            networks: vec![NetworkSlot {
                id: "tor".into(),
                is_tor: true,
                network: Ok(tor),
            }],
            firewall: mock_fw(),
            ifaces: Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        })
        .await;
        let text = r.render();
        assert!(!r.complete(), "{text}");
        assert!(
            text.contains("LEFT            onion services of network 'tor'")
                && text.contains("aaaa.onion"),
            "{text}"
        );
        assert!(!text.contains("removed         onion"), "{text}");
        assert!(ledger::load(&db).await.unwrap().owned.contains("aaaa"));
    }

    #[tokio::test]
    async fn ledger_ids_without_any_tor_network_are_left_not_forgotten() {
        let db = db().await;
        ledger::add_owned(&db, &BTreeSet::from(["aaaa".to_string()]))
            .await
            .unwrap();
        let r = disable_with_db(DisableInput {
            exposure: None,
            db: &db,
            interfaces: &HashMap::new(),
            networks: vec![],
            firewall: mock_fw(),
            ifaces: Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        })
        .await;
        assert!(!r.complete(), "{}", r.render());
    }
    #[tokio::test]
    async fn what_stays_reachable_is_part_of_the_report() {
        use socketguard_core::api_types::{ExposedListener, ExposureResponse, NetworkExposure};
        let db = db().await;
        let exposure = ExposureResponse {
            networks: vec![NetworkExposure {
                network: "yggdrasil".into(),
                kind: socketguard_core::NetworkKind::Yggdrasil,
                interface: None,
                node_running: true,
                listeners: vec![ExposedListener {
                    app: "nginx".into(),
                    port: 80,
                    proto: socketguard_core::Protocol::Tcp,
                }],
            }],
        };
        let r = disable_with_db(DisableInput {
            exposure: Some(exposure),
            db: &db,
            interfaces: &HashMap::new(),
            networks: vec![],
            firewall: mock_fw(),
            ifaces: Arc::new(MockInterfaceManager::new(Arc::new(Mutex::new(vec![])))),
        })
        .await;
        assert!(r.complete());
        assert!(
            r.notes.iter().any(|n| n.contains("yggdrasil keeps running")
                && n.contains("nginx (port 80/tcp)")),
            "{:?}",
            r.notes
        );
    }
}
