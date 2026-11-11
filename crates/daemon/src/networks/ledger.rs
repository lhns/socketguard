//! What the daemon owes a non-IP network (the Tor control port), persisted in the settings
//! table (no schema): the services it ever created, and the ones it must still remove.
//! With these a revocation survives Tor being down, and a service whose address was deleted
//! while the daemon was off is still swept. Services this daemon did not create are never
//! in either list, so never touched.

use crate::state::Database;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use tracing::warn;

const OWNED: &str = "tor_owned_services";
const TOMBSTONES: &str = "tor_tombstones";

/// Read-modify-write of the two lists must not interleave.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    pub owned: BTreeSet<String>,
    pub tombstones: BTreeSet<String>,
}

async fn read(db: &Database, key: &str) -> Result<BTreeSet<String>> {
    match db.get_setting(key).await? {
        None => Ok(BTreeSet::new()),
        Some(json) => {
            serde_json::from_str(&json).with_context(|| format!("setting {key} is not a JSON list"))
        }
    }
}

async fn write(db: &Database, key: &str, ids: &BTreeSet<String>) -> Result<()> {
    db.set_setting(key, &serde_json::to_string(ids)?).await
}

pub async fn load(db: &Database) -> Result<Ledger> {
    let _g = LOCK.lock().await;
    Ok(Ledger {
        owned: read(db, OWNED).await?,
        tombstones: read(db, TOMBSTONES).await?,
    })
}

/// Record services about to exist, before anything is published.
pub async fn add_owned(db: &Database, ids: &BTreeSet<String>) -> Result<()> {
    let _g = LOCK.lock().await;
    let mut owned = read(db, OWNED).await?;
    if ids.is_subset(&owned) {
        return Ok(());
    }
    owned.extend(ids.iter().cloned());
    write(db, OWNED, &owned).await
}

/// Own the service of every stored onion key. Services created before the ledger existed
/// were never recorded, so none could be swept once their address was gone. Idempotent.
pub async fn adopt_stored_keys(db: &Database) -> Result<()> {
    let ids: BTreeSet<String> = db
        .onion_keys()
        .await?
        .iter()
        .filter_map(|(address, secret)| {
            super::onion_key::service_id_of_secret(secret)
                .map_err(|e| warn!("Ignoring the onion key of address {address}: {e:#}"))
                .ok()
        })
        .collect();
    add_owned(db, &ids).await
}

/// Record services that must be removed, before removing them.
pub async fn add_tombstones(db: &Database, ids: &[String]) -> Result<()> {
    let _g = LOCK.lock().await;
    let mut owned = read(db, OWNED).await?;
    let mut tombs = read(db, TOMBSTONES).await?;
    owned.extend(ids.iter().cloned());
    tombs.extend(ids.iter().cloned());
    write(db, OWNED, &owned).await?;
    write(db, TOMBSTONES, &tombs).await
}

/// A removal was confirmed.
pub async fn clear_tombstones(db: &Database, ids: &[String]) -> Result<()> {
    let _g = LOCK.lock().await;
    let mut tombs = read(db, TOMBSTONES).await?;
    for id in ids {
        tombs.remove(id);
    }
    write(db, TOMBSTONES, &tombs).await
}

/// Enforcement with `passed` as input succeeded: everything in it that is not `wanted` has
/// been removed or was not running. Entries added meanwhile stay.
pub async fn settle(db: &Database, passed: &Ledger, wanted: &BTreeSet<String>) -> Result<()> {
    let _g = LOCK.lock().await;
    let mut owned = read(db, OWNED).await?;
    let mut tombs = read(db, TOMBSTONES).await?;
    owned.retain(|id| !passed.owned.contains(id));
    owned.extend(wanted.iter().cloned());
    tombs.retain(|id| !passed.tombstones.contains(id));
    write(db, OWNED, &owned).await?;
    write(db, TOMBSTONES, &tombs).await
}

/// Services are gone (removed or never there): drop them from both lists.
pub async fn forget(db: &Database, ids: &[String]) -> Result<()> {
    let _g = LOCK.lock().await;
    let mut owned = read(db, OWNED).await?;
    let mut tombs = read(db, TOMBSTONES).await?;
    for id in ids {
        owned.remove(id);
        tombs.remove(id);
    }
    write(db, OWNED, &owned).await?;
    write(db, TOMBSTONES, &tombs).await
}
