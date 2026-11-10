//! SQLite persistence, schema v4 (ADR 0027, 0037, 0040): apps, ports, addresses, peers, credentials,
//! groups, grants, settings, activity and onion service keys. Versioned with
//! `PRAGMA user_version`; a database from before the redesign is renamed out of the way,
//! never migrated.
//!
//! The database holds private keys (`onion_keys`), so it is protected at rest: on Unix the
//! file (and its -wal/-shm) is mode 0600. On Windows the file is created with a protected
//! DACL (SYSTEM and Administrators only) before SQLite opens it, and the DACL is applied to
//! the -wal/-shm files and any `.pre-v1` backup too.

mod protect;
mod schema;
mod settings;
#[cfg(windows)]
mod winacl;

pub use protect::ALLOW_UNPROTECTED_DB_ENV;
pub use schema::SCHEMA_VERSION;
pub use settings::parse_protect_host;

use protect::{precreate_protected, protect_files};
use schema::{archive_pre_v1, is_pre_v1};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use socketguard_core::{
    ActivityKind, ActivityQuery, ActivityRecord, Address, App, AppPort, Credential, CredentialKind,
    Grant, Locator, Peer, PeerGroup, PortRef, PortSet, Protocol, Subject,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::warn;

/// Activity retention: whichever limit trims more.
const ACTIVITY_MAX_AGE_DAYS: i64 = 30;
const ACTIVITY_MAX_ROWS: i64 = 10_000;

/// An address the daemon has put on (or is taking off) an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedAddress {
    pub addr: Ipv6Addr,
    pub interface: String,
    pub network_id: Option<String>,
    /// Being removed: not wanted any more, but still denied until it is really gone.
    pub retiring: bool,
}

pub struct Database {
    pool: SqlitePool,
    /// The file, for protecting it after the schema (and -wal/-shm) exist.
    path: Option<String>,
}

fn ts(dt: DateTime<Utc>) -> String {
    // Fixed width, so text comparison orders like time.
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("bad timestamp {s:?}"))?
        .with_timezone(&Utc))
}

fn to_port(v: i64) -> Result<u16> {
    u16::try_from(v).with_context(|| format!("bad port {v}"))
}

/// Whether `err` is a violated UNIQUE constraint (a duplicate label or credential).
pub fn is_unique_violation(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        matches!(e.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(d)) if d.is_unique_violation())
    })
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

impl Database {
    /// Open (creating if needed) the database at `path`. A pre-v1 file is renamed first.
    /// Call [`Database::migrate`] next.
    pub async fn new(path: &str) -> Result<Self> {
        if path != ":memory:" && Path::new(path).exists() && is_pre_v1(Path::new(path)).await {
            let moved = archive_pre_v1(Path::new(path))?;
            warn!(
                "{path} is from before schema v1 and is not migrated; moved to {}",
                moved.display()
            );
            // The rename keeps the ACL; re-apply it (and to the WAL files) to be sure.
            protect_files(&moved)?;
        }
        // sqlx maps ":memory:" to a uniquely named shared-cache in-memory DB, so every
        // pooled connection sees the same data (covered by memory_pool_tests).
        if path != ":memory:" {
            precreate_protected(Path::new(path))?;
        }
        let options =
            SqliteConnectOptions::from_str(&format!("sqlite:{path}?mode=rwc"))?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        if path != ":memory:" {
            protect_files(Path::new(path))?;
        }
        Ok(Self {
            pool,
            path: (path != ":memory:").then(|| path.to_string()),
        })
    }

    // ======== Apps ========

    pub async fn insert_app(&self, app: &App) -> Result<()> {
        sqlx::query(
            "INSERT INTO apps (id, name, process_name, exe_path, interpreter_arg, identity_note, \
             reviewed, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&app.id)
        .bind(&app.name)
        .bind(&app.process_name)
        .bind(&app.exe_path)
        .bind(&app.interpreter_arg)
        .bind(&app.identity_note)
        .bind(app.reviewed)
        .bind(ts(app.first_seen))
        .bind(ts(app.last_seen))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record another sighting of a known app.
    pub async fn touch_app(
        &self,
        id: &str,
        process_name: &str,
        exe_path: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query("UPDATE apps SET process_name = ?, exe_path = ?, last_seen = ? WHERE id = ?")
            .bind(process_name)
            .bind(exe_path)
            .bind(ts(now))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns false when the app does not exist.
    pub async fn set_reviewed(&self, id: &str, reviewed: bool) -> Result<bool> {
        let r = sqlx::query("UPDATE apps SET reviewed = ? WHERE id = ?")
            .bind(reviewed)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete an app; its ports, addresses and grants go with it. False if unknown.
    pub async fn delete_app(&self, id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM apps WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn get_app(&self, id: &str) -> Result<Option<App>> {
        Ok(self.load_apps(Some(id)).await?.into_iter().next())
    }

    pub async fn list_apps(&self) -> Result<Vec<App>> {
        self.load_apps(None).await
    }

    async fn load_apps(&self, only: Option<&str>) -> Result<Vec<App>> {
        let rows = match only {
            Some(id) => {
                sqlx::query("SELECT id, name, process_name, exe_path, interpreter_arg, identity_note, reviewed, first_seen, last_seen FROM apps WHERE id = ?")
                    .bind(id)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query("SELECT id, name, process_name, exe_path, interpreter_arg, identity_note, reviewed, first_seen, last_seen FROM apps ORDER BY name, id")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        let mut apps = Vec::with_capacity(rows.len());
        for r in rows {
            apps.push(App {
                id: r.get("id"),
                name: r.get("name"),
                process_name: r.get("process_name"),
                exe_path: r.get("exe_path"),
                interpreter_arg: r.get("interpreter_arg"),
                identity_note: r.get("identity_note"),
                reviewed: r.get("reviewed"),
                first_seen: parse_ts(r.get("first_seen"))?,
                last_seen: parse_ts(r.get("last_seen"))?,
                ports: Vec::new(),
                addresses: Vec::new(),
            });
        }
        let mut ports = self.load_ports(only).await?;
        let mut addresses = self.load_addresses(only).await?;
        for app in &mut apps {
            app.ports = ports.remove(&app.id).unwrap_or_default();
            app.addresses = addresses.remove(&app.id).unwrap_or_default();
        }
        Ok(apps)
    }

    // ======== App ports ========

    async fn load_ports(&self, only: Option<&str>) -> Result<HashMap<String, Vec<AppPort>>> {
        let rows = sqlx::query(
            "SELECT app_id, port, proto, listening, last_seen FROM app_ports \
             WHERE (?1 IS NULL OR app_id = ?1) ORDER BY port, proto",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Vec<AppPort>> = HashMap::new();
        for r in rows {
            out.entry(r.get("app_id")).or_default().push(AppPort {
                port: to_port(r.get("port"))?,
                proto: r
                    .get::<String, _>("proto")
                    .parse()
                    .map_err(anyhow::Error::msg)?,
                listening: r.get("listening"),
                last_seen: parse_ts(r.get("last_seen"))?,
            });
        }
        Ok(out)
    }

    /// Record which ports an app listens on now: those in `live` become listening (and
    /// are created when new), every other known port stops listening. Returns the ports
    /// seen for the first time.
    pub async fn sync_app_ports(
        &self,
        app_id: &str,
        live: &[PortRef],
        now: DateTime<Utc>,
    ) -> Result<Vec<PortRef>> {
        let mut tx = self.pool.begin().await?;
        let known: Vec<(i64, String)> =
            sqlx::query_as("SELECT port, proto FROM app_ports WHERE app_id = ?")
                .bind(app_id)
                .fetch_all(&mut *tx)
                .await?;
        let known: Vec<PortRef> = known
            .into_iter()
            .map(|(p, pr)| {
                Ok(PortRef {
                    port: to_port(p)?,
                    proto: pr.parse().map_err(anyhow::Error::msg)?,
                })
            })
            .collect::<Result<_>>()?;
        let mut new_ports = Vec::new();
        for p in live {
            if !known.contains(p) {
                new_ports.push(*p);
            }
            sqlx::query(
                "INSERT INTO app_ports (app_id, port, proto, listening, last_seen) \
                 VALUES (?, ?, ?, 1, ?) ON CONFLICT(app_id, port, proto) \
                 DO UPDATE SET listening = 1, last_seen = excluded.last_seen",
            )
            .bind(app_id)
            .bind(p.port)
            .bind(p.proto.to_string())
            .bind(ts(now))
            .execute(&mut *tx)
            .await?;
        }
        for k in known.iter().filter(|k| !live.contains(k)) {
            sqlx::query(
                "UPDATE app_ports SET listening = 0 WHERE app_id = ? AND port = ? AND proto = ?",
            )
            .bind(app_id)
            .bind(k.port)
            .bind(k.proto.to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(new_ports)
    }

    // ======== Addresses ========

    pub async fn insert_address(&self, a: &Address) -> Result<()> {
        self.insert_address_with_secret(a, None).await
    }

    /// Insert an address together with its locator secret (the onion service key) in one
    /// transaction, so a stored address never lacks its key.
    pub async fn insert_address_with_secret(
        &self,
        a: &Address,
        secret: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        insert_address_in(&mut tx, a, secret).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Insert a new address and shrink the `Only` set of the address its port came from,
    /// in one transaction: a crash between the two would leave the port on both.
    pub async fn split_address(
        &self,
        new: &Address,
        secret: Option<&str>,
        shrink: Option<(&str, &PortSet)>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        insert_address_in(&mut tx, new, secret).await?;
        if let Some((id, ports)) = shrink {
            sqlx::query("UPDATE addresses SET ports = ? WHERE id = ?")
                .bind(encode_ports(ports)?)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The onion service keys by address id.
    pub async fn onion_keys(&self) -> Result<HashMap<String, String>> {
        Ok(
            sqlx::query_as::<_, (String, String)>("SELECT address_id, private_key FROM onion_keys")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .collect(),
        )
    }

    #[cfg(test)]
    pub async fn get_address(&self, id: &str) -> Result<Option<Address>> {
        let rows = sqlx::query(&format!("{ADDRESS_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().next().map(address_from_row).transpose()
    }

    pub async fn list_addresses(&self) -> Result<Vec<Address>> {
        sqlx::query(&format!("{ADDRESS_SELECT} ORDER BY created_at, id"))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(address_from_row)
            .collect()
    }

    async fn load_addresses(&self, only: Option<&str>) -> Result<HashMap<String, Vec<Address>>> {
        let rows = sqlx::query(&format!(
            "{ADDRESS_SELECT} WHERE (?1 IS NULL OR app_id = ?1) ORDER BY created_at, id"
        ))
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Vec<Address>> = HashMap::new();
        for r in rows {
            let a = address_from_row(r)?;
            out.entry(a.app_id.clone()).or_default().push(a);
        }
        Ok(out)
    }

    pub async fn update_address_ports(&self, id: &str, ports: &PortSet) -> Result<bool> {
        let r = sqlx::query("UPDATE addresses SET ports = ? WHERE id = ?")
            .bind(encode_ports(ports)?)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_address_ipv6(&self, id: &str, addr: Ipv6Addr) -> Result<bool> {
        let r = sqlx::query("UPDATE addresses SET locator_kind = 'ipv6', locator = ? WHERE id = ?")
            .bind(addr.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn delete_address(&self, id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM addresses WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete every address of a network, returning them (the caller takes them off the
    /// interface).
    pub async fn delete_addresses_by_network(&self, network_id: &str) -> Result<Vec<Address>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(&format!("{ADDRESS_SELECT} WHERE network_id = ?"))
            .bind(network_id)
            .fetch_all(&mut *tx)
            .await?;
        let addrs = rows
            .into_iter()
            .map(address_from_row)
            .collect::<Result<Vec<_>>>()?;
        sqlx::query("DELETE FROM addresses WHERE network_id = ?")
            .bind(network_id)
            .execute(&mut *tx)
            .await?;
        // A grant tied to the network cannot apply any more.
        sqlx::query("DELETE FROM grants WHERE network_id = ?")
            .bind(network_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(addrs)
    }

    // ======== Owned addresses ========

    /// Record, before it is added to an interface, that the daemon owns `addr` there.
    /// An address that was retiring is active again.
    pub async fn claim_address(
        &self,
        addr: Ipv6Addr,
        interface: &str,
        network_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO owned_addresses (addr, interface, network_id, state, since) \
             VALUES (?1, ?2, ?3, 'active', ?4) \
             ON CONFLICT(addr) DO UPDATE SET interface = ?2, network_id = ?3, \
             state = 'active', since = ?4",
        )
        .bind(addr.to_string())
        .bind(interface)
        .bind(network_id)
        .bind(ts(Utc::now()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark `addr` as being removed. It stays owned (and so denied) until
    /// [`Database::forget_address`] confirms it is gone.
    pub async fn retire_address(
        &self,
        addr: Ipv6Addr,
        interface: &str,
        network_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO owned_addresses (addr, interface, network_id, state, since) \
             VALUES (?1, ?2, ?3, 'retiring', ?4) \
             ON CONFLICT(addr) DO UPDATE SET state = 'retiring', \
             since = CASE WHEN state = 'retiring' THEN since ELSE ?4 END",
        )
        .bind(addr.to_string())
        .bind(interface)
        .bind(network_id)
        .bind(ts(Utc::now()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete the row of an address that is confirmed off its interface.
    pub async fn forget_address(&self, addr: Ipv6Addr) -> Result<()> {
        sqlx::query("DELETE FROM owned_addresses WHERE addr = ?")
            .bind(addr.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_owned_addresses(&self) -> Result<Vec<OwnedAddress>> {
        let rows = sqlx::query(
            "SELECT addr, interface, network_id, state FROM owned_addresses ORDER BY addr",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let addr: String = r.get("addr");
            let Ok(addr) = addr.parse() else {
                warn!("Ignoring owned address row with an invalid address: {addr}");
                continue;
            };
            let state: String = r.get("state");
            out.push(OwnedAddress {
                addr,
                interface: r.get("interface"),
                network_id: r.get("network_id"),
                retiring: state == "retiring",
            });
        }
        Ok(out)
    }

    // ======== Peers ========

    /// Insert a peer with its credentials in one transaction.
    pub async fn insert_peer(&self, peer: &Peer) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO peers (id, label, created_at) VALUES (?, ?, ?)")
            .bind(&peer.id)
            .bind(&peer.label)
            .bind(ts(peer.created_at))
            .execute(&mut *tx)
            .await?;
        for c in &peer.credentials {
            insert_credential(&mut tx, &peer.id, c).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> Result<Option<Peer>> {
        Ok(self.load_peers(Some(id)).await?.into_iter().next())
    }

    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        self.load_peers(None).await
    }

    async fn load_peers(&self, only: Option<&str>) -> Result<Vec<Peer>> {
        let rows = sqlx::query(
            "SELECT id, label, created_at FROM peers WHERE (?1 IS NULL OR id = ?1) ORDER BY label",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut peers = Vec::with_capacity(rows.len());
        for r in rows {
            peers.push(Peer {
                id: r.get("id"),
                label: r.get("label"),
                credentials: Vec::new(),
                groups: Vec::new(),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        let creds = sqlx::query(
            "SELECT id, peer_id, kind, value, label FROM peer_credentials \
             WHERE (?1 IS NULL OR peer_id = ?1) ORDER BY rowid",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut by_peer: HashMap<String, Vec<Credential>> = HashMap::new();
        for r in creds {
            by_peer
                .entry(r.get("peer_id"))
                .or_default()
                .push(Credential {
                    id: r.get("id"),
                    kind: r
                        .get::<String, _>("kind")
                        .parse()
                        .map_err(anyhow::Error::msg)?,
                    value: r.get("value"),
                    label: r.get("label"),
                });
        }
        let members = sqlx::query(
            "SELECT group_id, peer_id FROM peer_group_members \
             WHERE (?1 IS NULL OR peer_id = ?1) ORDER BY group_id",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for r in members {
            groups
                .entry(r.get("peer_id"))
                .or_default()
                .push(r.get("group_id"));
        }
        for p in &mut peers {
            p.credentials = by_peer.remove(&p.id).unwrap_or_default();
            p.groups = groups.remove(&p.id).unwrap_or_default();
        }
        Ok(peers)
    }

    pub async fn rename_peer(&self, id: &str, label: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE peers SET label = ? WHERE id = ?")
            .bind(label)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete a peer with its credentials, memberships and the grants naming it.
    pub async fn delete_peer(&self, id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM grants WHERE subject_kind = 'peer' AND subject_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let r = sqlx::query("DELETE FROM peers WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn add_credential(&self, peer_id: &str, c: &Credential) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        insert_credential(&mut tx, peer_id, c).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_credential(&self, peer_id: &str, cred_id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM peer_credentials WHERE id = ? AND peer_id = ?")
            .bind(cred_id)
            .bind(peer_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The peer that holds a credential, if any.
    pub async fn find_credential_owner(
        &self,
        kind: CredentialKind,
        value: &str,
    ) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT peer_id FROM peer_credentials WHERE kind = ? AND value = ?")
                .bind(kind.as_str())
                .bind(value)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    // ======== Peer groups ========

    pub async fn insert_group(&self, g: &PeerGroup) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO peer_groups (id, label, created_at) VALUES (?, ?, ?)")
            .bind(&g.id)
            .bind(&g.label)
            .bind(ts(g.created_at))
            .execute(&mut *tx)
            .await?;
        for m in &g.members {
            sqlx::query("INSERT INTO peer_group_members (group_id, peer_id) VALUES (?, ?)")
                .bind(&g.id)
                .bind(m)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_group(&self, id: &str) -> Result<Option<PeerGroup>> {
        Ok(self.load_groups(Some(id)).await?.into_iter().next())
    }

    pub async fn list_groups(&self) -> Result<Vec<PeerGroup>> {
        self.load_groups(None).await
    }

    async fn load_groups(&self, only: Option<&str>) -> Result<Vec<PeerGroup>> {
        let rows = sqlx::query(
            "SELECT id, label, created_at FROM peer_groups WHERE (?1 IS NULL OR id = ?1) ORDER BY label",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let members = sqlx::query(
            "SELECT group_id, peer_id FROM peer_group_members \
             WHERE (?1 IS NULL OR group_id = ?1) ORDER BY peer_id",
        )
        .bind(only)
        .fetch_all(&self.pool)
        .await?;
        let mut by_group: HashMap<String, Vec<String>> = HashMap::new();
        for r in members {
            by_group
                .entry(r.get("group_id"))
                .or_default()
                .push(r.get("peer_id"));
        }
        let mut groups = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.get("id");
            groups.push(PeerGroup {
                members: by_group.remove(&id).unwrap_or_default(),
                id,
                label: r.get("label"),
                created_at: parse_ts(r.get("created_at"))?,
            });
        }
        Ok(groups)
    }

    pub async fn rename_group(&self, id: &str, label: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE peer_groups SET label = ? WHERE id = ?")
            .bind(label)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete a group with its memberships and the grants naming it.
    pub async fn delete_group(&self, id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM grants WHERE subject_kind = 'group' AND subject_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let r = sqlx::query("DELETE FROM peer_groups WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(r.rows_affected() > 0)
    }

    /// Replace a group's members.
    pub async fn set_group_members(&self, id: &str, members: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM peer_group_members WHERE group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for m in members {
            sqlx::query(
                "INSERT OR IGNORE INTO peer_group_members (group_id, peer_id) VALUES (?, ?)",
            )
            .bind(id)
            .bind(m)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // ======== Grants ========

    pub async fn insert_grant(&self, g: &Grant) -> Result<()> {
        let (kind, subject_id) = match &g.subject {
            Subject::Peer(id) => ("peer", Some(id.as_str())),
            Subject::Group(id) => ("group", Some(id.as_str())),
            Subject::Anyone => ("anyone", None),
        };
        sqlx::query(
            "INSERT INTO grants (id, app_id, port, proto, network_id, subject_kind, subject_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&g.id)
        .bind(&g.app_id)
        .bind(g.port.map(|p| p.port))
        .bind(g.port.map(|p| p.proto.to_string()))
        .bind(&g.network_id)
        .bind(kind)
        .bind(subject_id)
        .bind(ts(g.created_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_grant(&self, id: &str) -> Result<Option<Grant>> {
        let rows = sqlx::query(&format!("{GRANT_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().next().map(grant_from_row).transpose()
    }

    pub async fn list_grants(&self) -> Result<Vec<Grant>> {
        sqlx::query(&format!("{GRANT_SELECT} ORDER BY created_at, id"))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(grant_from_row)
            .collect()
    }

    pub async fn delete_grant(&self, id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM grants WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ======== Activity ========

    /// Append records, then prune by the retention limits.
    pub async fn insert_activity(&self, records: &[NewActivity]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for r in records {
            sqlx::query(
                "INSERT INTO activity (at, kind, app_id, peer_id, network_id, src, port, proto, count, message) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(ts(r.at))
            .bind(r.kind.as_str())
            .bind(&r.app_id)
            .bind(&r.peer_id)
            .bind(&r.network_id)
            .bind(r.src.map(|s| s.to_string()))
            .bind(r.port)
            .bind(r.proto.map(|p| p.to_string()))
            .bind(r.count)
            .bind(&r.message)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.prune_activity(Duration::days(ACTIVITY_MAX_AGE_DAYS), ACTIVITY_MAX_ROWS)
            .await?;
        Ok(())
    }

    /// Delete activity older than `max_age`, then everything but the newest `max_rows`.
    pub async fn prune_activity(&self, max_age: Duration, max_rows: i64) -> Result<()> {
        sqlx::query("DELETE FROM activity WHERE at < ?")
            .bind(ts(Utc::now() - max_age))
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY id DESC LIMIT ?)",
        )
        .bind(max_rows)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Activity matching `q`, newest first.
    pub async fn list_activity(&self, q: &ActivityQuery) -> Result<Vec<ActivityRecord>> {
        let rows = sqlx::query(
            "SELECT id, at, kind, app_id, peer_id, network_id, src, port, proto, count, message \
             FROM activity \
             WHERE (?1 IS NULL OR at >= ?1) AND (?2 IS NULL OR kind = ?2) \
               AND (?3 IS NULL OR app_id = ?3) AND (?4 IS NULL OR peer_id = ?4) \
               AND (?5 IS NULL OR id < ?5) \
             ORDER BY id DESC LIMIT ?6",
        )
        .bind(q.since.map(ts))
        .bind(q.kind.map(|k| k.as_str()))
        .bind(&q.app_id)
        .bind(&q.peer_id)
        .bind(q.before)
        .bind(i64::from(q.limit.unwrap_or(100)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(activity_from_row).collect()
    }
}

/// An activity record before it gets an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewActivity {
    pub at: DateTime<Utc>,
    pub kind: ActivityKind,
    pub app_id: Option<String>,
    pub peer_id: Option<String>,
    pub network_id: Option<String>,
    pub src: Option<IpAddr>,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
    pub count: u32,
    pub message: String,
}

impl NewActivity {
    pub fn new(kind: ActivityKind, message: impl Into<String>) -> Self {
        Self {
            at: Utc::now(),
            kind,
            app_id: None,
            peer_id: None,
            network_id: None,
            src: None,
            port: None,
            proto: None,
            count: 1,
            message: message.into(),
        }
    }

    pub fn app(mut self, id: &str) -> Self {
        self.app_id = Some(id.to_string());
        self
    }

    pub fn peer(mut self, id: &str) -> Self {
        self.peer_id = Some(id.to_string());
        self
    }
}

const ADDRESS_SELECT: &str = "SELECT id, app_id, network_id, ports, locator_kind, locator, \
     created_at FROM addresses";

const GRANT_SELECT: &str = "SELECT id, app_id, port, proto, network_id, subject_kind, subject_id, \
     created_at FROM grants";

async fn insert_address_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    a: &Address,
    secret: Option<&str>,
) -> Result<()> {
    let (kind, locator) = match &a.locator {
        Locator::Ipv6 { addr } => ("ipv6", addr.to_string()),
        Locator::Onion { hostname } => ("onion", hostname.clone()),
    };
    sqlx::query(
        "INSERT INTO addresses (id, app_id, network_id, ports, locator_kind, locator, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&a.id)
    .bind(&a.app_id)
    .bind(&a.network_id)
    .bind(encode_ports(&a.ports)?)
    .bind(kind)
    .bind(locator)
    .bind(ts(a.created_at))
    .execute(&mut **tx)
    .await?;
    if let Some(secret) = secret {
        sqlx::query("INSERT INTO onion_keys (address_id, private_key) VALUES (?, ?)")
            .bind(&a.id)
            .bind(secret)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn insert_credential(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    peer_id: &str,
    c: &Credential,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO peer_credentials (id, peer_id, kind, value, label) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&c.id)
    .bind(peer_id)
    .bind(c.kind.as_str())
    .bind(&c.value)
    .bind(&c.label)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn encode_ports(p: &PortSet) -> Result<String> {
    Ok(match p {
        PortSet::All => "all".to_string(),
        PortSet::Only(list) => serde_json::to_string(list)?,
    })
}

fn decode_ports(s: &str) -> Result<PortSet> {
    if s == "all" {
        Ok(PortSet::All)
    } else {
        Ok(PortSet::Only(serde_json::from_str(s)?))
    }
}

fn address_from_row(r: sqlx::sqlite::SqliteRow) -> Result<Address> {
    let locator: String = r.get("locator");
    let locator = match r.get::<String, _>("locator_kind").as_str() {
        "ipv6" => Locator::Ipv6 {
            addr: locator.parse().context("bad IPv6 locator")?,
        },
        "onion" => Locator::Onion { hostname: locator },
        other => bail!("unknown locator kind {other:?}"),
    };
    Ok(Address {
        id: r.get("id"),
        app_id: r.get("app_id"),
        network_id: r.get("network_id"),
        ports: decode_ports(r.get("ports"))?,
        locator,
        created_at: parse_ts(r.get("created_at"))?,
    })
}

fn grant_from_row(r: sqlx::sqlite::SqliteRow) -> Result<Grant> {
    let port: Option<i64> = r.get("port");
    let proto: Option<String> = r.get("proto");
    let port = match (port, proto) {
        (Some(p), Some(pr)) => Some(PortRef {
            port: to_port(p)?,
            proto: pr.parse().map_err(anyhow::Error::msg)?,
        }),
        _ => None,
    };
    let subject_id: Option<String> = r.get("subject_id");
    let subject = match (r.get::<String, _>("subject_kind").as_str(), subject_id) {
        ("peer", Some(id)) => Subject::Peer(id),
        ("group", Some(id)) => Subject::Group(id),
        ("anyone", _) => Subject::Anyone,
        (k, _) => bail!("bad grant subject {k:?}"),
    };
    Ok(Grant {
        id: r.get("id"),
        app_id: r.get("app_id"),
        port,
        network_id: r.get("network_id"),
        subject,
        created_at: parse_ts(r.get("created_at"))?,
    })
}

fn activity_from_row(r: sqlx::sqlite::SqliteRow) -> Result<ActivityRecord> {
    let src: Option<String> = r.get("src");
    let port: Option<i64> = r.get("port");
    let proto: Option<String> = r.get("proto");
    Ok(ActivityRecord {
        id: r.get("id"),
        at: parse_ts(r.get("at"))?,
        kind: r
            .get::<String, _>("kind")
            .parse()
            .map_err(anyhow::Error::msg)?,
        app_id: r.get("app_id"),
        peer_id: r.get("peer_id"),
        network_id: r.get("network_id"),
        src: src.map(|s| s.parse()).transpose()?,
        port: port.map(to_port).transpose()?,
        proto: proto
            .map(|p| p.parse().map_err(anyhow::Error::msg))
            .transpose()?,
        count: u32::try_from(r.get::<i64, _>("count")).unwrap_or(1),
        message: r.get("message"),
    })
}

#[cfg(test)]
mod test_util {
    use super::*;
    use socketguard_core::new_id;

    pub(super) async fn db() -> Database {
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    pub(super) fn now() -> DateTime<Utc> {
        Utc::now()
    }

    pub(super) fn app(id: &str) -> App {
        App {
            id: id.into(),
            name: format!("app-{id}"),
            process_name: "proc".into(),
            exe_path: Some("/usr/bin/proc".into()),
            interpreter_arg: None,
            identity_note: None,
            reviewed: false,
            first_seen: now(),
            last_seen: now(),
            ports: vec![],
            addresses: vec![],
        }
    }

    pub(super) fn address(app_id: &str, net: &str, a: &str) -> Address {
        Address {
            id: new_id(),
            app_id: app_id.into(),
            network_id: net.into(),
            ports: PortSet::All,
            locator: Locator::Ipv6 {
                addr: a.parse().unwrap(),
            },
            created_at: now(),
        }
    }

    pub(super) fn peer(label: &str, creds: &[(CredentialKind, &str)]) -> Peer {
        Peer {
            id: new_id(),
            label: label.into(),
            credentials: creds
                .iter()
                .map(|(k, v)| Credential {
                    id: new_id(),
                    kind: *k,
                    value: (*v).into(),
                    label: None,
                })
                .collect(),
            groups: vec![],
            created_at: now(),
        }
    }

    pub(super) fn grant(app_id: &str, subject: Subject) -> Grant {
        Grant {
            id: new_id(),
            app_id: app_id.into(),
            port: Some(PortRef {
                port: 80,
                proto: Protocol::Tcp,
            }),
            network_id: None,
            subject,
            created_at: now(),
        }
    }

    pub(super) async fn count(db: &Database, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&db.pool)
            .await
            .unwrap()
    }

    pub(super) fn temp_db_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sg-state-{tag}-{}.db", new_id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::*;
    use socketguard_core::new_id;

    #[tokio::test]
    async fn foreign_keys_are_on_for_every_connection() {
        let db = db().await;
        let mut conns = Vec::new();
        for _ in 0..4 {
            conns.push(db.pool.acquire().await.unwrap());
        }
        for c in &mut conns {
            let on: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
                .fetch_one(&mut **c)
                .await
                .unwrap();
            assert_eq!(on, 1);
        }
        // And they are enforced: no address for an unknown app.
        assert!(db
            .insert_address(&address("nope", "n", "fd00::1"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn app_ports_sync_tracks_listening() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let p80 = PortRef {
            port: 80,
            proto: Protocol::Tcp,
        };
        let p53 = PortRef {
            port: 53,
            proto: Protocol::Udp,
        };
        let new = db.sync_app_ports("a1", &[p80, p53], now()).await.unwrap();
        assert_eq!(new.len(), 2);
        let new = db.sync_app_ports("a1", &[p80], now()).await.unwrap();
        assert!(new.is_empty());
        let got = db.get_app("a1").await.unwrap().unwrap();
        let listening: Vec<_> = got.ports.iter().map(|p| (p.port, p.listening)).collect();
        assert_eq!(listening, [(53, false), (80, true)]);
        let new = db.sync_app_ports("a1", &[p80, p53], now()).await.unwrap();
        assert!(new.is_empty(), "a returning port is not new");
    }

    #[tokio::test]
    async fn address_roundtrip_and_updates() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let mut a = address("a1", "ygg", "300:1:2:3::5");
        a.ports = PortSet::Only(vec![PortRef {
            port: 8080,
            proto: Protocol::Tcp,
        }]);
        db.insert_address(&a).await.unwrap();
        assert_eq!(db.get_address(&a.id).await.unwrap().unwrap(), {
            let mut b = a.clone();
            b.created_at = db.get_address(&a.id).await.unwrap().unwrap().created_at;
            b
        });
        db.update_address_ports(&a.id, &PortSet::All).await.unwrap();
        db.update_address_ipv6(&a.id, "300:9::5".parse().unwrap())
            .await
            .unwrap();
        let got = db.get_address(&a.id).await.unwrap().unwrap();
        assert_eq!(got.ports, PortSet::All);
        assert_eq!(got.locator.ipv6(), Some("300:9::5".parse().unwrap()));
        assert_eq!(db.get_app("a1").await.unwrap().unwrap().addresses.len(), 1);
    }

    #[tokio::test]
    async fn list_addresses_is_ordered_by_creation() {
        let db = db().await;
        for app_id in ["a1", "a2", "a3"] {
            db.insert_app(&app(app_id)).await.unwrap();
        }
        let mut ids = Vec::new();
        for i in 0..9 {
            let mut a = address(
                ["a1", "a2", "a3"][i as usize % 3],
                "n",
                &format!("fd00::{}", i + 1),
            );
            a.created_at = now() + Duration::seconds(i);
            ids.push(a.id.clone());
            db.insert_address(&a).await.unwrap();
        }
        let listed: Vec<_> = db
            .list_addresses()
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(listed, ids);
    }

    #[tokio::test]
    async fn split_address_is_all_or_nothing() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let p = |port| PortRef {
            port,
            proto: Protocol::Tcp,
        };
        let mut old = address("a1", "n", "fd00::1");
        old.ports = PortSet::Only(vec![p(80), p(81)]);
        db.insert_address(&old).await.unwrap();

        // The new address cannot be stored (unknown app): the old one keeps both ports.
        let mut bad = address("nope", "n", "fd00::2");
        bad.ports = PortSet::Only(vec![p(81)]);
        let rest = PortSet::Only(vec![p(80)]);
        assert!(db
            .split_address(&bad, None, Some((&old.id, &rest)))
            .await
            .is_err());
        let kept = db.get_address(&old.id).await.unwrap().unwrap();
        assert_eq!(kept.ports, PortSet::Only(vec![p(80), p(81)]));

        let mut good = address("a1", "n", "fd00::2");
        good.ports = PortSet::Only(vec![p(81)]);
        db.split_address(&good, None, Some((&old.id, &rest)))
            .await
            .unwrap();
        assert_eq!(db.get_address(&old.id).await.unwrap().unwrap().ports, rest);
        assert!(db.get_address(&good.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn deleting_a_peer_deletes_its_grants_and_memberships() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let p = peer("laptop", &[(CredentialKind::Ip, "fd00::5/128")]);
        let other = peer("phone", &[(CredentialKind::Ip, "fd00::6/128")]);
        db.insert_peer(&p).await.unwrap();
        db.insert_peer(&other).await.unwrap();
        let g = PeerGroup {
            id: new_id(),
            label: "family".into(),
            members: vec![p.id.clone(), other.id.clone()],
            created_at: now(),
        };
        db.insert_group(&g).await.unwrap();
        db.insert_grant(&grant("a1", Subject::Peer(p.id.clone())))
            .await
            .unwrap();
        db.insert_grant(&grant("a1", Subject::Peer(other.id.clone())))
            .await
            .unwrap();
        db.insert_grant(&grant("a1", Subject::Group(g.id.clone())))
            .await
            .unwrap();
        db.insert_grant(&grant("a1", Subject::Anyone))
            .await
            .unwrap();

        assert!(db.delete_peer(&p.id).await.unwrap());
        assert_eq!(
            count(&db, "peer_credentials").await,
            1,
            "credentials cascade"
        );
        assert_eq!(
            count(&db, "peer_group_members").await,
            1,
            "memberships cascade"
        );
        let subjects: Vec<_> = db
            .list_grants()
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.subject)
            .collect();
        assert_eq!(subjects.len(), 3, "only the deleted peer's grant is gone");
        assert!(!subjects.contains(&Subject::Peer(p.id.clone())));
        assert_eq!(
            db.get_group(&g.id).await.unwrap().unwrap().members,
            vec![other.id.clone()]
        );
        assert!(!db.delete_peer(&p.id).await.unwrap());
    }

    #[tokio::test]
    async fn deleting_a_group_deletes_its_grants_but_not_members() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let p = peer("laptop", &[]);
        db.insert_peer(&p).await.unwrap();
        let g = PeerGroup {
            id: new_id(),
            label: "g".into(),
            members: vec![p.id.clone()],
            created_at: now(),
        };
        db.insert_group(&g).await.unwrap();
        db.insert_grant(&grant("a1", Subject::Group(g.id.clone())))
            .await
            .unwrap();
        db.insert_grant(&grant("a1", Subject::Peer(p.id.clone())))
            .await
            .unwrap();
        assert!(db.delete_group(&g.id).await.unwrap());
        assert_eq!(db.list_grants().await.unwrap().len(), 1);
        assert_eq!(count(&db, "peer_group_members").await, 0);
        assert!(db.get_peer(&p.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn owned_addresses_are_claimed_retired_and_forgotten() {
        let db = db().await;
        let a: Ipv6Addr = "300:1::1".parse().unwrap();
        db.claim_address(a, "ygg0", Some("ygg")).await.unwrap();
        db.claim_address(a, "ygg0", Some("ygg")).await.unwrap();
        let rows = db.list_owned_addresses().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].retiring);
        db.retire_address(a, "ygg0", Some("ygg")).await.unwrap();
        assert!(db.list_owned_addresses().await.unwrap()[0].retiring);
        // Retiring an unknown address records it too (adopting a legacy one).
        let b: Ipv6Addr = "300:1::2".parse().unwrap();
        db.retire_address(b, "ygg0", None).await.unwrap();
        assert_eq!(db.list_owned_addresses().await.unwrap().len(), 2);
        // Claiming again makes it active.
        db.claim_address(a, "ygg0", Some("ygg")).await.unwrap();
        assert!(!db.list_owned_addresses().await.unwrap()[0].retiring);
        db.forget_address(a).await.unwrap();
        db.forget_address(b).await.unwrap();
        assert!(db.list_owned_addresses().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn onion_keys_follow_their_address() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        let mut a = address("a1", "tor", "fd00::1");
        a.locator = Locator::Onion {
            hostname: "abc.onion".into(),
        };
        db.insert_address_with_secret(&a, Some("ED25519-V3:k"))
            .await
            .unwrap();
        assert_eq!(db.onion_keys().await.unwrap()[&a.id], "ED25519-V3:k");
        assert_eq!(
            db.get_address(&a.id).await.unwrap().unwrap().locator,
            a.locator
        );
        // The key is stored with the address or not at all.
        let mut b = address("a1", "tor", "fd00::2");
        b.id = a.id.clone();
        assert!(db.insert_address_with_secret(&b, Some("x")).await.is_err());
        assert_eq!(count(&db, "onion_keys").await, 1);
        // Gone with the address.
        db.delete_address(&a.id).await.unwrap();
        assert_eq!(count(&db, "onion_keys").await, 0);
        // And with the app.
        let mut c = address("a1", "tor", "fd00::3");
        c.locator = Locator::Onion {
            hostname: "def.onion".into(),
        };
        db.insert_address_with_secret(&c, Some("ED25519-V3:k2"))
            .await
            .unwrap();
        db.delete_app("a1").await.unwrap();
        assert_eq!(count(&db, "onion_keys").await, 0);
    }

    #[tokio::test]
    async fn deleting_an_app_cascades() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        db.insert_app(&app("a2")).await.unwrap();
        for id in ["a1", "a2"] {
            db.sync_app_ports(
                id,
                &[PortRef {
                    port: 80,
                    proto: Protocol::Tcp,
                }],
                now(),
            )
            .await
            .unwrap();
            db.insert_address(&address(
                id,
                "n",
                &format!("fd00::{}", id.len() + id.as_bytes()[1] as usize),
            ))
            .await
            .unwrap();
            db.insert_grant(&grant(id, Subject::Anyone)).await.unwrap();
        }
        assert!(db.delete_app("a1").await.unwrap());
        assert_eq!(count(&db, "app_ports").await, 1);
        assert_eq!(count(&db, "addresses").await, 1);
        assert_eq!(count(&db, "grants").await, 1);
    }

    #[tokio::test]
    async fn credentials_are_unique_across_peers() {
        let db = db().await;
        let a = peer("a", &[(CredentialKind::Ip, "fd00::5/128")]);
        db.insert_peer(&a).await.unwrap();
        let b = peer("b", &[(CredentialKind::Ip, "fd00::5/128")]);
        let err = db.insert_peer(&b).await.unwrap_err();
        assert!(is_unique_violation(&err));
        assert!(
            db.get_peer(&b.id).await.unwrap().is_none(),
            "insert is atomic"
        );
        // Same value under another kind is a different credential.
        db.add_credential(
            &a.id,
            &Credential {
                id: new_id(),
                kind: CredentialKind::IpSuffix,
                value: "fd00::5/128".into(),
                label: None,
            },
        )
        .await
        .unwrap();
        // Labels are unique too.
        assert!(is_unique_violation(
            &db.insert_peer(&peer("a", &[])).await.unwrap_err()
        ));
        assert_eq!(
            db.find_credential_owner(CredentialKind::Ip, "fd00::5/128")
                .await
                .unwrap(),
            Some(a.id.clone())
        );
        let cid = db.get_peer(&a.id).await.unwrap().unwrap().credentials[0]
            .id
            .clone();
        assert!(db.remove_credential(&a.id, &cid).await.unwrap());
        assert!(!db.remove_credential(&a.id, &cid).await.unwrap());
    }

    fn act(kind: ActivityKind, at: DateTime<Utc>) -> NewActivity {
        let mut a = NewActivity::new(kind, "x");
        a.at = at;
        a
    }

    #[tokio::test]
    async fn activity_retention_by_age_and_rows() {
        let db = db().await;
        db.insert_activity(&[
            act(ActivityKind::PeerAdded, now() - Duration::days(31)),
            act(ActivityKind::PeerAdded, now() - Duration::days(29)),
        ])
        .await
        .unwrap();
        // Insert prunes: the 31-day-old row is gone.
        assert_eq!(count(&db, "activity").await, 1);

        let batch: Vec<_> = (0..30).map(|_| act(ActivityKind::Blocked, now())).collect();
        db.insert_activity(&batch).await.unwrap();
        assert_eq!(count(&db, "activity").await, 31);
        db.prune_activity(Duration::days(30), 10).await.unwrap();
        assert_eq!(count(&db, "activity").await, 10);
        let kept = db
            .list_activity(&ActivityQuery {
                limit: Some(100),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(kept.len(), 10);
        assert!(
            kept.iter().all(|r| r.kind == ActivityKind::Blocked),
            "newest rows kept"
        );
    }

    #[tokio::test]
    async fn activity_query_filters_and_pages() {
        let db = db().await;
        let mut blocked = NewActivity::new(ActivityKind::Blocked, "drop");
        blocked.app_id = Some("a1".into());
        blocked.src = Some("fd00::5".parse().unwrap());
        blocked.port = Some(80);
        blocked.proto = Some(Protocol::Tcp);
        blocked.count = 7;
        db.insert_activity(&[
            blocked,
            NewActivity::new(ActivityKind::GrantAdded, "g")
                .app("a1")
                .peer("p1"),
            NewActivity::new(ActivityKind::GrantAdded, "g2").app("a2"),
        ])
        .await
        .unwrap();
        let all = db.list_activity(&ActivityQuery::default()).await.unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[0].id > all[1].id, "newest first");
        let b = db
            .list_activity(&ActivityQuery {
                kind: Some(ActivityKind::Blocked),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(
            (b[0].count, b[0].port, b[0].src),
            (7, Some(80), Some("fd00::5".parse().unwrap()))
        );
        let a1 = db
            .list_activity(&ActivityQuery {
                app_id: Some("a1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(a1.len(), 2);
        let p1 = db
            .list_activity(&ActivityQuery {
                peer_id: Some("p1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(p1.len(), 1);
        let page = db
            .list_activity(&ActivityQuery {
                limit: Some(1),
                before: Some(all[0].id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page[0].id, all[1].id);
        let future = db
            .list_activity(&ActivityQuery {
                since: Some(now() + Duration::hours(1)),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(future.is_empty());
    }

    #[tokio::test]
    async fn grant_roundtrip_and_network_cleanup() {
        let db = db().await;
        db.insert_app(&app("a1")).await.unwrap();
        db.insert_address(&address("a1", "ygg", "300:1::5"))
            .await
            .unwrap();
        db.insert_address(&address("a1", "lan", "2001:db8::5"))
            .await
            .unwrap();
        let mut g = grant("a1", Subject::Anyone);
        g.network_id = Some("ygg".into());
        db.insert_grant(&g).await.unwrap();
        let mut whole = grant("a1", Subject::Anyone);
        whole.port = None;
        db.insert_grant(&whole).await.unwrap();
        let got = db.get_grant(&g.id).await.unwrap().unwrap();
        assert_eq!((got.port, got.network_id.as_deref()), (g.port, Some("ygg")));
        assert_eq!(db.get_grant(&whole.id).await.unwrap().unwrap().port, None);

        let removed = db.delete_addresses_by_network("ygg").await.unwrap();
        assert_eq!(removed.len(), 1);
        let left = db.list_grants().await.unwrap();
        assert_eq!(left.len(), 1, "a grant tied to the removed network goes");
        assert_eq!(db.list_addresses().await.unwrap().len(), 1);
    }
}

#[cfg(test)]
mod memory_pool_tests {
    use super::*;

    #[tokio::test]
    async fn memory_pool_shares_one_database() {
        let db = Database::new(":memory:").await.unwrap();
        let mut a = db.pool.acquire().await.unwrap();
        let mut b = db.pool.acquire().await.unwrap();
        sqlx::query("CREATE TABLE t (x INTEGER)")
            .execute(&mut *a)
            .await
            .unwrap();
        sqlx::query("INSERT INTO t VALUES (1)")
            .execute(&mut *a)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t")
            .fetch_one(&mut *b)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn memory_databases_are_isolated_from_each_other() {
        let a = Database::new(":memory:").await.unwrap();
        let b = Database::new(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE t (x INTEGER)")
            .execute(&a.pool)
            .await
            .unwrap();
        assert!(sqlx::query("SELECT * FROM t")
            .fetch_all(&b.pool)
            .await
            .is_err());
    }
}
