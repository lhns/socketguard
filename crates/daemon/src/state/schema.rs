//! The schema (v8), its migrations and the archive of pre-v1 databases.

use super::protect::protect_files;
use super::settings::FRESH_DB_KEY;
use super::{ts, with_suffix, Database};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use socketguard_core::{new_id, normalize_ranges, ranges_text, PortRange, PortRef};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

pub const SCHEMA_VERSION: i64 = 8;

/// Schema v1 -> v2: the service keys of onion addresses (ADR 0037).
const MIGRATION_1_TO_2: &str = r#"
CREATE TABLE onion_keys (
    address_id TEXT PRIMARY KEY REFERENCES addresses(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL
);
"#;

/// Schema v2 -> v3: why an app's identity is special (ADR 0027 amendment), and the
/// addresses the daemon has put on interfaces, written ahead of the change so an address
/// can never be on an interface without the ruleset knowing about it.
///
/// Existing app ids are not recomputed (the uid they now include was never stored): they
/// stay as inert records and their programs reappear as new, pending apps.
const MIGRATION_2_TO_3: &str = r#"
ALTER TABLE apps ADD COLUMN identity_note TEXT;
CREATE TABLE owned_addresses (
    addr TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    network_id TEXT,
    state TEXT NOT NULL,
    since TEXT
);
"#;

/// Schema v3 -> v4: a grant exists once. Two requests racing past the engine's check used
/// to store the same grant twice. Duplicates are dropped first (the oldest stays); NULLs
/// are folded because a unique index treats them as distinct.
const MIGRATION_3_TO_4: &str = r#"
DELETE FROM grants WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM grants
    GROUP BY app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(network_id, ''),
             subject_kind, COALESCE(subject_id, '')
);
CREATE UNIQUE INDEX grants_unique ON grants (
    app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(network_id, ''),
    subject_kind, COALESCE(subject_id, '')
);
"#;

/// Listening ports record over which IP versions they accept connections. Rows stored
/// before count as dual until the next scan says otherwise.
const MIGRATION_4_TO_5: &str = r#"
ALTER TABLE app_ports ADD COLUMN family TEXT NOT NULL DEFAULT 'dual';
"#;

/// Schema v5 -> v6: tags, grants that target an app or a tag, the system flag of apps and
/// the private Tor client keys the daemon generated (ADRs 0043, 0045).
///
/// A grant's target has no foreign key (it points at two tables), so deleting an app or a
/// tag deletes its grants explicitly. SQLite cannot drop `NOT NULL` or retarget a column,
/// hence the rebuild of `grants`.
const MIGRATION_5_TO_6: &str = r#"
CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    patterns TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE tag_members (
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    port INTEGER,
    proto TEXT
);
CREATE UNIQUE INDEX tag_members_unique ON tag_members (
    tag_id, app_id, COALESCE(port, -1), COALESCE(proto, '')
);
CREATE INDEX tag_members_app ON tag_members(app_id);
CREATE TABLE tag_exclusions (
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    PRIMARY KEY (tag_id, app_id)
);

CREATE TABLE grants_new (
    id TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    port INTEGER,
    proto TEXT,
    network_id TEXT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    created_at TEXT NOT NULL
);
INSERT INTO grants_new (id, target_kind, target_id, port, proto, network_id, subject_kind,
                        subject_id, created_at)
    SELECT id, 'app', app_id, port, proto, network_id, subject_kind, subject_id, created_at
    FROM grants;
DROP TABLE grants;
ALTER TABLE grants_new RENAME TO grants;
CREATE INDEX grants_target ON grants(target_kind, target_id);
CREATE UNIQUE INDEX grants_unique ON grants (
    target_kind, target_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(network_id, ''),
    subject_kind, COALESCE(subject_id, '')
);

ALTER TABLE apps ADD COLUMN system INTEGER NOT NULL DEFAULT 0;

CREATE TABLE tor_client_keys (
    credential_id TEXT PRIMARY KEY REFERENCES peer_credentials(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL
);
"#;

/// Schema v6 -> v7: socket groups and scopes (ADR 0047). Grants, tag members and addresses
/// get a `socket_group` column next to `port`/`proto`: all NULL = every socket, a port with
/// its protocol, or a group. The unique indexes cover it.
///
/// `addresses` is altered in place rather than rebuilt: `onion_keys` cascades from it, and
/// dropping the table would delete the keys. The old `ports` column is read by
/// [`finish_6_to_7`], which turns what SQL cannot (several ports) into socket groups, and
/// then drops it.
const MIGRATION_6_TO_7: &str = r#"
CREATE TABLE socket_groups (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    ports TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE socket_group_apps (
    group_id TEXT NOT NULL REFERENCES socket_groups(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, app_id)
);
CREATE INDEX socket_group_apps_app ON socket_group_apps(app_id);

ALTER TABLE grants ADD COLUMN socket_group TEXT;
DROP INDEX grants_unique;
CREATE UNIQUE INDEX grants_unique ON grants (
    target_kind, target_id, COALESCE(port, -1), COALESCE(proto, ''),
    COALESCE(socket_group, ''), COALESCE(network_id, ''),
    subject_kind, COALESCE(subject_id, '')
);

ALTER TABLE tag_members ADD COLUMN socket_group TEXT;
DROP INDEX tag_members_unique;
CREATE UNIQUE INDEX tag_members_unique ON tag_members (
    tag_id, app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(socket_group, '')
);

ALTER TABLE addresses ADD COLUMN port INTEGER;
ALTER TABLE addresses ADD COLUMN proto TEXT;
ALTER TABLE addresses ADD COLUMN socket_group TEXT;
UPDATE addresses
    SET port = json_extract(ports, '$[0].port'), proto = json_extract(ports, '$[0].proto')
    WHERE CASE WHEN ports = 'all' THEN 0 ELSE json_array_length(ports) = 1 END;
"#;

/// The part of v6 -> v7 that needs code: an address that served several ports becomes a
/// socket group of those ports (labelled by them, so one group serves every app with the
/// same set) attached to its app, with the address scoped to the group; one that served
/// none is dropped; then the old `ports` column goes.
async fn finish_6_to_7(conn: &mut SqliteConnection) -> Result<()> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, app_id, ports FROM addresses \
         WHERE CASE WHEN ports = 'all' THEN 0 ELSE json_array_length(ports) != 1 END",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut by_label: HashMap<String, String> = HashMap::new();
    for (id, app_id, ports) in rows {
        let refs: Vec<PortRef> = serde_json::from_str(&ports)
            .with_context(|| format!("address {id} has unreadable ports"))?;
        if refs.is_empty() {
            // Served nothing; scope All would widen it.
            sqlx::query("DELETE FROM addresses WHERE id = ?")
                .bind(&id)
                .execute(&mut *conn)
                .await?;
            continue;
        }
        let ranges = normalize_ranges(
            &refs
                .iter()
                .map(|p| PortRange::single(*p))
                .collect::<Vec<_>>(),
        );
        let label = ranges_text(&ranges);
        let group_id = match by_label.get(&label) {
            Some(g) => g.clone(),
            None => {
                let g = new_id();
                sqlx::query(
                    "INSERT INTO socket_groups (id, label, ports, created_at) VALUES (?, ?, ?, ?)",
                )
                .bind(&g)
                .bind(&label)
                .bind(serde_json::to_string(&ranges)?)
                .bind(ts(Utc::now()))
                .execute(&mut *conn)
                .await?;
                by_label.insert(label, g.clone());
                g
            }
        };
        sqlx::query("INSERT OR IGNORE INTO socket_group_apps (group_id, app_id) VALUES (?, ?)")
            .bind(&group_id)
            .bind(&app_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("UPDATE addresses SET socket_group = ? WHERE id = ?")
            .bind(&group_id)
            .bind(&id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::raw_sql("ALTER TABLE addresses DROP COLUMN ports")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Schema v7 -> v8: addresses on demand and reservations (ADR 0047).
///
/// A reservation is a named object with bindings, an address per network (`addresses` gets
/// a `reservation_id`) and grants that target it. `addresses.app_id` becomes nullable (a
/// reservation's address belongs to no app, so forgetting an app leaves it), which SQLite
/// can only do by rebuilding the table. `onion_keys` cascades from `addresses`, so its
/// rows are copied aside and put back. Duplicate automatic addresses of one row (the
/// oldest stays) would break the unique index and are dropped first.
///
/// Every existing address stays automatic; which of them are reservations is decided by
/// [`Engine::classify_legacy_addresses`], which needs the networks, once the daemon starts
/// (marker `classify_addresses`). The address mode setting is gone.
const MIGRATION_7_TO_8: &str = r#"
CREATE TABLE reservations (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE reservation_bindings (
    id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL REFERENCES reservations(id) ON DELETE CASCADE,
    app_id TEXT REFERENCES apps(id) ON DELETE CASCADE,
    port INTEGER,
    proto TEXT,
    socket_group TEXT,
    tag_id TEXT REFERENCES tags(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX reservation_bindings_unique ON reservation_bindings (
    reservation_id, COALESCE(app_id, ''), COALESCE(tag_id, ''), COALESCE(port, -1),
    COALESCE(proto, ''), COALESCE(socket_group, '')
);
CREATE INDEX reservation_bindings_app ON reservation_bindings(app_id);

CREATE TABLE onion_keys_bak AS SELECT address_id, private_key FROM onion_keys;
DELETE FROM addresses WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM addresses
    GROUP BY app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(socket_group, ''),
             network_id
);
CREATE TABLE addresses_new (
    id TEXT PRIMARY KEY,
    app_id TEXT REFERENCES apps(id) ON DELETE CASCADE,
    reservation_id TEXT REFERENCES reservations(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL,
    port INTEGER,
    proto TEXT,
    socket_group TEXT,
    locator_kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    created_at TEXT NOT NULL
);
INSERT INTO addresses_new (id, app_id, network_id, port, proto, socket_group, locator_kind,
                           locator, created_at)
    SELECT id, app_id, network_id, port, proto, socket_group, locator_kind, locator,
           created_at FROM addresses;
DROP TABLE addresses;
ALTER TABLE addresses_new RENAME TO addresses;
CREATE INDEX addresses_app ON addresses(app_id);
CREATE UNIQUE INDEX addresses_row ON addresses (
    app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(socket_group, ''), network_id
) WHERE app_id IS NOT NULL;
CREATE UNIQUE INDEX addresses_reservation ON addresses (reservation_id, network_id)
    WHERE reservation_id IS NOT NULL;
INSERT INTO onion_keys (address_id, private_key)
    SELECT address_id, private_key FROM onion_keys_bak
    WHERE address_id IN (SELECT id FROM addresses);
DROP TABLE onion_keys_bak;

DELETE FROM settings WHERE key = 'address_mode';
INSERT OR REPLACE INTO settings (key, value) VALUES ('classify_addresses', 'pending');
"#;

/// `MIGRATIONS[n]` takes the schema from v(n+1) to v(n+2).
const MIGRATIONS: [&str; 7] = [
    MIGRATION_1_TO_2,
    MIGRATION_2_TO_3,
    MIGRATION_3_TO_4,
    MIGRATION_4_TO_5,
    MIGRATION_5_TO_6,
    MIGRATION_6_TO_7,
    MIGRATION_7_TO_8,
];

const SCHEMA: &str = r#"
CREATE TABLE apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    process_name TEXT NOT NULL,
    exe_path TEXT,
    interpreter_arg TEXT,
    reviewed INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE app_ports (
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    listening INTEGER NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (app_id, port, proto)
);
CREATE TABLE addresses (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL,
    ports TEXT NOT NULL,
    locator_kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX addresses_app ON addresses(app_id);
CREATE TABLE peers (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE peer_credentials (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT,
    UNIQUE (kind, value)
);
CREATE TABLE peer_groups (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE peer_group_members (
    group_id TEXT NOT NULL REFERENCES peer_groups(id) ON DELETE CASCADE,
    peer_id TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, peer_id)
);
CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    port INTEGER,
    proto TEXT,
    network_id TEXT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX grants_app ON grants(app_id);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    app_id TEXT,
    peer_id TEXT,
    network_id TEXT,
    src TEXT,
    port INTEGER,
    proto TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    message TEXT NOT NULL
);
CREATE INDEX activity_at ON activity(at);
"#;

/// A database from before schema v1: `user_version` 0 with a `sockets` table.
pub(super) async fn is_pre_v1(path: &Path) -> bool {
    let opts = SqliteConnectOptions::new().filename(path);
    let Ok(mut conn) = SqliteConnection::connect_with(&opts).await else {
        return false; // not a database we can open; the normal open reports it
    };
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut conn)
        .await
        .unwrap_or(-1);
    let sockets: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sockets'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap_or(0);
    // Close before any rename: Windows refuses to move a file with an open handle.
    let _ = conn.close().await;
    version == 0 && sockets > 0
}

/// Move a pre-v1 database (and its WAL files) to `<db>.pre-v1`, or the first free
/// `<db>.pre-v1.N`. Returns the new path of the database file.
pub(super) fn archive_pre_v1(path: &Path) -> Result<PathBuf> {
    let mut target = with_suffix(path, ".pre-v1");
    let mut n = 1;
    while target.exists() {
        target = with_suffix(path, &format!(".pre-v1.{n}"));
        n += 1;
    }
    std::fs::rename(path, &target)
        .with_context(|| format!("cannot move old database {}", path.display()))?;
    for side in ["-wal", "-shm"] {
        let from = with_suffix(path, side);
        if from.exists() {
            std::fs::rename(&from, with_suffix(&target, side))
                .with_context(|| format!("cannot move {}", from.display()))?;
        }
    }
    Ok(target)
}

impl Database {
    /// Bring the schema to the current version: create it on a fresh database, run the
    /// pending migrations on an older one, refuse one from a newer daemon.
    pub async fn migrate(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *tx)
            .await?;
        if version > SCHEMA_VERSION {
            bail!(
                "database schema v{version} is newer than this daemon supports (v{SCHEMA_VERSION})"
            );
        }
        if version == 0 {
            sqlx::raw_sql(SCHEMA).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO settings (key, value) VALUES (?, 'true')")
                .bind(FRESH_DB_KEY)
                .execute(&mut *tx)
                .await?;
        }
        // `SCHEMA` is v1; MIGRATIONS[n] takes vN+1 to vN+2.
        let first = usize::try_from(version.max(1) - 1)?;
        for (n, sql) in MIGRATIONS.iter().enumerate().skip(first) {
            sqlx::raw_sql(sql).execute(&mut *tx).await?;
            // v6 -> v7 needs code before the next migration rebuilds `addresses`.
            if n == 5 && version < 7 {
                finish_6_to_7(&mut tx).await?;
            }
        }
        if version != SCHEMA_VERSION {
            sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
                .execute(&mut *tx)
                .await?;
            if version == 0 {
                info!("Created database schema v{SCHEMA_VERSION}");
            } else {
                info!("Migrated database schema v{version} to v{SCHEMA_VERSION}");
            }
        }
        tx.commit().await?;
        if let Some(path) = self.path.as_deref() {
            protect_files(Path::new(path))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::*;
    use socketguard_core::Subject;

    #[tokio::test]
    async fn schema_v1_is_created_once() {
        let db = db().await;
        let v: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let mut tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        tables.sort();
        assert_eq!(
            tables,
            [
                "activity",
                "addresses",
                "app_ports",
                "apps",
                "grants",
                "onion_keys",
                "owned_addresses",
                "peer_credentials",
                "peer_group_members",
                "peer_groups",
                "peers",
                "reservation_bindings",
                "reservations",
                "settings",
                "socket_group_apps",
                "socket_groups",
                "tag_exclusions",
                "tag_members",
                "tags",
                "tor_client_keys"
            ]
        );
        db.migrate().await.expect("migrate is idempotent");
    }

    #[tokio::test]
    async fn newer_schema_is_refused() {
        let db = db().await;
        sqlx::query("PRAGMA user_version = 99")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(db.migrate().await.is_err());
    }

    async fn make_old_db(path: &Path) {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&opts).await.unwrap();
        sqlx::query("CREATE TABLE sockets (id TEXT PRIMARY KEY)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sockets VALUES ('old')")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn pre_v1_database_is_renamed_not_migrated() {
        let path = temp_db_path("prev1");
        make_old_db(&path).await;
        let archived = with_suffix(&path, ".pre-v1");
        // A leftover WAL file moves along with it.
        std::fs::write(with_suffix(&path, "-wal"), b"").unwrap();

        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        assert!(archived.exists(), "old database kept as .pre-v1");
        assert!(with_suffix(&archived, "-wal").exists());
        assert!(!with_suffix(&path, "-wal").exists());
        // The fresh database is v1 and has none of the old data.
        let old_table: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = 'sockets'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(old_table, 0);
        assert_eq!(count(&db, "apps").await, 0);
        let kept = SqliteConnectOptions::new().filename(&archived);
        let mut c = SqliteConnection::connect_with(&kept).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sockets")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(n, 1);
        c.close().await.unwrap();
        db.pool.close().await;

        // Reopening a v1 database leaves it alone.
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        db.pool.close().await;

        // A second old database does not overwrite the first archive.
        let _ = std::fs::remove_file(&path);
        make_old_db(&path).await;
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        assert!(with_suffix(&path, ".pre-v1.1").exists());
        db.pool.close().await;
        for suffix in ["", ".pre-v1", ".pre-v1.1", "-wal", "-shm", ".pre-v1-wal"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[tokio::test]
    async fn an_empty_or_v1_file_is_not_archived() {
        let path = temp_db_path("v1");
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        db.insert_app(&app("a1")).await.unwrap();
        drop(db);
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        assert!(db.get_app("a1").await.unwrap().is_some());
        assert!(!with_suffix(&path, ".pre-v1").exists());
        db.pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[tokio::test]
    async fn v1_database_migrates_to_v2() {
        let path = temp_db_path("v1-to-v2");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::raw_sql(SCHEMA).execute(&mut c).await.unwrap();
            sqlx::query("PRAGMA user_version = 1")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::query("INSERT INTO settings (key, value) VALUES ('k', 'kept')")
                .execute(&mut c)
                .await
                .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let v: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert_eq!(count(&db, "onion_keys").await, 0);
        assert_eq!(db.get_setting("k").await.unwrap().as_deref(), Some("kept"));
        db.migrate().await.expect("idempotent");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v2_database_migrates_to_v3() {
        let path = temp_db_path("v2-to-v3");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::raw_sql(SCHEMA).execute(&mut c).await.unwrap();
            sqlx::raw_sql(MIGRATION_1_TO_2)
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::query("PRAGMA user_version = 2")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen) \
                 VALUES ('old', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            )
            .execute(&mut c)
            .await
            .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let app = db.get_app("old").await.unwrap().unwrap();
        assert_eq!(app.identity_note, None);
        assert_eq!(db.list_owned_addresses().await.unwrap().len(), 0);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v3_database_migrates_to_v4_and_drops_duplicate_grants() {
        let path = temp_db_path("v3-to-v4");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            for sql in [SCHEMA, MIGRATION_1_TO_2, MIGRATION_2_TO_3] {
                sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
            }
            sqlx::query("PRAGMA user_version = 3")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen)                  VALUES ('a', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            )
            .execute(&mut c)
            .await
            .unwrap();
            // Two grants to Anyone on the whole app (NULL port and network), one to a peer.
            for (id, port, kind, subject) in [
                ("g1", None, "anyone", None),
                ("g2", None, "anyone", None),
                ("g3", Some(80), "peer", Some("p1")),
                ("g4", Some(80), "peer", Some("p1")),
            ] {
                sqlx::query(
                    "INSERT INTO grants (id, app_id, port, proto, network_id, subject_kind,                      subject_id, created_at) VALUES (?, 'a', ?, ?, NULL, ?, ?, '2026-01-01T00:00:00Z')",
                )
                .bind(id)
                .bind(port)
                .bind(port.map(|_| "tcp"))
                .bind(kind)
                .bind(subject)
                .execute(&mut c)
                .await
                .unwrap();
            }
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let ids: Vec<String> = db
            .list_grants()
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect();
        assert_eq!(ids, ["g1", "g3"], "the oldest of each duplicate stays");

        let mut again = grant("a", Subject::Anyone);
        again.scope = socketguard_core::Scope::All;
        let err = db.insert_grant(&again).await.unwrap_err();
        assert!(super::super::is_unique_violation(&err), "{err:#}");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v4_database_migrates_to_v5_with_dual_ports() {
        let path = temp_db_path("v4-to-v5");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            for sql in [SCHEMA, MIGRATION_1_TO_2, MIGRATION_2_TO_3, MIGRATION_3_TO_4] {
                sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
            }
            sqlx::query("PRAGMA user_version = 4")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::raw_sql(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen)                  VALUES ('a', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');                  INSERT INTO app_ports (app_id, port, proto, listening, last_seen)                  VALUES ('a', 80, 'tcp', 1, '2026-01-01T00:00:00Z');",
            )
            .execute(&mut c)
            .await
            .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let app = db.get_app("a").await.unwrap().unwrap();
        assert_eq!(app.ports[0].family, socketguard_core::AddrFamily::Dual);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v5_database_migrates_to_v6_with_app_targets() {
        let path = temp_db_path("v5-to-v6");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::raw_sql(SCHEMA).execute(&mut c).await.unwrap();
            for sql in &MIGRATIONS[..4] {
                sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
            }
            sqlx::query("PRAGMA user_version = 5")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::raw_sql(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen) \
                 VALUES ('a', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'); \
                 INSERT INTO grants (id, app_id, port, proto, network_id, subject_kind, \
                 subject_id, created_at) VALUES \
                 ('g1', 'a', 80, 'tcp', NULL, 'peer', 'p1', '2026-01-01T00:00:00Z'), \
                 ('g2', 'a', NULL, NULL, 'lan', 'anyone', NULL, '2026-01-01T00:00:00Z');",
            )
            .execute(&mut c)
            .await
            .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let grants = db.list_grants().await.unwrap();
        assert_eq!(grants.len(), 2);
        assert!(grants
            .iter()
            .all(|g| g.target == socketguard_core::Target::App("a".into())));
        assert_eq!(grants[0].network_id, None);
        assert_eq!(grants[1].network_id.as_deref(), Some("lan"));
        assert!(!db.get_app("a").await.unwrap().unwrap().system);
        // The unique index still holds, and now covers the target.
        let mut dup = grant("a", Subject::Peer("p1".into()));
        dup.id = "g3".into();
        let err = db.insert_grant(&dup).await.unwrap_err();
        assert!(super::super::is_unique_violation(&err), "{err:#}");
        dup.target = socketguard_core::Target::Tag("a".into());
        db.insert_grant(&dup)
            .await
            .expect("a tag with the same id is another target");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v6_database_migrates_to_v7_with_scopes_and_socket_groups() {
        use socketguard_core::{Protocol, Scope, Target};
        let path = temp_db_path("v6-to-v7");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::raw_sql(SCHEMA).execute(&mut c).await.unwrap();
            for sql in &MIGRATIONS[..5] {
                sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
            }
            sqlx::query("PRAGMA user_version = 6")
                .execute(&mut c)
                .await
                .unwrap();
            let web = r#"[{"port":80,"proto":"tcp"},{"port":443,"proto":"tcp"}]"#;
            let web_rev = r#"[{"port":443,"proto":"tcp"},{"port":80,"proto":"tcp"}]"#;
            let dns = r#"[{"port":53,"proto":"udp"},{"port":54,"proto":"udp"}]"#;
            let one = r#"[{"port":8080,"proto":"tcp"}]"#;
            sqlx::raw_sql(&format!(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen) \
                 VALUES ('a', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), \
                        ('b', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'); \
                 INSERT INTO addresses (id, app_id, network_id, ports, locator_kind, locator, \
                                        created_at) VALUES \
                 ('all', 'a', 'ygg', 'all', 'ipv6', '300:1::1', '2026-01-01T00:00:00Z'), \
                 ('one', 'a', 'ygg', '{one}', 'ipv6', '300:1::2', '2026-01-01T00:00:01Z'), \
                 ('many', 'a', 'ygg', '{web_rev}', 'ipv6', '300:1::3', '2026-01-01T00:00:02Z'), \
                 ('many_b', 'b', 'ygg', '{web}', 'ipv6', '300:1::4', '2026-01-01T00:00:03Z'), \
                 ('none', 'b', 'ygg', '[]', 'ipv6', '300:1::5', '2026-01-01T00:00:04Z'), \
                 ('onion', 'b', 'tor', '{dns}', 'onion', 'abc.onion', '2026-01-01T00:00:05Z'); \
                 INSERT INTO onion_keys (address_id, private_key) VALUES ('onion', 'secret'); \
                 INSERT INTO grants (id, target_kind, target_id, port, proto, network_id, \
                                     subject_kind, subject_id, created_at) VALUES \
                 ('g1', 'app', 'a', 80, 'tcp', NULL, 'peer', 'p1', '2026-01-01T00:00:00Z'), \
                 ('g2', 'app', 'a', NULL, NULL, NULL, 'anyone', NULL, '2026-01-01T00:00:00Z'); \
                 INSERT INTO tags (id, label, patterns, created_at) \
                 VALUES ('t', 'dev', '[]', '2026-01-01T00:00:00Z'); \
                 INSERT INTO tag_members (tag_id, app_id, port, proto) VALUES \
                 ('t', 'a', NULL, NULL), ('t', 'b', 22, 'tcp');"
            ))
            .execute(&mut c)
            .await
            .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        // Addresses: all stays All, one port becomes Port, several ports a group of those
        // ports attached to the app (shared by apps with the same set), none is dropped.
        let addrs: std::collections::HashMap<String, socketguard_core::Address> = db
            .list_addresses()
            .await
            .unwrap()
            .into_iter()
            .map(|a| (a.id.clone(), a))
            .collect();
        assert_eq!(addrs["all"].scope, Scope::All);
        assert_eq!(
            addrs["one"].scope,
            Scope::Port {
                port: 8080,
                proto: Protocol::Tcp
            }
        );
        assert!(
            !addrs.contains_key("none"),
            "an address serving nothing is dropped"
        );
        let groups = db.list_socket_groups().await.unwrap();
        let labels: Vec<&str> = groups.iter().map(|g| g.label.as_str()).collect();
        assert_eq!(labels, ["53-54/udp", "80/tcp, 443/tcp"]);
        let web = groups
            .iter()
            .find(|g| g.label == "80/tcp, 443/tcp")
            .unwrap();
        assert_eq!(web.apps, ["a", "b"], "the same ports share a group");
        assert_eq!(addrs["many"].scope, Scope::Group { id: web.id.clone() });
        assert_eq!(addrs["many_b"].scope, addrs["many"].scope);
        let dns = groups.iter().find(|g| g.label == "53-54/udp").unwrap();
        assert_eq!(addrs["onion"].scope, Scope::Group { id: dns.id.clone() });
        assert_eq!(dns.apps, ["b"]);
        // The onion key survived the change of the addresses table.
        assert_eq!(db.onion_keys().await.unwrap()["onion"], "secret");
        let cols: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('addresses')")
                .fetch_all(&db.pool)
                .await
                .unwrap();
        assert!(!cols.contains(&"ports".to_string()));

        // Grants and tag members keep their meaning.
        let grants = db.list_grants().await.unwrap();
        assert_eq!(
            grants[0].scope,
            Scope::Port {
                port: 80,
                proto: Protocol::Tcp
            }
        );
        assert_eq!(grants[1].scope, Scope::All);
        assert!(grants.iter().all(|g| g.target == Target::App("a".into())));
        let tag = db.get_tag("t").await.unwrap().unwrap();
        assert_eq!(tag.members[0].scope, Scope::All);
        assert_eq!(
            tag.members[1].scope,
            Scope::Port {
                port: 22,
                proto: Protocol::Tcp
            }
        );
        // The unique indexes now cover the group column.
        let mut by_group = grant("a", Subject::Peer("p1".into()));
        by_group.scope = Scope::Group { id: web.id.clone() };
        db.insert_grant(&by_group).await.unwrap();
        let mut again = by_group.clone();
        again.id = "other".into();
        let err = db.insert_grant(&again).await.unwrap_err();
        assert!(super::super::is_unique_violation(&err), "{err:#}");
        again.scope = Scope::Group {
            id: "elsewhere".into(),
        };
        db.insert_grant(&again)
            .await
            .expect("another group is another grant");
        db.migrate().await.expect("idempotent");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn v7_database_migrates_to_v8_keeping_addresses_and_onion_keys() {
        let path = temp_db_path("v7-to-v8");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut c = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::raw_sql(SCHEMA).execute(&mut c).await.unwrap();
            for sql in &MIGRATIONS[..6] {
                sqlx::raw_sql(sql).execute(&mut c).await.unwrap();
            }
            finish_6_to_7(&mut c).await.unwrap();
            sqlx::query("PRAGMA user_version = 7")
                .execute(&mut c)
                .await
                .unwrap();
            sqlx::raw_sql(
                "INSERT INTO apps (id, name, process_name, reviewed, first_seen, last_seen) \
                 VALUES ('a', 'n', 'p', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'); \
                 INSERT INTO addresses (id, app_id, network_id, port, proto, socket_group, \
                                        locator_kind, locator, created_at) VALUES \
                 ('all', 'a', 'ygg', NULL, NULL, NULL, 'ipv6', '300:1::1', '2026-01-01T00:00:00Z'), \
                 ('p80', 'a', 'ygg', 80, 'tcp', NULL, 'ipv6', '300:1::2', '2026-01-01T00:00:01Z'), \
                 ('dup', 'a', 'ygg', 80, 'tcp', NULL, 'ipv6', '300:1::3', '2026-01-01T00:00:02Z'), \
                 ('lo', 'a', 'local', NULL, NULL, NULL, 'ipv6', 'fd00::1', '2026-01-01T00:00:03Z'), \
                 ('onion', 'a', 'tor', 80, 'tcp', NULL, 'onion', 'abc.onion', '2026-01-01T00:00:04Z'); \
                 INSERT INTO onion_keys (address_id, private_key) VALUES \
                 ('onion', 'secret'), ('dup', 'gone'); \
                 INSERT INTO settings (key, value) VALUES ('address_mode', 'per_port');",
            )
            .execute(&mut c)
            .await
            .unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        let v: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);

        // Every address stays, automatic; a second address for the same row is dropped.
        let ids: Vec<String> = db
            .list_addresses()
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, ["all", "p80", "lo", "onion"]);
        for a in db.list_addresses().await.unwrap() {
            assert_eq!(a.app_id.as_deref(), Some("a"));
            assert_eq!(a.reservation_id, None);
        }
        // The onion key survived the rebuild of the table; the dropped address's did not.
        let keys = db.onion_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys["onion"], "secret");
        // The address mode is gone; the classification is pending for the daemon.
        assert_eq!(db.get_setting("address_mode").await.unwrap(), None);
        assert_eq!(
            db.get_setting("classify_addresses")
                .await
                .unwrap()
                .as_deref(),
            Some("pending")
        );
        // A reservation's address belongs to no app, so it survives forgetting one.
        let res = socketguard_core::Reservation {
            id: "r".into(),
            label: "res".into(),
            bindings: vec![],
            created_at: chrono::Utc::now(),
        };
        db.insert_reservation(&res).await.unwrap();
        db.assign_address("p80", "r").await.unwrap();
        assert!(db.delete_app("a").await.unwrap());
        let left = db.list_addresses().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].reservation_id.as_deref(), Some("r"));
        db.migrate().await.expect("idempotent");
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
