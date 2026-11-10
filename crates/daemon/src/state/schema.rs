//! The schema (v4), its migrations and the archive of pre-v1 databases.

use super::protect::protect_files;
use super::settings::FRESH_DB_KEY;
use super::{with_suffix, Database};
use anyhow::{bail, Context, Result};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use std::path::{Path, PathBuf};
use tracing::info;

pub const SCHEMA_VERSION: i64 = 5;

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

/// `MIGRATIONS[n]` takes the schema from v(n+1) to v(n+2).
const MIGRATIONS: [&str; 4] = [
    MIGRATION_1_TO_2,
    MIGRATION_2_TO_3,
    MIGRATION_3_TO_4,
    MIGRATION_4_TO_5,
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
        for sql in &MIGRATIONS[usize::try_from(version.max(1) - 1)?..] {
            sqlx::raw_sql(sql).execute(&mut *tx).await?;
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
                "settings"
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
        again.port = None;
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
}
