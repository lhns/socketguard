//! The schema. There is one version and no migrations (ADR 0055): a database written by
//! another version is refused.

use super::protect::protect_files;
use super::settings::FRESH_DB_KEY;
use super::Database;
use anyhow::{bail, Result};
use std::path::Path;
use tracing::info;

pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    process_name TEXT NOT NULL,
    exe_path TEXT,
    interpreter_arg TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    identity_note TEXT,
    system INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE app_ports (
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    listening INTEGER NOT NULL,
    last_seen TEXT NOT NULL,
    family TEXT NOT NULL DEFAULT 'dual',
    PRIMARY KEY (app_id, port, proto)
);
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
    proto TEXT,
    port_group TEXT
);
CREATE UNIQUE INDEX tag_members_unique ON tag_members (
    tag_id, app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(port_group, '')
);
CREATE INDEX tag_members_app ON tag_members(app_id);
CREATE TABLE tag_exclusions (
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    PRIMARY KEY (tag_id, app_id)
);
CREATE TABLE port_groups (
    id TEXT PRIMARY KEY,
    label TEXT UNIQUE NOT NULL,
    ports TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE port_group_apps (
    group_id TEXT NOT NULL REFERENCES port_groups(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, app_id)
);
CREATE INDEX port_group_apps_app ON port_group_apps(app_id);
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
    port_group TEXT,
    tag_id TEXT REFERENCES tags(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX reservation_bindings_unique ON reservation_bindings (
    reservation_id, COALESCE(app_id, ''), COALESCE(tag_id, ''), COALESCE(port, -1),
    COALESCE(proto, ''), COALESCE(port_group, '')
);
CREATE INDEX reservation_bindings_app ON reservation_bindings(app_id);
CREATE TABLE addresses (
    id TEXT PRIMARY KEY,
    app_id TEXT REFERENCES apps(id) ON DELETE CASCADE,
    reservation_id TEXT REFERENCES reservations(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL,
    port INTEGER,
    proto TEXT,
    port_group TEXT,
    locator_kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX addresses_app ON addresses(app_id);
CREATE UNIQUE INDEX addresses_row ON addresses (
    app_id, COALESCE(port, -1), COALESCE(proto, ''), COALESCE(port_group, ''), network_id
) WHERE app_id IS NOT NULL;
CREATE UNIQUE INDEX addresses_reservation ON addresses (reservation_id, network_id)
    WHERE reservation_id IS NOT NULL;
CREATE TABLE onion_keys (
    address_id TEXT PRIMARY KEY REFERENCES addresses(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL
);
CREATE TABLE tor_client_keys (
    credential_id TEXT PRIMARY KEY REFERENCES peer_credentials(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL
);
CREATE TABLE owned_addresses (
    addr TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    network_id TEXT,
    state TEXT NOT NULL,
    since TEXT
);
CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    port INTEGER,
    proto TEXT,
    network_id TEXT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    created_at TEXT NOT NULL,
    port_group TEXT
);
CREATE INDEX grants_target ON grants(target_kind, target_id);
CREATE UNIQUE INDEX grants_unique ON grants (
    target_kind, target_id, COALESCE(port, -1), COALESCE(proto, ''),
    COALESCE(port_group, ''), COALESCE(network_id, ''),
    subject_kind, COALESCE(subject_id, '')
);
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

impl Database {
    /// Create the schema in a new database. Any other database is refused: one from
    /// another `user_version`, and one with tables but no version (the layout from before
    /// the schema was versioned).
    pub async fn init_schema(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *tx)
            .await?;
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(&mut *tx)
        .await?;
        if version != SCHEMA_VERSION && (version != 0 || tables > 0) {
            let what = self.path.as_deref().unwrap_or("the database");
            bail!(
                "{what} was written by an earlier development build (schema version {version}, \
                 this build uses {SCHEMA_VERSION}) and cannot be used; remove it and start over"
            );
        }
        if version == 0 {
            sqlx::raw_sql(SCHEMA).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO settings (key, value) VALUES (?, 'true')")
                .bind(FRESH_DB_KEY)
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
                .execute(&mut *tx)
                .await?;
            info!("Created database schema v{SCHEMA_VERSION}");
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
    use crate::state::with_suffix;
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{Connection, SqliteConnection};

    async fn names(db: &Database, kind: &str) -> Vec<String> {
        sqlx::query_scalar(&format!(
            "SELECT name FROM sqlite_master WHERE type = '{kind}' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ))
        .fetch_all(&db.pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_fresh_database_has_exactly_the_current_schema() {
        let db = db().await;
        let v: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(v, 1);
        assert_eq!(
            names(&db, "table").await,
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
                "port_group_apps",
                "port_groups",
                "reservation_bindings",
                "reservations",
                "settings",
                "tag_exclusions",
                "tag_members",
                "tags",
                "tor_client_keys"
            ]
        );
        assert_eq!(
            names(&db, "index").await,
            [
                "activity_at",
                "addresses_app",
                "addresses_reservation",
                "addresses_row",
                "grants_target",
                "grants_unique",
                "port_group_apps_app",
                "reservation_bindings_app",
                "reservation_bindings_unique",
                "tag_members_app",
                "tag_members_unique"
            ]
        );
        let apps: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('apps') ORDER BY cid")
                .fetch_all(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            apps,
            [
                "id",
                "name",
                "process_name",
                "exe_path",
                "interpreter_arg",
                "first_seen",
                "last_seen",
                "identity_note",
                "system"
            ]
        );
        db.init_schema().await.expect("init_schema is idempotent");
    }

    #[tokio::test]
    async fn a_database_of_another_version_is_refused_with_its_path() {
        let path = temp_db_path("other-version");
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.init_schema().await.unwrap();
        sqlx::query("PRAGMA user_version = 10")
            .execute(&db.pool)
            .await
            .unwrap();
        db.pool.close().await;

        for open in [true, false] {
            let p = path.to_str().unwrap();
            let db = if open {
                Database::open_existing(p).await.unwrap()
            } else {
                Database::new(p).await.unwrap()
            };
            let err = format!("{:#}", db.init_schema().await.unwrap_err());
            assert!(err.contains(p), "{err}");
            assert!(err.contains("earlier development build"), "{err}");
            db.pool.close().await;
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[tokio::test]
    async fn an_old_layout_database_is_refused_and_left_alone() {
        let path = temp_db_path("old-layout");
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let mut conn = SqliteConnection::connect_with(&opts).await.unwrap();
            sqlx::query("CREATE TABLE sockets (id TEXT PRIMARY KEY)")
                .execute(&mut conn)
                .await
                .unwrap();
            conn.close().await.unwrap();
        }
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        let err = format!("{:#}", db.init_schema().await.unwrap_err());
        assert!(err.contains(path.to_str().unwrap()), "{err}");
        assert!(err.contains("earlier development build"), "{err}");
        assert_eq!(names(&db, "table").await, ["sockets"], "nothing was added");
        db.pool.close().await;
        assert!(path.exists() && !with_suffix(&path, ".pre-v1").exists());
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[tokio::test]
    async fn a_reopened_database_is_kept() {
        let path = temp_db_path("reopen");
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.init_schema().await.unwrap();
        db.insert_app(&app("a1")).await.unwrap();
        db.pool.close().await;
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.init_schema().await.unwrap();
        assert!(db.get_app("a1").await.unwrap().is_some());
        db.pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }
}
