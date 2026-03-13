use anyhow::Result;
use socketguard_core::{AclEntry, ManagedSocket, Policy};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}?mode=rwc"))?;
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        // Enable foreign key enforcement (required for ON DELETE CASCADE)
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sockets (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                assigned_ipv6 TEXT NOT NULL,
                backend TEXT NOT NULL,
                policy TEXT NOT NULL DEFAULT 'closed',
                keypair_id TEXT,
                exe_path TEXT,
                cmdline TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS acl_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                socket_id TEXT NOT NULL REFERENCES sockets(id) ON DELETE CASCADE,
                allowed_ip TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS keypairs (
                id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                private_key_encrypted BLOB NOT NULL,
                derived_ipv6 TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_socket(&self, socket: &ManagedSocket) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sockets (id, pid, process_name, port, protocol, assigned_ipv6, backend, policy, keypair_id, exe_path, cmdline, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                pid = excluded.pid,
                process_name = excluded.process_name,
                exe_path = excluded.exe_path,
                cmdline = excluded.cmdline,
                last_seen = excluded.last_seen
            "#,
        )
        .bind(&socket.id)
        .bind(socket.pid as i64)
        .bind(&socket.process_name)
        .bind(socket.port as i64)
        .bind(socket.protocol.to_string())
        .bind(socket.assigned_ipv6.to_string())
        .bind(socket.backend.to_string())
        .bind(socket.policy.to_string())
        .bind(&socket.keypair_id)
        .bind(&socket.exe_path)
        .bind(&socket.cmdline)
        .bind(socket.first_seen.to_rfc3339())
        .bind(socket.last_seen.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_sockets(&self) -> Result<Vec<ManagedSocket>> {
        let rows = sqlx::query_as::<_, SocketRow>("SELECT * FROM sockets ORDER BY last_seen DESC")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    pub async fn get_socket(&self, id: &str) -> Result<Option<ManagedSocket>> {
        let row = sqlx::query_as::<_, SocketRow>("SELECT * FROM sockets WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(r.try_into()?)),
            None => Ok(None),
        }
    }

    pub async fn delete_socket(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sockets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_policy(&self, id: &str, policy: Policy) -> Result<()> {
        sqlx::query("UPDATE sockets SET policy = ? WHERE id = ?")
            .bind(policy.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_acl(&self, socket_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclRow>(
            "SELECT * FROM acl_entries WHERE socket_id = ? ORDER BY created_at",
        )
        .bind(socket_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    pub async fn add_acl_entry(
        &self,
        socket_id: &str,
        allowed_ip: &str,
        label: Option<&str>,
    ) -> Result<AclEntry> {
        // Defense-in-depth: validate that it's a valid IPv6 address
        allowed_ip
            .parse::<std::net::Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid IPv6 address '{}': {}", allowed_ip, e))?;

        let now = chrono::Utc::now();
        let result = sqlx::query(
            "INSERT INTO acl_entries (socket_id, allowed_ip, label, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(socket_id)
        .bind(allowed_ip)
        .bind(label)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AclEntry {
            id: result.last_insert_rowid(),
            socket_id: socket_id.to_string(),
            allowed_ip: allowed_ip.to_string(),
            label: label.map(|s| s.to_string()),
            created_at: now,
        })
    }

    pub async fn delete_acl_entry(&self, entry_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM acl_entries WHERE id = ?")
            .bind(entry_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn replace_acl(
        &self,
        socket_id: &str,
        entries: &[(String, Option<String>)],
    ) -> Result<Vec<AclEntry>> {
        sqlx::query("DELETE FROM acl_entries WHERE socket_id = ?")
            .bind(socket_id)
            .execute(&self.pool)
            .await?;

        let mut result = Vec::new();
        for (ip, label) in entries {
            let entry = self
                .add_acl_entry(socket_id, ip, label.as_deref())
                .await?;
            result.push(entry);
        }

        Ok(result)
    }

    pub async fn save_keypair(
        &self,
        id: &str,
        public_key: &[u8],
        private_key: &[u8],
        derived_ipv6: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO keypairs (id, public_key, private_key_encrypted, derived_ipv6, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(public_key)
        .bind(private_key)
        .bind(derived_ipv6)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn stale_sockets(&self, before: chrono::DateTime<chrono::Utc>) -> Result<Vec<ManagedSocket>> {
        let rows = sqlx::query_as::<_, SocketRow>(
            "SELECT * FROM sockets WHERE last_seen < ?",
        )
        .bind(before.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

#[derive(sqlx::FromRow)]
struct SocketRow {
    id: String,
    pid: i64,
    process_name: String,
    port: i64,
    protocol: String,
    assigned_ipv6: String,
    backend: String,
    policy: String,
    keypair_id: Option<String>,
    exe_path: Option<String>,
    cmdline: Option<String>,
    first_seen: String,
    last_seen: String,
}

impl TryFrom<SocketRow> for ManagedSocket {
    type Error = anyhow::Error;

    fn try_from(row: SocketRow) -> Result<Self> {
        Ok(ManagedSocket {
            id: row.id,
            pid: row.pid as u32,
            process_name: row.process_name,
            port: row.port as u16,
            protocol: row.protocol.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            assigned_ipv6: row.assigned_ipv6.parse()?,
            backend: row.backend.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            policy: row.policy.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            keypair_id: row.keypair_id,
            exe_path: row.exe_path,
            cmdline: row.cmdline,
            first_seen: chrono::DateTime::parse_from_rfc3339(&row.first_seen)?.with_timezone(&chrono::Utc),
            last_seen: chrono::DateTime::parse_from_rfc3339(&row.last_seen)?.with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct AclRow {
    id: i64,
    socket_id: String,
    allowed_ip: String,
    label: Option<String>,
    created_at: String,
}

impl TryFrom<AclRow> for AclEntry {
    type Error = anyhow::Error;

    fn try_from(row: AclRow) -> Result<Self> {
        Ok(AclEntry {
            id: row.id,
            socket_id: row.socket_id,
            allowed_ip: row.allowed_ip,
            label: row.label,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socketguard_core::{BackendType, Protocol};

    async fn test_db() -> Database {
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    fn test_socket(id: &str, name: &str, port: u16) -> ManagedSocket {
        ManagedSocket {
            id: id.to_string(),
            pid: 1234,
            process_name: name.to_string(),
            port,
            protocol: Protocol::Tcp,
            assigned_ipv6: "fd00::1".parse().unwrap(),
            backend: BackendType::Ula,
            policy: Policy::Closed,
            keypair_id: None,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn upsert_and_get_socket() {
        let db = test_db().await;
        let socket = test_socket("abc123", "nginx", 80);

        db.upsert_socket(&socket).await.unwrap();
        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();

        assert_eq!(retrieved.id, "abc123");
        assert_eq!(retrieved.process_name, "nginx");
        assert_eq!(retrieved.port, 80);
        assert_eq!(retrieved.protocol, Protocol::Tcp);
        assert_eq!(retrieved.policy, Policy::Closed);
    }

    #[tokio::test]
    async fn get_nonexistent_socket_returns_none() {
        let db = test_db().await;
        let result = db.get_socket("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn upsert_updates_pid_on_conflict() {
        let db = test_db().await;
        let mut socket = test_socket("abc123", "nginx", 80);
        db.upsert_socket(&socket).await.unwrap();

        // Simulate process restart: new PID, same socket ID
        socket.pid = 5678;
        socket.last_seen = chrono::Utc::now();
        db.upsert_socket(&socket).await.unwrap();

        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.pid, 5678);
        // Policy should be preserved
        assert_eq!(retrieved.policy, Policy::Closed);
    }

    #[tokio::test]
    async fn list_sockets_returns_all() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("id1", "nginx", 80)).await.unwrap();
        db.upsert_socket(&test_socket("id2", "sshd", 22)).await.unwrap();

        let sockets = db.list_sockets().await.unwrap();
        assert_eq!(sockets.len(), 2);
    }

    #[tokio::test]
    async fn delete_socket() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();
        db.delete_socket("abc123").await.unwrap();

        let result = db.get_socket("abc123").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_policy() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();

        db.update_policy("abc123", Policy::Open).await.unwrap();
        let socket = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(socket.policy, Policy::Open);

        db.update_policy("abc123", Policy::Closed).await.unwrap();
        let socket = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(socket.policy, Policy::Closed);
    }

    #[tokio::test]
    async fn acl_crud() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();

        // Add ACL entry
        let entry = db
            .add_acl_entry("abc123", "fd00::100", Some("laptop"))
            .await
            .unwrap();
        assert_eq!(entry.allowed_ip, "fd00::100");
        assert_eq!(entry.label, Some("laptop".to_string()));

        // List ACL entries
        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].allowed_ip, "fd00::100");

        // Delete ACL entry
        db.delete_acl_entry(entry.id).await.unwrap();
        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    #[tokio::test]
    async fn acl_rejects_invalid_ipv6() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();

        let result = db.add_acl_entry("abc123", "not-an-ip", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn replace_acl() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();

        // Add initial entries
        db.add_acl_entry("abc123", "fd00::1", Some("host1")).await.unwrap();
        db.add_acl_entry("abc123", "fd00::2", Some("host2")).await.unwrap();

        // Replace with new set
        let entries = vec![
            ("fd00::10".to_string(), Some("new1".to_string())),
            ("fd00::20".to_string(), None),
        ];
        let result = db.replace_acl("abc123", &entries).await.unwrap();
        assert_eq!(result.len(), 2);

        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 2);
        assert_eq!(acl[0].allowed_ip, "fd00::10");
        assert_eq!(acl[1].allowed_ip, "fd00::20");
    }

    #[tokio::test]
    async fn stale_sockets() {
        let db = test_db().await;
        let mut socket = test_socket("old_one", "old", 9999);
        socket.last_seen = chrono::Utc::now() - chrono::Duration::seconds(60);
        db.upsert_socket(&socket).await.unwrap();

        let mut fresh = test_socket("new_one", "fresh", 8888);
        fresh.last_seen = chrono::Utc::now();
        db.upsert_socket(&fresh).await.unwrap();

        let threshold = chrono::Utc::now() - chrono::Duration::seconds(30);
        let stale = db.stale_sockets(threshold).await.unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, "old_one");
    }

    #[tokio::test]
    async fn cascade_delete_removes_acl() {
        let db = test_db().await;
        db.upsert_socket(&test_socket("abc123", "nginx", 80)).await.unwrap();
        db.add_acl_entry("abc123", "fd00::1", None).await.unwrap();
        db.add_acl_entry("abc123", "fd00::2", None).await.unwrap();

        // Deleting the socket should cascade-delete ACL entries
        db.delete_socket("abc123").await.unwrap();
        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    #[tokio::test]
    async fn save_and_query_keypair() {
        let db = test_db().await;
        let pub_key = vec![1u8; 32];
        let priv_key = vec![2u8; 32];
        db.save_keypair("kp1", &pub_key, &priv_key, "fd00::1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn socket_preserves_exe_path_and_cmdline() {
        let db = test_db().await;
        let mut socket = test_socket("abc123", "nginx", 80);
        socket.exe_path = Some("/usr/sbin/nginx".to_string());
        socket.cmdline = Some("nginx -g daemon off;".to_string());
        db.upsert_socket(&socket).await.unwrap();

        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.exe_path, Some("/usr/sbin/nginx".to_string()));
        assert_eq!(
            retrieved.cmdline,
            Some("nginx -g daemon off;".to_string())
        );
    }
}
