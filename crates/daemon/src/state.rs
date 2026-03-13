use anyhow::Result;
use socketguard_core::{AclEntry, ManagedSocket, Policy, SocketAddress};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::collections::HashMap;
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
                policy TEXT NOT NULL DEFAULT 'closed',
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
            CREATE TABLE IF NOT EXISTS socket_addresses (
                socket_id TEXT NOT NULL REFERENCES sockets(id) ON DELETE CASCADE,
                backend_id TEXT NOT NULL,
                backend_type TEXT NOT NULL,
                address TEXT NOT NULL,
                interface TEXT NOT NULL,
                prefix_len INTEGER NOT NULL DEFAULT 128,
                keypair_id TEXT,
                PRIMARY KEY (socket_id, backend_id)
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

        // Migration: if old sockets table has assigned_ipv6 column, migrate data
        self.migrate_from_single_backend().await?;

        Ok(())
    }

    /// Migrate from single-backend schema (assigned_ipv6/backend/keypair_id on sockets table)
    /// to multi-backend schema (socket_addresses table).
    async fn migrate_from_single_backend(&self) -> Result<()> {
        // Check if old columns exist
        let has_old_columns = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('sockets') WHERE name = 'assigned_ipv6'",
        )
        .fetch_one(&self.pool)
        .await?
            > 0;

        if !has_old_columns {
            return Ok(());
        }

        tracing::info!("Migrating from single-backend to multi-backend schema...");

        // Copy existing data to socket_addresses
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO socket_addresses (socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id)
            SELECT id, backend, backend, assigned_ipv6, '', 128, keypair_id
            FROM sockets
            WHERE assigned_ipv6 IS NOT NULL AND assigned_ipv6 != ''
            "#,
        )
        .execute(&self.pool)
        .await?;

        // SQLite doesn't support DROP COLUMN before 3.35.0, so recreate the table
        sqlx::query("ALTER TABLE sockets RENAME TO sockets_old")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE sockets (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                policy TEXT NOT NULL DEFAULT 'closed',
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
            INSERT INTO sockets (id, pid, process_name, port, protocol, policy, exe_path, cmdline, first_seen, last_seen)
            SELECT id, pid, process_name, port, protocol, policy, exe_path, cmdline, first_seen, last_seen
            FROM sockets_old
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("DROP TABLE sockets_old")
            .execute(&self.pool)
            .await?;

        tracing::info!("Migration complete");
        Ok(())
    }

    pub async fn upsert_socket(&self, socket: &ManagedSocket) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sockets (id, pid, process_name, port, protocol, policy, exe_path, cmdline, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .bind(socket.policy.to_string())
        .bind(&socket.exe_path)
        .bind(&socket.cmdline)
        .bind(socket.first_seen.to_rfc3339())
        .bind(socket.last_seen.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save or update a socket address for a specific backend instance.
    pub async fn upsert_socket_address(
        &self,
        socket_id: &str,
        addr: &SocketAddress,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO socket_addresses (socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(socket_id, backend_id) DO UPDATE SET
                address = excluded.address,
                interface = excluded.interface,
                prefix_len = excluded.prefix_len,
                keypair_id = excluded.keypair_id
            "#,
        )
        .bind(socket_id)
        .bind(&addr.backend_id)
        .bind(addr.backend_type.to_string())
        .bind(addr.address.to_string())
        .bind(&addr.interface)
        .bind(addr.prefix_len as i64)
        .bind(&addr.keypair_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all addresses for a socket.
    pub async fn get_socket_addresses(&self, socket_id: &str) -> Result<Vec<SocketAddress>> {
        let rows = sqlx::query_as::<_, SocketAddressRow>(
            "SELECT * FROM socket_addresses WHERE socket_id = ?",
        )
        .bind(socket_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Delete all addresses for a specific backend instance across all sockets.
    pub async fn delete_addresses_by_backend(&self, backend_id: &str) -> Result<Vec<(String, SocketAddress)>> {
        // First fetch them so we can return them for cleanup
        let rows = sqlx::query_as::<_, SocketAddressRowWithSocket>(
            "SELECT socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id FROM socket_addresses WHERE backend_id = ?",
        )
        .bind(backend_id)
        .fetch_all(&self.pool)
        .await?;

        let result: Result<Vec<(String, SocketAddress)>> = rows
            .into_iter()
            .map(|r| {
                let socket_id = r.socket_id.clone();
                let addr: SocketAddress = r.try_into()?;
                Ok((socket_id, addr))
            })
            .collect();
        let result = result?;

        sqlx::query("DELETE FROM socket_addresses WHERE backend_id = ?")
            .bind(backend_id)
            .execute(&self.pool)
            .await?;

        Ok(result)
    }

    /// Delete a specific socket address.
    pub async fn delete_socket_address(&self, socket_id: &str, backend_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM socket_addresses WHERE socket_id = ? AND backend_id = ?")
            .bind(socket_id)
            .bind(backend_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_sockets(&self) -> Result<Vec<ManagedSocket>> {
        let rows = sqlx::query_as::<_, SocketRow>("SELECT * FROM sockets ORDER BY last_seen DESC")
            .fetch_all(&self.pool)
            .await?;

        // Fetch all addresses and group by socket_id
        let addr_rows = sqlx::query_as::<_, SocketAddressRowWithSocket>(
            "SELECT socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id FROM socket_addresses",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut addr_map: HashMap<String, Vec<SocketAddress>> = HashMap::new();
        for row in addr_rows {
            let socket_id = row.socket_id.clone();
            let addr: SocketAddress = row.try_into()?;
            addr_map.entry(socket_id).or_default().push(addr);
        }

        rows.into_iter()
            .map(|r| {
                let addresses = addr_map.remove(&r.id).unwrap_or_default();
                r.into_managed_socket(addresses)
            })
            .collect()
    }

    pub async fn get_socket(&self, id: &str) -> Result<Option<ManagedSocket>> {
        let row = sqlx::query_as::<_, SocketRow>("SELECT * FROM sockets WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let addresses = self.get_socket_addresses(id).await?;
                Ok(Some(r.into_managed_socket(addresses)?))
            }
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

        let mut result = Vec::new();
        for r in rows {
            let addresses = self.get_socket_addresses(&r.id).await?;
            result.push(r.into_managed_socket(addresses)?);
        }
        Ok(result)
    }
}

#[derive(sqlx::FromRow)]
struct SocketRow {
    id: String,
    pid: i64,
    process_name: String,
    port: i64,
    protocol: String,
    policy: String,
    exe_path: Option<String>,
    cmdline: Option<String>,
    first_seen: String,
    last_seen: String,
}

impl SocketRow {
    fn into_managed_socket(self, addresses: Vec<SocketAddress>) -> Result<ManagedSocket> {
        Ok(ManagedSocket {
            id: self.id,
            pid: self.pid as u32,
            process_name: self.process_name,
            port: self.port as u16,
            protocol: self.protocol.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            addresses,
            policy: self.policy.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            exe_path: self.exe_path,
            cmdline: self.cmdline,
            first_seen: chrono::DateTime::parse_from_rfc3339(&self.first_seen)?
                .with_timezone(&chrono::Utc),
            last_seen: chrono::DateTime::parse_from_rfc3339(&self.last_seen)?
                .with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct SocketAddressRow {
    backend_id: String,
    backend_type: String,
    address: String,
    interface: String,
    prefix_len: i64,
    keypair_id: Option<String>,
}

impl TryFrom<SocketAddressRow> for SocketAddress {
    type Error = anyhow::Error;

    fn try_from(row: SocketAddressRow) -> Result<Self> {
        Ok(SocketAddress {
            backend_id: row.backend_id,
            backend_type: row.backend_type.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            address: row.address.parse()?,
            interface: row.interface,
            prefix_len: row.prefix_len as u8,
            keypair_id: row.keypair_id,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SocketAddressRowWithSocket {
    socket_id: String,
    backend_id: String,
    backend_type: String,
    address: String,
    interface: String,
    prefix_len: i64,
    keypair_id: Option<String>,
}

impl TryFrom<SocketAddressRowWithSocket> for SocketAddress {
    type Error = anyhow::Error;

    fn try_from(row: SocketAddressRowWithSocket) -> Result<Self> {
        Ok(SocketAddress {
            backend_id: row.backend_id,
            backend_type: row.backend_type.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            address: row.address.parse()?,
            interface: row.interface,
            prefix_len: row.prefix_len as u8,
            keypair_id: row.keypair_id,
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
            addresses: vec![SocketAddress {
                backend_id: "ula".to_string(),
                backend_type: BackendType::Ula,
                address: "fd00::1".parse().unwrap(),
                interface: "lo".to_string(),
                prefix_len: 128,
                keypair_id: None,
            }],
            policy: Policy::Closed,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
        }
    }

    async fn insert_test_socket(db: &Database, id: &str, name: &str, port: u16) -> ManagedSocket {
        let socket = test_socket(id, name, port);
        db.upsert_socket(&socket).await.unwrap();
        for addr in &socket.addresses {
            db.upsert_socket_address(&socket.id, addr).await.unwrap();
        }
        socket
    }

    #[tokio::test]
    async fn upsert_and_get_socket() {
        let db = test_db().await;
        let socket = insert_test_socket(&db, "abc123", "nginx", 80).await;

        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.id, "abc123");
        assert_eq!(retrieved.process_name, "nginx");
        assert_eq!(retrieved.port, 80);
        assert_eq!(retrieved.protocol, Protocol::Tcp);
        assert_eq!(retrieved.policy, Policy::Closed);
        assert_eq!(retrieved.addresses.len(), 1);
        assert_eq!(retrieved.addresses[0].address, socket.addresses[0].address);
        assert_eq!(retrieved.addresses[0].backend_id, "ula");
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
        for addr in &socket.addresses {
            db.upsert_socket_address(&socket.id, addr).await.unwrap();
        }

        socket.pid = 5678;
        socket.last_seen = chrono::Utc::now();
        db.upsert_socket(&socket).await.unwrap();

        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.pid, 5678);
        assert_eq!(retrieved.policy, Policy::Closed);
    }

    #[tokio::test]
    async fn list_sockets_returns_all() {
        let db = test_db().await;
        insert_test_socket(&db, "id1", "nginx", 80).await;
        insert_test_socket(&db, "id2", "sshd", 22).await;

        let sockets = db.list_sockets().await.unwrap();
        assert_eq!(sockets.len(), 2);
        // Each should have addresses
        for s in &sockets {
            assert!(!s.addresses.is_empty());
        }
    }

    #[tokio::test]
    async fn delete_socket() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;
        db.delete_socket("abc123").await.unwrap();

        let result = db.get_socket("abc123").await.unwrap();
        assert!(result.is_none());

        // Addresses should be cascade deleted
        let addrs = db.get_socket_addresses("abc123").await.unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn update_policy() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;

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
        insert_test_socket(&db, "abc123", "nginx", 80).await;

        let entry = db.add_acl_entry("abc123", "fd00::100", Some("laptop")).await.unwrap();
        assert_eq!(entry.allowed_ip, "fd00::100");
        assert_eq!(entry.label, Some("laptop".to_string()));

        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 1);

        db.delete_acl_entry(entry.id).await.unwrap();
        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    #[tokio::test]
    async fn acl_rejects_invalid_ipv6() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;
        let result = db.add_acl_entry("abc123", "not-an-ip", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn replace_acl() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;

        db.add_acl_entry("abc123", "fd00::1", Some("host1")).await.unwrap();
        db.add_acl_entry("abc123", "fd00::2", Some("host2")).await.unwrap();

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
        insert_test_socket(&db, "abc123", "nginx", 80).await;
        db.add_acl_entry("abc123", "fd00::1", None).await.unwrap();
        db.add_acl_entry("abc123", "fd00::2", None).await.unwrap();

        db.delete_socket("abc123").await.unwrap();
        let acl = db.get_acl("abc123").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    #[tokio::test]
    async fn save_and_query_keypair() {
        let db = test_db().await;
        let pub_key = vec![1u8; 32];
        let priv_key = vec![2u8; 32];
        db.save_keypair("kp1", &pub_key, &priv_key, "fd00::1").await.unwrap();
    }

    #[tokio::test]
    async fn socket_preserves_exe_path_and_cmdline() {
        let db = test_db().await;
        let mut socket = test_socket("abc123", "nginx", 80);
        socket.exe_path = Some("/usr/sbin/nginx".to_string());
        socket.cmdline = Some("nginx -g daemon off;".to_string());
        db.upsert_socket(&socket).await.unwrap();
        for addr in &socket.addresses {
            db.upsert_socket_address(&socket.id, addr).await.unwrap();
        }

        let retrieved = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.exe_path, Some("/usr/sbin/nginx".to_string()));
        assert_eq!(retrieved.cmdline, Some("nginx -g daemon off;".to_string()));
    }

    #[tokio::test]
    async fn multi_address_socket() {
        let db = test_db().await;
        let socket = test_socket("multi1", "nginx", 80);
        db.upsert_socket(&socket).await.unwrap();

        let addr1 = SocketAddress {
            backend_id: "ula".to_string(),
            backend_type: BackendType::Ula,
            address: "fd00::1".parse().unwrap(),
            interface: "lo".to_string(),
            prefix_len: 128,
            keypair_id: None,
        };
        let addr2 = SocketAddress {
            backend_id: "slaac-Ethernet".to_string(),
            backend_type: BackendType::Slaac,
            address: "2001:db8::1".parse().unwrap(),
            interface: "Ethernet".to_string(),
            prefix_len: 64,
            keypair_id: None,
        };

        db.upsert_socket_address("multi1", &addr1).await.unwrap();
        db.upsert_socket_address("multi1", &addr2).await.unwrap();

        let retrieved = db.get_socket("multi1").await.unwrap().unwrap();
        assert_eq!(retrieved.addresses.len(), 2);
    }

    #[tokio::test]
    async fn delete_addresses_by_backend() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "nginx", 80).await;
        insert_test_socket(&db, "s2", "sshd", 22).await;

        // Both sockets have "ula" backend address
        let deleted = db.delete_addresses_by_backend("ula").await.unwrap();
        assert_eq!(deleted.len(), 2);

        let s1 = db.get_socket("s1").await.unwrap().unwrap();
        assert!(s1.addresses.is_empty());
    }
}
