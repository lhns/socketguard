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
