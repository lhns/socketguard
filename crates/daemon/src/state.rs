use anyhow::Result;
use socketguard_core::{AclEntry, AclGroup, ManagedSocket, Policy, SocketAddress, SocketGroup, SocketGroupAddress};
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
                policy TEXT NOT NULL DEFAULT 'closed',
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
                socket_id TEXT NOT NULL,
                backend_id TEXT NOT NULL,
                allowed_ip TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (socket_id, backend_id) REFERENCES socket_addresses(socket_id, backend_id) ON DELETE CASCADE
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

        // Migration: ADR 0017 — per-backend policy and ACL
        self.migrate_per_backend_policy_acl().await?;

        // Migration: ADR 0018 — ACL groups, socket groups, remove disabled
        self.migrate_add_groups().await?;

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

    /// Migrate to per-backend policy and ACL (ADR 0017).
    ///
    /// 1. Add `policy` column to `socket_addresses` (if missing), copy from `sockets.policy`.
    /// 2. Add `backend_id` column to `acl_entries` (if missing), duplicate entries per backend.
    async fn migrate_per_backend_policy_acl(&self) -> Result<()> {
        // Check if socket_addresses already has a policy column
        let has_addr_policy = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('socket_addresses') WHERE name = 'policy'",
        )
        .fetch_one(&self.pool)
        .await?
            > 0;

        if has_addr_policy {
            // Already migrated — check if acl_entries needs backend_id
            let has_acl_backend = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pragma_table_info('acl_entries') WHERE name = 'backend_id'",
            )
            .fetch_one(&self.pool)
            .await?
                > 0;

            if has_acl_backend {
                return Ok(()); // Fully migrated
            }
        }

        tracing::info!("Migrating to per-backend policy and ACL (ADR 0017)...");

        // Step 1: Add policy column to socket_addresses
        if !has_addr_policy {
            sqlx::query("ALTER TABLE socket_addresses ADD COLUMN policy TEXT NOT NULL DEFAULT 'closed'")
                .execute(&self.pool)
                .await?;

            // Copy existing socket-level policy to each address
            sqlx::query(
                r#"
                UPDATE socket_addresses SET policy = (
                    SELECT policy FROM sockets WHERE sockets.id = socket_addresses.socket_id
                )
                "#,
            )
            .execute(&self.pool)
            .await?;
        }

        // Step 2: Add backend_id to acl_entries by recreating the table
        let has_acl_backend = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('acl_entries') WHERE name = 'backend_id'",
        )
        .fetch_one(&self.pool)
        .await?
            > 0;

        if !has_acl_backend {
            sqlx::query("ALTER TABLE acl_entries RENAME TO acl_entries_old")
                .execute(&self.pool)
                .await?;

            sqlx::query(
                r#"
                CREATE TABLE acl_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    socket_id TEXT NOT NULL,
                    backend_id TEXT NOT NULL,
                    allowed_ip TEXT NOT NULL,
                    label TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (socket_id, backend_id) REFERENCES socket_addresses(socket_id, backend_id) ON DELETE CASCADE
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            // Duplicate each old ACL entry for every backend the socket has
            sqlx::query(
                r#"
                INSERT INTO acl_entries (socket_id, backend_id, allowed_ip, label, created_at)
                SELECT ao.socket_id, sa.backend_id, ao.allowed_ip, ao.label, ao.created_at
                FROM acl_entries_old ao
                JOIN socket_addresses sa ON ao.socket_id = sa.socket_id
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query("DROP TABLE acl_entries_old")
                .execute(&self.pool)
                .await?;
        }

        tracing::info!("Per-backend policy/ACL migration complete");
        Ok(())
    }

    /// ADR 0018 migration: create group tables, migrate disabled→closed, add group columns.
    async fn migrate_add_groups(&self) -> Result<()> {
        // Check if already migrated by looking for acl_groups table
        let has_acl_groups = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='acl_groups'",
        )
        .fetch_one(&self.pool)
        .await?
            > 0;

        if has_acl_groups {
            return Ok(());
        }

        tracing::info!("Migrating to ACL groups, socket groups (ADR 0018)...");

        // Create ACL group tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS acl_groups (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                policy TEXT NOT NULL DEFAULT 'closed',
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS acl_group_members (
                group_id TEXT NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
                socket_id TEXT NOT NULL REFERENCES sockets(id) ON DELETE CASCADE,
                PRIMARY KEY (group_id, socket_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // A socket can only be in one ACL group
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_group_member_socket ON acl_group_members(socket_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS acl_group_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
                backend_id TEXT NOT NULL,
                allowed_ip TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create socket group tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS socket_groups (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                app_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add socket_group_id column to sockets
        let has_sg_col = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('sockets') WHERE name = 'socket_group_id'",
        )
        .fetch_one(&self.pool)
        .await?
            > 0;

        if !has_sg_col {
            sqlx::query(
                "ALTER TABLE sockets ADD COLUMN socket_group_id TEXT REFERENCES socket_groups(id) ON DELETE SET NULL",
            )
            .execute(&self.pool)
            .await?;
        }

        // Socket group addresses (shared IPv6 per backend)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS socket_group_addresses (
                group_id TEXT NOT NULL REFERENCES socket_groups(id) ON DELETE CASCADE,
                backend_id TEXT NOT NULL,
                address TEXT NOT NULL,
                interface TEXT NOT NULL,
                prefix_len INTEGER NOT NULL,
                keypair_id TEXT,
                PRIMARY KEY (group_id, backend_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Migrate disabled → closed (ADR 0018: closed+no ACL = inactive)
        sqlx::query("UPDATE socket_addresses SET policy = 'closed' WHERE policy = 'disabled'")
            .execute(&self.pool)
            .await?;
        sqlx::query("UPDATE sockets SET policy = 'closed' WHERE policy = 'disabled'")
            .execute(&self.pool)
            .await?;

        tracing::info!("ADR 0018 migration complete");
        Ok(())
    }

    // ======== Socket CRUD ========

    pub async fn upsert_socket(&self, socket: &ManagedSocket) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sockets (id, pid, process_name, port, protocol, policy, exe_path, cmdline, first_seen, last_seen, socket_group_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .bind(&socket.socket_group_id)
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
            INSERT INTO socket_addresses (socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id, policy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(socket_id, backend_id) DO UPDATE SET
                address = excluded.address,
                interface = excluded.interface,
                prefix_len = excluded.prefix_len,
                keypair_id = excluded.keypair_id,
                policy = excluded.policy
            "#,
        )
        .bind(socket_id)
        .bind(&addr.backend_id)
        .bind(addr.backend_type.to_string())
        .bind(addr.address.to_string())
        .bind(&addr.interface)
        .bind(addr.prefix_len as i64)
        .bind(&addr.keypair_id)
        .bind(addr.policy.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all addresses for a socket.
    pub async fn get_socket_addresses(&self, socket_id: &str) -> Result<Vec<SocketAddress>> {
        let rows = sqlx::query_as::<_, SocketAddressRow>(
            "SELECT backend_id, backend_type, address, interface, prefix_len, keypair_id, policy FROM socket_addresses WHERE socket_id = ?",
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
            "SELECT socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id, policy FROM socket_addresses WHERE backend_id = ?",
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

    /// Update the policy of a specific socket address (per-backend).
    pub async fn update_address_policy(&self, socket_id: &str, backend_id: &str, policy: Policy) -> Result<()> {
        sqlx::query("UPDATE socket_addresses SET policy = ? WHERE socket_id = ? AND backend_id = ?")
            .bind(policy.to_string())
            .bind(socket_id)
            .bind(backend_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update the default policy on the socket (used when adding new backends).
    pub async fn update_default_policy(&self, id: &str, policy: Policy) -> Result<()> {
        sqlx::query("UPDATE sockets SET policy = ? WHERE id = ?")
            .bind(policy.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update policy on ALL addresses for a socket (fan-out).
    pub async fn update_policy_all_backends(&self, socket_id: &str, policy: Policy) -> Result<()> {
        sqlx::query("UPDATE socket_addresses SET policy = ? WHERE socket_id = ?")
            .bind(policy.to_string())
            .bind(socket_id)
            .execute(&self.pool)
            .await?;
        // Also update the default policy
        self.update_default_policy(socket_id, policy).await?;
        Ok(())
    }

    pub async fn list_sockets(&self) -> Result<Vec<ManagedSocket>> {
        let rows = sqlx::query_as::<_, SocketRow>("SELECT * FROM sockets ORDER BY last_seen DESC")
            .fetch_all(&self.pool)
            .await?;

        // Fetch all addresses and group by socket_id
        let addr_rows = sqlx::query_as::<_, SocketAddressRowWithSocket>(
            "SELECT socket_id, backend_id, backend_type, address, interface, prefix_len, keypair_id, policy FROM socket_addresses",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut addr_map: HashMap<String, Vec<SocketAddress>> = HashMap::new();
        for row in addr_rows {
            let socket_id = row.socket_id.clone();
            let addr: SocketAddress = row.try_into()?;
            addr_map.entry(socket_id).or_default().push(addr);
        }

        // Fetch ACL group memberships
        let membership_rows = sqlx::query_as::<_, (String, String)>(
            "SELECT socket_id, group_id FROM acl_group_members",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut group_map: HashMap<String, String> = HashMap::new();
        for (socket_id, group_id) in membership_rows {
            group_map.insert(socket_id, group_id);
        }

        rows.into_iter()
            .map(|r| {
                let addresses = addr_map.remove(&r.id).unwrap_or_default();
                let acl_group_id = group_map.remove(&r.id);
                r.into_managed_socket(addresses, acl_group_id)
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
                let acl_group_id = self.get_acl_group_for_socket(id).await?;
                Ok(Some(r.into_managed_socket(addresses, acl_group_id)?))
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

    // ======== ACL Entries (per-socket) ========

    /// Get ACL entries for a specific socket+backend pair.
    pub async fn get_acl_for_backend(&self, socket_id: &str, backend_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclRow>(
            "SELECT * FROM acl_entries WHERE socket_id = ? AND backend_id = ? ORDER BY created_at",
        )
        .bind(socket_id)
        .bind(backend_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Get all ACL entries for a socket (across all backends).
    pub async fn get_acl(&self, socket_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclRow>(
            "SELECT * FROM acl_entries WHERE socket_id = ? ORDER BY backend_id, created_at",
        )
        .bind(socket_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Add an ACL entry for a specific backend.
    pub async fn add_acl_entry(
        &self,
        socket_id: &str,
        backend_id: &str,
        allowed_ip: &str,
        label: Option<&str>,
    ) -> Result<AclEntry> {
        // Defense-in-depth: validate that it's a valid IPv6 address
        allowed_ip
            .parse::<std::net::Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid IPv6 address '{}': {}", allowed_ip, e))?;

        let now = chrono::Utc::now();
        let result = sqlx::query(
            "INSERT INTO acl_entries (socket_id, backend_id, allowed_ip, label, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(socket_id)
        .bind(backend_id)
        .bind(allowed_ip)
        .bind(label)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AclEntry {
            id: result.last_insert_rowid(),
            socket_id: socket_id.to_string(),
            backend_id: backend_id.to_string(),
            allowed_ip: allowed_ip.to_string(),
            label: label.map(|s| s.to_string()),
            created_at: now,
        })
    }

    /// Add an ACL entry to ALL backends for a socket (fan-out).
    pub async fn add_acl_entry_all_backends(
        &self,
        socket_id: &str,
        allowed_ip: &str,
        label: Option<&str>,
    ) -> Result<Vec<AclEntry>> {
        let addresses = self.get_socket_addresses(socket_id).await?;
        let mut entries = Vec::new();
        for addr in &addresses {
            let entry = self.add_acl_entry(socket_id, &addr.backend_id, allowed_ip, label).await?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub async fn delete_acl_entry(&self, entry_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM acl_entries WHERE id = ?")
            .bind(entry_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ======== ACL Groups (ADR 0018) ========

    pub async fn create_acl_group(&self, label: &str) -> Result<AclGroup> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO acl_groups (id, label, policy, created_at) VALUES (?, ?, 'closed', ?)",
        )
        .bind(&id)
        .bind(label)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AclGroup {
            id,
            label: label.to_string(),
            policy: Policy::Closed,
            created_at: now,
        })
    }

    pub async fn get_acl_group(&self, id: &str) -> Result<Option<AclGroup>> {
        let row = sqlx::query_as::<_, AclGroupRow>("SELECT * FROM acl_groups WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(r.try_into()?)),
            None => Ok(None),
        }
    }

    pub async fn list_acl_groups(&self) -> Result<Vec<AclGroup>> {
        let rows = sqlx::query_as::<_, AclGroupRow>(
            "SELECT * FROM acl_groups ORDER BY label",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    pub async fn update_acl_group(&self, id: &str, label: Option<&str>, policy: Option<Policy>) -> Result<()> {
        if let Some(label) = label {
            sqlx::query("UPDATE acl_groups SET label = ? WHERE id = ?")
                .bind(label)
                .bind(id)
                .execute(&self.pool)
                .await?;
        }
        if let Some(policy) = policy {
            sqlx::query("UPDATE acl_groups SET policy = ? WHERE id = ?")
                .bind(policy.to_string())
                .bind(id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_acl_group(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM acl_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ACL group members

    pub async fn add_to_acl_group(&self, group_id: &str, socket_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO acl_group_members (group_id, socket_id) VALUES (?, ?)",
        )
        .bind(group_id)
        .bind(socket_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_from_acl_group(&self, group_id: &str, socket_id: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM acl_group_members WHERE group_id = ? AND socket_id = ?",
        )
        .bind(group_id)
        .bind(socket_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_acl_group_for_socket(&self, socket_id: &str) -> Result<Option<String>> {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT group_id FROM acl_group_members WHERE socket_id = ?",
        )
        .bind(socket_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_acl_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT socket_id FROM acl_group_members WHERE group_id = ?",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ACL group entries

    pub async fn add_acl_group_entry(
        &self,
        group_id: &str,
        backend_id: &str,
        allowed_ip: &str,
        label: Option<&str>,
    ) -> Result<AclEntry> {
        allowed_ip
            .parse::<std::net::Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid IPv6 address '{}': {}", allowed_ip, e))?;

        let now = chrono::Utc::now();
        let result = sqlx::query(
            "INSERT INTO acl_group_entries (group_id, backend_id, allowed_ip, label, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(group_id)
        .bind(backend_id)
        .bind(allowed_ip)
        .bind(label)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AclEntry {
            id: result.last_insert_rowid(),
            socket_id: group_id.to_string(),
            backend_id: backend_id.to_string(),
            allowed_ip: allowed_ip.to_string(),
            label: label.map(|s| s.to_string()),
            created_at: now,
        })
    }

    pub async fn remove_acl_group_entry(&self, entry_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM acl_group_entries WHERE id = ?")
            .bind(entry_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_acl_group_entries(&self, group_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclGroupEntryRow>(
            "SELECT * FROM acl_group_entries WHERE group_id = ? ORDER BY backend_id, created_at",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Get group ACL entries for a specific backend.
    pub async fn get_acl_group_entries_for_backend(&self, group_id: &str, backend_id: &str) -> Result<Vec<AclEntry>> {
        let rows = sqlx::query_as::<_, AclGroupEntryRow>(
            "SELECT * FROM acl_group_entries WHERE group_id = ? AND backend_id = ? ORDER BY created_at",
        )
        .bind(group_id)
        .bind(backend_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ======== Socket Groups (ADR 0018) ========

    pub async fn create_socket_group(&self, label: &str, app_name: &str) -> Result<SocketGroup> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO socket_groups (id, label, app_name, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(label)
        .bind(app_name)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(SocketGroup {
            id,
            label: label.to_string(),
            app_name: app_name.to_string(),
            created_at: now,
        })
    }

    pub async fn list_socket_groups(&self) -> Result<Vec<SocketGroup>> {
        let rows = sqlx::query_as::<_, SocketGroupRow>(
            "SELECT * FROM socket_groups ORDER BY app_name, label",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    pub async fn delete_socket_group(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM socket_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_socket_to_group(&self, group_id: &str, socket_id: &str) -> Result<()> {
        sqlx::query("UPDATE sockets SET socket_group_id = ? WHERE id = ?")
            .bind(group_id)
            .bind(socket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn remove_socket_from_group(&self, socket_id: &str) -> Result<()> {
        sqlx::query("UPDATE sockets SET socket_group_id = NULL WHERE id = ?")
            .bind(socket_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_socket_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT id FROM sockets WHERE socket_group_id = ?",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // Socket group addresses

    pub async fn upsert_socket_group_address(&self, addr: &SocketGroupAddress) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO socket_group_addresses (group_id, backend_id, address, interface, prefix_len, keypair_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_id, backend_id) DO UPDATE SET
                address = excluded.address,
                interface = excluded.interface,
                prefix_len = excluded.prefix_len,
                keypair_id = excluded.keypair_id
            "#,
        )
        .bind(&addr.group_id)
        .bind(&addr.backend_id)
        .bind(addr.address.to_string())
        .bind(&addr.interface)
        .bind(addr.prefix_len as i64)
        .bind(&addr.keypair_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_socket_group_addresses(&self, group_id: &str) -> Result<Vec<SocketGroupAddress>> {
        let rows = sqlx::query_as::<_, SocketGroupAddressRow>(
            "SELECT * FROM socket_group_addresses WHERE group_id = ?",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.try_into()).collect()
    }

    // ======== Misc ========

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
            let acl_group_id = self.get_acl_group_for_socket(&r.id).await?;
            result.push(r.into_managed_socket(addresses, acl_group_id)?);
        }
        Ok(result)
    }

    /// Resolve the effective policy for a socket address.
    /// Returns (effective_policy, source) where source is "address", "group", or "default".
    pub async fn resolve_effective_policy(
        &self,
        socket_id: &str,
        backend_id: &str,
    ) -> Result<(Policy, String)> {
        // Get the address policy
        let addrs = self.get_socket_addresses(socket_id).await?;
        let addr = addrs.iter().find(|a| a.backend_id == backend_id);
        let addr_policy = addr.map(|a| a.policy).unwrap_or(Policy::Closed);

        match addr_policy {
            Policy::Group => {
                // Look up ACL group
                if let Some(group_id) = self.get_acl_group_for_socket(socket_id).await? {
                    if let Some(group) = self.get_acl_group(&group_id).await? {
                        return Ok((group.policy, "group".to_string()));
                    }
                }
                // Not in a group — treat as closed with no ACL = inactive
                Ok((Policy::Closed, "default".to_string()))
            }
            other => Ok((other, "address".to_string())),
        }
    }
}

// ======== Row types ========

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
    socket_group_id: Option<String>,
}

impl SocketRow {
    fn into_managed_socket(self, addresses: Vec<SocketAddress>, acl_group_id: Option<String>) -> Result<ManagedSocket> {
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
            acl_group_id,
            socket_group_id: self.socket_group_id,
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
    policy: String,
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
            policy: row.policy.parse().map_err(|e: String| anyhow::anyhow!(e))?,
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
    policy: String,
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
            policy: row.policy.parse().map_err(|e: String| anyhow::anyhow!(e))?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct AclRow {
    id: i64,
    socket_id: String,
    backend_id: String,
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
            backend_id: row.backend_id,
            allowed_ip: row.allowed_ip,
            label: row.label,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct AclGroupRow {
    id: String,
    label: String,
    policy: String,
    created_at: String,
}

impl TryFrom<AclGroupRow> for AclGroup {
    type Error = anyhow::Error;

    fn try_from(row: AclGroupRow) -> Result<Self> {
        Ok(AclGroup {
            id: row.id,
            label: row.label,
            policy: row.policy.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct AclGroupEntryRow {
    id: i64,
    group_id: String,
    backend_id: String,
    allowed_ip: String,
    label: Option<String>,
    created_at: String,
}

impl TryFrom<AclGroupEntryRow> for AclEntry {
    type Error = anyhow::Error;

    fn try_from(row: AclGroupEntryRow) -> Result<Self> {
        Ok(AclEntry {
            id: row.id,
            socket_id: row.group_id, // reuse socket_id field for group_id
            backend_id: row.backend_id,
            allowed_ip: row.allowed_ip,
            label: row.label,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct SocketGroupRow {
    id: String,
    label: String,
    app_name: String,
    created_at: String,
}

impl TryFrom<SocketGroupRow> for SocketGroup {
    type Error = anyhow::Error;

    fn try_from(row: SocketGroupRow) -> Result<Self> {
        Ok(SocketGroup {
            id: row.id,
            label: row.label,
            app_name: row.app_name,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct SocketGroupAddressRow {
    group_id: String,
    backend_id: String,
    address: String,
    interface: String,
    prefix_len: i64,
    keypair_id: Option<String>,
}

impl TryFrom<SocketGroupAddressRow> for SocketGroupAddress {
    type Error = anyhow::Error;

    fn try_from(row: SocketGroupAddressRow) -> Result<Self> {
        Ok(SocketGroupAddress {
            group_id: row.group_id,
            backend_id: row.backend_id,
            address: row.address.parse()?,
            interface: row.interface,
            prefix_len: row.prefix_len as u8,
            keypair_id: row.keypair_id,
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
                policy: Policy::Closed,
            }],
            policy: Policy::Closed,
            exe_path: None,
            cmdline: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            acl_group_id: None,
            socket_group_id: None,
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
        assert_eq!(retrieved.addresses[0].policy, Policy::Closed);
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
    async fn update_address_policy() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;

        db.update_address_policy("abc123", "ula", Policy::Open).await.unwrap();
        let socket = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(socket.addresses[0].policy, Policy::Open);

        db.update_address_policy("abc123", "ula", Policy::Group).await.unwrap();
        let socket = db.get_socket("abc123").await.unwrap().unwrap();
        assert_eq!(socket.addresses[0].policy, Policy::Group);
    }

    #[tokio::test]
    async fn update_policy_all_backends() {
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
            policy: Policy::Closed,
        };
        let addr2 = SocketAddress {
            backend_id: "slaac-Ethernet".to_string(),
            backend_type: BackendType::Slaac,
            address: "2001:db8::1".parse().unwrap(),
            interface: "Ethernet".to_string(),
            prefix_len: 64,
            keypair_id: None,
            policy: Policy::Closed,
        };
        db.upsert_socket_address("multi1", &addr1).await.unwrap();
        db.upsert_socket_address("multi1", &addr2).await.unwrap();

        db.update_policy_all_backends("multi1", Policy::Open).await.unwrap();

        let retrieved = db.get_socket("multi1").await.unwrap().unwrap();
        assert_eq!(retrieved.policy, Policy::Open); // default policy updated
        for a in &retrieved.addresses {
            assert_eq!(a.policy, Policy::Open);
        }
    }

    #[tokio::test]
    async fn acl_crud_per_backend() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;

        let entry = db.add_acl_entry("abc123", "ula", "fd00::100", Some("laptop")).await.unwrap();
        assert_eq!(entry.allowed_ip, "fd00::100");
        assert_eq!(entry.backend_id, "ula");
        assert_eq!(entry.label, Some("laptop".to_string()));

        let acl = db.get_acl_for_backend("abc123", "ula").await.unwrap();
        assert_eq!(acl.len(), 1);

        // Different backend has no entries
        let acl_other = db.get_acl_for_backend("abc123", "slaac").await.unwrap();
        assert_eq!(acl_other.len(), 0);

        db.delete_acl_entry(entry.id).await.unwrap();
        let acl = db.get_acl_for_backend("abc123", "ula").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    #[tokio::test]
    async fn acl_fan_out_all_backends() {
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
            policy: Policy::Closed,
        };
        let addr2 = SocketAddress {
            backend_id: "slaac-Ethernet".to_string(),
            backend_type: BackendType::Slaac,
            address: "2001:db8::1".parse().unwrap(),
            interface: "Ethernet".to_string(),
            prefix_len: 64,
            keypair_id: None,
            policy: Policy::Closed,
        };
        db.upsert_socket_address("multi1", &addr1).await.unwrap();
        db.upsert_socket_address("multi1", &addr2).await.unwrap();

        let entries = db.add_acl_entry_all_backends("multi1", "fd00::100", Some("peer")).await.unwrap();
        assert_eq!(entries.len(), 2);

        // Each backend should have one entry
        let acl_ula = db.get_acl_for_backend("multi1", "ula").await.unwrap();
        assert_eq!(acl_ula.len(), 1);
        let acl_slaac = db.get_acl_for_backend("multi1", "slaac-Ethernet").await.unwrap();
        assert_eq!(acl_slaac.len(), 1);

        // get_acl returns all
        let all = db.get_acl("multi1").await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn acl_rejects_invalid_ipv6() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;
        let result = db.add_acl_entry("abc123", "ula", "not-an-ip", None).await;
        assert!(result.is_err());
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
        db.add_acl_entry("abc123", "ula", "fd00::1", None).await.unwrap();
        db.add_acl_entry("abc123", "ula", "fd00::2", None).await.unwrap();

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
            policy: Policy::Closed,
        };
        let addr2 = SocketAddress {
            backend_id: "slaac-Ethernet".to_string(),
            backend_type: BackendType::Slaac,
            address: "2001:db8::1".parse().unwrap(),
            interface: "Ethernet".to_string(),
            prefix_len: 64,
            keypair_id: None,
            policy: Policy::Open,
        };

        db.upsert_socket_address("multi1", &addr1).await.unwrap();
        db.upsert_socket_address("multi1", &addr2).await.unwrap();

        let retrieved = db.get_socket("multi1").await.unwrap().unwrap();
        assert_eq!(retrieved.addresses.len(), 2);
        // Verify per-address policies
        let ula = retrieved.addresses.iter().find(|a| a.backend_id == "ula").unwrap();
        let slaac = retrieved.addresses.iter().find(|a| a.backend_id == "slaac-Ethernet").unwrap();
        assert_eq!(ula.policy, Policy::Closed);
        assert_eq!(slaac.policy, Policy::Open);
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

    #[tokio::test]
    async fn delete_address_cascades_acl() {
        let db = test_db().await;
        insert_test_socket(&db, "abc123", "nginx", 80).await;
        db.add_acl_entry("abc123", "ula", "fd00::100", None).await.unwrap();

        db.delete_socket_address("abc123", "ula").await.unwrap();

        let acl = db.get_acl_for_backend("abc123", "ula").await.unwrap();
        assert_eq!(acl.len(), 0);
    }

    // ADR 0018 tests

    #[tokio::test]
    async fn acl_group_crud() {
        let db = test_db().await;

        let group = db.create_acl_group("Web Servers").await.unwrap();
        assert_eq!(group.label, "Web Servers");
        assert_eq!(group.policy, Policy::Closed);

        let fetched = db.get_acl_group(&group.id).await.unwrap().unwrap();
        assert_eq!(fetched.label, "Web Servers");

        db.update_acl_group(&group.id, Some("HTTP Servers"), Some(Policy::Open)).await.unwrap();
        let updated = db.get_acl_group(&group.id).await.unwrap().unwrap();
        assert_eq!(updated.label, "HTTP Servers");
        assert_eq!(updated.policy, Policy::Open);

        let groups = db.list_acl_groups().await.unwrap();
        assert_eq!(groups.len(), 1);

        db.delete_acl_group(&group.id).await.unwrap();
        assert!(db.get_acl_group(&group.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn acl_group_membership() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "nginx", 80).await;
        insert_test_socket(&db, "s2", "nginx", 443).await;

        let group = db.create_acl_group("Web").await.unwrap();
        db.add_to_acl_group(&group.id, "s1").await.unwrap();
        db.add_to_acl_group(&group.id, "s2").await.unwrap();

        let members = db.get_acl_group_members(&group.id).await.unwrap();
        assert_eq!(members.len(), 2);

        assert_eq!(db.get_acl_group_for_socket("s1").await.unwrap(), Some(group.id.clone()));

        db.remove_from_acl_group(&group.id, "s1").await.unwrap();
        let members = db.get_acl_group_members(&group.id).await.unwrap();
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn acl_group_entries() {
        let db = test_db().await;
        let group = db.create_acl_group("Test").await.unwrap();

        let entry = db.add_acl_group_entry(&group.id, "ula", "fd00::100", Some("peer")).await.unwrap();
        assert_eq!(entry.allowed_ip, "fd00::100");

        let entries = db.get_acl_group_entries(&group.id).await.unwrap();
        assert_eq!(entries.len(), 1);

        let by_backend = db.get_acl_group_entries_for_backend(&group.id, "ula").await.unwrap();
        assert_eq!(by_backend.len(), 1);

        db.remove_acl_group_entry(entry.id).await.unwrap();
        let entries = db.get_acl_group_entries(&group.id).await.unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn socket_group_crud() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "vsftpd", 20).await;
        insert_test_socket(&db, "s2", "vsftpd", 21).await;

        let group = db.create_socket_group("FTP", "vsftpd").await.unwrap();
        assert_eq!(group.label, "FTP");
        assert_eq!(group.app_name, "vsftpd");

        db.add_socket_to_group(&group.id, "s1").await.unwrap();
        db.add_socket_to_group(&group.id, "s2").await.unwrap();

        let members = db.get_socket_group_members(&group.id).await.unwrap();
        assert_eq!(members.len(), 2);

        let s1 = db.get_socket("s1").await.unwrap().unwrap();
        assert_eq!(s1.socket_group_id, Some(group.id.clone()));

        db.remove_socket_from_group("s1").await.unwrap();
        let s1 = db.get_socket("s1").await.unwrap().unwrap();
        assert_eq!(s1.socket_group_id, None);

        let groups = db.list_socket_groups().await.unwrap();
        assert_eq!(groups.len(), 1);

        db.delete_socket_group(&group.id).await.unwrap();
        let groups = db.list_socket_groups().await.unwrap();
        assert_eq!(groups.len(), 0);
    }

    #[tokio::test]
    async fn resolve_effective_policy_direct() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "nginx", 80).await;

        let (policy, source) = db.resolve_effective_policy("s1", "ula").await.unwrap();
        assert_eq!(policy, Policy::Closed);
        assert_eq!(source, "address");

        db.update_address_policy("s1", "ula", Policy::Open).await.unwrap();
        let (policy, source) = db.resolve_effective_policy("s1", "ula").await.unwrap();
        assert_eq!(policy, Policy::Open);
        assert_eq!(source, "address");
    }

    #[tokio::test]
    async fn resolve_effective_policy_group() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "nginx", 80).await;

        let group = db.create_acl_group("Web").await.unwrap();
        db.update_acl_group(&group.id, None, Some(Policy::Open)).await.unwrap();
        db.add_to_acl_group(&group.id, "s1").await.unwrap();

        db.update_address_policy("s1", "ula", Policy::Group).await.unwrap();

        let (policy, source) = db.resolve_effective_policy("s1", "ula").await.unwrap();
        assert_eq!(policy, Policy::Open);
        assert_eq!(source, "group");
    }

    #[tokio::test]
    async fn resolve_effective_policy_group_no_membership() {
        let db = test_db().await;
        insert_test_socket(&db, "s1", "nginx", 80).await;

        db.update_address_policy("s1", "ula", Policy::Group).await.unwrap();

        // Not in any group → defaults to closed
        let (policy, source) = db.resolve_effective_policy("s1", "ula").await.unwrap();
        assert_eq!(policy, Policy::Closed);
        assert_eq!(source, "default");
    }
}
