//! Keys of the `settings` table and the typed accessors over them.

use super::Database;
use anyhow::Result;
use socketguard_core::Settings;
use tracing::warn;

/// Settings keys.
const PROTECT_HOST_KEY: &str = "protect_host_interfaces";
/// Set by `disable` (API or `--disable`), cleared by `enable`: while set, the daemon puts
/// no rules and no addresses back.
const DISABLED_KEY: &str = "disabled";
/// Set when the database was created by this start (no prior schema), consumed by the
/// first successful apply or the startup check.
pub(super) const FRESH_DB_KEY: &str = "fresh_db";
/// Set when a fresh database met an existing SocketGuard ruleset: nothing is applied or
/// added until `enable` adopts the new state (or `disable` removes the old one).
const UNADOPTED_KEY: &str = "unadopted";
const ULA_GLOBAL_ID_KEY: &str = "ula_global_id";

impl Database {
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The installation's ULA global ID (40 bits), generated and stored on first use so
    /// ULA addresses stay in the same /48 across restarts.
    pub async fn ula_global_id(&self) -> Result<[u8; 5]> {
        if let Some(stored) = self.get_setting(ULA_GLOBAL_ID_KEY).await? {
            if let Some(id) = parse_global_id(&stored) {
                return Ok(id);
            }
            warn!("Invalid stored ULA global ID {stored:?}, generating a new one");
        }
        let id = crate::networks::ip::ula::UlaBackend::random_global_id();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        self.set_setting(ULA_GLOBAL_ID_KEY, &hex).await?;
        Ok(id)
    }

    /// Interfaces under whole-host protection; absent or invalid means off.
    pub async fn protect_host(&self) -> Result<Vec<String>> {
        Ok(parse_protect_host(
            self.get_setting(PROTECT_HOST_KEY).await?.as_deref(),
        ))
    }

    pub async fn set_protect_host(&self, interfaces: &[String]) -> Result<()> {
        self.set_setting(PROTECT_HOST_KEY, &serde_json::to_string(interfaces)?)
            .await
    }

    /// A boolean setting; absent means false.
    async fn flag(&self, key: &str) -> Result<bool> {
        Ok(self.get_setting(key).await?.as_deref() == Some("true"))
    }

    async fn set_flag(&self, key: &str, value: bool) -> Result<()> {
        self.set_setting(key, if value { "true" } else { "false" })
            .await
    }

    /// Whether enforcement is switched off (see [`DISABLED_KEY`]).
    ///
    /// This is the one place that decides what an unreadable latch means: it fails closed,
    /// so a read error counts as disabled and the daemon adds and publishes nothing on a
    /// guess. Callers therefore get a plain `bool`.
    pub async fn disabled(&self) -> bool {
        self.flag(DISABLED_KEY).await.unwrap_or_else(|e| {
            warn!("Cannot read the disabled latch, treating it as set: {e:#}");
            true
        })
    }

    pub async fn set_disabled(&self, disabled: bool) -> Result<()> {
        self.set_flag(DISABLED_KEY, disabled).await
    }

    /// Whether this database was created by the current start and nothing has adopted it.
    pub async fn fresh(&self) -> Result<bool> {
        self.flag(FRESH_DB_KEY).await
    }

    pub async fn clear_fresh(&self) -> Result<()> {
        self.set_flag(FRESH_DB_KEY, false).await
    }

    /// Whether an existing ruleset was found with an empty database (see [`UNADOPTED_KEY`]).
    pub async fn unadopted(&self) -> Result<bool> {
        self.flag(UNADOPTED_KEY).await
    }

    pub async fn set_unadopted(&self, unadopted: bool) -> Result<()> {
        self.set_flag(UNADOPTED_KEY, unadopted).await
    }

    pub async fn settings(&self) -> Result<Settings> {
        Ok(Settings {
            protect_host_interfaces: self.protect_host().await?,
        })
    }
}

/// Parse the stored `protect_host_interfaces` value; absent or invalid means off.
pub fn parse_protect_host(value: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = value
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    v.retain(|s| !s.trim().is_empty());
    v.sort();
    v.dedup();
    v
}

fn parse_global_id(hex: &str) -> Option<[u8; 5]> {
    if hex.len() != 10 || !hex.is_ascii() {
        return None;
    }
    let mut id = [0u8; 5];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::*;

    #[tokio::test]
    async fn settings_and_ula_global_id() {
        let db = db().await;
        assert_eq!(
            db.settings().await.unwrap(),
            Settings {
                protect_host_interfaces: vec![]
            }
        );
        db.set_protect_host(&["eth0".into()]).await.unwrap();
        let s = db.settings().await.unwrap();
        assert_eq!(s.protect_host_interfaces, ["eth0"]);
        let id = db.ula_global_id().await.unwrap();
        assert_eq!(db.ula_global_id().await.unwrap(), id);
        assert!(parse_global_id("zz").is_none());
        assert_eq!(parse_protect_host(Some(r#"["b","a","a",""]"#)), ["a", "b"]);
        assert!(parse_protect_host(Some("not json")).is_empty());
    }
}
