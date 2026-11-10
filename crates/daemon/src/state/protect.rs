//! Keeping the database file (it holds onion service keys) readable by its owner only.

#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use std::path::Path;

/// Restrict the database file and its WAL companions to the owner (Unix). Failures are
/// logged: a daemon that cannot chmod its own database should still run.
#[cfg(unix)]
pub(super) fn protect_files(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let file = super::with_suffix(path, suffix);
        if !file.exists() {
            continue;
        }
        if let Err(e) = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("Could not restrict {} to its owner: {e}", file.display());
        }
    }
    Ok(())
}

/// Set to `1` to run on Windows with a database file whose ACL could not be restricted.
/// For tests and development only: the database holds the onion service keys.
pub const ALLOW_UNPROTECTED_DB_ENV: &str = "SOCKETGUARD_ALLOW_UNPROTECTED_DB";

/// Restrict the database file and its WAL companions to SYSTEM and Administrators
/// (Windows). The database holds onion keys, so a failure fails startup, unless
/// [`ALLOW_UNPROTECTED_DB_ENV`] is `1` (then it is logged).
#[cfg(windows)]
pub(super) fn protect_files(path: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let file = super::with_suffix(path, suffix);
        if file.exists() {
            enforce_protected(super::winacl::protect(&file), &file)?;
        }
    }
    Ok(())
}

/// Fail on `result` unless the override is set.
#[cfg(windows)]
fn enforce_protected(result: Result<()>, file: &Path) -> Result<()> {
    let allow = std::env::var(ALLOW_UNPROTECTED_DB_ENV).as_deref() == Ok("1");
    enforce_protected_with(result, file, allow)
}

#[cfg(windows)]
fn enforce_protected_with(result: Result<()>, file: &Path, allow: bool) -> Result<()> {
    let Err(e) = result else { return Ok(()) };
    if allow {
        tracing::warn!(
            "Could not restrict {} to SYSTEM and Administrators: {e:#} ({ALLOW_UNPROTECTED_DB_ENV}=1, continuing)",
            file.display()
        );
        return Ok(());
    }
    Err(e).with_context(|| {
        format!(
            "cannot restrict {} to SYSTEM and Administrators; it holds onion service keys \
             (set {ALLOW_UNPROTECTED_DB_ENV}=1 to run anyway, for tests only)",
            file.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
pub(super) fn protect_files(_path: &Path) -> Result<()> {
    Ok(())
}

/// Create the database file empty, with the protected DACL from the start (an existing
/// file gets it applied), so it is never readable by others (SQLite then opens the
/// existing file). Elsewhere a no-op: the file is chmod'ed right after SQLite creates it,
/// before any secret is written.
#[cfg(windows)]
pub(super) fn precreate_protected(path: &Path) -> Result<()> {
    enforce_protected(super::winacl::create_protected(path), path)
}

#[cfg(not(windows))]
pub(super) fn precreate_protected(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;
    #[cfg(unix)]
    use crate::state::{test_util::*, with_suffix, Database};

    #[cfg(unix)]
    #[tokio::test]
    async fn database_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db_path("perms");
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        db.set_setting("k", "v").await.unwrap();
        db.migrate().await.unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let f = with_suffix(&path, suffix);
            if let Ok(m) = std::fs::metadata(&f) {
                assert_eq!(m.permissions().mode() & 0o777, 0o600, "{}", f.display());
            }
        }
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_unprotectable_database_fails_startup_unless_overridden() {
        let file = Path::new("db.sqlite");
        let err = || Err(anyhow::anyhow!("access denied"));
        let e = enforce_protected_with(err(), file, false).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("onion service keys") && msg.contains(ALLOW_UNPROTECTED_DB_ENV));
        assert!(enforce_protected_with(err(), file, true).is_ok());
        assert!(enforce_protected_with(Ok(()), file, false).is_ok());
    }
}
