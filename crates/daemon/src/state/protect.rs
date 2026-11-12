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

static UNPROTECTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the database is (to be) restricted to SYSTEM and Administrators. False only after
/// [`give_up_protection`].
pub fn db_protected() -> bool {
    !UNPROTECTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Portable mode on a volume without access control lists (ADR 0054): skip every DACL
/// step, once, before the database is opened.
pub fn give_up_protection() {
    UNPROTECTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// `FILE_PERSISTENT_ACLS` of `GetVolumeInformationW`'s file-system flags.
pub const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;

/// Whether files in `dir` can be protected: the volume's flags (from `volume_flags`, which
/// takes the directory) include persistent ACLs. A volume that cannot be asked is assumed to
/// support them, so the normal protection runs and fails loudly if it is wrong.
pub fn volume_supports_acls(
    dir: &Path,
    volume_flags: impl FnOnce(&Path) -> std::io::Result<u32>,
) -> bool {
    volume_flags(dir).map_or(true, |f| f & FILE_PERSISTENT_ACLS != 0)
}

/// The file-system flags of the volume that holds `path`.
#[cfg(windows)]
pub fn system_volume_flags(path: &Path) -> std::io::Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut root = [0u16; 261];
    let mut flags = 0u32;
    // SAFETY: NUL-terminated input and output buffers of the sizes given.
    unsafe {
        GetVolumePathNameW(PCWSTR(wide.as_ptr()), &mut root).map_err(std::io::Error::other)?;
        GetVolumeInformationW(
            PCWSTR(root.as_ptr()),
            None,
            None,
            None,
            Some(&mut flags),
            None,
        )
        .map_err(std::io::Error::other)?;
    }
    Ok(flags)
}

/// Set to `1` to run on Windows with a database file whose ACL could not be restricted.
/// For tests and development only: the database holds the onion service keys.
pub const ALLOW_UNPROTECTED_DB_ENV: &str = "SOCKETGUARD_ALLOW_UNPROTECTED_DB";

/// Restrict the database file and its WAL companions to SYSTEM and Administrators
/// (Windows). The database holds onion keys, so a failure fails startup, unless
/// [`ALLOW_UNPROTECTED_DB_ENV`] is `1` (then it is logged).
#[cfg(windows)]
pub(super) fn protect_files(path: &Path) -> Result<()> {
    if !db_protected() {
        return Ok(());
    }
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
    if !db_protected() {
        return Ok(());
    }
    enforce_protected(super::winacl::create_protected(path), path)
}

#[cfg(not(windows))]
pub(super) fn precreate_protected(_path: &Path) -> Result<()> {
    Ok(())
}

/// Protect a directory SocketGuard created (ADR 0050): Unix mode 0755 for `shared` (the
/// config directory), 0700 otherwise; on Windows the directory gets the SYSTEM and
/// Administrators only ACL. Files inside keep their own protection.
pub fn protect_dir(path: &Path, shared: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if shared { 0o755 } else { 0o700 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let _ = shared;
        if db_protected() {
            enforce_protected(super::winacl::protect_dir(path), path)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, shared);
    }
    Ok(())
}

/// Windows: protect the data directory of a managed child (ADR 0052) so that SYSTEM and
/// Administrators, and LocalService when `local_service`, and nobody else, can use it and
/// what is created inside. Elsewhere the caller sets mode and owner itself.
#[cfg(windows)]
pub fn protect_service_dir(path: &Path, local_service: bool) -> Result<()> {
    super::winacl::protect_service_dir(path, local_service)
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

    #[test]
    fn a_volume_without_persistent_acls_gets_no_dacl_protection() {
        use super::{volume_supports_acls, FILE_PERSISTENT_ACLS};
        let dir = std::path::Path::new("D:/portable/data");
        // NTFS: case-preserved, unicode, persistent ACLs (0x7 | 0x8 ...).
        assert!(volume_supports_acls(dir, |_| Ok(
            0x0000_00FF | FILE_PERSISTENT_ACLS
        )));
        // exFAT / FAT32: no ACLs.
        assert!(!volume_supports_acls(dir, |_| Ok(0x0000_0007)));
        // Cannot ask: protect as usual, which fails loudly if the volume cannot do it.
        assert!(volume_supports_acls(dir, |_| Err(std::io::Error::other(
            "no"
        ))));
        // The decision is made for the directory it is given.
        assert!(!volume_supports_acls(dir, |p| {
            assert_eq!(p, dir);
            Ok(0)
        }));
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
