//! Windows DACLs for the database file: SYSTEM and Administrators only.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    CheckTokenMembership, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// SYSTEM and Administrators full control, nobody else, inheritance blocked.
pub const DB_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// The account running the process, when neither SYSTEM nor an elevated administrator
/// already covers it (a daemon started by hand from a normal user, as the tests are).
/// Without its own ACE such a process would lock itself out of the file.
pub fn extra_principal() -> Option<String> {
    // SAFETY: plain token queries on the current process; buffers are sized by the
    // first call and the string SID is freed after use.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut admin = windows::core::BOOL::default();
        let mut ba = PSID::default();
        let mut sid_str = None;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        if len > 0
            && GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                len,
                &mut len,
            )
            .is_ok()
            && ConvertStringSidToSidW(w!("BA"), &mut ba).is_ok()
        {
            let user = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let mut out = PWSTR::null();
            if ConvertSidToStringSidW(user, &mut out).is_ok() {
                let s = out.to_string().ok();
                let _ = LocalFree(Some(HLOCAL(out.0.cast())));
                let _ = CheckTokenMembership(None, ba, &mut admin);
                if !admin.as_bool() && s.as_deref() != Some("S-1-5-18") {
                    sid_str = s;
                }
            }
        }
        if !ba.is_invalid() {
            let _ = LocalFree(Some(HLOCAL(ba.0)));
        }
        let _ = CloseHandle(token);
        sid_str
    }
}

pub fn sddl() -> String {
    match extra_principal() {
        Some(sid) => format!("{DB_SDDL}(A;;FA;;;{sid})"),
        None => DB_SDDL.to_string(),
    }
}

/// The same principals for a directory, inherited by the files and directories created in
/// it. Without the inheritance flags a file written there (the install record, the config)
/// gets the default DACL of the creating process, which for a service is SYSTEM only: an
/// elevated administrator then cannot read the record to uninstall.
pub fn dir_sddl() -> String {
    let mut s = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_string();
    if let Some(sid) = extra_principal() {
        s.push_str(&format!("(A;OICI;FA;;;{sid})"));
    }
    s
}

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn new(sddl: &str) -> anyhow::Result<Self> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sd` receives a LocalAlloc'd descriptor that Drop frees.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
        }
        Ok(Self(sd))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Create an empty file with the descriptor; an existing file gets the descriptor
/// applied, so a file left by an earlier run or planted by someone else is covered too.
pub fn create_protected(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return protect(path);
    }
    let sd = Descriptor::new(&sddl())?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: false.into(),
    };
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; `attrs` and its descriptor outlive the call.
    unsafe {
        let h = CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&attrs),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?;
        let _ = CloseHandle(h);
    }
    Ok(())
}

/// The data directory of a managed child (ADR 0052): SYSTEM and Administrators, and
/// LocalService when the child runs as it, inherited by what is created inside (the child
/// writes there). When neither SYSTEM nor an elevated administrator runs the daemon, its
/// own account gets an entry too.
pub fn service_dir_sddl(local_service: bool) -> String {
    let mut sddl = String::from("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    if local_service {
        sddl.push_str("(A;OICI;FA;;;LS)");
    }
    if let Some(sid) = extra_principal() {
        sddl.push_str(&format!("(A;OICI;FA;;;{sid})"));
    }
    sddl
}

/// Replace the DACL of an existing file with the protected one.
pub fn protect(path: &Path) -> anyhow::Result<()> {
    protect_with(path, &sddl())
}

/// Replace the DACL of a directory with the protected, inheritable one ([`dir_sddl`]).
pub fn protect_dir(path: &Path) -> anyhow::Result<()> {
    protect_with(path, &dir_sddl())
}

/// [`protect`] the data directory of a managed child, see [`service_dir_sddl`].
pub fn protect_service_dir(path: &Path, local_service: bool) -> anyhow::Result<()> {
    protect_with(path, &service_dir_sddl(local_service))
}

fn protect_with(path: &Path, sddl: &str) -> anyhow::Result<()> {
    let sd = Descriptor::new(sddl)?;
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let name = wide(path);
    // SAFETY: the descriptor is valid; `dacl` points into it for the whole call.
    unsafe {
        GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted)?;
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
        .ok()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::*;
    use crate::state::*;
    use std::path::Path;

    /// The DACL of `path` as SDDL.
    #[cfg(windows)]
    fn dacl_sddl(path: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut out = PWSTR::null();
        // SAFETY: out-pointers are valid; the buffers are freed after use.
        unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
            .ok()
            .unwrap();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut out,
                None,
            )
            .unwrap();
            let s = out.to_string().unwrap();
            let _ = LocalFree(Some(HLOCAL(out.0.cast())));
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            s
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_database_files_have_a_protected_dacl() {
        let path = temp_db_path("acl");
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        db.insert_app(&app("a1")).await.unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let file = with_suffix(&path, suffix);
            if !file.exists() {
                continue;
            }
            let sddl = dacl_sddl(&file);
            assert!(sddl.starts_with("D:P"), "{suffix}: not protected: {sddl}");
            // SYSTEM and Administrators, plus the running account when it is neither
            // (a test run from a normal user; a service is covered by the first two).
            let extra = extra_principal();
            assert_eq!(
                sddl.matches("(A;").count(),
                2 + usize::from(extra.is_some()),
                "{suffix}: unexpected ACEs: {sddl}"
            );
            if let Some(sid) = extra {
                assert!(sddl.contains(&format!(";;;{sid})")), "{sddl}");
            }
            assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
        }
        db.pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_a_protected_directory_gives_new_files_system_and_administrators() {
        let dir = std::env::temp_dir().join(format!("sg-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        super::protect_dir(&dir).unwrap();
        let file = dir.join("setup-log.json");
        std::fs::write(&file, b"{}").unwrap();
        let sddl = dacl_sddl(&file);
        assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_existing_database_files_get_the_protected_dacl() {
        let path = temp_db_path("acl-existing");
        // A file from before, with the inherited (user-readable) ACL.
        std::fs::write(&path, b"").unwrap();
        assert!(!dacl_sddl(&path).starts_with("D:P"));
        let db = Database::new(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        assert!(dacl_sddl(&path).starts_with("D:P"), "{}", dacl_sddl(&path));
        db.pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(with_suffix(&path, suffix));
        }
    }
}
