//! The API's transport and its authorization (ADR 0032): a Unix socket guarded by file
//! permissions and a peer-credential check, or a Windows named pipe guarded by its ACL.
//! There is no TCP listener. Authorization is OS identity: root (or Administrators and
//! SYSTEM), the daemon's own user, and members of the `socketguard` group (Unix) or the
//! local `SocketGuard Users` group (Windows).

use axum::Router;
use socketguard_core::config::DaemonConfig;
use std::future::Future;
use tracing::{info, warn};

/// Group whose members may use the API on Unix.
pub const UNIX_GROUP: &str = "socketguard";
/// Local group whose members may use the API on Windows.
pub const WINDOWS_GROUP: &str = "SocketGuard Users";

/// How long open connections get after a shutdown signal.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// A bound but not yet serving API endpoint.
pub struct Server {
    listener: platform::Listener,
    /// The socket file to remove on shutdown.
    #[cfg(unix)]
    path: std::path::PathBuf,
}

/// Bind the endpoint named by `config` for this platform.
pub fn bind(config: &DaemonConfig) -> anyhow::Result<Server> {
    #[cfg(unix)]
    {
        bind_unix(std::path::Path::new(&config.api_socket), UNIX_GROUP)
    }
    #[cfg(windows)]
    {
        let group = platform::group_sid(WINDOWS_GROUP);
        if group.is_none() {
            warn!(
                "Local group '{WINDOWS_GROUP}' does not exist: only SYSTEM and Administrators can \
                 use the API pipe. Create it with: net localgroup \"{WINDOWS_GROUP}\" /add"
            );
        }
        bind_pipe(&config.api_pipe, &platform::pipe_sddl(group.as_deref()))
    }
}

impl Server {
    /// Serve `app` until `shutdown` resolves.
    pub async fn serve(
        self,
        app: Router,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        // Graceful shutdown waits for open connections, and an event stream never ends on
        // its own: after the signal, requests get SHUTDOWN_GRACE and then are cut off.
        let (signalled, signal) = tokio::sync::oneshot::channel::<()>();
        let serving = axum::serve(self.listener, app).with_graceful_shutdown(async move {
            shutdown.await;
            let _ = signalled.send(());
        });
        let result = tokio::select! {
            r = serving => r,
            _ = async {
                let _ = signal.await;
                tokio::time::sleep(SHUTDOWN_GRACE).await;
            } => {
                info!("Closing API connections that are still open");
                Ok(())
            }
        };
        #[cfg(unix)]
        {
            if let Err(e) = std::fs::remove_file(&self.path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Could not remove {}: {e}", self.path.display());
                }
            }
        }
        result
    }
}

// ─── Unix ────────────────────────────────────────────────────────────────────

/// Bind a Unix socket at `path`: group `group` and mode 0660 when that group exists,
/// otherwise mode 0600 (owner only). Peers are checked by uid and group membership on
/// every connection.
#[cfg(unix)]
pub fn bind_unix(path: &std::path::Path, group: &str) -> anyhow::Result<Server> {
    use anyhow::Context;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    // A leftover socket from a crashed run is replaced; a live one means we are already
    // running.
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            anyhow::bail!("{} is in use: another daemon is running", path.display());
        }
        std::fs::remove_file(path)
            .with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }
    // Created owner-only, so there is no window with wider access before the chown/chmod.
    // SAFETY: umask only changes this process's file creation mask.
    let old_umask = unsafe { libc::umask(0o177) };
    let bound = tokio::net::UnixListener::bind(path);
    unsafe { libc::umask(old_umask) };
    let inner = bound.with_context(|| format!("cannot bind {}", path.display()))?;

    let gid = platform::group_gid(group);
    match gid {
        Some(gid) => {
            platform::chown_group(path, gid)
                .with_context(|| format!("cannot give {} to group {group}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
            info!("API socket {} (mode 0660, group {group})", path.display());
        }
        None => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            warn!(
                "Group '{group}' does not exist: API socket {} is owner-only (mode 0600). \
                 Create the group and add users to it to let them in.",
                path.display()
            );
        }
    }
    Ok(Server {
        listener: platform::Listener {
            inner,
            own_uid: unsafe { libc::geteuid() },
            group: gid,
        },
        path: path.to_path_buf(),
    })
}

/// Whether a peer with this uid and primary gid may use the API: root, the daemon's own
/// user, or a member of the API group. `groups_of` lists a user's groups.
#[cfg(unix)]
pub fn peer_allowed(
    uid: u32,
    gid: u32,
    own_uid: u32,
    api_group: Option<u32>,
    groups_of: impl Fn(u32, u32) -> Vec<u32>,
) -> bool {
    if uid == 0 || uid == own_uid {
        return true;
    }
    match api_group {
        Some(g) => gid == g || groups_of(uid, gid).contains(&g),
        None => false,
    }
}

// ─── Windows ─────────────────────────────────────────────────────────────────

/// Bind the named pipe `name` with the access control described by `sddl`. The first
/// instance is created here, so clients can connect as soon as this returns.
#[cfg(windows)]
pub fn bind_pipe(name: &str, sddl: &str) -> anyhow::Result<Server> {
    let listener = platform::Listener::bind(name, sddl)?;
    info!("API pipe {name}");
    Ok(Server { listener })
}

#[cfg(windows)]
pub use platform::pipe_sddl;

#[cfg(unix)]
mod platform {
    use super::peer_allowed;
    use std::ffi::CString;
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};
    use tracing::warn;

    pub struct Listener {
        pub inner: UnixListener,
        pub own_uid: u32,
        pub group: Option<u32>,
    }

    impl axum::serve::Listener for Listener {
        type Io = UnixStream;
        type Addr = tokio::net::unix::SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                match self.inner.accept().await {
                    Ok((stream, addr)) => match stream.peer_cred() {
                        Ok(c)
                            if peer_allowed(
                                c.uid(),
                                c.gid(),
                                self.own_uid,
                                self.group,
                                groups_of,
                            ) =>
                        {
                            return (stream, addr)
                        }
                        Ok(c) => warn!("Refused API connection from uid {}", c.uid()),
                        Err(e) => warn!("Refused API connection, no peer credentials: {e}"),
                    },
                    Err(e) => {
                        warn!("API accept failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.inner.local_addr()
        }
    }

    /// The gid of group `name`, if it exists.
    pub fn group_gid(name: &str) -> Option<u32> {
        let name = CString::new(name).ok()?;
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut out: *mut libc::group = std::ptr::null_mut();
        // SAFETY: all pointers refer to live locals; `buf` outlives the call.
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut out,
            )
        };
        (rc == 0 && !out.is_null()).then_some(grp.gr_gid)
    }

    /// All groups of the user `uid` (primary `gid` included), from the user database.
    // `G` is `c_int` on macOS and already `u32` elsewhere, so the final cast is a no-op there.
    #[allow(clippy::unnecessary_cast)]
    fn groups_of(uid: u32, gid: u32) -> Vec<u32> {
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: as above.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
        if rc != 0 || out.is_null() {
            return vec![gid];
        }
        #[cfg(target_os = "macos")]
        type G = libc::c_int;
        #[cfg(not(target_os = "macos"))]
        type G = libc::gid_t;
        let mut groups: Vec<G> = vec![0; 64];
        loop {
            let mut n = groups.len() as libc::c_int;
            // SAFETY: `groups` has room for `n` entries; pw_name is a NUL-terminated string
            // inside `buf`.
            let rc =
                unsafe { libc::getgrouplist(pw.pw_name, gid as G, groups.as_mut_ptr(), &mut n) };
            if rc >= 0 {
                groups.truncate(n.max(0) as usize);
                break;
            }
            // Too small: `n` now holds the needed size.
            groups.resize((n as usize).max(groups.len() * 2), 0);
        }
        groups.into_iter().map(|g| g as u32).collect()
    }

    pub fn chown_group(path: &Path, gid: u32) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: `c` is a valid NUL-terminated path; uid (uid_t)-1 leaves the owner alone.
        let rc = unsafe { libc::chown(c.as_ptr(), libc::uid_t::MAX, gid as libc::gid_t) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tracing::warn;
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        LookupAccountNameW, SidTypeAlias, SidTypeGroup, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, SID_NAME_USE,
    };

    /// What the group may do on the pipe: FILE_GENERIC_READ (0x120089, with SYNCHRONIZE)
    /// plus FILE_WRITE_DATA (0x2). Not GENERIC_WRITE: that includes FILE_APPEND_DATA
    /// (0x4), the same bit as FILE_CREATE_PIPE_INSTANCE, which would let a member create
    /// a rogue server instance and capture other users' requests.
    pub const GROUP_PIPE_MASK: u32 = 0x0012_0089 | 0x2;

    /// SYSTEM and Administrators get full access, the group (when it exists) read and
    /// write data. The DACL is protected, so nothing is inherited.
    pub fn pipe_sddl(group_sid: Option<&str>) -> String {
        let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        if let Some(sid) = group_sid {
            s.push_str(&format!("(A;;0x{GROUP_PIPE_MASK:X};;;{sid})"));
        }
        s
    }

    /// The SID of the local group `name` as a string, if it exists and is a group (a
    /// user or other account of that name is ignored with a warning: it would hand the
    /// pipe to one account).
    pub fn group_sid(name: &str) -> Option<String> {
        let name = HSTRING::from(name);
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_ = SID_NAME_USE::default();
        // SAFETY: the first call only reports the buffer sizes (and fails by design).
        unsafe {
            let _ = LookupAccountNameW(
                None,
                &name,
                None,
                &mut sid_len,
                None,
                &mut domain_len,
                &mut use_,
            );
        }
        if sid_len == 0 {
            return None;
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: the buffers have the sizes the first call asked for.
        unsafe {
            LookupAccountNameW(
                None,
                &name,
                Some(PSID(sid.as_mut_ptr().cast())),
                &mut sid_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut use_,
            )
            .ok()?;
            if use_ != SidTypeAlias && use_ != SidTypeGroup {
                warn!(
                    "{name} is not a group (account type {}); ignoring it for the API pipe",
                    use_.0
                );
                return None;
            }
            let mut out = PWSTR::null();
            ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut out).ok()?;
            let s = out.to_string().ok();
            let _ = LocalFree(Some(HLOCAL(out.0.cast())));
            s
        }
    }

    /// A security descriptor built from SDDL, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is immutable memory owned by this value.
    unsafe impl Send for Descriptor {}
    unsafe impl Sync for Descriptor {}

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    pub struct Listener {
        name: String,
        descriptor: Descriptor,
        /// The instance waiting for the next client. There is always one.
        next: NamedPipeServer,
    }

    impl Listener {
        pub fn bind(name: &str, sddl: &str) -> anyhow::Result<Self> {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `sd` receives a LocalAlloc'd descriptor that Descriptor frees.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &HSTRING::from(sddl),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )?;
            }
            let descriptor = Descriptor(sd);
            let next = create_instance(name, &descriptor, true)?;
            Ok(Self {
                name: name.to_string(),
                descriptor,
                next,
            })
        }
    }

    fn create_instance(
        name: &str,
        descriptor: &Descriptor,
        first: bool,
    ) -> std::io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: `attrs` and the descriptor it points to are valid for the call.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }

    impl axum::serve::Listener for Listener {
        type Io = NamedPipeServer;
        type Addr = ();

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                if let Err(e) = self.next.connect().await {
                    warn!("API pipe connect failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                // Hand the connected instance out only once its replacement exists, so a
                // new client always finds a free instance.
                let replacement = loop {
                    match create_instance(&self.name, &self.descriptor, false) {
                        Ok(r) => break r,
                        Err(e) => {
                            warn!("Cannot create the next API pipe instance: {e}");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                };
                return (std::mem::replace(&mut self.next, replacement), ());
            }
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn nobody_groups(_: u32, _: u32) -> Vec<u32> {
        vec![]
    }

    #[test]
    fn root_and_own_user_are_always_allowed() {
        assert!(peer_allowed(0, 0, 1000, None, nobody_groups));
        assert!(peer_allowed(1000, 1000, 1000, None, nobody_groups));
    }

    #[test]
    fn others_need_the_group() {
        // No API group: only root and the daemon's user.
        assert!(!peer_allowed(1001, 1001, 1000, None, nobody_groups));
        // Primary group match.
        assert!(peer_allowed(1001, 77, 1000, Some(77), nobody_groups));
        // Supplementary group match.
        assert!(peer_allowed(1001, 1001, 1000, Some(77), |_, _| vec![
            1001, 77
        ]));
        // A user outside the group is refused.
        assert!(!peer_allowed(1001, 1001, 1000, Some(77), |_, _| vec![
            1001, 5
        ]));
    }

    #[test]
    fn group_lookup() {
        // gid 0 is `root` on Linux and `wheel` on macOS.
        let gid0 = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        assert_eq!(platform::group_gid(gid0), Some(0));
        assert_eq!(platform::group_gid("no-such-group-sg-test"), None);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn sddl_has_admins_system_and_the_group() {
        assert_eq!(platform::pipe_sddl(None), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(
            platform::pipe_sddl(Some("S-1-5-21-1")),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008B;;;S-1-5-21-1)"
        );
    }

    /// GENERIC_WRITE would carry FILE_APPEND_DATA (0x4) = FILE_CREATE_PIPE_INSTANCE.
    #[test]
    fn the_group_cannot_create_pipe_instances() {
        let mask = platform::GROUP_PIPE_MASK;
        assert_eq!(mask & 0x4, 0, "FILE_CREATE_PIPE_INSTANCE");
        assert_ne!(mask & 0x0010_0000, 0, "SYNCHRONIZE");
        assert_ne!(mask & 0x1, 0, "FILE_READ_DATA");
        assert_ne!(mask & 0x2, 0, "FILE_WRITE_DATA");
        let sddl = platform::pipe_sddl(Some("S-1-5-21-1"));
        assert!(
            !sddl.contains("GW") && !sddl.contains("GA;;;S-1-5-21"),
            "{sddl}"
        );
    }

    /// The (localized) name of the BUILTIN Users group.
    fn users_group_name() -> String {
        use windows::core::{w, PWSTR};
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
        let mut sid = PSID::default();
        let (mut name_len, mut domain_len) = (0u32, 0u32);
        let mut use_ = SID_NAME_USE::default();
        // SAFETY: buffers are sized by the first call; the SID lives for the whole function.
        unsafe {
            ConvertStringSidToSidW(w!("S-1-5-32-545"), &mut sid).unwrap();
            let _ = LookupAccountSidW(
                None,
                sid,
                None,
                &mut name_len,
                None,
                &mut domain_len,
                &mut use_,
            );
            let mut name = vec![0u16; name_len as usize];
            let mut domain = vec![0u16; domain_len as usize];
            LookupAccountSidW(
                None,
                sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut use_,
            )
            .unwrap();
            String::from_utf16_lossy(&name[..name_len as usize])
        }
    }

    #[test]
    fn groups_resolve_to_sids_but_other_accounts_do_not() {
        // BUILTIN Users is an alias (its name is localized); SYSTEM is a well-known
        // account, not a group.
        let users = users_group_name();
        assert_eq!(
            platform::group_sid(&users).as_deref(),
            Some("S-1-5-32-545"),
            "{users}"
        );
        assert_eq!(platform::group_sid("SYSTEM"), None);
        let me = std::env::var("USERNAME").unwrap();
        assert_eq!(platform::group_sid(&me), None, "a user is not a group");
    }

    #[test]
    fn missing_group_has_no_sid() {
        assert_eq!(platform::group_sid("No Such Group sg-test"), None);
    }
}
