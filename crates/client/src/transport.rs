//! Connecting to the daemon: a Unix socket, or a Windows named pipe.

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;

#[cfg(unix)]
pub async fn connect(path: &str) -> std::io::Result<Stream> {
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// `ERROR_PIPE_BUSY`: every server instance is serving someone; wait for a free one.
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

/// What a client may do on the pipe: FILE_GENERIC_READ | FILE_WRITE_DATA. GENERIC_WRITE
/// would add FILE_APPEND_DATA, the same bit as FILE_CREATE_PIPE_INSTANCE, which the
/// daemon's ACL does not grant to the SocketGuard Users group. Keep in step with
/// `GROUP_PIPE_MASK` in the daemon's transport.
#[cfg(windows)]
const PIPE_ACCESS: u32 = 0x0012_0089 | 0x2;

/// SECURITY_IDENTIFICATION: the server may learn who we are but not act as us, so a rogue
/// server on the pipe name cannot use our token.
#[cfg(windows)]
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// Set to `1` to talk to a pipe server that is not SYSTEM or an administrator (a daemon
/// started by hand from a normal account). For tests and development only.
#[cfg(windows)]
pub const TRUST_PIPE_SERVER_ENV: &str = "SOCKETGUARD_TRUST_PIPE_SERVER";

/// SYSTEM and BUILTIN\Administrators.
#[cfg(windows)]
const SERVICE_OWNERS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// The SID string of the owner of the pipe `file` is connected to.
#[cfg(windows)]
fn pipe_owner(file: &std::fs::File) -> std::io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle is open for the call (READ_CONTROL is part of PIPE_ACCESS); `owner`
    // points into `sd`, which is read before it is freed, as is the string.
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()?;
        let mut text = windows::core::PWSTR::null();
        let converted = ConvertSidToStringSidW(owner, &mut text).map(|()| {
            let s = text.to_string();
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            s
        });
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        converted?.map_err(std::io::Error::other)
    }
}

/// Whether the owner of a pipe is an account only an administrator or the service can
/// be: a normal user cannot create an object owned by SYSTEM or Administrators.
#[cfg(windows)]
fn is_service_owner(sid: &str) -> bool {
    SERVICE_OWNERS.contains(&sid)
}

/// Refuse a pipe whose server is not the SocketGuard service, so a process that took the
/// pipe name while the daemon is down cannot read our requests. The server's process
/// token cannot be inspected by an unprivileged client (OpenProcess is denied on SYSTEM
/// processes), but the owner of the pipe object, which the server's token chose and a
/// normal user cannot set to SYSTEM or Administrators, can.
#[cfg(windows)]
fn check_server(file: &std::fs::File) -> std::io::Result<()> {
    if std::env::var(TRUST_PIPE_SERVER_ENV).as_deref() == Ok("1") {
        return Ok(());
    }
    let owner = pipe_owner(file)?;
    if is_service_owner(&owner) {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "pipe server is not the SocketGuard service (the pipe is owned by {owner}, not \
             SYSTEM or Administrators)"
        ),
    ))
}

#[cfg(windows)]
fn open_pipe(name: &str) -> std::io::Result<Stream> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::IntoRawHandle;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    let file = std::fs::OpenOptions::new()
        .access_mode(PIPE_ACCESS)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)?;
    check_server(&file)?;
    // SAFETY: the handle was just opened for overlapped I/O and is owned by nobody else.
    unsafe { Stream::from_raw_handle(file.into_raw_handle()) }
}

#[cfg(windows)]
pub async fn connect(name: &str) -> std::io::Result<Stream> {
    let mut attempts = 0;
    loop {
        match open_pipe(name) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 100 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    #[test]
    fn only_system_and_administrators_own_the_service_pipe() {
        assert!(is_service_owner("S-1-5-18"));
        assert!(is_service_owner("S-1-5-32-544"));
        assert!(!is_service_owner("S-1-5-21-1-2-3-1001"));
        assert!(!is_service_owner("S-1-1-0"));
    }

    /// The test's own pipe is owned by the account running it: refused as a squatter
    /// unless that account's default owner is Administrators (run elevated), and let
    /// through with the escape hatch. One test, because it sets a process-wide variable.
    #[tokio::test]
    async fn a_pipe_server_that_is_not_the_service_is_refused() {
        let name = format!(r"\\.\pipe\socketguard-client-test-{}", std::process::id());
        // One idle instance per connection below.
        let mut servers = vec![ServerOptions::new().create(&name).unwrap()];
        for _ in 0..2 {
            servers.push(
                ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&name)
                    .unwrap(),
            );
        }
        std::env::remove_var(TRUST_PIPE_SERVER_ENV);
        let probe = std::fs::OpenOptions::new()
            .access_mode(PIPE_ACCESS)
            .open(&name)
            .unwrap();
        let owner = pipe_owner(&probe).unwrap();
        drop(probe);

        let refused = connect(&name).await;
        if is_service_owner(&owner) {
            assert!(refused.is_ok());
        } else {
            let Err(err) = refused else {
                panic!("a non-service owner is refused");
            };
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(
                err.to_string().contains("not the SocketGuard service"),
                "{err}"
            );
        }
        std::env::set_var(TRUST_PIPE_SERVER_ENV, "1");
        let trusted = connect(&name).await;
        std::env::remove_var(TRUST_PIPE_SERVER_ENV);
        assert!(trusted.is_ok(), "{:?}", trusted.err());
    }
}
