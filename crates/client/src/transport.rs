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
