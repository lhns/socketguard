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

#[cfg(windows)]
pub async fn connect(name: &str) -> std::io::Result<Stream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut attempts = 0;
    loop {
        match ClientOptions::new().open(name) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 100 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
