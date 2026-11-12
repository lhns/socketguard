//! Telling the service manager how far start-up is (the sd_notify protocol: one datagram of
//! `KEY=value` lines to the socket in `$NOTIFY_SOCKET`). The systemd unit is `Type=notify`
//! (ADR 0051): the daemon says `READY=1` after its first ruleset apply attempt, so units
//! ordered after it, the network among them, start only once the rules are in force.
//! Without `$NOTIFY_SOCKET` (not under systemd, launchd, Windows) everything here does nothing.

/// Send `message` to `$NOTIFY_SOCKET`, if set. Failures are only logged: a daemon that cannot
/// report must still run.
pub fn notify(message: &str) {
    #[cfg(unix)]
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET") {
        if let Err(e) = send(&socket.to_string_lossy(), message) {
            tracing::warn!("Could not notify the service manager: {e}");
        }
    }
    #[cfg(not(unix))]
    let _ = message;
}

/// `READY=1` with a status line for `systemctl status`.
pub fn ready(status: &str) {
    notify(&format!("READY=1\nSTATUS={}", status.replace('\n', " ")));
}

/// `STOPPING=1`, at the start of a shutdown.
pub fn stopping() {
    notify("STOPPING=1\nSTATUS=Stopping (the rules stay in force)");
}

/// One datagram to `socket`: a path, or `@name` for an abstract socket (Linux).
#[cfg(unix)]
fn send(socket: &str, message: &str) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    let sock = UnixDatagram::unbound()?;
    if let Some(name) = socket.strip_prefix('@') {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(message.as_bytes(), &addr)?;
            return Ok(());
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = name;
            return Err(std::io::Error::other("abstract sockets need Linux"));
        }
    }
    sock.send_to(message.as_bytes(), socket)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn a_datagram_reaches_a_path_socket() {
        let dir = std::env::temp_dir().join(format!("sg-notify-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let rx = UnixDatagram::bind(&path).unwrap();
        send(path.to_str().unwrap(), "READY=1\nSTATUS=up").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=up");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_datagram_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("sg-notify-{}", uuid::Uuid::new_v4());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();
        send(&format!("@{name}"), "READY=1").unwrap();
        let mut buf = [0u8; 16];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn a_missing_socket_is_an_error_that_notify_swallows() {
        assert!(send("/nonexistent/sg-notify", "READY=1").is_err());
        notify("READY=1");
    }
}
