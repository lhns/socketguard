//! The real transport (ADR 0032): a Unix socket or a Windows named pipe, with the shared
//! client on the other end. Refusing a connection from a stranger's uid needs a second
//! user and is covered at the decision level by `transport::tests`.

mod common;

use common::*;
use futures_util::StreamExt;
use socketguard_client::{ApiEvent, Client};
use socketguard_core::api_types::NewPeer;
use socketguard_daemon::{api, transport};
use std::time::Duration;

struct Running {
    client: Client,
    _daemon: Daemon,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Running {
    async fn start(server: transport::Server, endpoint: String) -> Self {
        let daemon = Daemon::new().await;
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let app = api::router(daemon.state.clone());
        let done = tokio::spawn(server.serve(app, async {
            let _ = rx.await;
        }));
        Self {
            client: Client::new(endpoint),
            _daemon: daemon,
            stop: Some(stop),
            done,
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(8), self.done)
            .await
            .expect("server stops")
            .unwrap()
            .unwrap();
    }
}

/// What every transport must do end to end. Shutdown must not wait for the open event
/// stream forever (see `stop`).
async fn exercise(r: &Running) -> socketguard_client::EventStream {
    let c = &r.client;
    let status = c.status().await.unwrap();
    assert_eq!(status.networks.len(), 3);
    assert_eq!(status.counts.apps, 1);

    // Typed errors carry the code and message.
    let err = c.get_peer("nope").await.unwrap_err();
    assert_eq!((err.code(), err.status()), (Some("not_found"), Some(404)));
    assert!(err.to_string().contains("nope"));

    // Mutations, and the push event for them.
    let mut events = c.events().await.unwrap();
    let peer = c
        .create_peer(&NewPeer {
            label: Some("alice".into()),
            credentials: vec![],
        })
        .await
        .unwrap();
    assert_eq!(c.list_peers().await.unwrap()[0].id, peer.id);
    let wanted = ApiEvent::PeersChanged;
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.next().await {
                Some(Ok(ev)) if ev == wanted => return ev,
                Some(Ok(_)) => continue,
                other => panic!("event stream ended: {other:?}"),
            }
        }
    })
    .await
    .expect("peers_changed event");
    assert_eq!(got, wanted);

    // Many clients at once (on Windows more than the pipe's idle instances).
    let calls: Vec<_> = (0..16)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.status().await.map(|s| s.counts.peers) })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap(), 1);
    }
    // Returned, so the event stream is still open when the server is stopped.
    events
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    fn temp_socket() -> PathBuf {
        std::env::temp_dir().join(format!("sg-test-{}.sock", uuid::Uuid::new_v4().simple()))
    }

    fn euid() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[tokio::test]
    async fn without_the_group_the_socket_is_owner_only_and_works_for_the_owner() {
        let path = temp_socket();
        let server = transport::bind_unix(&path, "no-such-group-sg-test").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let r = Running::start(server, path.to_str().unwrap().to_string()).await;
        let _open_events = exercise(&r).await;
        r.stop().await;
        assert!(!path.exists(), "the socket file is removed on shutdown");
    }

    #[tokio::test]
    async fn with_the_group_the_socket_is_group_writable() {
        if euid() != 0 {
            eprintln!("skipping: chown to a group needs root");
            return;
        }
        let path = temp_socket();
        // The group of gid 0 exists everywhere and stands in for `socketguard`.
        let gid0 = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        let server = transport::bind_unix(&path, gid0).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        assert_eq!(meta.gid(), 0);
        let r = Running::start(server, path.to_str().unwrap().to_string()).await;
        let _open_events = exercise(&r).await;
        r.stop().await;
    }

    /// Binding must not touch the process umask: it once did, and concurrent binds left
    /// it at 0o177, so other threads' directories lost their search bit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_binds_leave_no_stray_files_and_the_umask_alone() {
        let dir = std::env::temp_dir().join(format!("sg-binds-{}", uuid::Uuid::new_v4().simple()));
        let tasks: Vec<_> = (0..16)
            .map(|i| {
                let path = dir.join(format!("s{i}.sock"));
                tokio::task::spawn_blocking(move || {
                    transport::bind_unix(&path, "no-such-group-sg-test").unwrap()
                })
            })
            .collect();
        let mut servers = Vec::new();
        for t in tasks {
            servers.push(t.await.unwrap());
        }
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut expected: Vec<_> = (0..16).map(|i| format!("s{i}.sock")).collect();
        expected.sort();
        assert_eq!(names, expected, "only the sockets remain");
        let probe = dir.join("probe");
        std::fs::create_dir(&probe).unwrap();
        let mode = std::fs::metadata(&probe).unwrap().permissions().mode();
        assert!(mode & 0o100 != 0, "umask was left restrictive: {mode:o}");
        drop(servers);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced_and_a_live_one_is_not() {
        let path = temp_socket();
        // A leftover file from a crashed run.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let server = transport::bind_unix(&path, "no-such-group-sg-test").unwrap();
        let err = transport::bind_unix(&path, "no-such-group-sg-test")
            .err()
            .expect("second bind fails")
            .to_string();
        assert!(err.contains("another daemon"), "{err}");
        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn the_client_reports_a_missing_daemon() {
        let c = Client::new("/nonexistent/sg.sock");
        let err = c.status().await.unwrap_err();
        assert!(
            matches!(err, socketguard_client::Error::Connect { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("/nonexistent/sg.sock"));
    }

    #[test]
    fn endpoint_comes_from_the_environment() {
        std::env::set_var("SOCKETGUARD_SOCKET", "/tmp/custom.sock");
        assert_eq!(Client::from_env().endpoint(), "/tmp/custom.sock");
        std::env::remove_var("SOCKETGUARD_SOCKET");
        assert_eq!(
            Client::from_env().endpoint(),
            socketguard_core::config::DEFAULT_API_SOCKET
        );
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    fn pipe_name() -> String {
        // The test daemon is not SYSTEM, which the client would otherwise insist on.
        std::env::set_var("SOCKETGUARD_TRUST_PIPE_SERVER", "1");
        format!(
            r"\\.\pipe\socketguard-test-{}",
            uuid::Uuid::new_v4().simple()
        )
    }

    #[tokio::test]
    async fn named_pipe_end_to_end() {
        let name = pipe_name();
        // Everyone: the test user is an unelevated administrator, which the production ACL
        // (SYSTEM, Administrators, SocketGuard Users) does not admit.
        let server = transport::bind_pipe(&name, "D:(A;;GA;;;WD)").unwrap();
        let r = Running::start(server, name).await;
        let _open_events = exercise(&r).await;
        r.stop().await;
    }

    /// The SID of the user running the test.
    fn my_sid() -> String {
        let out = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.trim().rsplit('"').nth(1).unwrap().to_string()
    }

    /// The production ACL shape with a group (BUILTIN Users stands in for `SocketGuard
    /// Users`), with the server account added: in production the daemon is SYSTEM, which
    /// may create the next pipe instance, but here the server is the test user, who
    /// would otherwise only be a group member and could not (see the next test).
    #[tokio::test]
    async fn the_client_works_against_the_production_acl_shape() {
        let name = pipe_name();
        let sddl = format!(
            "{}(A;;GA;;;{})",
            transport::pipe_sddl(Some("S-1-5-32-545")),
            my_sid()
        );
        let server = transport::bind_pipe(&name, &sddl).unwrap();
        let r = Running::start(server, name).await;
        assert_eq!(r.client.status().await.unwrap().counts.apps, 1);
        r.stop().await;
    }

    /// A second server on a name that is taken fails (FILE_FLAG_FIRST_PIPE_INSTANCE), so a
    /// squatter cannot be stood in for the daemon, nor the daemon for a squatter.
    #[tokio::test]
    async fn a_second_server_cannot_take_the_pipe_name() {
        let name = pipe_name();
        let _first = transport::bind_pipe(&name, "D:(A;;GA;;;WD)").unwrap();
        assert!(transport::bind_pipe(&name, "D:(A;;GA;;;WD)").is_err());
    }

    /// With only the group entry in the ACL, even a member cannot add a server instance
    /// to the daemon's pipe.
    #[tokio::test]
    async fn a_group_member_cannot_create_a_pipe_instance() {
        use socketguard_daemon::host::{Host, SystemHost};
        use tokio::net::windows::named_pipe::ServerOptions;
        // An elevated process (a CI runner is an administrator) holds the rights over a
        // pipe it created itself: the check is meant for a member of the group.
        if SystemHost.is_elevated() {
            eprintln!("skipping: this process is elevated");
            return;
        }
        let name = pipe_name();
        let sddl = transport::pipe_sddl(Some("S-1-5-32-545"));
        let _server = transport::bind_pipe(&name, &sddl).unwrap();
        let rogue = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&name);
        let err = rogue.expect_err("a rogue instance must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    #[tokio::test]
    async fn the_client_reports_a_missing_daemon() {
        let c = Client::new(r"\\.\pipe\socketguard-test-nobody-home");
        let err = c.status().await.unwrap_err();
        assert!(
            matches!(err, socketguard_client::Error::Connect { .. }),
            "{err}"
        );
    }

    #[test]
    fn endpoint_comes_from_the_environment() {
        std::env::set_var("SOCKETGUARD_SOCKET", r"\\.\pipe\custom");
        assert_eq!(Client::from_env().endpoint(), r"\\.\pipe\custom");
        std::env::remove_var("SOCKETGUARD_SOCKET");
        assert_eq!(Client::from_env().endpoint(), r"\\.\pipe\socketguard");
    }
}
