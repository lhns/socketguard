//! The client only talks to the SocketGuard service on a Windows named pipe (ADR 0032): a
//! process that took the pipe name while the daemon was down is refused before any
//! request is sent. Its own binary, because it sets a process-wide variable.
#![cfg(windows)]

mod common;

use common::*;
use socketguard_client::Client;
use socketguard_daemon::{api, transport};

/// The SID of the user running the test.
fn my_sid() -> String {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.trim().rsplit('"').nth(1).unwrap().to_string()
}

async fn serve(name: &str, sddl: &str) -> Option<(Daemon, tokio::task::JoinHandle<()>)> {
    let server = transport::bind_pipe(name, sddl).ok()?;
    let daemon = Daemon::new().await;
    let app = api::router(daemon.state.clone());
    let task = tokio::spawn(async move {
        let _ = server.serve(app, std::future::pending()).await;
    });
    Some((daemon, task))
}

#[tokio::test]
async fn a_server_owned_by_a_normal_account_is_refused_unless_trusted() {
    let name = format!(
        r"\\.\pipe\socketguard-auth-{}",
        uuid::Uuid::new_v4().simple()
    );
    std::env::remove_var("SOCKETGUARD_TRUST_PIPE_SERVER");

    // A squatter: a pipe owned by the account running the test, open to everyone.
    let sddl = format!("O:{}D:(A;;GA;;;WD)", my_sid());
    let (_daemon, task) = serve(&name, &sddl).await.expect("own-owner pipe");
    let err = Client::new(name.clone()).status().await.unwrap_err();
    assert!(
        err.to_string().contains("not the SocketGuard service"),
        "{err}"
    );

    // The escape hatch for tests and development.
    std::env::set_var("SOCKETGUARD_TRUST_PIPE_SERVER", "1");
    let status = Client::new(name.clone()).status().await;
    std::env::remove_var("SOCKETGUARD_TRUST_PIPE_SERVER");
    assert!(status.is_ok(), "{:?}", status.err());
    task.abort();

    administrators_owned_server_is_accepted().await;
}

/// Part of the test above (the variable is process-wide, so they must not overlap).
async fn administrators_owned_server_is_accepted() {
    let name = format!(
        r"\\.\pipe\socketguard-auth-{}",
        uuid::Uuid::new_v4().simple()
    );
    std::env::remove_var("SOCKETGUARD_TRUST_PIPE_SERVER");
    // Only a process with the right to own objects as Administrators can create this (the
    // service, or an elevated shell); without it the test has nothing to check.
    let Some((_daemon, task)) = serve(&name, "O:BAD:(A;;GA;;;WD)").await else {
        eprintln!("skipped: this account cannot create an Administrators-owned pipe");
        return;
    };
    let status = Client::new(name).status().await;
    assert!(status.is_ok(), "{:?}", status.err());
    task.abort();
}
