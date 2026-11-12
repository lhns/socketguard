//! Sockets without an identifiable process become apps (ADR 0046), and OS components
//! carry the `system` flag.

mod common;

use common::*;
use socketguard_core::{ListeningSocket, Protocol};

fn unidentified(port: u16) -> ListeningSocket {
    let mut s = ListeningSocket::new(0, port, Protocol::Tcp, "::".parse().unwrap())
        .with_process_name("unknown");
    s.unidentified = true;
    s
}

/// A listener that counts as an OS component on the platform the test runs on.
fn system_listener() -> ListeningSocket {
    let mut s = listener("svchost.exe", 135);
    if cfg!(windows) {
        s.exe_path = Some("C:\\Windows\\System32\\svchost.exe".into());
        s.cmdline = Some(vec!["svchost.exe".into(), "-k".into(), "rpcss".into()]);
    } else if cfg!(target_os = "macos") {
        s.exe_path = Some("/usr/libexec/rapportd".into());
    } else {
        s.exe_path = Some("/usr/sbin/sshd".into());
        s.uid = Some("0".into());
        s.in_service_unit = true;
    }
    s
}

#[tokio::test]
async fn an_unidentified_listener_is_an_app_of_its_own_and_system_apps_are_flagged() {
    let d = Daemon::new().await;
    d.sockets
        .lock()
        .unwrap()
        .extend([unidentified(9999), unidentified(9998), system_listener()]);
    d.reconcile().await;

    let apps = d.state.db.list_apps().await.unwrap();
    let unknown: Vec<_> = apps
        .iter()
        .filter(|a| a.identity_note.as_deref() == Some("unidentified"))
        .collect();
    assert_eq!(unknown.len(), 2, "one app per unidentified port");
    assert_ne!(unknown[0].id, unknown[1].id);
    let a = unknown
        .iter()
        .find(|a| a.name == "unknown:tcp/9999")
        .unwrap();
    assert!(!a.system);
    assert_eq!(a.ports.len(), 1);
    assert_eq!(a.ports[0].port, 9999);
    let own = d
        .state
        .db
        .list_addresses()
        .await
        .unwrap()
        .into_iter()
        .filter(|x| x.app_id.as_deref() == Some(a.id.as_str()))
        .count();
    assert_eq!(
        own, 1,
        "only loopback has an address until a grant names it"
    );

    let nginx = apps.iter().find(|a| a.name == "nginx").unwrap();
    assert!(!nginx.system);
    let sys = apps.iter().find(|a| a.ports[0].port == 135).unwrap();
    assert!(sys.system, "an OS component: {sys:?}");

    // A grant on one unknown socket does not open the other.
    let anyone = serde_json::json!({
        "target": {"kind": "app", "id": a.id}, "subject": {"kind": "anyone"}, "confirm_open": true
    });
    assert_eq!(
        d.post("/api/grants", anyone).await.0,
        axum::http::StatusCode::CREATED
    );
    let other = unknown.iter().find(|x| x.id != a.id).unwrap();
    let (_, detail) = d.get(&format!("/api/apps/{}", other.id)).await;
    assert_eq!(detail["grants"], serde_json::json!([]));

    // The same socket is the same app on the next pass (the id survives restarts).
    d.reconcile().await;
    assert_eq!(d.state.db.list_apps().await.unwrap().len(), apps.len());
}
