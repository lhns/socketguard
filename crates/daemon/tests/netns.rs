//! Linux network-namespace tests of the real nftables enforcement (ADR 0029, 0035).
//!
//! Each test builds a ruleset with the real producer, renders and applies it with
//! `NftablesFirewall` inside namespace A (the test thread enters it with `setns`), and
//! probes a wildcard TCP listener there from namespace B.
//!
//! Needs root/CAP_NET_ADMIN, `ip` (iproute2), `nft` and `python3`; opt in with
//! `SOCKETGUARD_NETNS_TESTS=1`.
//! Compiles to nothing on other platforms.
#![cfg(target_os = "linux")]

use std::process::{Command, Output};

/// True when netns tests were requested; prints a skip note otherwise.
fn enabled() -> bool {
    let on = std::env::var("SOCKETGUARD_NETNS_TESTS").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipping netns test: set SOCKETGUARD_NETNS_TESTS=1 (needs CAP_NET_ADMIN)");
    }
    on
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("run ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Two namespaces `<prefix>-a` and `<prefix>-b` joined by a veth pair, each with an
/// IPv6 address (`fd00:5a::1/64` and `::2/64`). Removed on drop.
struct NsPair {
    pub a: String,
    pub b: String,
}

impl NsPair {
    fn new(prefix: &str) -> Self {
        let (a, b) = (format!("{prefix}-a"), format!("{prefix}-b"));
        let pair = Self {
            a: a.clone(),
            b: b.clone(),
        }; // drop cleans up on partial failure
        ip(&["netns", "add", &a]);
        ip(&["netns", "add", &b]);
        // Short interface names: the kernel limit is 15 chars.
        ip(&[
            "link", "add", "sgv-a", "netns", &a, "type", "veth", "peer", "name", "sgv-b", "netns",
            &b,
        ]);
        for (ns, ifc, addr) in [
            (&a, "sgv-a", "fd00:5a::1/64"),
            (&b, "sgv-b", "fd00:5a::2/64"),
        ] {
            ip(&["-n", ns, "addr", "add", addr, "dev", ifc, "nodad"]);
            ip(&["-n", ns, "link", "set", ifc, "up"]);
            ip(&["-n", ns, "link", "set", "lo", "up"]);
        }
        pair
    }

    /// Run `cmd` inside namespace `ns`.
    fn exec(&self, ns: &str, cmd: &[&str]) -> Output {
        Command::new("ip")
            .args(["netns", "exec", ns])
            .args(cmd)
            .output()
            .expect("run ip netns exec")
    }
}

impl Drop for NsPair {
    fn drop(&mut self) {
        // Deleting the namespaces also removes the veth pair.
        for ns in [&self.a, &self.b] {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
    }
}

// ─── Enforcement tests ───────────────────────────────────────────────────────

use chrono::Utc;
use socketguard_core::{
    Address, App, AppPort, Credential, CredentialKind, Grant, Locator, Network, NetworkKind,
    NetworkStatus, Peer, PortSet, Protocol, Subject,
};
use socketguard_daemon::firewall::nftables::NftablesFirewall;
use socketguard_daemon::firewall::{DesiredRuleset, DropEvent, Firewall};
use socketguard_daemon::ruleset::{self, Snapshot};
use std::os::fd::AsRawFd;
use std::process::{Child, Stdio};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::Duration;

const PORT: u16 = 8080;
/// A's managed address on the ordinary veth, and on the overlay-named one.
const MANAGED: &str = "fd00:5a::100";
const MANAGED_YGG: &str = "300:5a::100";
/// A source in 200::/7 that B owns on both of its veths.
const YGG_SRC: &str = "200:5a::77";

const LISTENER: &str = "
import socket
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 8080))
s.listen(16)
while True:
    c, _ = s.accept()
    c.sendall(b'ok')
    c.close()
";

const PROBE: &str = "
import socket, sys
dst, src = sys.argv[1], sys.argv[2]
try:
    s = socket.create_connection((dst, 8080), timeout=1.5, source_address=(src, 0) if src else None)
    sys.exit(0 if s.recv(2) == b'ok' else 1)
except Exception:
    sys.exit(1)
";

/// The tests share nft state names, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn enter_netns(name: &str) {
    let f = std::fs::File::open(format!("/var/run/netns/{name}")).expect("open netns");
    // SAFETY: setns on a valid netns fd; affects only the calling test thread.
    let rc = unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns: {}", std::io::Error::last_os_error());
}

struct Fixture {
    ns: NsPair,
    listener: Child,
    fw: NftablesFirewall,
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    /// Namespaces A and B with an ordinary veth (`sgv-a`/`sgv-b`) and an overlay-named one
    /// (`ygg0` on both sides), a managed address on each of A's, and a wildcard listener
    /// on A. The calling thread ends up inside A.
    fn new(test: &str) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let ns = NsPair::new(&format!("sgn{}{}", std::process::id() % 10000, test));
        let (a, b) = (ns.a.clone(), ns.b.clone());
        ip(&[
            "link", "add", "ygg0", "netns", &a, "type", "veth", "peer", "name", "ygg0", "netns", &b,
        ]);
        for (n, addrs) in [
            (&a, ["200:5a::1/64", "300:5a::100/128"]),
            (&b, ["200:5a::2/64", "200:5a::77/128"]),
        ] {
            for addr in addrs {
                ip(&["-n", n, "addr", "add", addr, "dev", "ygg0", "nodad"]);
            }
            ip(&["-n", n, "link", "set", "ygg0", "up"]);
        }
        let managed = format!("{MANAGED}/128");
        ip(&["-n", &a, "addr", "add", &managed, "dev", "sgv-a", "nodad"]);
        let forged = format!("{YGG_SRC}/128");
        ip(&["-n", &b, "addr", "add", &forged, "dev", "sgv-b", "nodad"]);
        let route = format!("{MANAGED_YGG}/128");
        ip(&["-n", &b, "-6", "route", "add", &route, "dev", "ygg0"]);

        let listener = Command::new("ip")
            .args(["netns", "exec", &a, "python3", "-c", LISTENER])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start listener");
        enter_netns(&a);
        let fx = Self {
            ns,
            listener,
            fw: NftablesFirewall::new(),
            _serial: serial,
        };
        // Link-local addresses are tentative for a moment after link-up.
        for _ in 0..40 {
            if fx.link_local("sgv-a").is_some() && fx.link_local("ygg0").is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        fx
    }

    /// A's non-tentative link-local address on `iface`.
    fn link_local(&self, iface: &str) -> Option<String> {
        let out = self.ns.exec(
            &self.ns.a,
            &[
                "ip", "-6", "-j", "addr", "show", "dev", iface, "scope", "link",
            ],
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        v[0]["addr_info"].as_array()?.iter().find_map(|a| {
            if a["tentative"].as_bool() == Some(true) {
                return None;
            }
            a["local"].as_str().map(String::from)
        })
    }

    /// Whether B can open a TCP connection to A's listener at `dst` (optionally from `src`).
    fn reachable(&self, dst: &str, src: Option<&str>) -> bool {
        self.ns
            .exec(
                &self.ns.b,
                &["python3", "-c", PROBE, dst, src.unwrap_or("")],
            )
            .status
            .success()
    }

    /// The ways to reach the listener from B: (label, address).
    fn targets(&self) -> Vec<(&'static str, String)> {
        let ll = |iface: &str, peer: &str| format!("{}%{peer}", self.link_local(iface).unwrap());
        vec![
            ("managed address", MANAGED.to_string()),
            ("A's own address on the veth", "fd00:5a::1".to_string()),
            ("link-local on the veth", ll("sgv-a", "sgv-b")),
            ("node address on ygg0", "200:5a::1".to_string()),
            ("link-local on ygg0", ll("ygg0", "ygg0")),
        ]
    }

    fn apply(&self, snap: &Snapshot) -> DesiredRuleset {
        let rs = ruleset::build(snap);
        self.fw.apply(&rs).expect("apply ruleset");
        rs
    }

    fn table_exists(&self) -> bool {
        Command::new("nft")
            .args(["list", "table", "inet", "socketguard"])
            .output()
            .unwrap()
            .status
            .success()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.listener.kill();
        let _ = self.listener.wait();
    }
}

/// One app on port 8080 with an address on each veth (a LAN network on `sgv-a`, a
/// Yggdrasil network on `ygg0`), whole-host protection of `sgv-a`, and, when `creds` is
/// not empty, a peer holding those credentials with a grant to the app.
fn snapshot(creds: &[(CredentialKind, &str)]) -> Snapshot {
    let now = Utc::now();
    let address = |id: &str, network: &str, a: &str| Address {
        id: id.into(),
        app_id: "web".into(),
        network_id: network.into(),
        ports: PortSet::All,
        locator: Locator::Ipv6 {
            addr: a.parse().unwrap(),
        },
        created_at: now,
    };
    let network = |id: &str, kind, iface: &str| Network {
        id: id.into(),
        kind,
        name: id.into(),
        interface: Some(iface.into()),
        grants_apply: true,
        status: NetworkStatus::Up,
        prefix: None,
    };
    let (peers, grants) = if creds.is_empty() {
        (vec![], vec![])
    } else {
        (
            vec![Peer {
                id: "b".into(),
                label: "b".into(),
                credentials: creds
                    .iter()
                    .enumerate()
                    .map(|(i, (kind, value))| Credential {
                        id: format!("c{i}"),
                        kind: *kind,
                        value: (*value).into(),
                        label: None,
                    })
                    .collect(),
                groups: vec![],
                created_at: now,
            }],
            vec![Grant {
                id: "g".into(),
                app_id: "web".into(),
                port: None,
                network_id: None,
                subject: Subject::Peer("b".into()),
                created_at: now,
            }],
        )
    };
    Snapshot {
        apps: vec![App {
            id: "web".into(),
            name: "web".into(),
            process_name: "python3".into(),
            exe_path: None,
            interpreter_arg: None,
            reviewed: true,
            first_seen: now,
            last_seen: now,
            ports: vec![AppPort {
                port: PORT,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: now,
            }],
            addresses: vec![
                address("lan-addr", "lan", MANAGED),
                address("ygg-addr", "ygg", MANAGED_YGG),
            ],
        }],
        networks: vec![
            network("lan", NetworkKind::Lan, "sgv-a"),
            network("ygg", NetworkKind::Yggdrasil, "ygg0"),
        ],
        peers,
        grants,
        protect_host: vec!["sgv-a".into()],
        ..Snapshot::default()
    }
}

/// Retries `f` for up to ~4 s; for checks that race interface or listener setup.
fn eventually(f: impl Fn() -> bool) -> bool {
    (0..20).any(|_| {
        f() || {
            std::thread::sleep(Duration::from_millis(200));
            false
        }
    })
}

#[test]
fn wildcard_listener_is_unreachable_inside_every_scope() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("scope");
    // Control: before any rules, every route to the listener works. Retried briefly: the
    // listener and B's link-local addresses may still be coming up.
    for (label, dst) in fx.targets() {
        assert!(
            eventually(|| fx.reachable(&dst, None)),
            "control: {label} ({dst}) should be reachable"
        );
    }

    fx.apply(&snapshot(&[]));
    for (label, dst) in fx.targets() {
        assert!(!fx.reachable(&dst, None), "{label} ({dst}) must be denied");
    }
}

#[test]
fn granted_source_reaches_the_listener_others_do_not() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("grant");
    fx.apply(&snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]));

    assert!(fx.reachable(MANAGED, None), "B (fd00:5a::2) is granted");
    // The grant is for that one address, not for the rest of the protected interface.
    assert!(!fx.reachable("fd00:5a::1", None));
    // Another source, same destination: denied.
    let other = [
        "-n",
        &fx.ns.b,
        "addr",
        "add",
        "fd00:5a::3/128",
        "dev",
        "sgv-b",
        "nodad",
    ];
    ip(&other);
    assert!(!fx.reachable(MANAGED, Some("fd00:5a::3")));
}

#[test]
fn forged_overlay_source_is_dropped_off_the_overlay_interface() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("forge");
    // A 200::/7 value is a Yggdrasil credential: the producer gives it a rule on the
    // overlay address bound to ygg0, and none on the LAN address.
    let rs = fx.apply(&snapshot(&[(CredentialKind::YggAddr, YGG_SRC)]));
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].iif.as_deref(), Some("ygg0"));

    // A 200::/7 source arriving over the ordinary veth is not trusted ...
    assert!(
        !fx.reachable(MANAGED, Some(YGG_SRC)),
        "forged 200:: source on sgv-a"
    );
    // ... the same source over the ygg0 veth is, for the granted address.
    assert!(
        fx.reachable(MANAGED_YGG, Some(YGG_SRC)),
        "granted source on ygg0"
    );
    // And an ungranted source on ygg0 is still denied.
    assert!(
        !fx.reachable(MANAGED_YGG, Some("200:5a::2")),
        "ungranted source on ygg0"
    );
}

#[test]
fn rules_persist_after_apply_and_disable_removes_them() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("persist");
    assert!(!fx.table_exists());
    fx.apply(&snapshot(&[]));
    assert!(fx.table_exists());

    // Nothing undoes the apply when the call is over and time passes.
    std::thread::sleep(Duration::from_secs(1));
    assert!(fx.table_exists());
    assert!(!fx.reachable(MANAGED, None));

    // Applying again replaces the table (no duplicates) and keeps it in force.
    fx.apply(&snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]));
    assert!(fx.reachable(MANAGED, None));

    fx.fw.disable().unwrap();
    assert!(!fx.table_exists());
    assert!(fx.reachable("fd00:5a::1", None));
    fx.fw.disable().expect("disable is idempotent");
}

#[test]
fn blocked_probe_produces_drop_event_and_counter() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("drops");
    let (tx, rx) = mpsc::channel::<DropEvent>();
    let tx = Mutex::new(tx);
    fx.fw
        .subscribe_drops(Box::new(move |ev| {
            let _ = tx.lock().unwrap().send(ev);
        }))
        .expect("subscribe to NFLOG");
    fx.apply(&snapshot(&[]));

    assert!(!fx.reachable(MANAGED, None));
    let managed_ip: std::net::IpAddr = MANAGED.parse().unwrap();
    let ev = (0..10)
        .find_map(|_| {
            rx.recv_timeout(Duration::from_millis(500))
                .ok()
                .filter(|e| e.dst == managed_ip)
        })
        .expect("a drop event for the probe");
    assert_eq!(ev.src, "fd00:5a::2".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(ev.port, Some(PORT));
    assert_eq!(ev.proto, Some(Protocol::Tcp));
    assert_eq!(ev.iif.as_deref(), Some("sgv-a"));
    assert_eq!(ev.scope_id.as_deref(), Some("managed"));

    let counters = fx.fw.counters().unwrap();
    let managed = counters
        .iter()
        .find(|c| c.id == "managed")
        .expect("managed counter");
    assert!(managed.packets > 0);
}
