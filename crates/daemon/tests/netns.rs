//! Linux network-namespace tests of the real nftables enforcement (ADR 0029, 0035).
//!
//! Each test builds a ruleset with the real producer, renders and applies it with
//! `NftablesFirewall` inside namespace A (the test thread enters it with `setns`), and
//! probes a wildcard TCP listener there from namespace B.
//!
//! Needs root/CAP_NET_ADMIN, `ip` (iproute2), `nft` and `python3`; opt in with `SOCKETGUARD_NETNS_TESTS=1`.
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
    NetworkStatus, Peer, Protocol, Scope, Subject, Target,
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

/// Greets with `ok`, then echoes until the client closes (so a client can hold a
/// connection open).
const LISTENER: &str = "
import socket, threading
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 8080))
s.listen(16)
def serve(c):
    try:
        c.sendall(b'ok')
        while True:
            d = c.recv(100)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
    finally:
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
";

/// Connects from `argv[2]` to `argv[1]`, prints `up`, then keeps the connection busy
/// until it breaks (prints `cut`).
const HOLD: &str = "
import socket, sys, time
dst, src = sys.argv[1], sys.argv[2]
s = socket.create_connection((dst, 8080), timeout=1.5, source_address=(src, 0))
assert s.recv(2) == b'ok'
print('up', flush=True)
while True:
    try:
        s.sendall(b'x')
        if s.recv(1) != b'x':
            break
    except Exception:
        break
    time.sleep(0.2)
print('cut', flush=True)
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

/// The automatic address of app "web" (scope All) on `network`.
fn address(id: &str, network: &str, a: &str) -> Address {
    Address {
        id: id.into(),
        ..Address::automatic(
            "web",
            Scope::All,
            network,
            Locator::Ipv6 {
                addr: a.parse().unwrap(),
            },
        )
    }
}

/// One app on port 8080 with an address on each veth (a LAN network on `sgv-a`, a
/// Yggdrasil network on `ygg0`), whole-host protection of `sgv-a`, and, when `creds` is
/// not empty, a peer holding those credentials with a grant to the app.
fn snapshot(creds: &[(CredentialKind, &str)]) -> Snapshot {
    let now = Utc::now();
    let network = |id: &str, kind, iface: &str| Network {
        id: id.into(),
        kind,
        name: id.into(),
        interface: Some(iface.into()),
        grants_apply: true,
        status: NetworkStatus::Up,
        prefix: None,
        vlan_id: None,
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
                target: Target::App("web".into()),
                scope: Scope::All,
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
            identity_note: None,
            exe_missing: false,
            reviewed: true,
            system: false,
            first_seen: now,
            last_seen: now,
            ports: vec![AppPort {
                port: PORT,
                proto: Protocol::Tcp,
                listening: true,
                last_seen: now,
                family: Default::default(),
            }],
            // Display only; the addresses are in `Snapshot::addresses`.
            addresses: vec![],
        }],
        addresses: vec![
            address("lan-addr", "lan", MANAGED),
            address("ygg-addr", "ygg", MANAGED_YGG),
        ],
        // The fixture puts both addresses on the veths. An address is up only while a grant
        // names its row (ADR 0047), so without one it is dormant but still on the interface:
        // `owned` keeps it denied, as the daemon does for addresses it has not yet removed.
        owned: vec![MANAGED.parse().unwrap(), MANAGED_YGG.parse().unwrap()],
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
fn eventually(mut f: impl FnMut() -> bool) -> bool {
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

/// ADR 0043: a tag with a match pattern and a grant on the tag. The listener starts after
/// the grant exists; discovery (the real `auto_tag_app`) puts it in the tag, the producer
/// expands the tag grant, and nftables lets the granted peer in and nobody else.
#[test]
fn a_tag_grant_covers_a_new_matching_listener_for_the_granted_peer_only() {
    use socketguard_daemon::state::{Database, Write};

    if !enabled() {
        return;
    }
    let fx = Fixture::new("tag");
    let mut snap = snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]);
    // The grant is on a tag, not on the app; the tag matches by process name.
    let now = Utc::now();
    snap.grants[0].target = Target::Tag("dev".into());
    let tag = socketguard_core::Tag {
        id: "dev".into(),
        label: "dev".into(),
        patterns: vec!["pytho*".into()],
        members: vec![],
        excluded: vec![],
        created_at: now,
    };
    snap.tags = vec![tag.clone()];
    fx.apply(&snap);
    assert!(
        !fx.reachable(MANAGED, None),
        "the app is not in the tag yet: nothing is granted"
    );

    // The app is discovered: the tag takes it in.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tags = rt.block_on(async {
        let db = Database::new(":memory:").await.unwrap();
        db.migrate().await.unwrap();
        db.insert_app(&snap.apps[0]).await.unwrap();
        db.apply_writes(&[Write::InsertTag(tag)]).await.unwrap();
        assert_eq!(db.auto_tag_app(&snap.apps[0]).await.unwrap(), ["dev"]);
        db.list_tags().await.unwrap()
    });
    snap.tags = tags;
    fx.apply(&snap);
    assert!(fx.reachable(MANAGED, None), "B is granted through the tag");
    assert!(
        !fx.reachable("fd00:5a::1", None),
        "not the rest of the interface"
    );
    ip(&[
        "-n",
        &fx.ns.b,
        "addr",
        "add",
        "fd00:5a::3/128",
        "dev",
        "sgv-b",
        "nodad",
    ]);
    assert!(
        !fx.reachable(MANAGED, Some("fd00:5a::3")),
        "another source is still denied"
    );
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

#[test]
fn forged_lan_source_is_refused_on_another_interface() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("forgelan");
    // An IP-only credential: its rule is bound to the LAN network's interface.
    let rs = fx.apply(&snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]));
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].iif.as_deref(), Some("sgv-a"));
    assert!(
        fx.reachable(MANAGED, Some("fd00:5a::2")),
        "the granted source on its own interface"
    );

    // B now sends the same source over the other veth (ygg0), as a forger would.
    ip(&[
        "-n",
        &fx.ns.b,
        "-6",
        "route",
        "replace",
        &format!("{MANAGED}/128"),
        "dev",
        "ygg0",
    ]);
    assert!(
        !fx.reachable(MANAGED, Some("fd00:5a::2")),
        "the granted LAN source arriving on ygg0 must be refused"
    );
}

/// Starts the HOLD client in B (source `fd00:5a::2`) and waits until it is connected.
fn hold_connection(fx: &Fixture) -> Child {
    let mut client = Command::new("ip")
        .args([
            "netns",
            "exec",
            &fx.ns.b,
            "python3",
            "-c",
            HOLD,
            MANAGED,
            "fd00:5a::2",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start client");
    let mut lines = std::io::BufReader::new(client.stdout.take().unwrap());
    let mut first = String::new();
    std::io::BufRead::read_line(&mut lines, &mut first).unwrap();
    assert_eq!(first.trim(), "up");
    client
}

#[test]
fn revoked_grant_cuts_an_established_connection_without_conntrack() {
    if !enabled() {
        return;
    }
    // Revocation is the rules' job: original-direction packets of an established flow are
    // matched on every packet, so the `conntrack` tool is never involved. This test never
    // calls `Firewall::revoke`, and the tool is hidden from PATH for good measure.
    let fx = Fixture::new("revoke"); // holds the serial lock, so PATH can change safely
    let tools = std::env::temp_dir().join(format!("sg-no-conntrack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tools);
    std::fs::create_dir_all(&tools).unwrap();
    for tool in ["nft", "ip", "python3"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .unwrap();
        let found = String::from_utf8_lossy(&found.stdout).trim().to_string();
        std::os::unix::fs::symlink(&found, tools.join(tool)).unwrap();
    }
    struct PathGuard(std::ffi::OsString, std::path::PathBuf);
    impl Drop for PathGuard {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.0);
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _path = PathGuard(std::env::var_os("PATH").unwrap_or_default(), tools.clone());
    std::env::set_var("PATH", &tools);
    assert!(
        Command::new("conntrack").arg("--version").output().is_err(),
        "conntrack must be hidden"
    );

    fx.apply(&snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]));
    assert!(eventually(|| fx.reachable(MANAGED, None)));
    let mut client = hold_connection(&fx);
    std::thread::sleep(Duration::from_secs(1));
    assert!(client.try_wait().unwrap().is_none(), "the flow is alive");

    // Revoke: the new ruleset has no grant. The next packet of the flow is dropped.
    fx.apply(&snapshot(&[]));
    let cut = eventually(|| client.try_wait().unwrap().is_some());
    let _ = client.kill();
    assert!(cut, "the revoked connection must be cut");
}

#[test]
fn established_flow_is_bound_to_its_interface() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("estif");
    fx.apply(&snapshot(&[(CredentialKind::Ip, "fd00:5a::2/128")]));
    assert!(eventually(|| fx.reachable(MANAGED, None)));
    let mut client = hold_connection(&fx);
    std::thread::sleep(Duration::from_secs(1));
    assert!(client.try_wait().unwrap().is_none(), "the flow is alive");

    // B now sends the packets of the same established flow (same addresses and ports) over
    // the other veth, as a forger would. They are original-direction packets arriving on
    // ygg0, which the grant (bound to sgv-a) does not cover, so they are dropped.
    ip(&[
        "-n",
        &fx.ns.b,
        "-6",
        "route",
        "replace",
        &format!("{MANAGED}/128"),
        "dev",
        "ygg0",
    ]);
    let cut = eventually(|| client.try_wait().unwrap().is_some());
    let _ = client.kill();
    assert!(
        cut,
        "an established flow's packets arriving on another interface must be dropped"
    );
}

#[test]
fn overlapping_sources_are_aggregated_and_apply() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("overlap");
    // Premise, for the record: what this nft version does with a raw overlap.
    let raw = "table inet sgcheck {\n chain input {\n type filter hook input priority 0; policy accept;\n ip6 saddr { fd00:5a::/64, fd00:5a::2/128 } accept\n }\n}\n";
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), raw.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    eprintln!(
        "raw overlapping set: success={} {}",
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "sgcheck"])
        .output();

    let rs = fx.apply(&snapshot(&[
        (CredentialKind::Ip, "fd00:5a::/64"),
        (CredentialKind::Ip, "fd00:5a::2/128"),
    ]));
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(
        rs.rules[0].sources,
        socketguard_daemon::firewall::Sources::Nets(vec!["fd00:5a::/64".parse().unwrap()])
    );
    assert!(
        fx.reachable(MANAGED, None),
        "B is inside the aggregated /64"
    );
}

// ─── IPv4 and segments (ADR 0044) ────────────────────────────────────────────

use socketguard_daemon::firewall::Dst;
use std::collections::BTreeMap;

#[test]
fn ipv4_peer_is_allowed_through_protect_host_and_unknown_ipv4_is_dropped() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("v4");
    for (ns, addr) in [
        (&fx.ns.a, "10.77.0.1/24"),
        (&fx.ns.b, "10.77.0.2/24"),
        (&fx.ns.b, "10.77.0.3/24"),
    ] {
        let ifc = if *ns == fx.ns.a { "sgv-a" } else { "sgv-b" };
        ip(&["-n", ns, "addr", "add", addr, "dev", ifc]);
    }
    assert!(
        eventually(|| fx.reachable("10.77.0.1", Some("10.77.0.3"))),
        "control: IPv4 reaches the listener before any rules"
    );

    let mut snap = snapshot(&[(CredentialKind::Ip, "10.77.0.2/32")]);
    snap.v4_subnets = BTreeMap::from([("sgv-a".into(), vec!["10.77.0.0/24".parse().unwrap()])]);
    let rs = fx.apply(&snap);
    assert!(rs.rules.iter().any(|r| r.dst == Dst::HostV4));

    assert!(
        fx.reachable("10.77.0.1", Some("10.77.0.2")),
        "the IPv4 peer is allowed"
    );
    assert!(
        !fx.reachable("10.77.0.1", Some("10.77.0.3")),
        "an unknown IPv4 source is dropped by the protect-host scope"
    );

    // Revoking the peer closes IPv4 again.
    let mut snap = snapshot(&[]);
    snap.v4_subnets = BTreeMap::from([("sgv-a".into(), vec!["10.77.0.0/24".parse().unwrap()])]);
    fx.apply(&snap);
    assert!(!fx.reachable("10.77.0.1", Some("10.77.0.2")));
}

#[test]
fn a_segment_grant_admits_its_own_prefix_and_not_the_other_segment() {
    if !enabled() {
        return;
    }
    let fx = Fixture::new("segs");
    // Segment B: a second veth with its own prefix and its own managed address.
    ip(&[
        "link", "add", "sgc-a", "netns", &fx.ns.a, "type", "veth", "peer", "name", "sgc-b",
        "netns", &fx.ns.b,
    ]);
    for (ns, ifc, addrs) in [
        (&fx.ns.a, "sgc-a", ["fd00:5b::1/64", "fd00:5b::100/128"]),
        (&fx.ns.b, "sgc-b", ["fd00:5b::2/64", "fd00:5b::3/128"]),
    ] {
        for addr in addrs {
            ip(&["-n", ns, "addr", "add", addr, "dev", ifc, "nodad"]);
        }
        ip(&["-n", ns, "link", "set", ifc, "up"]);
    }
    const B_ADDR: &str = "fd00:5b::100";
    // B can also source packets from segment B's prefix towards segment A's address.
    for dst in [MANAGED, B_ADDR] {
        assert!(
            eventually(|| fx.reachable(dst, Some("fd00:5b::2"))),
            "control: {dst} reachable before any rules"
        );
    }

    let mut snap = snapshot(&[]);
    let now = Utc::now();
    snap.networks = vec![
        Network {
            prefix: Some("fd00:5a::".parse().unwrap()),
            ..snap.networks[0].clone()
        },
        Network {
            id: "segb".into(),
            name: "segb".into(),
            interface: Some("sgc-a".into()),
            prefix: Some("fd00:5b::".parse().unwrap()),
            ..snap.networks[0].clone()
        },
    ];
    snap.addresses = vec![
        address("a-addr", "lan", MANAGED),
        address("b-addr", "segb", B_ADDR),
    ];
    snap.owned = vec![MANAGED.parse().unwrap(), B_ADDR.parse().unwrap()];
    snap.protect_host = vec!["sgv-a".into(), "sgc-a".into()];
    snap.grants = vec![Grant {
        id: "seg".into(),
        target: Target::App("web".into()),
        scope: Scope::All,
        network_id: Some("lan".into()),
        subject: Subject::Anyone,
        created_at: now,
    }];
    fx.apply(&snap);

    assert!(
        fx.reachable(MANAGED, Some("fd00:5a::2")),
        "a source from segment A's prefix is allowed on A"
    );
    assert!(
        !fx.reachable(B_ADDR, Some("fd00:5b::2")),
        "segment B has no grant"
    );
    assert!(
        !fx.reachable(MANAGED, Some("fd00:5b::2")),
        "a segment B source arriving on A's interface is not on A's link"
    );
}

/// Namespaces A (the host), R (a router) and H (a host behind it): A and R share segment A
/// (`fd00:5a::/64`), R and H share segment B (`fd00:5b::/64`). Removed on drop.
struct Routed {
    ns: [String; 3],
    listener: Option<Child>,
    _serial: MutexGuard<'static, ()>,
}

impl Routed {
    fn new(test: &str) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let p = format!("sgr{}{}", std::process::id() % 10000, test);
        let ns = [format!("{p}-a"), format!("{p}-r"), format!("{p}-h")];
        // Dropped (and the namespaces removed) even if the setup fails halfway.
        let mut routed = Self {
            ns: ns.clone(),
            listener: None,
            _serial: serial,
        };
        let [a, r, h] = &ns;
        for n in &ns {
            ip(&["netns", "add", n]);
        }
        ip(&[
            "link", "add", "sgv-a", "netns", a, "type", "veth", "peer", "name", "sgr-a", "netns", r,
        ]);
        ip(&[
            "link", "add", "sgr-h", "netns", r, "type", "veth", "peer", "name", "sgh-h", "netns", h,
        ]);
        for (n, ifc, addr) in [
            (a, "sgv-a", "fd00:5a::1/64"),
            (a, "sgv-a", "fd00:5a::100/128"),
            (r, "sgr-a", "fd00:5a::2/64"),
            (r, "sgr-h", "fd00:5b::2/64"),
            (h, "sgh-h", "fd00:5b::7/64"),
        ] {
            ip(&["-n", n, "addr", "add", addr, "dev", ifc, "nodad"]);
        }
        for (n, ifc) in [
            (a, "sgv-a"),
            (r, "sgr-a"),
            (r, "sgr-h"),
            (h, "sgh-h"),
            (a, "lo"),
            (r, "lo"),
            (h, "lo"),
        ] {
            ip(&["-n", n, "link", "set", ifc, "up"]);
        }
        let sysctl = Command::new("ip")
            .args([
                "netns",
                "exec",
                r,
                "sysctl",
                "-q",
                "-w",
                "net.ipv6.conf.all.forwarding=1",
            ])
            .output()
            .unwrap();
        assert!(
            sysctl.status.success(),
            "forwarding: {}",
            String::from_utf8_lossy(&sysctl.stderr)
        );
        ip(&[
            "-n",
            h,
            "-6",
            "route",
            "add",
            "default",
            "via",
            "fd00:5b::2",
        ]);
        ip(&[
            "-n",
            a,
            "-6",
            "route",
            "add",
            "fd00:5b::/64",
            "via",
            "fd00:5a::2",
        ]);
        let listener = Command::new("ip")
            .args(["netns", "exec", a, "python3", "-c", LISTENER])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start listener");
        routed.listener = Some(listener);
        enter_netns(a);
        routed
    }

    /// Whether `ns` can open a TCP connection to A's listener at `dst` from `src`.
    fn reachable_from(&self, ns: &str, dst: &str, src: &str) -> bool {
        Command::new("ip")
            .args(["netns", "exec", ns, "python3", "-c", PROBE, dst, src])
            .output()
            .expect("run probe")
            .status
            .success()
    }
}

impl Drop for Routed {
    fn drop(&mut self) {
        if let Some(l) = &mut self.listener {
            let _ = l.kill();
            let _ = l.wait();
        }
        for ns in &self.ns {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
    }
}

#[test]
fn a_router_cannot_deliver_another_segments_source_to_a_segment_grant() {
    if !enabled() {
        return;
    }
    let rt = Routed::new("route");
    let [_, r, h] = &rt.ns;
    // Control: H (behind the router, source in segment B's prefix) reaches A's listener.
    assert!(
        eventually(|| rt.reachable_from(h, MANAGED, "fd00:5b::7")),
        "control: the routed path works before any rules"
    );

    let mut snap = snapshot(&[]);
    let now = Utc::now();
    snap.networks = vec![Network {
        prefix: Some("fd00:5a::".parse().unwrap()),
        ..snap.networks[0].clone()
    }];
    snap.addresses.truncate(1);
    snap.owned.truncate(1);
    snap.grants = vec![Grant {
        id: "seg".into(),
        target: Target::App("web".into()),
        scope: Scope::All,
        network_id: Some("lan".into()),
        subject: Subject::Anyone,
        created_at: now,
    }];
    let fw = NftablesFirewall::new();
    fw.apply(&ruleset::build(&snap)).expect("apply ruleset");

    assert!(
        rt.reachable_from(r, MANAGED, "fd00:5a::2"),
        "a source on A's own link is allowed"
    );
    assert!(
        !rt.reachable_from(h, MANAGED, "fd00:5b::7"),
        "the router delivers segment B's source on A's interface: dropped"
    );
}
