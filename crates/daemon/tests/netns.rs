//! Linux network-namespace test helper and placeholder test.
//!
//! Needs root/CAP_NET_ADMIN and `ip` (iproute2); opt in with `SOCKETGUARD_NETNS_TESTS=1`.
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

#[test]
fn veth_pair_can_ping() {
    if !enabled() {
        return;
    }
    let ns = NsPair::new(&format!("sgt{}", std::process::id()));
    let out = ns.exec(&ns.a, &["ping", "-6", "-c", "1", "-W", "2", "fd00:5a::2"]);
    assert!(
        out.status.success(),
        "ping failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
