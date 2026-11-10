use super::SocketMonitor;
use anyhow::Result;
use socketguard_core::{normalize_exe_path, ListeningSocket, Platform, Protocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::debug;

pub struct LinuxSocketMonitor;

/// A listening socket from /proc/net before its owner is known.
struct RawSocket {
    inode: u64,
    port: u16,
    protocol: Protocol,
    bind_address: IpAddr,
}

/// Set once the first unattributable socket was logged.
static LOGGED_UNATTRIBUTABLE: AtomicBool = AtomicBool::new(false);

impl SocketMonitor for LinuxSocketMonitor {
    fn list_listening_sockets(&self) -> Result<Vec<ListeningSocket>> {
        let mut raw = Vec::new();
        for (file, protocol) in [
            ("/proc/net/tcp6", Protocol::Tcp),
            ("/proc/net/tcp", Protocol::Tcp),
            ("/proc/net/udp6", Protocol::Udp),
            ("/proc/net/udp", Protocol::Udp),
        ] {
            if let Ok(content) = std::fs::read_to_string(file) {
                raw.extend(
                    content
                        .lines()
                        .skip(1)
                        .filter_map(|l| parse_proc_net_line(l, protocol)),
                );
            }
        }

        let wanted: HashSet<u64> = raw.iter().map(|r| r.inode).collect();
        let holders = socket_holders(&wanted);
        let mut procs: HashMap<u32, Proc> = HashMap::new();
        let mut sockets = Vec::new();
        for r in raw {
            let pids = holders.get(&r.inode).map(Vec::as_slice).unwrap_or_default();
            for pid in pids {
                procs.entry(*pid).or_insert_with(|| read_proc(*pid));
            }
            let candidates: Vec<&Proc> = pids
                .iter()
                .map(|pid| &procs[pid])
                .filter(|p| p.valid)
                .collect();
            let Some(p) = pick_owner(&candidates) else {
                // Not attributable to one program: it gets no app and no addresses.
                if !LOGGED_UNATTRIBUTABLE.swap(true, Ordering::Relaxed) {
                    debug!(
                        "Skipping socket on port {} {}: {} (further ones are not logged)",
                        r.port,
                        r.protocol,
                        if candidates.is_empty() {
                            "no process holds it"
                        } else {
                            "processes of different programs or users hold it"
                        }
                    );
                }
                continue;
            };
            sockets.push(ListeningSocket {
                pid: p.pid,
                process_name: p.name.clone(),
                port: r.port,
                protocol: r.protocol,
                bind_address: r.bind_address,
                exe_path: p.exe_path.clone(),
                cmdline: p.cmdline.clone(),
                uid: p.uid.clone(),
                foreign_mntns: p.foreign_mntns,
                cwd: p.cwd.clone(),
            });
        }
        Ok(sockets)
    }
}

fn parse_proc_net_line(line: &str, protocol: Protocol) -> Option<RawSocket> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    // State: 0A = LISTEN for TCP; UDP sockets don't have a LISTEN state
    let state = fields[3];
    if protocol == Protocol::Tcp && state != "0A" {
        return None;
    }

    let local = fields[1];
    let (addr_hex, port_hex) = local.rsplit_once(':')?;
    Some(RawSocket {
        inode: fields[9].parse().ok()?,
        port: u16::from_str_radix(port_hex, 16).ok()?,
        protocol,
        bind_address: parse_hex_addr(addr_hex)?,
    })
}

fn parse_hex_addr(hex: &str) -> Option<IpAddr> {
    if hex.len() == 32 {
        let bytes: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
            .collect();
        // /proc/net/tcp6 stores in host byte order per 32-bit word
        let mut addr_bytes = [0u8; 16];
        for group in 0..4 {
            let offset = group * 4;
            addr_bytes[offset] = bytes[offset + 3];
            addr_bytes[offset + 1] = bytes[offset + 2];
            addr_bytes[offset + 2] = bytes[offset + 1];
            addr_bytes[offset + 3] = bytes[offset];
        }
        Some(IpAddr::V6(Ipv6Addr::from(addr_bytes)))
    } else if hex.len() == 8 {
        let n = u32::from_str_radix(hex, 16).ok()?;
        let bytes = n.to_le_bytes();
        Some(IpAddr::from(bytes))
    } else {
        None
    }
}

/// Split /proc/pid/cmdline (NUL-terminated arguments) into argv.
fn parse_cmdline(raw: &[u8]) -> Vec<String> {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|b| *b == 0)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// What the daemon knows about a process holding a socket.
struct Proc {
    pid: u32,
    /// False when the process vanished or cannot be read.
    valid: bool,
    name: String,
    exe_path: Option<String>,
    cmdline: Option<Vec<String>>,
    uid: Option<String>,
    foreign_mntns: bool,
    cwd: Option<String>,
}

/// One pass over /proc: which processes hold each of the `wanted` socket inodes.
fn socket_holders(wanted: &HashSet<u64>) -> HashMap<u64, Vec<u32>> {
    let mut holders: HashMap<u64, Vec<u32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return holders;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let inode = link
                .to_str()
                .and_then(|l| l.strip_prefix("socket:["))
                .and_then(|l| l.strip_suffix(']'))
                .and_then(|l| l.parse::<u64>().ok());
            if let Some(inode) = inode.filter(|i| wanted.contains(i)) {
                let pids = holders.entry(inode).or_default();
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
    }
    for pids in holders.values_mut() {
        pids.sort_unstable();
    }
    holders
}

fn read_proc(pid: u32) -> Proc {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|n| n.trim().to_string())
        .ok();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok();
    let (Some(name), Some(status)) = (name, status) else {
        return Proc {
            pid,
            valid: false,
            name: String::new(),
            exe_path: None,
            cmdline: None,
            uid: None,
            foreign_mntns: false,
            cwd: None,
        };
    };
    // A binary replaced by an upgrade shows as "... (deleted)".
    let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| normalize_exe_path(&p.to_string_lossy(), Platform::Linux));
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|raw| parse_cmdline(&raw))
        .filter(|args| !args.is_empty());
    // Another mount namespace can show any file under a trusted path. When either side
    // cannot be read, assume the worst.
    let own = std::fs::read_link("/proc/self/ns/mnt").ok();
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok();
    let foreign_mntns = own.is_none() || theirs.is_none() || own != theirs;
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Proc {
        pid,
        valid: true,
        name,
        exe_path,
        cmdline,
        uid: parse_status_uid(&status),
        foreign_mntns,
        cwd,
    }
}

/// The effective uid from /proc/pid/status (`Uid: real effective saved fs`): what the
/// process runs as, which is what its grants must be tied to.
fn parse_status_uid(status: &str) -> Option<String> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut fields = line.split_whitespace();
    let real = fields.next()?;
    Some(fields.next().unwrap_or(real).to_string())
}

/// The process to attribute a socket to. Several processes may share a socket (a forked
/// server); that is fine when they are the same program under the same user, and
/// otherwise the socket cannot be attributed.
fn pick_owner<'a>(holders: &[&'a Proc]) -> Option<&'a Proc> {
    let first = holders.first()?;
    holders
        .iter()
        .all(|p| {
            p.exe_path == first.exe_path
                && p.uid == first.uid
                && p.foreign_mntns == first.foreign_mntns
        })
        .then_some(*first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, exe: Option<&str>, uid: &str) -> Proc {
        Proc {
            pid,
            valid: true,
            name: "x".into(),
            exe_path: exe.map(Into::into),
            cmdline: None,
            uid: Some(uid.into()),
            foreign_mntns: false,
            cwd: None,
        }
    }

    #[test]
    fn cmdline_is_split_on_nul() {
        assert_eq!(
            parse_cmdline(b"python3\0-m\0http.server\08080\0"),
            ["python3", "-m", "http.server", "8080"]
        );
        // An empty argument in the middle survives; a trailing NUL does not add one.
        assert_eq!(parse_cmdline(b"a\0\0b\0"), ["a", "", "b"]);
        assert!(parse_cmdline(b"").is_empty());
        assert!(parse_cmdline(b"\0").is_empty());
    }

    #[test]
    fn status_uid_is_the_effective_one() {
        let status = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_uid(status).as_deref(), Some("0"));
        assert_eq!(parse_status_uid("Uid:\t7\n").as_deref(), Some("7"));
        assert_eq!(parse_status_uid("Name:\tx\n"), None);
    }

    #[test]
    fn shared_sockets_need_one_program_and_user() {
        let a = proc(10, Some("/usr/sbin/nginx"), "0");
        let b = proc(11, Some("/usr/sbin/nginx"), "0");
        assert_eq!(pick_owner(&[&a, &b]).map(|p| p.pid), Some(10));
        // Another program or user holding the same socket: ambiguous.
        let other_exe = proc(12, Some("/tmp/evil"), "0");
        assert!(pick_owner(&[&a, &other_exe]).is_none());
        let other_uid = proc(13, Some("/usr/sbin/nginx"), "1000");
        assert!(pick_owner(&[&a, &other_uid]).is_none());
        let mut foreign = proc(14, Some("/usr/sbin/nginx"), "0");
        foreign.foreign_mntns = true;
        assert!(pick_owner(&[&a, &foreign]).is_none());
        // Nobody: unattributable.
        assert!(pick_owner(&[]).is_none());
    }

    #[test]
    fn proc_net_lines_are_parsed_without_an_owner() {
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let r = parse_proc_net_line(line, Protocol::Tcp).unwrap();
        assert_eq!((r.inode, r.port), (12345, 8080));
        assert!(r.bind_address.is_loopback());
        assert!(parse_proc_net_line(&line.replace(" 0A ", " 01 "), Protocol::Tcp).is_none());
    }
}
