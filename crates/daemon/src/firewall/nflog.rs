//! NFLOG listener (ADR 0029, 0034): reads packets that nftables logs with `log group N`
//! straight from an `AF_NETLINK`/`NETLINK_NETFILTER` socket, without libnetfilter_log.
//! Message parsing is pure and platform independent; only the socket code is Linux-only.

use super::DropEvent;
use socketguard_core::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_IFINDEX_INDEV: u16 = 4;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST_ACK: u16 = 0x1 | 0x4;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// Enough for the IP header, extension headers and the transport ports.
const COPY_RANGE: u32 = 128;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16_ne(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_ne(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The netlink message that binds this socket to NFLOG `group` and asks for packet copies.
pub fn config_message(group: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(&[0; 16]); // nlmsghdr, filled below
    m.extend_from_slice(&[0, 0]); // nfgenmsg: AF_UNSPEC, NFNETLINK_V0
    m.extend_from_slice(&group.to_be_bytes());
    // NFULA_CFG_CMD: bind. Attribute = 4-byte header + 1 byte, padded to 8.
    m.extend_from_slice(&5u16.to_ne_bytes());
    m.extend_from_slice(&NFULA_CFG_CMD.to_ne_bytes());
    m.extend_from_slice(&[NFULNL_CFG_CMD_BIND, 0, 0, 0]);
    // NFULA_CFG_MODE: copy range (be32), mode, padding.
    m.extend_from_slice(&10u16.to_ne_bytes());
    m.extend_from_slice(&NFULA_CFG_MODE.to_ne_bytes());
    m.extend_from_slice(&COPY_RANGE.to_be_bytes());
    m.extend_from_slice(&[NFULNL_COPY_PACKET, 0, 0, 0]);
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    let ty = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    m[4..6].copy_from_slice(&ty.to_ne_bytes());
    m[6..8].copy_from_slice(&NLM_F_REQUEST_ACK.to_ne_bytes());
    m
}

/// The errno carried by an `NLMSG_ERROR` ack (0 = success), if `buf` starts with one.
pub fn ack_error(buf: &[u8]) -> Option<i32> {
    if u16_ne(buf, 4)? != NLMSG_ERROR {
        return None;
    }
    Some(-i32::from_ne_bytes(buf.get(16..20)?.try_into().ok()?))
}

/// One logged packet, as delivered by the kernel.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogPacket {
    pub family: u8,
    pub in_ifindex: Option<u32>,
    pub prefix: Option<String>,
    pub payload: Vec<u8>,
}

/// Split a received datagram into the NFLOG packet messages it contains.
pub fn parse_datagram(buf: &[u8]) -> Vec<LogPacket> {
    let mut out = Vec::new();
    let mut off = 0;
    while let (Some(len), Some(ty)) = (u32_ne(buf, off), u16_ne(buf, off + 4)) {
        let len = len as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        if ty == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET {
            if let Some(p) = parse_packet(&buf[off + 16..off + len]) {
                out.push(p);
            }
        }
        off += align4(len);
    }
    out
}

/// `msg` starts at the `nfgenmsg` header.
fn parse_packet(msg: &[u8]) -> Option<LogPacket> {
    let mut p = LogPacket {
        family: *msg.first()?,
        ..LogPacket::default()
    };
    let mut off = 4;
    while let (Some(len), Some(ty)) = (u16_ne(msg, off), u16_ne(msg, off + 2)) {
        let len = len as usize;
        if len < 4 || off + len > msg.len() {
            break;
        }
        let data = &msg[off + 4..off + len];
        match ty & 0x3fff {
            NFULA_IFINDEX_INDEV => {
                p.in_ifindex = data
                    .get(..4)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            }
            NFULA_PAYLOAD => p.payload = data.to_vec(),
            NFULA_PREFIX => {
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                p.prefix = Some(String::from_utf8_lossy(&data[..end]).into_owned());
            }
            _ => {}
        }
        off += align4(len);
    }
    Some(p)
}

/// (src, dst, transport protocol number, destination port) from a raw IP packet.
fn parse_ip(family: u8, p: &[u8]) -> Option<(IpAddr, IpAddr, u8, Option<u16>)> {
    let (src, dst, proto, l4) = match (family, p.first()? >> 4) {
        (AF_INET6, 6) | (0, 6) => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(8..24)?).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(24..40)?).ok()?);
            // Walk hop-by-hop, routing, destination-options and fragment headers.
            let (mut nh, mut off) = (*p.get(6)?, 40);
            while matches!(nh, 0 | 43 | 60 | 44) {
                let next = *p.get(off)?;
                off += if nh == 44 {
                    8
                } else {
                    (*p.get(off + 1)? as usize + 1) * 8
                };
                nh = next;
            }
            (IpAddr::V6(src), IpAddr::V6(dst), nh, off)
        }
        (AF_INET, 4) | (0, 4) => {
            let ihl = (p[0] & 0xf) as usize * 4;
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(12..16)?).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(16..20)?).ok()?);
            (IpAddr::V4(src), IpAddr::V4(dst), *p.get(9)?, ihl)
        }
        _ => return None,
    };
    let port = match proto {
        6 | 17 => p
            .get(l4 + 2..l4 + 4)
            .map(|b| u16::from_be_bytes([b[0], b[1]])),
        _ => None,
    };
    Some((src, dst, proto, port))
}

/// Turn a logged packet into a drop event. `ifname` resolves interface indexes.
pub fn to_event(p: &LogPacket, ifname: impl Fn(u32) -> Option<String>) -> Option<DropEvent> {
    let (src, dst, proto, port) = parse_ip(p.family, &p.payload)?;
    Some(DropEvent {
        at: SystemTime::now(),
        src,
        dst,
        port,
        proto: match proto {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            _ => None,
        },
        iif: p.in_ifindex.and_then(ifname),
        scope_id: p
            .prefix
            .as_deref()
            .and_then(|s| s.strip_prefix("sg:"))
            .map(str::to_string),
    })
}

/// Bind to NFLOG `group` and deliver events to `sink` from a background thread. The
/// socket belongs to the calling thread's network namespace.
#[cfg(target_os = "linux")]
pub fn subscribe(group: u16, sink: super::DropSink) -> anyhow::Result<()> {
    use anyhow::bail;
    use std::io::Error;

    // SAFETY: plain libc calls on a fd we own; buffers outlive each call.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        );
        if fd < 0 {
            bail!("netlink socket: {}", Error::last_os_error());
        }
        let fail = |what: &str| {
            let e = Error::last_os_error();
            libc::close(fd);
            anyhow::anyhow!("{what}: {e}")
        };
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        ) < 0
        {
            return Err(fail("netlink bind"));
        }
        let msg = config_message(group);
        if libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) < 0 {
            return Err(fail("nflog config"));
        }
        // Wait for the kernel's ack so a missing nfnetlink_log or permission error surfaces.
        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
        let mut buf = vec![0u8; 65536];
        let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
        if n < 0 {
            return Err(fail("nflog config ack"));
        }
        if let Some(errno) = ack_error(&buf[..n as usize]).filter(|&e| e != 0) {
            libc::close(fd);
            bail!("nflog config rejected: {}", Error::from_raw_os_error(errno));
        }
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );

        std::thread::Builder::new()
            .name("nflog".into())
            .spawn(move || loop {
                let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
                if n < 0 {
                    match Error::last_os_error().raw_os_error() {
                        Some(libc::EINTR) | Some(libc::ENOBUFS) => continue,
                        _ => break,
                    }
                }
                for p in parse_datagram(&buf[..n as usize]) {
                    if let Some(ev) = to_event(&p, if_name) {
                        sink(ev);
                    }
                }
            })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn if_name(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, as if_indextoname requires.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success the buffer holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut a = ((data.len() + 4) as u16).to_ne_bytes().to_vec();
        a.extend_from_slice(&ty.to_ne_bytes());
        a.extend_from_slice(data);
        a.resize(align4(a.len()), 0);
        a
    }

    fn packet_msg(family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut m = vec![0u8; 16];
        m.extend_from_slice(&[family, 0, 0, 7]);
        for a in attrs {
            m.extend_from_slice(a);
        }
        let len = m.len() as u32;
        m[0..4].copy_from_slice(&len.to_ne_bytes());
        let ty = NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET;
        m[4..6].copy_from_slice(&ty.to_ne_bytes());
        m
    }

    fn v6_tcp(src: &str, dst: &str, dport: u16) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        p.extend_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&[0x9c, 0x40]);
        p.extend_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn config_message_layout() {
        let m = config_message(7);
        assert_eq!(m.len(), 40);
        assert_eq!(u32_ne(&m, 0), Some(40));
        assert_eq!(u16_ne(&m, 4), Some(0x0401));
        assert_eq!(&m[16..20], &[0, 0, 0, 7]);
    }

    #[test]
    fn parses_ipv6_tcp_drop() {
        let msg = packet_msg(
            AF_INET6,
            &[
                attr(NFULA_IFINDEX_INDEV | 0x4000, &3u32.to_be_bytes()),
                attr(NFULA_PAYLOAD, &v6_tcp("200:1::5", "301::1", 8080)),
                attr(NFULA_PREFIX, b"sg:managed\0"),
            ],
        );
        let pkts = parse_datagram(&msg);
        assert_eq!(pkts.len(), 1);
        let ev = to_event(&pkts[0], |i| (i == 3).then(|| "ygg0".to_string())).unwrap();
        assert_eq!(ev.src, "200:1::5".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst, "301::1".parse::<IpAddr>().unwrap());
        assert_eq!(ev.port, Some(8080));
        assert_eq!(ev.proto, Some(Protocol::Tcp));
        assert_eq!(ev.iif.as_deref(), Some("ygg0"));
        assert_eq!(ev.scope_id.as_deref(), Some("managed"));
    }

    #[test]
    fn parses_ipv4_udp_and_two_messages_per_datagram() {
        let mut ip4 = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ip4.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 8, 0, 0]);
        let a = packet_msg(AF_INET, &[attr(NFULA_PAYLOAD, &ip4)]);
        let b = packet_msg(
            AF_INET6,
            &[attr(NFULA_PAYLOAD, &v6_tcp("fd00::1", "fd00::2", 22))],
        );
        let mut dg = a.clone();
        dg.resize(align4(dg.len()), 0);
        dg.extend_from_slice(&b);
        let pkts = parse_datagram(&dg);
        assert_eq!(pkts.len(), 2);
        let ev = to_event(&pkts[0], |_| None).unwrap();
        assert_eq!(ev.dst, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!((ev.port, ev.proto), (Some(53), Some(Protocol::Udp)));
        assert_eq!(ev.scope_id, None);
    }

    #[test]
    fn skips_extension_headers_and_garbage() {
        // Hop-by-hop header (8 bytes) before TCP.
        let mut p = v6_tcp("fd00::1", "fd00::2", 443);
        p[6] = 0;
        let tcp = p.split_off(40);
        p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&tcp);
        let (_, _, proto, port) = parse_ip(AF_INET6, &p).unwrap();
        assert_eq!((proto, port), (6, Some(443)));
        assert!(parse_ip(AF_INET6, &[0x60, 0, 0]).is_none());
        assert!(parse_datagram(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn ack_error_reads_errno() {
        let mut m = vec![0u8; 20];
        m[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert_eq!(ack_error(&m), Some(0));
        m[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        assert_eq!(ack_error(&m), Some(1));
    }
}
