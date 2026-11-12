//! Tor bridge lines (ADR 0052), as strictly as ADR 0040 needs.
//!
//! A bridge line comes from outside (pasted by the user, sent through the API) and ends up
//! in the `torrc` of the managed Tor. It must never be able to add another option there, so
//! it is not "sanitised": it is parsed token by token against the one form SocketGuard
//! supports and written out again in a canonical form built from the parsed parts.
//!
//! The form (only `obfs4` is shipped):
//!
//! ```text
//! [Bridge ]obfs4 <IPv4>:<port> | [<IPv6>]:<port>  <40 hex>  cert=<70 base64>  iat-mode=<0|1|2>
//! ```
//!
//! Canonical form: no `Bridge ` prefix, single spaces, upper-case fingerprint, the address as
//! Rust writes it. `torrc` gets `Bridge ` in front.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The only transport the shipped helper is enabled for.
pub const TRANSPORT: &str = "obfs4";
/// Longest accepted input line; a real obfs4 line is about 150 characters.
pub const MAX_LINE_LEN: usize = 300;
/// Most bridges one network takes.
pub const MAX_BRIDGES: usize = 32;
/// Length of an obfs4 `cert=`: base64 (no padding) of 52 bytes, node id and public key.
pub const CERT_LEN: usize = 70;

/// What a bridge line has to look like, for messages.
pub const EXPECTED: &str = "Only obfs4 bridges are supported, in the form \
    `obfs4 IP:port FINGERPRINT cert=CERT iat-mode=0` (a Tor Project bridge line; an IPv6 \
    address is written [address]:port; iat-mode is 0, 1 or 2)";

/// A parsed obfs4 bridge line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeLine {
    address: String,
    fingerprint: String,
    cert: String,
    iat_mode: u8,
}

impl BridgeLine {
    /// The canonical one-line form, without the `Bridge ` keyword.
    pub fn canonical(&self) -> String {
        format!(
            "{TRANSPORT} {} {} cert={} iat-mode={}",
            self.address, self.fingerprint, self.cert, self.iat_mode
        )
    }
}

/// How the input is shown back in an error: escaped and cut, so a hostile line does not
/// reach a terminal or a log as it is.
fn shown(line: &str) -> String {
    let cut: String = line.chars().take(40).collect();
    let more = if line.chars().count() > 40 { "..." } else { "" };
    format!("{:?}{more}", cut)
}

/// Parse one bridge line, with or without the leading `Bridge `.
pub fn parse_bridge_line(input: &str) -> Result<BridgeLine, String> {
    let bad = |why: &str| {
        Err(format!(
            "invalid bridge {}: {why}. {EXPECTED}",
            shown(input)
        ))
    };
    if input.len() > MAX_LINE_LEN {
        return bad("the line is too long");
    }
    // Printable ASCII and plain spaces only: this excludes line breaks (also U+2028/U+2029),
    // tabs, NUL and every other control or non-ASCII character in one test.
    if !input.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return bad("it must be a single line of plain ASCII text");
    }
    if input.contains(['"', '\'', '#', '\\']) {
        return bad("quotes, # and backslashes are not allowed");
    }
    let mut tokens: Vec<&str> = input.split(' ').filter(|t| !t.is_empty()).collect();
    if tokens.first() == Some(&"Bridge") {
        tokens.remove(0);
    }
    let Some(transport) = tokens.first() else {
        return bad("the line is empty");
    };
    if *transport != TRANSPORT {
        return bad(&format!(
            "the transport must be {TRANSPORT}, not {}",
            shown(transport)
        ));
    }
    if tokens.len() != 5 {
        return bad(&format!(
            "expected 5 fields (transport, address, fingerprint, cert, iat-mode), found {}",
            tokens.len()
        ));
    }
    let address = socket_address(tokens[1])
        .map_err(|why| format!("invalid bridge {}: {why}. {EXPECTED}", shown(input)))?;
    let fp = tokens[2];
    if fp.len() != 40 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return bad("the fingerprint must be 40 hexadecimal characters");
    }
    let cert = match tokens[3].strip_prefix("cert=") {
        Some(c)
            if c.len() == CERT_LEN
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') =>
        {
            c
        }
        _ => return bad("cert= must be followed by 70 base64 characters (A-Z a-z 0-9 + /)"),
    };
    let iat_mode = match tokens[4] {
        "iat-mode=0" => 0,
        "iat-mode=1" => 1,
        "iat-mode=2" => 2,
        _ => return bad("the last field must be iat-mode=0, iat-mode=1 or iat-mode=2"),
    };
    Ok(BridgeLine {
        address,
        fingerprint: fp.to_ascii_uppercase(),
        cert: cert.to_string(),
        iat_mode,
    })
}

/// `1.2.3.4:443` or `[2001:db8::1]:443`, port 1 to 65535, in the form Rust prints it.
fn socket_address(token: &str) -> Result<String, String> {
    let (host, port) = if let Some(rest) = token.strip_prefix('[') {
        rest.split_once("]:")
            .ok_or("an IPv6 address is written [address]:port")?
    } else {
        token.split_once(':').ok_or("the address must be IP:port")?
    };
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.starts_with('0')
    {
        return Err("the port must be a number from 1 to 65535".into());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| "the port must be a number from 1 to 65535".to_string())?;
    if token.starts_with('[') {
        let ip: Ipv6Addr = host
            .parse()
            .map_err(|_| "not an IPv6 address".to_string())?;
        Ok(format!("[{ip}]:{port}"))
    } else {
        let ip: Ipv4Addr = host.parse().map_err(|_| {
            "the address must be an IPv4 address (a name is not accepted)".to_string()
        })?;
        Ok(format!("{ip}:{port}"))
    }
}

/// Validate and normalise a list of bridge lines: each in canonical form, duplicates
/// dropped (the first stays), at most [`MAX_BRIDGES`].
pub fn normalize_bridges<S: AsRef<str>>(lines: &[S]) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for l in lines {
        let canonical = parse_bridge_line(l.as_ref())?.canonical();
        if seen.insert(canonical.clone()) {
            out.push(canonical);
        }
    }
    if out.len() > MAX_BRIDGES {
        return Err(format!("at most {MAX_BRIDGES} bridges are supported"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    fn good() -> String {
        format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=0")
    }

    #[test]
    fn a_documentation_range_line_is_accepted_and_canonical() {
        assert_eq!(parse_bridge_line(&good()).unwrap().canonical(), good());
        // The optional keyword, extra spaces and a lower-case fingerprint normalise.
        let messy = format!(
            "Bridge  obfs4   192.0.2.10:443 {} cert={CERT}  iat-mode=0 ",
            FP.to_lowercase()
        );
        assert_eq!(parse_bridge_line(&messy).unwrap().canonical(), good());
    }

    #[test]
    fn ipv6_and_every_iat_mode() {
        for m in 0..=2 {
            let l = format!("obfs4 [2001:DB8::1]:9001 {FP} cert={CERT} iat-mode={m}");
            assert_eq!(
                parse_bridge_line(&l).unwrap().canonical(),
                format!("obfs4 [2001:db8::1]:9001 {FP} cert={CERT} iat-mode={m}")
            );
        }
    }

    fn rejected(l: &str) {
        let e = parse_bridge_line(l).expect_err(&format!("accepted {l:?}"));
        assert!(e.contains("obfs4"), "{e}");
        assert!(
            !e.contains('\n') && !e.contains('\r') && !e.contains('\u{2028}'),
            "{e:?}"
        );
    }

    #[test]
    fn hostile_input_is_rejected() {
        let g = good();
        for l in [
            // Line breaks and other separators: a second torrc line would be a second option.
            format!("{g}\nSocksPort 9050"),
            format!("{g}\r\nControlPort 9051"),
            format!("{g}\rSocksPort 1"),
            format!("{g}\u{2028}SocksPort 1"),
            format!("{g}\u{2029}SocksPort 1"),
            format!("{g}\u{85}SocksPort 1"),
            format!("{g}\0SocksPort 1"),
            format!("{g}\tSocksPort 1"),
            format!("{g}\x0bSocksPort 1"),
            format!("{g}\x0cSocksPort 1"),
            "\nSocksPort 1".to_string(),
            // Extra tokens and trailing options.
            format!("{g} SocksPort 9050"),
            format!("{g} iat-mode=1"),
            format!("{g} # comment"),
            format!("{g}#"),
            format!("{g} \\"),
            format!("{g}\\\nSocksPort 1"),
            format!("{g} \"x\""),
            format!("\"{g}\""),
            format!("'{g}'"),
            // Wrong shapes.
            String::new(),
            " ".into(),
            "Bridge".into(),
            "Bridge ".into(),
            "obfs4".into(),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT}"),
            format!("obfs4 192.0.2.10:443 {FP} iat-mode=0"),
            format!("obfs4 192.0.2.10:443 cert={CERT} iat-mode=0"),
            format!("obfs4 {FP} cert={CERT} iat-mode=0"),
            format!("Bridge Bridge {}", good()),
            format!("bridge {}", good()),
            format!("OBFS4 192.0.2.10:443 {FP} cert={CERT} iat-mode=0"),
            // Other transports and a bridge without a transport.
            format!("snowflake 192.0.2.3:80 {FP} fingerprint={FP} url=https://x.example/ fronts=a.example"),
            format!("meek_lite 192.0.2.20:80 url=https://x.example/ front=a.example utls=HelloRandomizedALPN"),
            format!("webtunnel [2001:db8::1]:443 {FP} url=https://x.example/y ver=0.0.3"),
            format!("scramblesuit 192.0.2.10:443 {FP} password=ABCD"),
            format!("obfs3 192.0.2.10:443 {FP}"),
            format!("192.0.2.10:443 {FP}"),
            format!("Bridge 192.0.2.10:443 {FP}"),
            // Addresses and ports.
            format!("obfs4 192.0.2.10:0 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:65536 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:-1 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:+443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:0443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:443443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10: {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.256:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 bridge.example.org:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 [2001:db8::1] {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 [2001:db8::1]443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 [::1:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 [zz::1]:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 [192.0.2.1]:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 2001:db8::1:443 {FP} cert={CERT} iat-mode=0"),
            // Fingerprint.
            format!("obfs4 192.0.2.10:443 {} cert={CERT} iat-mode=0", &FP[..39]),
            format!("obfs4 192.0.2.10:443 {FP}0 cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:443 {}G cert={CERT} iat-mode=0", &FP[..39]),
            // cert and iat-mode.
            format!("obfs4 192.0.2.10:443 {FP} cert={} iat-mode=0", &CERT[..69]),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT}A iat-mode=0"),
            format!("obfs4 192.0.2.10:443 {FP} cert={}= iat-mode=0", &CERT[..69]),
            format!("obfs4 192.0.2.10:443 {FP} cert={}; iat-mode=0", &CERT[..68]),
            format!("obfs4 192.0.2.10:443 {FP} CERT={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:443 {FP} cert= iat-mode=0"),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=3"),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=00"),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode="),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=-1"),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=0x1"),
            // Non-ASCII look-alikes.
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=\u{ff10}"),
            format!("obfs4\u{a0}192.0.2.10:443 {FP} cert={CERT} iat-mode=0"),
            format!("obfs4 192.0.2.10:443 {FP} cert={CERT} iat-mode=0\u{200b}"),
            // Very long.
            format!("{g} {}", "a".repeat(10_000)),
            "a".repeat(1_000_000),
            format!("obfs4 192.0.2.10:443 {FP} cert={} iat-mode=0", "A".repeat(5_000)),
        ] {
            rejected(&l);
        }
    }

    #[test]
    fn the_error_does_not_echo_a_hostile_line_raw() {
        let e = parse_bridge_line("obfs4 \u{2028}\nSocksPort 1\0").unwrap_err();
        assert!(
            !e.contains('\u{2028}') && !e.contains('\0') && !e.contains('\n'),
            "{e:?}"
        );
        let long = parse_bridge_line(&"x".repeat(5_000)).unwrap_err();
        assert!(long.len() < 600, "{}", long.len());
    }

    #[test]
    fn lists_are_deduplicated_in_canonical_form() {
        let a = good();
        let b = format!(
            "Bridge obfs4 192.0.2.10:443 {} cert={CERT} iat-mode=0",
            FP.to_lowercase()
        );
        let c = format!("obfs4 192.0.2.11:443 {FP} cert={CERT} iat-mode=1");
        let n = normalize_bridges(&[a.clone(), b, c.clone()]).unwrap();
        assert_eq!(n, vec![a, c]);
        assert!(normalize_bridges::<&str>(&[]).unwrap().is_empty());
        // One bad entry fails the list.
        assert!(normalize_bridges(&[good(), format!("{}\nX", good())]).is_err());
    }

    #[test]
    fn the_number_of_bridges_is_bounded() {
        let many: Vec<String> = (0..=MAX_BRIDGES)
            .map(|i| {
                format!(
                    "obfs4 192.0.2.{}:{} {FP} cert={CERT} iat-mode=0",
                    i % 250 + 1,
                    1000 + i
                )
            })
            .collect();
        assert!(normalize_bridges(&many).unwrap_err().contains("at most"));
        assert!(normalize_bridges(&many[..MAX_BRIDGES]).is_ok());
    }
}
