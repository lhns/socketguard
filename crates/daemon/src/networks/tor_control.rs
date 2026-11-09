//! A minimal blocking Tor control-port client (control-spec): connect over TCP or a Unix
//! socket, PROTOCOLINFO, AUTHENTICATE, GETINFO, ADD_ONION and DEL_ONION. Replies are
//! parsed per the spec's reply syntax, including multi-line and data replies.

use anyhow::{anyhow, bail, Context, Result};
use socketguard_core::config::TorAuth;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the control port listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(String),
    #[cfg_attr(not(unix), allow(dead_code))]
    Unix(String),
}

impl Endpoint {
    /// `host:port`, or `unix:/path`.
    pub fn parse(s: &str) -> Self {
        match s.strip_prefix("unix:") {
            Some(path) => Endpoint::Unix(path.trim_start_matches("//").to_string()),
            None => Endpoint::Tcp(s.to_string()),
        }
    }
}

/// One control-port reply: the final status code and the text of every line, in order
/// (for data replies the lines of the data block follow the `key=` line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// The reply as an error unless it is a 2xx.
    pub fn ok(self) -> Result<Reply> {
        if self.is_ok() {
            Ok(self)
        } else {
            bail!("Tor replied {} {}", self.code, self.lines.join(" "))
        }
    }

    /// The value of the `key=` line (`250-key=value`).
    pub fn value(&self, key: &str) -> Option<&str> {
        self.lines
            .iter()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    }
}

/// Parse one reply from `r`. Mid lines are `250-text`, data blocks `250+text` followed by
/// lines up to a lone `.`, and the last line is `250 text`. Asynchronous events (6xx)
/// are not expected: we subscribe to none.
pub fn read_reply(r: &mut impl BufRead) -> Result<Reply> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(r)?;
        if line.len() < 4 || !line.is_char_boundary(3) {
            bail!("malformed control reply line {line:?}");
        }
        let (code, rest) = line.split_at(3);
        let code: u16 = code
            .parse()
            .map_err(|_| anyhow!("malformed control reply line {line:?}"))?;
        let mut chars = rest.chars();
        let sep = chars.next().unwrap();
        let text = chars.as_str().to_string();
        match sep {
            '-' => lines.push(text),
            '+' => {
                lines.push(text);
                loop {
                    let data = read_line(r)?;
                    if data == "." {
                        break;
                    }
                    // Dot-stuffing: a leading dot is doubled.
                    lines.push(
                        data.strip_prefix("..")
                            .map_or(data.clone(), |d| format!(".{d}")),
                    );
                }
            }
            ' ' => {
                lines.push(text);
                return Ok(Reply { code, lines });
            }
            _ => bail!("malformed control reply line {line:?}"),
        }
    }
}

fn read_line(r: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        bail!("Tor closed the control connection");
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// What PROTOCOLINFO told us.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub methods: Vec<String>,
    pub cookie_file: Option<String>,
    pub version: Option<String>,
}

/// Parse the lines of a PROTOCOLINFO reply.
pub fn parse_protocolinfo(reply: &Reply) -> ProtocolInfo {
    let mut info = ProtocolInfo::default();
    for line in &reply.lines {
        if let Some(rest) = line.strip_prefix("AUTH ") {
            for (key, value) in parse_keywords(rest) {
                match key.as_str() {
                    "METHODS" => info.methods = value.split(',').map(str::to_string).collect(),
                    "COOKIEFILE" => info.cookie_file = Some(value),
                    _ => {}
                }
            }
        } else if let Some(rest) = line.strip_prefix("VERSION ") {
            info.version = parse_keywords(rest)
                .into_iter()
                .find(|(k, _)| k == "Tor")
                .map(|(_, v)| v);
        }
    }
    info
}

/// Split `KEY=value KEY2="quoted \"value\""` into pairs.
fn parse_keywords(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if key.is_empty() {
            break;
        }
        let mut value = String::new();
        if chars.peek() == Some(&'=') {
            chars.next();
            if chars.peek() == Some(&'"') {
                chars.next();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                value.push(match n {
                                    'n' => '\n',
                                    'r' => '\r',
                                    't' => '\t',
                                    other => other,
                                });
                            }
                        }
                        c => value.push(c),
                    }
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ' ' {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
            }
        }
        out.push((key, value));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// A control-spec quoted string.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The AUTHENTICATE command for `auth`. Cookie auth needs the cookie file's contents.
pub fn authenticate_command(auth: &TorAuth, cookie: Option<&[u8]>) -> Result<String> {
    Ok(match auth {
        TorAuth::None => "AUTHENTICATE".to_string(),
        TorAuth::Password(pw) => format!("AUTHENTICATE {}", quote(pw)),
        TorAuth::Cookie => {
            let cookie = cookie.context("no cookie to authenticate with")?;
            format!("AUTHENTICATE {}", hex(cookie))
        }
    })
}

/// RFC 4648 base32, uppercase, no padding (Tor's encoding for x25519 client keys).
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// What an onion service should be, for ADD_ONION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// `ED25519-V3:<key>` to reuse a key, None to create one (`NEW:ED25519-V3`).
    pub key: Option<String>,
    /// (virtual port, target `host:port`), sorted.
    pub ports: Vec<(u16, String)>,
    /// Base32 x25519 public keys of authorized clients, sorted; empty = open to anyone
    /// who knows the name.
    pub clients: Vec<String>,
}

/// The ADD_ONION command for `spec`. Services are detached, so they outlive the control
/// connection and the daemon.
pub fn add_onion_command(spec: &ServiceSpec) -> String {
    let mut cmd = format!(
        "ADD_ONION {}",
        spec.key.as_deref().unwrap_or("NEW:ED25519-V3")
    );
    cmd.push_str(if spec.clients.is_empty() {
        " Flags=Detach"
    } else {
        " Flags=Detach,V3Auth"
    });
    for (virt, target) in &spec.ports {
        cmd.push_str(&format!(" Port={virt},{target}"));
    }
    for c in &spec.clients {
        cmd.push_str(&format!(" ClientAuthV3={c}"));
    }
    cmd
}

/// What ADD_ONION returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    pub service_id: String,
    /// Only returned for a created key.
    pub private_key: Option<String>,
}

pub fn parse_add_onion(reply: &Reply) -> Result<Added> {
    Ok(Added {
        service_id: reply
            .value("ServiceID")
            .context("ADD_ONION returned no ServiceID")?
            .to_string(),
        private_key: reply.value("PrivateKey").map(str::to_string),
    })
}

/// The service ids in a `GETINFO onions/detached` reply.
pub fn parse_detached(reply: &Reply) -> Vec<String> {
    reply
        .lines
        .iter()
        .map(|l| l.strip_prefix("onions/detached=").unwrap_or(l).trim())
        .filter(|l| !l.is_empty() && *l != "OK")
        .map(str::to_string)
        .collect()
}

/// An authenticated control connection.
pub struct Control {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
}

impl Control {
    /// Connect and authenticate.
    pub fn connect(endpoint: &Endpoint, auth: &TorAuth) -> Result<Self> {
        let (reader, writer): (Box<dyn Read + Send>, Box<dyn Write + Send>) = match endpoint {
            Endpoint::Tcp(addr) => {
                let sock = addr
                    .to_socket_addrs()
                    .with_context(|| format!("bad Tor control address {addr}"))?
                    .next()
                    .with_context(|| format!("no address for {addr}"))?;
                let s = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)
                    .with_context(|| format!("cannot reach the Tor control port at {addr}"))?;
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                (Box::new(s.try_clone()?), Box::new(s))
            }
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                let s = std::os::unix::net::UnixStream::connect(path)
                    .with_context(|| format!("cannot reach the Tor control socket {path}"))?;
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                (Box::new(s.try_clone()?), Box::new(s))
            }
            #[cfg(not(unix))]
            Endpoint::Unix(_) => bail!("Unix sockets are not available on this platform"),
        };
        Self::over(reader, writer, auth)
    }

    /// Authenticate over an already open stream.
    pub fn over(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        auth: &TorAuth,
    ) -> Result<Self> {
        let mut c = Self {
            reader: BufReader::new(reader),
            writer,
        };
        let cookie = if matches!(auth, TorAuth::Cookie) {
            let info = parse_protocolinfo(&c.command("PROTOCOLINFO 1")?.ok()?);
            if !info.methods.iter().any(|m| m == "COOKIE") {
                bail!(
                    "the Tor control port does not offer cookie authentication (methods: {})",
                    info.methods.join(",")
                );
            }
            let path = info
                .cookie_file
                .context("PROTOCOLINFO named no cookie file")?;
            Some(
                std::fs::read(&path)
                    .with_context(|| format!("cannot read the Tor cookie file {path}"))?,
            )
        } else {
            None
        };
        c.command(&authenticate_command(auth, cookie.as_deref())?)?
            .ok()
            .context("Tor refused the control authentication")?;
        Ok(c)
    }

    /// Send one command and read its reply.
    pub fn command(&mut self, cmd: &str) -> Result<Reply> {
        self.writer.write_all(cmd.as_bytes())?;
        self.writer.write_all(b"\r\n")?;
        self.writer.flush()?;
        read_reply(&mut self.reader)
    }

    pub fn version(&mut self) -> Result<String> {
        let r = self.command("GETINFO version")?.ok()?;
        Ok(r.value("version").unwrap_or_default().to_string())
    }

    /// Service ids of every detached onion service Tor is running.
    pub fn detached(&mut self) -> Result<Vec<String>> {
        Ok(parse_detached(
            &self.command("GETINFO onions/detached")?.ok()?,
        ))
    }

    pub fn add_onion(&mut self, spec: &ServiceSpec) -> Result<Added> {
        parse_add_onion(&self.command(&add_onion_command(spec))?.ok()?)
    }

    /// Remove a service; one Tor does not know (552) counts as removed.
    pub fn del_onion(&mut self, service_id: &str) -> Result<()> {
        let r = self.command(&format!("DEL_ONION {service_id}"))?;
        if r.is_ok() || r.code == 552 {
            Ok(())
        } else {
            bail!(
                "DEL_ONION {service_id}: Tor replied {} {}",
                r.code,
                r.lines.join(" ")
            )
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = self.command("QUIT");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reply(s: &str) -> Result<Reply> {
        read_reply(&mut Cursor::new(s.replace('\n', "\r\n")))
    }

    #[test]
    fn single_line_reply() {
        let r = reply("250 OK\n").unwrap();
        assert_eq!(
            r,
            Reply {
                code: 250,
                lines: vec!["OK".into()]
            }
        );
        assert!(r.is_ok());
    }

    #[test]
    fn multi_line_add_onion_reply() {
        let r =
            reply("250-ServiceID=abcdefghijklmnop\n250-PrivateKey=ED25519-V3:c2VjcmV0\n250 OK\n")
                .unwrap();
        assert_eq!(r.code, 250);
        let added = parse_add_onion(&r).unwrap();
        assert_eq!(added.service_id, "abcdefghijklmnop");
        assert_eq!(added.private_key.as_deref(), Some("ED25519-V3:c2VjcmV0"));
        // A reused key returns no PrivateKey.
        let r = reply("250-ServiceID=x\n250 OK\n").unwrap();
        assert_eq!(parse_add_onion(&r).unwrap().private_key, None);
    }

    #[test]
    fn data_reply_lists_detached_services() {
        let r = reply("250+onions/detached=\nid1\nid2\n.\n250 OK\n").unwrap();
        assert_eq!(parse_detached(&r), ["id1", "id2"]);
        let r = reply("250-onions/detached=only\n250 OK\n").unwrap();
        assert_eq!(parse_detached(&r), ["only"]);
        let r = reply("250-onions/detached=\n250 OK\n").unwrap();
        assert!(parse_detached(&r).is_empty());
    }

    #[test]
    fn error_replies_are_not_ok() {
        let r = reply("551 Failed to add onion\n").unwrap();
        assert!(!r.is_ok());
        assert!(r.ok().unwrap_err().to_string().contains("551"));
        assert!(reply("515 Authentication failed: bad cookie\n")
            .unwrap()
            .ok()
            .is_err());
        assert!(reply("garbage\n").is_err());
        assert!(
            reply("250-half a reply\n").is_err(),
            "EOF before the final line"
        );
    }

    #[test]
    fn protocolinfo_gives_methods_and_cookie_file() {
        let r = reply(
            "250-PROTOCOLINFO 1\n\
             250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/run/tor/my \\\"c\\\".cookie\"\n\
             250-VERSION Tor=\"0.4.8.9\"\n250 OK\n",
        )
        .unwrap();
        let info = parse_protocolinfo(&r);
        assert_eq!(info.methods, ["COOKIE", "SAFECOOKIE", "HASHEDPASSWORD"]);
        assert_eq!(
            info.cookie_file.as_deref(),
            Some("/run/tor/my \"c\".cookie")
        );
        assert_eq!(info.version.as_deref(), Some("0.4.8.9"));
    }

    #[test]
    fn authenticate_commands() {
        assert_eq!(
            authenticate_command(&TorAuth::None, None).unwrap(),
            "AUTHENTICATE"
        );
        assert_eq!(
            authenticate_command(&TorAuth::Password("pa\"ss\\".into()), None).unwrap(),
            r#"AUTHENTICATE "pa\"ss\\""#
        );
        assert_eq!(
            authenticate_command(&TorAuth::Cookie, Some(&[0x00, 0xab, 0xff])).unwrap(),
            "AUTHENTICATE 00ABFF"
        );
        assert!(authenticate_command(&TorAuth::Cookie, None).is_err());
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            Endpoint::parse("127.0.0.1:9051"),
            Endpoint::Tcp("127.0.0.1:9051".into())
        );
        assert_eq!(
            Endpoint::parse("unix:/run/tor/control"),
            Endpoint::Unix("/run/tor/control".into())
        );
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(&[0u8; 32]).len(), 52);
    }

    #[test]
    fn add_onion_command_from_spec() {
        let open = ServiceSpec {
            key: Some("ED25519-V3:a2V5".into()),
            ports: vec![(80, "127.0.0.1:80".into()), (8080, "[::1]:8080".into())],
            clients: vec![],
        };
        assert_eq!(
            add_onion_command(&open),
            "ADD_ONION ED25519-V3:a2V5 Flags=Detach Port=80,127.0.0.1:80 Port=8080,[::1]:8080"
        );
        let closed = ServiceSpec {
            key: None,
            ports: vec![(1, "127.0.0.1:1".into())],
            clients: vec!["AAAA".into(), "BBBB".into()],
        };
        assert_eq!(
            add_onion_command(&closed),
            "ADD_ONION NEW:ED25519-V3 Flags=Detach,V3Auth Port=1,127.0.0.1:1 ClientAuthV3=AAAA ClientAuthV3=BBBB"
        );
    }
}
