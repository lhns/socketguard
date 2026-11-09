//! A minimal blocking Tor control-port client (control-spec): connect over TCP or a Unix
//! socket, PROTOCOLINFO, AUTHENTICATE (SAFECOOKIE, password or none), GETINFO, ADD_ONION
//! and DEL_ONION. Replies are parsed per the spec's reply syntax, including multi-line and
//! data replies.
//!
//! Whoever answers on the control address is trusted with our onion keys, and the default
//! TCP address can be bound by any local user while Tor is down (ADR 0039). So a `Control`
//! only exists once the server has proved itself (SAFECOOKIE) or was configured to be
//! trusted (password, `none` on a Unix socket, explicit `cookie_insecure`), and the cookie
//! file is checked before it is read.

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
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

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        bail!("malformed hex in a control reply");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow!("malformed hex")))
        .collect()
}

const COOKIE_LEN: usize = 32;
/// HMAC key of the server's proof.
pub const SERVER_TO_CONTROLLER: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
/// HMAC key of the controller's proof.
pub const CONTROLLER_TO_SERVER: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// HMAC-SHA256 of cookie | client nonce | server nonce under `key` (control-spec,
/// SAFECOOKIE). The mock Tor server in `test_support` uses it too.
pub fn safecookie_mac(key: &[u8], cookie: &[u8], client: &[u8], server: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(cookie);
    mac.update(client);
    mac.update(server);
    mac
}

/// The tag of [`safecookie_mac`].
pub fn safecookie_hash(key: &[u8], cookie: &[u8], client: &[u8], server: &[u8]) -> Vec<u8> {
    safecookie_mac(key, cookie, client, server)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// How to authenticate to the control port and how far to trust what answers.
#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    pub auth: TorAuth,
    /// The cookie file PROTOCOLINFO must report.
    pub cookie_path: Option<String>,
    /// The directory whose owner may own the cookie file (default: the directory of
    /// `cookie_path`). Root may always.
    pub cookie_dir: Option<String>,
    /// On a Unix control socket: the uid the peer (Tor) must run as.
    pub expect_tor_uid: Option<u32>,
    /// Tests only (never set from the config): accept `none` over TCP.
    pub allow_none_over_tcp: bool,
}

impl AuthOptions {
    pub fn new(auth: TorAuth) -> Self {
        Self {
            auth,
            ..Self::default()
        }
    }
}

/// Read the cookie file PROTOCOLINFO named, after checking that it is what Tor writes: a
/// regular file (not a link, which could point at any root-only file), exactly 32 bytes,
/// and on Unix owned by root, by Tor's configured uid or by the owner of the Tor data
/// directory, and not writable by others.
pub fn read_cookie_file(path: &str, opts: &AuthOptions) -> Result<Vec<u8>> {
    let p = std::path::Path::new(path);
    let link = std::fs::symlink_metadata(p)
        .with_context(|| format!("cannot read the Tor cookie file {path}"))?;
    if link.file_type().is_symlink() {
        bail!("the Tor cookie file {path} is a symbolic link; refusing to follow it");
    }
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW);
    }
    let file = open
        .open(p)
        .with_context(|| format!("cannot read the Tor cookie file {path}"))?;
    // Judge the file we opened, not the path, so it cannot be swapped in between.
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("the Tor cookie file {path} is not a regular file");
    }
    if meta.len() != COOKIE_LEN as u64 {
        bail!(
            "the Tor cookie file {path} is {} bytes, not {COOKIE_LEN}",
            meta.len()
        );
    }
    #[cfg(unix)]
    check_cookie_owner(path, &meta, opts)?;
    #[cfg(not(unix))]
    let _ = opts;
    let mut buf = Vec::new();
    file.take(COOKIE_LEN as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() != COOKIE_LEN {
        bail!("the Tor cookie file {path} changed while it was read");
    }
    Ok(buf)
}

#[cfg(unix)]
fn check_cookie_owner(path: &str, meta: &std::fs::Metadata, opts: &AuthOptions) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = meta.uid();
    if meta.mode() & 0o022 != 0 {
        bail!("the Tor cookie file {path} is writable by others");
    }
    let data_dir = opts
        .cookie_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let parent = std::path::Path::new(opts.cookie_path.as_deref()?).parent()?;
            Some(parent.to_path_buf())
        });
    let dir_owner = data_dir
        .and_then(|d| std::fs::metadata(d).ok())
        .map(|m| m.uid());
    if uid == 0 || opts.expect_tor_uid == Some(uid) || dir_owner == Some(uid) {
        Ok(())
    } else {
        bail!(
            "the Tor cookie file {path} is owned by uid {uid}, who is neither root nor the owner \
             of the Tor data directory; set cookie_path (or cookie_dir) to trust it"
        )
    }
}

/// The uid of the process on the other end of a Unix socket.
#[cfg(target_os = "linux")]
fn peer_uid(s: &std::os::unix::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for the call and match SO_PEERCRED's layout.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED failed");
    }
    Ok(cred.uid)
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

/// The AUTHENTICATE command for `auth`. Plain cookie auth sends the cookie file's contents.
pub fn authenticate_command(auth: &TorAuth, cookie: Option<&[u8]>) -> Result<String> {
    Ok(match auth {
        TorAuth::None => "AUTHENTICATE".to_string(),
        TorAuth::Password(pw) => format!("AUTHENTICATE {}", quote(pw)),
        TorAuth::Cookie | TorAuth::CookieInsecure => {
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

/// An authenticated control connection. One only exists after the server was accepted
/// (see the module comment), so every ADD_ONION on it goes to a server we trust.
pub struct Control {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
    /// AUTHENTICATE succeeded, so QUIT is polite; before that we send nothing more.
    authenticated: bool,
}

impl Control {
    /// Connect and authenticate.
    pub fn connect(endpoint: &Endpoint, opts: &AuthOptions) -> Result<Self> {
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
                if let Some(want) = opts.expect_tor_uid {
                    #[cfg(target_os = "linux")]
                    {
                        let got = peer_uid(&s)?;
                        if got != want {
                            bail!(
                                "the Tor control socket {path} is served by uid {got}, expected {want}"
                            );
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    bail!("expect_tor_uid is only supported on Linux (wanted uid {want})");
                }
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                (Box::new(s.try_clone()?), Box::new(s))
            }
            #[cfg(not(unix))]
            Endpoint::Unix(_) => bail!("Unix sockets are not available on this platform"),
        };
        Self::over(reader, writer, opts, matches!(endpoint, Endpoint::Unix(_)))
    }

    /// Authenticate over an already open stream. `unix`: it is a local Unix socket, which
    /// no other user can have bound at Tor's path.
    pub fn over(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        opts: &AuthOptions,
        unix: bool,
    ) -> Result<Self> {
        let mut c = Self {
            reader: BufReader::new(reader),
            writer,
            authenticated: false,
        };
        match &opts.auth {
            TorAuth::None if !unix && !opts.allow_none_over_tcp => bail!(
                "auth \"none\" is only accepted on a Unix control socket (unix:/path): anyone \
                 can listen on a TCP control address while Tor is down"
            ),
            TorAuth::None | TorAuth::Password(_) => c.send_authenticate(&opts.auth, None)?,
            TorAuth::Cookie | TorAuth::CookieInsecure => c.cookie_auth(opts)?,
        }
        Ok(c)
    }

    fn send_authenticate(&mut self, auth: &TorAuth, cookie: Option<&[u8]>) -> Result<()> {
        self.command(&authenticate_command(auth, cookie)?)?
            .ok()
            .context("Tor refused the control authentication")?;
        self.authenticated = true;
        Ok(())
    }

    /// SAFECOOKIE (or, only if configured, plain COOKIE) with the cookie file checked
    /// before it is read.
    fn cookie_auth(&mut self, opts: &AuthOptions) -> Result<()> {
        let info = parse_protocolinfo(&self.command("PROTOCOLINFO 1")?.ok()?);
        let offers = |m: &str| info.methods.iter().any(|x| x == m);
        let safe = offers("SAFECOOKIE");
        if !safe {
            if !matches!(opts.auth, TorAuth::CookieInsecure) {
                bail!(
                    "the Tor control port does not offer SAFECOOKIE (methods: {}); plain COOKIE \
                     would hand the cookie to whatever answers there, set auth \"cookie_insecure\" \
                     to accept that",
                    info.methods.join(",")
                );
            }
            if !offers("COOKIE") {
                bail!(
                    "the Tor control port offers no cookie authentication (methods: {})",
                    info.methods.join(",")
                );
            }
        }
        let path = info
            .cookie_file
            .context("PROTOCOLINFO named no cookie file")?;
        if let Some(want) = &opts.cookie_path {
            if *want != path {
                bail!("the Tor control port names the cookie file {path}, configured is {want}");
            }
        }
        let cookie = read_cookie_file(&path, opts)?;
        if !safe {
            return self.send_authenticate(&opts.auth, Some(&cookie));
        }
        let client_nonce: [u8; 32] = rand::random();
        let reply = self
            .command(&format!("AUTHCHALLENGE SAFECOOKIE {}", hex(&client_nonce)))?
            .ok()?;
        let fields = reply
            .lines
            .iter()
            .find_map(|l| l.strip_prefix("AUTHCHALLENGE "))
            .map(parse_keywords)
            .context("AUTHCHALLENGE reply has no challenge")?;
        let field = |k: &str| {
            fields
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| unhex(v))
                .with_context(|| format!("AUTHCHALLENGE reply has no {k}"))?
        };
        let (server_hash, server_nonce) = (field("SERVERHASH")?, field("SERVERNONCE")?);
        if server_nonce.len() != 32 {
            bail!(
                "the Tor control port sent a server nonce of {} bytes",
                server_nonce.len()
            );
        }
        // The server must prove it knows the cookie before we send anything that depends
        // on it, let alone onion keys.
        safecookie_mac(SERVER_TO_CONTROLLER, &cookie, &client_nonce, &server_nonce)
            .verify_slice(&server_hash)
            .map_err(|_| {
                anyhow!(
                    "the Tor control port failed to prove it knows the cookie; \
                     something else may be listening there"
                )
            })?;
        let client_hash =
            safecookie_hash(CONTROLLER_TO_SERVER, &cookie, &client_nonce, &server_nonce);
        self.command(&format!("AUTHENTICATE {}", hex(&client_hash)))?
            .ok()
            .context("Tor refused the control authentication")?;
        self.authenticated = true;
        Ok(())
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
        if self.authenticated {
            let _ = self.command("QUIT");
        }
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

    // ── Authentication against a control port that may be an impostor ──

    use crate::test_support::{MockAuth, MockTorControl};

    const COOKIE: [u8; 32] = [0x5a; 32];

    /// A scratch directory holding a cookie file with `contents`.
    fn cookie_file(contents: &[u8]) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("sg-cookie-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control_auth_cookie");
        std::fs::write(&path, contents).unwrap();
        let s = path.to_string_lossy().into_owned();
        (dir, s)
    }

    fn safecookie_mock(path: &str, wrong_server_hash: bool) -> MockTorControl {
        MockTorControl::start_with(MockAuth::SafeCookie {
            cookie: COOKIE,
            cookie_path: path.to_string(),
            wrong_server_hash,
        })
    }

    fn connect(mock: &MockTorControl, opts: &AuthOptions) -> Result<Control> {
        Control::connect(&Endpoint::Tcp(mock.addr()), opts)
    }

    #[test]
    fn safecookie_authenticates_without_sending_the_cookie() {
        let (dir, path) = cookie_file(&COOKIE);
        let mock = safecookie_mock(&path, false);
        let mut c = connect(&mock, &mock.auth_options()).unwrap();
        let added = c
            .add_onion(&ServiceSpec {
                key: None,
                ports: vec![(80, "127.0.0.1:80".into())],
                clients: vec![],
            })
            .unwrap();
        assert!(added.private_key.is_some());
        drop(c);
        let cmds = mock.commands();
        assert_eq!(cmds[0], "PROTOCOLINFO 1");
        assert!(cmds[1].starts_with("AUTHCHALLENGE SAFECOOKIE "), "{cmds:?}");
        assert!(cmds[2].starts_with("AUTHENTICATE "));
        assert!(
            !cmds.iter().any(|c| c.contains(&hex(&COOKIE))),
            "the cookie itself must never be sent: {cmds:?}"
        );
        assert!(cmds[3].starts_with("ADD_ONION"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_server_that_cannot_prove_the_cookie_gets_nothing_more() {
        let (dir, path) = cookie_file(&COOKIE);
        let mock = safecookie_mock(&path, true);
        let err = connect(&mock, &mock.auth_options()).err().unwrap();
        assert!(err.to_string().contains("failed to prove"), "{err:#}");
        let cmds = mock.commands();
        assert_eq!(
            cmds.len(),
            2,
            "PROTOCOLINFO and AUTHCHALLENGE only: {cmds:?}"
        );
        assert!(cmds[1].starts_with("AUTHCHALLENGE"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn plain_cookie_is_refused_unless_configured() {
        let (dir, path) = cookie_file(&COOKIE);
        let mock = MockTorControl::start_with(MockAuth::CookieOnly {
            cookie: COOKIE,
            cookie_path: path,
        });
        let err = connect(&mock, &mock.auth_options()).err().unwrap();
        assert!(err.to_string().contains("SAFECOOKIE"), "{err:#}");
        assert_eq!(mock.commands(), ["PROTOCOLINFO 1"], "nothing was sent");

        let opts = AuthOptions {
            auth: TorAuth::CookieInsecure,
            ..mock.auth_options()
        };
        connect(&mock, &opts).unwrap();
        assert!(mock
            .commands()
            .contains(&format!("AUTHENTICATE {}", hex(&COOKIE))));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_cookie_file_that_is_not_32_bytes_is_not_read() {
        for contents in [vec![1u8; 33], vec![1u8; 4096], vec![]] {
            let (dir, path) = cookie_file(&contents);
            let mock = safecookie_mock(&path, false);
            let err = connect(&mock, &mock.auth_options()).err().unwrap();
            assert!(err.to_string().contains("not 32"), "{err:#}");
            assert_eq!(mock.commands(), ["PROTOCOLINFO 1"]);
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_cookie_file_is_refused() {
        let (dir, target) = cookie_file(&COOKIE);
        let link = format!("{target}.link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mock = safecookie_mock(&link, false);
        let err = connect(&mock, &mock.auth_options()).err().unwrap();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        assert_eq!(mock.commands(), ["PROTOCOLINFO 1"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_or_foreign_owner_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let (dir, path) = cookie_file(&COOKIE);
        // Not a regular file.
        let err = read_cookie_file(dir.to_str().unwrap(), &AuthOptions::default())
            .err()
            .unwrap();
        assert!(err.to_string().contains("not"), "{err:#}");
        // Owned by someone who is neither root nor trusted: only decidable as non-root.
        let uid = std::fs::metadata(&path).unwrap().uid();
        if uid != 0 {
            let none = AuthOptions::default();
            let err = read_cookie_file(&path, &none).err().unwrap();
            assert!(err.to_string().contains("owned by uid"), "{err:#}");
            // Trusted through the data directory, the pinned path or the uid.
            for opts in [
                AuthOptions {
                    cookie_dir: Some(dir.to_string_lossy().into_owned()),
                    ..none.clone()
                },
                AuthOptions {
                    cookie_path: Some(path.clone()),
                    ..none.clone()
                },
                AuthOptions {
                    expect_tor_uid: Some(uid),
                    ..none
                },
            ] {
                assert_eq!(read_cookie_file(&path, &opts).unwrap(), COOKIE);
            }
        }
        // Writable by others.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            let opts = AuthOptions {
                cookie_path: Some(path.clone()),
                ..AuthOptions::default()
            };
            let err = read_cookie_file(&path, &opts).err().unwrap();
            assert!(err.to_string().contains("writable"), "{err:#}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_cookie_file_must_be_the_configured_one() {
        let (dir, path) = cookie_file(&COOKIE);
        let mock = safecookie_mock(&path, false);
        let opts = AuthOptions {
            cookie_path: Some("/somewhere/else/control_auth_cookie".into()),
            ..mock.auth_options()
        };
        let err = connect(&mock, &opts).err().unwrap();
        assert!(err.to_string().contains("configured is"), "{err:#}");
        assert_eq!(mock.commands(), ["PROTOCOLINFO 1"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn no_authentication_is_refused_over_tcp() {
        let mock = MockTorControl::start();
        let opts = AuthOptions::new(TorAuth::None);
        let err = connect(&mock, &opts).err().unwrap();
        assert!(err.to_string().contains("Unix control socket"), "{err:#}");
        assert!(mock.commands().is_empty(), "nothing was sent");
        // The test-only escape hatch works.
        connect(&mock, &mock.auth_options()).unwrap();
    }

    #[test]
    fn a_wrong_cookie_is_not_authenticated_and_gets_no_keys() {
        // The mock expects another cookie than the file holds: AUTHENTICATE fails, so no
        // Control exists to send ADD_ONION on.
        let (dir, path) = cookie_file(&[9u8; 32]);
        let mock = safecookie_mock(&path, false);
        let err = connect(&mock, &mock.auth_options()).err().unwrap();
        assert!(err.to_string().contains("failed to prove"), "{err:#}");
        assert!(mock.add_commands().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_unix_control_socket_must_be_served_by_the_expected_uid() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("sg-ctl-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = unsafe { libc::geteuid() };
        let opts = AuthOptions {
            expect_tor_uid: Some(me + 1),
            ..AuthOptions::new(TorAuth::None)
        };
        let handle = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let err = Control::connect(&Endpoint::Unix(sock.to_string_lossy().into_owned()), &opts)
            .err()
            .unwrap();
        assert!(err.to_string().contains("expected"), "{err:#}");
        handle.join().unwrap();
        std::fs::remove_dir_all(dir).ok();
    }
}
