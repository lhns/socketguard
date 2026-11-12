//! A client for Yggdrasil's admin socket (`yggdrasilctl` is not shipped): JSON over a Unix
//! socket (Windows 10 and later have them too; `socket2` opens them on every system).
//!
//! The protocol (yggdrasil-go `src/admin/admin.go`, v0.5.15): the client sends one JSON
//! object `{"request": "<name>", "arguments": {..}, "keepalive": false}`, the node answers
//! `{"status": "success"|"error", "error": "..", "request": {..}, "response": {..}}` and,
//! without `keepalive`, closes the connection. Names are case-insensitive. The node reads at
//! most 1 MB of requests and waits 10 s for a request to arrive; the client enforces the
//! same bounds on the answer.
//!
//! A TCP admin endpoint is deliberately not spoken here: other local users could reach it.
//! Existing nodes that use one stay on `yggdrasilctl`.

use super::yggdrasil::{parse_get_self, NodeInfo, NodeProblem};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The most an answer may be, and how long the node gets to answer.
const MAX_ANSWER: u64 = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

/// The path of a `unix://` admin endpoint (`unix:///run/yggdrasil.sock`); None for any
/// other kind (a TCP endpoint, a bare `host:port`).
pub fn unix_endpoint(endpoint: &str) -> Option<PathBuf> {
    let path = endpoint.strip_prefix("unix://")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// One peer of the node, as `getPeers` lists it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PeerInfo {
    /// The peering URI (`tcp://host:port`).
    pub remote: String,
    pub up: bool,
    #[serde(default)]
    pub inbound: bool,
    /// The peer's public key, empty while it is down.
    #[serde(default)]
    pub key: String,
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    response: serde_json::Value,
}

pub struct AdminClient {
    path: PathBuf,
}

impl AdminClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Send `request` and return the `response` object of the answer as JSON text.
    pub fn request(&self, name: &str) -> Result<String> {
        let mut sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        sock.set_read_timeout(Some(DEADLINE))?;
        sock.set_write_timeout(Some(DEADLINE))?;
        sock.connect(&SockAddr::unix(&self.path)?)
            .with_context(|| format!("cannot connect to {}", self.path.display()))?;
        let request = serde_json::json!({ "request": name });
        sock.write_all(request.to_string().as_bytes())?;
        let mut answer = Vec::new();
        (&mut sock).take(MAX_ANSWER + 1).read_to_end(&mut answer)?;
        if answer.len() as u64 > MAX_ANSWER {
            bail!("the admin socket answered with more than 1 MB");
        }
        let envelope: Envelope =
            serde_json::from_slice(&answer).context("unreadable answer from the admin socket")?;
        if envelope.status != "success" {
            bail!("the admin socket refused {name}: {}", envelope.error);
        }
        Ok(envelope.response.to_string())
    }

    /// `getSelf`: the node's key, address and subnet.
    pub fn get_self(&self) -> Result<NodeInfo> {
        parse_get_self(&self.request("getself")?)
    }

    /// `getPeers`: every peering, connected or not.
    pub fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        parse_get_peers(&self.request("getpeers")?)
    }
}

/// The peers of a `getPeers` response.
pub fn parse_get_peers(json: &str) -> Result<Vec<PeerInfo>> {
    #[derive(Deserialize)]
    struct Peers {
        #[serde(default)]
        peers: Vec<PeerInfo>,
    }
    Ok(serde_json::from_str::<Peers>(json)
        .context("invalid getPeers JSON")?
        .peers)
}

/// How many of `peers` are connected now.
pub fn connected(peers: &[PeerInfo]) -> u32 {
    peers.iter().filter(|p| p.up).count() as u32
}

/// An existing node reached through a `unix://` admin endpoint.
pub struct AdminNode {
    client: AdminClient,
}

impl AdminNode {
    pub fn new(path: PathBuf) -> Self {
        Self {
            client: AdminClient::new(path),
        }
    }
}

impl super::yggdrasil::YggdrasilNode for AdminNode {
    fn get_self(&self) -> Result<NodeInfo> {
        self.client
            .get_self()
            .map_err(|e| NodeProblem::NotRunning(format!("{e:#}")).into())
    }
}

/// Real answers of the node, and a fake admin socket serving them: for the tests of this
/// module and of the engine.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use super::*;

    /// Real answers of Yggdrasil 0.5.15 (the build of `deploy/bundle/fetch.sh
    /// --build-yggdrasil`, run in Docker with a minimal config), read from its admin
    /// socket with `{"request":"getself"}` and `{"request":"getpeers"}`. Whitespace and the
    /// `request` echo are as the node sent them.
    pub const GET_SELF_ANSWER: &str = r#"{
  "status": "success",
  "request": {
    "request": "getself",
    "arguments": {}
  },
  "response": {
    "build_name": "yggdrasil",
    "build_version": "0.5.15",
    "key": "58926089882365c29f6aaf27fc64955554ff9568c78a5e17d9d87dba8ed1c44d",
    "address": "201:9db6:7dd9:df72:68f5:8255:4360:e6d",
    "routing_entries": 1,
    "subnet": "301:9db6:7dd9:df72::/64"
  }
}
"#;

    pub const GET_PEERS_ANSWER: &str = r#"{
  "status": "success",
  "request": {
    "request": "getpeers",
    "arguments": {}
  },
  "response": {
    "peers": [
      {
        "remote": "tcp://sg-w-b:9001",
        "up": true,
        "inbound": false,
        "address": "200:fde4:98b9:8616:1129:dd78:7424:3345",
        "key": "810db3a33cf4f76b1143c5ede65d4a149d87938d5650b41887b365fdd21e0865",
        "port": 1,
        "priority": 0,
        "cost": 3,
        "bytes_recvd": 619,
        "bytes_sent": 562,
        "uptime": 10.172117128,
        "latency": 2200000
      },
      {
        "remote": "tcp://sg-w-x:9001",
        "up": false,
        "inbound": false,
        "key": "",
        "port": 0,
        "priority": 0,
        "cost": 0,
        "last_error_time": 725138405,
        "last_error": "lookup sg-w-x on 127.0.0.11:53: no such host"
      }
    ]
  }
}
"#;

    pub const ERROR_ANSWER: &str = r#"{
  "status": "error",
  "error": "unknown action 'nope', try 'list' for help",
  "request": {
    "request": "nope",
    "arguments": {}
  },
  "response": null
}
"#;

    /// Serves one canned answer per connection on a Unix socket in a temp directory, and
    /// records the requests it got.
    pub struct FakeAdmin {
        pub path: PathBuf,
        pub requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FakeAdmin {
        /// `answers` maps a request name to the bytes to send back; any other request is
        /// answered with [`ERROR_ANSWER`].
        pub fn start(answers: Vec<(&'static str, String)>) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("sg-adm-{}", &uuid::Uuid::new_v4().to_string()[..8]));
            std::fs::create_dir_all(&dir).unwrap();
            Self::start_at(&dir.join("a.sock"), answers)
        }

        /// [`FakeAdmin::start`] at `path`.
        pub fn start_at(path: &Path, answers: Vec<(&'static str, String)>) -> Self {
            let path = path.to_path_buf();
            let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
            listener.listen(8).unwrap();
            let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = requests.clone();
            std::thread::spawn(move || {
                while let Ok((mut conn, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let n = conn.read(&mut buf).unwrap_or(0);
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    seen.lock().unwrap().push(text.clone());
                    let name = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v["request"].as_str().map(str::to_ascii_lowercase))
                        .unwrap_or_default();
                    let answer = answers
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, a)| a.clone())
                        .unwrap_or_else(|| ERROR_ANSWER.to_string());
                    let _ = conn.write_all(answer.as_bytes());
                }
            });
            Self { path, requests }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    fn admin() -> FakeAdmin {
        FakeAdmin::start(vec![
            ("getself", GET_SELF_ANSWER.to_string()),
            ("getpeers", GET_PEERS_ANSWER.to_string()),
        ])
    }

    #[test]
    fn get_self_reads_the_real_answer() {
        let a = admin();
        let info = AdminClient::new(&a.path).get_self().unwrap();
        assert_eq!(
            info.key,
            "58926089882365c29f6aaf27fc64955554ff9568c78a5e17d9d87dba8ed1c44d"
        );
        assert_eq!(
            info.address,
            "201:9db6:7dd9:df72:68f5:8255:4360:e6d"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(info.subnet.len, 64);
        assert_eq!(
            a.requests.lock().unwrap().as_slice(),
            [r#"{"request":"getself"}"#]
        );
    }

    #[test]
    fn get_peers_reads_up_and_down_peers() {
        let a = admin();
        let peers = AdminClient::new(&a.path).get_peers().unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers[0].up && !peers[0].inbound && peers[0].remote == "tcp://sg-w-b:9001");
        assert!(peers[0].key.starts_with("810db3a3"));
        assert!(!peers[1].up && peers[1].key.is_empty());
        assert_eq!(connected(&peers), 1);
        assert_eq!(parse_get_peers(r#"{"peers": []}"#).unwrap(), vec![]);
        assert!(parse_get_peers("5").is_err());
    }

    #[test]
    fn an_error_answer_is_an_error_with_the_nodes_words() {
        let a = admin();
        let e = AdminClient::new(&a.path).request("nope").unwrap_err();
        assert!(format!("{e:#}").contains("unknown action 'nope'"), "{e:#}");
    }

    #[test]
    fn an_answer_over_the_cap_is_refused() {
        let big = format!(
            r#"{{"status":"success","response":{{"x":"{}"}}}}"#,
            "a".repeat(MAX_ANSWER as usize)
        );
        let a = FakeAdmin::start(vec![("getself", big)]);
        let e = AdminClient::new(&a.path).request("getself").unwrap_err();
        assert!(format!("{e:#}").contains("more than 1 MB"), "{e:#}");
    }

    #[test]
    fn garbage_and_a_missing_socket_are_errors() {
        let a = FakeAdmin::start(vec![("getself", "not json".into())]);
        assert!(AdminClient::new(&a.path).get_self().is_err());
        let gone = a.path.with_file_name("none.sock");
        let e = AdminClient::new(&gone).get_self().unwrap_err();
        assert!(format!("{e:#}").contains("cannot connect"), "{e:#}");
    }

    #[test]
    fn only_unix_endpoints_are_spoken_here() {
        assert_eq!(
            unix_endpoint("unix:///var/run/yggdrasil.sock"),
            Some(PathBuf::from("/var/run/yggdrasil.sock"))
        );
        assert_eq!(unix_endpoint("tcp://localhost:9001"), None);
        assert_eq!(unix_endpoint("localhost:9001"), None);
        assert_eq!(unix_endpoint("unix://"), None);
    }
}
