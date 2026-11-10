//! The real `socketguard` binary against an in-process daemon (mock firewall, network and
//! socket monitor from `test_support`) on a temporary Unix socket or named pipe.

use serde_json::Value;
use socketguard_core::{ListeningSocket, Protocol};
use socketguard_daemon::test_support::{standard_daemon, StandardDaemon};
use socketguard_daemon::{api, transport};
use std::net::IpAddr;
use std::path::PathBuf;

const KEY: &str = "ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b";

fn listener(name: &str, port: u16) -> ListeningSocket {
    ListeningSocket {
        pid: 1000,
        process_name: name.to_string(),
        port,
        protocol: Protocol::Tcp,
        bind_address: IpAddr::V6("::".parse().unwrap()),
        exe_path: Some(format!("/usr/bin/{name}")),
        cmdline: Some(vec![name.to_string()]),
        uid: Some("1000".into()),
        foreign_mntns: false,
        cwd: None,
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{}", self.stdout, self.stderr))
    }
}

struct Env {
    daemon: StandardDaemon,
    endpoint: String,
    dir: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Env {
    async fn start() -> Self {
        Self::start_with(vec![listener("nginx", 80)]).await
    }

    async fn start_with(sockets: Vec<ListeningSocket>) -> Self {
        let dir = std::env::temp_dir().join(format!("sg-cli-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let daemon = standard_daemon(sockets, Some(dir.join("sg.json"))).await;
        reconcile(&daemon).await;

        #[cfg(unix)]
        let (server, endpoint) = {
            let path = dir.join("sg.sock");
            let server = transport::bind_unix(&path, "no-such-group-sg-test").unwrap();
            (server, path.to_str().unwrap().to_string())
        };
        #[cfg(windows)]
        let (server, endpoint) = {
            // The test daemon is not SYSTEM, which the client would otherwise insist on.
            std::env::set_var("SOCKETGUARD_TRUST_PIPE_SERVER", "1");
            let name = format!(
                r"\\.\pipe\socketguard-cli-test-{}",
                uuid::Uuid::new_v4().simple()
            );
            // Everyone: the production ACL does not admit an unelevated administrator.
            (transport::bind_pipe(&name, "D:(A;;GA;;;WD)").unwrap(), name)
        };

        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let app = api::router(daemon.state.clone());
        let done = tokio::spawn(server.serve(app, async {
            let _ = rx.await;
        }));
        Self {
            daemon,
            endpoint,
            dir,
            stop: Some(stop),
            done,
        }
    }

    fn client(&self) -> socketguard_client::Client {
        socketguard_client::Client::new(&self.endpoint)
    }

    /// Run `socketguard args...` with the daemon's endpoint, off the async runtime.
    async fn sg(&self, args: &[&str]) -> Out {
        let endpoint = self.endpoint.clone();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        tokio::task::spawn_blocking(move || {
            let out = assert_cmd::Command::new(env!("CARGO_BIN_EXE_socketguard"))
                .env("SOCKETGUARD_SOCKET", endpoint)
                .args(args)
                .timeout(std::time::Duration::from_secs(30))
                .output()
                .unwrap();
            Out {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        })
        .await
        .unwrap()
    }

    /// Like `sg`, but the command must succeed.
    async fn ok(&self, args: &[&str]) -> Out {
        let out = self.sg(args).await;
        assert_eq!(
            out.code, 0,
            "{args:?} failed:\n{}\n{}",
            out.stdout, out.stderr
        );
        out
    }

    /// Like `sg`, but the command must fail with exit code 1.
    async fn fails(&self, args: &[&str]) -> Out {
        let out = self.sg(args).await;
        assert_eq!(
            out.code, 1,
            "{args:?} should fail:\n{}\n{}",
            out.stdout, out.stderr
        );
        out
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), self.done).await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn reconcile(d: &StandardDaemon) {
    d.state
        .engine
        .write()
        .await
        .reconcile(&d.state)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_grants_and_revoke() {
    let env = Env::start().await;

    let out = env.ok(&["peers", "add", "bnode", "--key", KEY]).await;
    assert!(out.stdout.contains("added peer bnode"), "{}", out.stdout);
    let peers = env.ok(&["--json", "peers", "list"]).await.json();
    assert_eq!(peers[0]["label"], "bnode");
    assert_eq!(peers[0]["credentials"][0]["kind"], "ygg_key");

    let apps = env.ok(&["apps", "list", "--json"]).await.json();
    assert_eq!(apps[0]["name"], "nginx");
    let app_id = apps[0]["id"].as_str().unwrap().to_string();
    assert!(env
        .ok(&["apps", "list", "--pending"])
        .await
        .stdout
        .contains("pending"));

    // Granting by name, by id prefix, with a port and a network.
    env.ok(&["grant", "nginx:80", "bnode", "--network", "ygg"])
        .await;
    let grants = env.ok(&["grants", "--json"]).await.json();
    assert_eq!(grants.as_array().unwrap().len(), 1);
    assert_eq!(grants[0]["reach"][0]["reach"], "verified");
    let show = env.ok(&["apps", "show", &app_id[..8]]).await;
    assert!(
        show.stdout.contains("verified") && show.stdout.contains("bnode"),
        "{}",
        show.stdout
    );
    // A duplicate is a conflict, reported with its code.
    let dup = env
        .fails(&["grant", "nginx:80", "bnode", "--network", "ygg"])
        .await;
    assert!(dup.stderr.starts_with("error: conflict:"), "{}", dup.stderr);

    // Anyone needs --yes when there is no terminal.
    let refused = env.fails(&["grant", "nginx", "anyone"]).await;
    assert!(refused.stderr.contains("--yes"), "{}", refused.stderr);
    env.ok(&["grant", "nginx", "anyone", "--yes"]).await;
    assert_eq!(
        env.ok(&["grants", "--json"])
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    env.ok(&["revoke", "nginx", "anyone"]).await;

    // Revoking by app, port and subject; then it is gone.
    env.ok(&["revoke", "nginx:80", "bnode"]).await;
    assert_eq!(
        env.ok(&["grants", "--json"]).await.json(),
        serde_json::json!([])
    );
    let gone = env.fails(&["revoke", "nginx:80", "bnode"]).await;
    assert!(gone.stderr.contains("no such grant"), "{}", gone.stderr);

    // Revoking by grant id.
    env.ok(&["grant", "nginx", "bnode"]).await;
    let id = env.ok(&["grants", "--json"]).await.json()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    env.ok(&["revoke", &id[..8]]).await;

    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_status_and_everything_else() {
    let env = Env::start().await;

    // Errors carry the code; unknown names list what was meant.
    let e = env.fails(&["apps", "show", "nosuchapp"]).await;
    assert!(e.stderr.contains("no app matches"), "{}", e.stderr);
    let e = env.fails(&["--json", "peers", "show", "nobody"]).await;
    assert!(e.stderr.contains("no peer matches"), "{}", e.stderr);
    let e = env
        .fails(&["--socket", "/definitely/not/here.sock", "status"])
        .await;
    assert!(e.stderr.contains("cannot reach the daemon"), "{}", e.stderr);
    assert_eq!(env.sg(&["bogus"]).await.code, 2, "usage errors exit with 2");

    let status = env.ok(&["status", "--json"]).await.json();
    assert_eq!(status["disabled"], false);
    assert_eq!(status["counts"]["apps"], 1);
    let human = env.ok(&["status"]).await.stdout;
    assert!(
        human.contains("enforcement   on") && human.contains("ygg"),
        "{human}"
    );

    // Peers: credentials guessed from bare values, groups, rename.
    env.ok(&["peers", "add", "carol", KEY, "--addr", "2001:db8::7"])
        .await;
    let carol = env.ok(&["peers", "show", "carol", "--json"]).await.json();
    let kinds: Vec<&str> = carol["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.len(), 2, "{carol}");
    let e = env
        .fails(&["peers", "add", "dave", "not-a-credential"])
        .await;
    assert!(e.stderr.contains("--cred kind=value"), "{}", e.stderr);
    let cred_id = carol["credentials"][1]["id"].as_str().unwrap().to_string();
    env.ok(&["peers", "cred", "rm", "carol", &cred_id[..8]])
        .await;
    env.ok(&["peers", "cred", "add", "carol", "ip=2001:db8::8"])
        .await;
    env.ok(&["peers", "rename", "carol", "caroline"]).await;
    env.ok(&["groups", "add", "team", "caroline"]).await;
    env.ok(&["groups", "members", "team", "caroline"]).await;
    assert!(env
        .ok(&["groups", "show", "team"])
        .await
        .stdout
        .contains("caroline"));
    env.ok(&["grant", "nginx:80", "group:team"]).await;
    let by_group = env
        .ok(&["grants", "--group", "team", "--json"])
        .await
        .json();
    assert_eq!(by_group.as_array().unwrap().len(), 1);
    env.ok(&["groups", "rename", "team", "crew"]).await;
    env.ok(&["groups", "rm", "crew"]).await;
    env.ok(&["peers", "rm", "caroline"]).await;
    assert_eq!(
        env.ok(&["grants", "--json"]).await.json(),
        serde_json::json!([])
    );

    // Share: connection strings, URL for web ports.
    let share = env.ok(&["share", "nginx", "--network", "ygg"]).await.stdout;
    let lines: Vec<&str> = share.lines().collect();
    assert_eq!(lines.len(), 2, "{share}");
    assert!(
        lines[0].starts_with("[300:1:2:3:") && lines[0].ends_with("]:80"),
        "{share}"
    );
    assert!(lines[1].starts_with("http://[300:1:2:3:"), "{share}");

    // Split and merge.
    env.ok(&["apps", "split", "nginx", "--network", "ygg", "80/tcp"])
        .await;
    let detail = env.ok(&["apps", "show", "nginx", "--json"]).await.json();
    let ids: Vec<String> = detail["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["network_id"] == "ygg")
        .map(|a| a["id"].as_str().unwrap()[..10].to_string())
        .collect();
    assert_eq!(ids.len(), 2);
    let mut merge = vec!["apps", "merge", "nginx", "--network", "ygg"];
    merge.extend(ids.iter().map(String::as_str));
    env.ok(&merge).await;

    // Review, settings, networks (and the config file).
    env.ok(&["apps", "review", "nginx", "--unreviewed"]).await;
    assert!(env.ok(&["pending"]).await.stdout.contains("nginx"));
    env.ok(&["apps", "review", "nginx"]).await;
    env.ok(&["settings", "address-mode", "per-port"]).await;
    assert!(env
        .ok(&["settings", "show"])
        .await
        .stdout
        .contains("per-port"));
    let nets = env.ok(&["networks", "list", "--json"]).await.json();
    assert_eq!(nets.as_array().unwrap().len(), 3);
    env.ok(&["networks", "rm", "lan"]).await;
    let saved = std::fs::read_to_string(env.dir.join("sg.json")).unwrap();
    assert!(!saved.contains("\"lan\""), "{saved}");
    let e = env.fails(&["networks", "add", "slaac"]).await;
    assert!(e.stderr.contains("--interface is required"), "{}", e.stderr);

    // Protect-host: refused with the risks, then forced.
    env.daemon
        .sockets
        .lock()
        .unwrap()
        .push(listener("sshd", 22));
    reconcile(&env.daemon).await;
    let refused = env.fails(&["protect-host", "on", "eth0"]).await;
    assert!(
        refused.stderr.contains("sshd") && refused.stderr.contains("--force"),
        "{}",
        refused.stderr
    );
    assert!(env
        .ok(&["protect-host", "status"])
        .await
        .stdout
        .contains("off"));
    env.ok(&["protect-host", "on", "eth0", "--force"]).await;
    assert!(env
        .ok(&["protect-host", "status"])
        .await
        .stdout
        .contains("eth0"));
    env.ok(&["protect-host", "off"]).await;

    // Activity.
    let all = env.ok(&["activity", "--json"]).await.json();
    assert!(all.as_array().unwrap().len() >= 2);
    assert!(env
        .ok(&["activity", "--app", "nginx"])
        .await
        .stdout
        .contains("app_discovered"));
    assert_eq!(
        env.ok(&["activity", "--blocked", "--json"]).await.json(),
        serde_json::json!([])
    );

    // Completions.
    let c = env.ok(&["completions", "bash"]).await.stdout;
    assert!(c.contains("socketguard"));

    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn export_apply_and_disable() {
    let env = Env::start().await;
    env.ok(&["peers", "add", "bnode", "--key", KEY]).await;
    env.ok(&["grant", "nginx:80", "bnode"]).await;

    // TOML by default, JSON by extension or flag.
    let toml_path = env.dir.join("sg.toml");
    let json_path = env.dir.join("sg.json.export");
    env.ok(&["export", "-o", toml_path.to_str().unwrap()]).await;
    let text = std::fs::read_to_string(&toml_path).unwrap();
    assert!(
        text.contains("bnode") && text.contains("[[grants]]"),
        "{text}"
    );
    env.ok(&[
        "export",
        "--format",
        "json",
        "-o",
        json_path.to_str().unwrap(),
    ])
    .await;
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(doc["peers"][0]["label"], "bnode");
    assert_eq!(env.ok(&["export", "--json"]).await.json(), doc);

    // Applying what was exported changes nothing.
    let same = env
        .ok(&["apply", "-f", toml_path.to_str().unwrap(), "--dry-run"])
        .await;
    assert!(same.stdout.contains("no changes"), "{}", same.stdout);

    // Edit the file: one more peer, and no grant.
    let mut doc = socketguard_cli::document::parse(&text, &toml_path).unwrap();
    doc.grants.clear();
    doc.peers.push(socketguard_core::api_types::ExportPeer {
        label: "carol".into(),
        credentials: vec![],
    });
    let path = env.dir.join("edited.toml");
    std::fs::write(&path, socketguard_cli::document::text(&doc, false).unwrap()).unwrap();
    let p = path.to_str().unwrap();

    let dry = env.ok(&["apply", "-f", p, "--dry-run"]).await;
    assert!(
        dry.stdout.contains("+ peer carol") && dry.stdout.contains("- grant"),
        "{}",
        dry.stdout
    );
    assert_eq!(
        env.ok(&["peers", "list", "--json"])
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Without a terminal, applying needs --yes.
    let e = env.fails(&["apply", "-f", p]).await;
    assert!(e.stderr.contains("--yes"), "{}", e.stderr);
    let done = env.ok(&["apply", "-f", p, "--yes"]).await;
    assert!(
        done.stdout.contains("applied 2 change(s)"),
        "{}",
        done.stdout
    );
    assert_eq!(
        env.ok(&["peers", "list", "--json"])
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        env.ok(&["grants", "--json"]).await.json(),
        serde_json::json!([])
    );
    let bad = env
        .fails(&[
            "apply",
            "-f",
            env.dir.join("missing.toml").to_str().unwrap(),
        ])
        .await;
    assert!(bad.stderr.contains("reading"), "{}", bad.stderr);

    // Disable stays off until enable.
    let e = env.fails(&["disable"]).await;
    assert!(e.stderr.contains("--yes"), "{}", e.stderr);
    env.ok(&["disable", "--yes"]).await;
    assert_eq!(env.ok(&["status", "--json"]).await.json()["disabled"], true);
    assert!(env.ok(&["status"]).await.stdout.contains("DISABLED"));
    env.ok(&["enable"]).await;
    assert_eq!(
        env.ok(&["status", "--json"]).await.json()["disabled"],
        false
    );

    env.stop().await;
}

// ─── Interactive flows (scripted prompter, in-process client) ─────────────────

use socketguard_cli::commands::Ctx;
use socketguard_cli::flows::{init, pending};
use socketguard_cli::prompt::Prompter;
use socketguard_core::api_types::NewPeer;
use socketguard_core::{GrantView, Subject};
use std::collections::VecDeque;

/// What the user types, in order.
enum A {
    Say(&'static str),
    Yes,
    No,
    Pick(usize),
}

struct Script {
    answers: VecDeque<A>,
    asked: Vec<String>,
}

impl Script {
    fn new(answers: Vec<A>) -> Self {
        Self {
            answers: answers.into(),
            asked: Vec::new(),
        }
    }

    fn next(&mut self, question: &str) -> A {
        self.asked.push(question.to_string());
        self.answers
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected question {question:?}"))
    }

    fn finished(&self) {
        assert!(
            self.answers.is_empty(),
            "unused answers; asked {:?}",
            self.asked
        );
    }
}

impl Prompter for Script {
    fn interactive(&self) -> bool {
        true
    }
    fn ask(&mut self, q: &str) -> String {
        match self.next(q) {
            A::Say(s) => s.to_string(),
            _ => panic!("{q:?} wants text"),
        }
    }
    fn confirm(&mut self, q: &str) -> bool {
        match self.next(q) {
            A::Yes => true,
            A::No => false,
            _ => panic!("{q:?} wants yes or no"),
        }
    }
    fn choose(&mut self, q: &str, options: &[String]) -> Option<usize> {
        match self.next(q) {
            A::Pick(n) => {
                assert!(n < options.len(), "{q:?}: option {n} of {options:?}");
                Some(n)
            }
            _ => panic!("{q:?} wants a choice"),
        }
    }
}

async fn ip_peer(env: &Env, label: &str, ip: &str) -> socketguard_core::Peer {
    env.client()
        .create_peer(&NewPeer {
            label: label.into(),
            credentials: vec![socketguard_cli::parse::guess_credential(ip).unwrap()],
        })
        .await
        .unwrap()
}

/// Whether the only app is reviewed, and its grants.
async fn the_app(env: &Env) -> (bool, Vec<GrantView>) {
    let c = env.client();
    let id = c.list_apps(false).await.unwrap()[0].id.clone();
    let d = c.get_app(&id).await.unwrap();
    (d.app.reviewed, d.grants)
}

/// Run `pending` with `answers` on a daemon with one pending app (nginx) and a peer.
async fn run_pending(answers: Vec<A>) -> (Env, Script) {
    let env = Env::start().await;
    ip_peer(&env, "friend", "2001:db8::7").await;
    let mut script = Script::new(answers);
    pending(&Ctx::new(env.client(), false), &mut script)
        .await
        .unwrap();
    script.finished();
    (env, script)
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_keep_closed_marks_the_app_reviewed() {
    let (env, _) = run_pending(vec![A::Pick(0)]).await;
    let (reviewed, grants) = the_app(&env).await;
    assert!(reviewed && grants.is_empty());
    assert!(env.client().list_apps(true).await.unwrap().is_empty());
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_grant_to_an_existing_peer_creates_the_grant() {
    // grant, then the first peer in the list.
    let (env, script) = run_pending(vec![A::Pick(1), A::Pick(0)]).await;
    assert!(script.asked.iter().any(|q| q == "Grant to:"));
    let (reviewed, grants) = the_app(&env).await;
    let friend = env.client().list_peers().await.unwrap()[0].id.clone();
    assert!(reviewed);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].grant.subject, Subject::Peer(friend));
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_open_to_anyone_needs_the_confirmation() {
    let (env, _) = run_pending(vec![A::Pick(2), A::Yes]).await;
    let (reviewed, grants) = the_app(&env).await;
    assert!(reviewed);
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].grant.subject, Subject::Anyone);
    env.stop().await;

    let (env, _) = run_pending(vec![A::Pick(2), A::No]).await;
    let (reviewed, grants) = the_app(&env).await;
    assert!(!reviewed && grants.is_empty(), "declined: nothing created");
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_skip_leaves_the_app_pending() {
    let (env, _) = run_pending(vec![A::Pick(3)]).await;
    let (reviewed, grants) = the_app(&env).await;
    assert!(!reviewed && grants.is_empty());
    assert_eq!(env.client().list_apps(true).await.unwrap().len(), 1);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn init_offers_a_grant_for_sshd_and_checks_protect_host_for_lockout() {
    // sshd stays closed: protect-host is refused and declined.
    let env = Env::start_with(vec![listener("sshd", 22)]).await;
    let mut script = Script::new(vec![
        A::Pick(1), // keep sshd closed
        A::Yes,     // turn on protect-host
        A::Say(""), // the default interfaces (the LAN)
        A::No,      // not anyway
    ]);
    init(&Ctx::new(env.client(), false), &mut script)
        .await
        .unwrap();
    script.finished();
    assert!(script
        .asked
        .iter()
        .any(|q| q.starts_with("What should happen to sshd")));
    assert!(env
        .client()
        .status()
        .await
        .unwrap()
        .protect_host_interfaces
        .is_empty());
    env.stop().await;

    // Granting sshd to a peer first lets protect-host through.
    let env = Env::start_with(vec![listener("sshd", 22)]).await;
    ip_peer(&env, "admin", "2001:db8::7").await;
    let mut script = Script::new(vec![
        A::Pick(0), // grant to a peer or group
        A::Pick(0), // admin
        A::Yes,
        A::Say("eth0"),
    ]);
    init(&Ctx::new(env.client(), false), &mut script)
        .await
        .unwrap();
    script.finished();
    let (reviewed, grants) = the_app(&env).await;
    assert_eq!(grants.len(), 1);
    // One port was granted; the app as a whole is still undecided.
    assert!(!reviewed);
    assert_eq!(
        env.client().status().await.unwrap().protect_host_interfaces,
        ["eth0"]
    );
    env.stop().await;
}
