//! `socketguard networks setup <yggdrasil|tor>` (ADR 0048): install, start and configure
//! the software behind a network, then add the network. It runs with administrator rights
//! and shows each step before it runs. Everything it does to the system goes through a
//! [`SetupRunner`] and everything it asks the daemon through a [`DaemonApi`], so the tests
//! use fakes.
//!
//! What it trusts: the Tor cookie file is never taken from the control port (whoever
//! listens there would name it). The path comes from the torrc, which the command locates
//! itself; the port is only asked to agree.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use socketguard_core::api_types::NewNetwork;
use socketguard_core::config::{BackendConfig, TorAuth};
use socketguard_core::setup::{
    download_link, install_command, NetworkSetup, SetupKind, SetupState, SetupStatus,
};
use socketguard_core::{Network, NetworkKind, NetworkStatus};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A step that needs a person: printed, and the command exits non-zero.
#[derive(Debug)]
pub struct ManualStep(pub String);

impl std::fmt::Display for ManualStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "manual step needed: {}", self.0)
    }
}

impl std::error::Error for ManualStep {}

fn manual<T>(msg: impl Into<String>) -> Result<T> {
    Err(ManualStep(msg.into()).into())
}

/// The command line options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub yes: bool,
    pub dry_run: bool,
    /// The daemon's config file; else the one the daemon reports.
    pub config: Option<PathBuf>,
    /// The torrc, when it is not in a standard place.
    pub torrc: Option<PathBuf>,
}

/// What the control port answers to PROTOCOLINFO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlAnswer {
    pub methods: Vec<String>,
    pub cookie_file: Option<String>,
}

/// Everything the command does to the system.
pub trait SetupRunner {
    fn os(&self) -> &'static str;
    fn is_elevated(&self) -> bool;
    fn has_program(&self, name: &str) -> bool;
    /// Run a program with its output on the terminal; an error if it fails.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<()>;
    /// The file's text; None if it does not exist.
    fn read_file(&self, path: &Path) -> Result<Option<String>>;
    /// Replace the file through a temp file and a rename.
    fn write_file(&mut self, path: &Path, content: &str) -> Result<()>;
    /// PROTOCOLINFO at `control` (`host:port` or `unix:/path`); an error if nothing answers.
    fn protocolinfo(&mut self, control: &str) -> Result<ControlAnswer>;
    fn sleep(&mut self, d: Duration);
    /// A line of output.
    fn say(&mut self, line: &str);
    /// Ask to proceed (only called without `--yes`).
    fn confirm(&mut self, question: &str) -> bool;
}

/// What the command asks the daemon.
#[allow(async_fn_in_trait)]
pub trait DaemonApi {
    async fn setup(&self) -> Result<NetworkSetup>;
    async fn networks(&self) -> Result<Vec<Network>>;
    async fn add(&self, req: &NewNetwork) -> Result<Network>;
}

impl DaemonApi for socketguard_client::Client {
    async fn setup(&self) -> Result<NetworkSetup> {
        Ok(self.network_setup().await?)
    }
    async fn networks(&self) -> Result<Vec<Network>> {
        Ok(self.list_networks().await?)
    }
    async fn add(&self, req: &NewNetwork) -> Result<Network> {
        Ok(self.add_network(req).await?)
    }
}

fn state_of(setup: &NetworkSetup, kind: SetupKind) -> &SetupState {
    match kind {
        SetupKind::Yggdrasil => &setup.yggdrasil,
        SetupKind::Tor => &setup.tor,
    }
}

/// What a run changed, for the summary (the daemon records no activity for it).
#[derive(Debug, Default)]
pub struct Changes(Vec<String>);

impl Changes {
    pub fn list(&self) -> &[String] {
        &self.0
    }
}

struct Ctx<'a, R: SetupRunner, A: DaemonApi> {
    kind: SetupKind,
    opts: &'a Options,
    run: &'a mut R,
    api: &'a A,
    changes: Changes,
    step: usize,
}

impl<R: SetupRunner, A: DaemonApi> Ctx<'_, R, A> {
    /// Announce a step; false (and not run) in a dry run.
    fn announce(&mut self, text: &str) -> bool {
        self.step += 1;
        let n = self.step;
        if self.opts.dry_run {
            self.run.say(&format!("{n}. would: {text}"));
            false
        } else {
            self.run.say(&format!("{n}. {text}"));
            true
        }
    }

    fn skip(&mut self, text: &str) {
        self.step += 1;
        let n = self.step;
        self.run.say(&format!("{n}. already done: {text}"));
    }

    async fn refetch(&mut self) -> Result<SetupState> {
        let s = self.api.setup().await?;
        Ok(state_of(&s, self.kind).clone())
    }

    /// Poll the daemon's detection until `done`, for up to ~15 s.
    async fn wait_for(&mut self, done: impl Fn(&SetupState) -> bool) -> Result<SetupState> {
        let mut state = self.refetch().await?;
        for _ in 0..30 {
            if done(&state) {
                break;
            }
            self.run.sleep(Duration::from_millis(500));
            state = self.refetch().await?;
        }
        Ok(state)
    }
}

/// Run the setup of `kind`. Returns what it changed. A step that needs a person is a
/// [`ManualStep`] error.
pub async fn run<R: SetupRunner, A: DaemonApi>(
    kind: SetupKind,
    opts: &Options,
    runner: &mut R,
    api: &A,
) -> Result<Changes> {
    if !opts.dry_run && !runner.is_elevated() {
        bail!(
            "networks setup changes the system and needs administrator rights: {}",
            if runner.os() == "windows" {
                "run it from an elevated terminal (Run as administrator)"
            } else {
                "run it with sudo"
            }
        );
    }
    let setup = api.setup().await.context(
        "cannot ask the daemon what is installed; start the daemon (and use --socket if it \
         listens elsewhere)",
    )?;
    let mut c = Ctx {
        kind,
        opts,
        run: runner,
        api,
        changes: Changes::default(),
        step: 0,
    };
    if !opts.yes && !opts.dry_run {
        // Show the steps first (a dry run of the same code), then ask.
        let dry = Options {
            dry_run: true,
            ..opts.clone()
        };
        let mut preview = Ctx {
            kind,
            opts: &dry,
            run: &mut *c.run,
            api,
            changes: Changes::default(),
            step: 0,
        };
        preview.run.say("These are the steps:");
        match steps(&mut preview, &setup).await {
            Ok(()) | Err(_) => {}
        }
        if !c.run.confirm("Proceed?") {
            c.run.say("Not confirmed; nothing changed.");
            return Ok(Changes::default());
        }
        c.step = 0;
    }
    steps(&mut c, &setup).await?;
    Ok(c.changes)
}

async fn steps<R: SetupRunner, A: DaemonApi>(
    c: &mut Ctx<'_, R, A>,
    setup: &NetworkSetup,
) -> Result<()> {
    let state = state_of(setup, c.kind).clone();
    if state.state == SetupStatus::Added {
        c.run
            .say(&format!("{} is already a network; nothing to do.", c.kind));
        return Ok(());
    }
    let state = install(c, state).await?;
    match c.kind {
        SetupKind::Yggdrasil => yggdrasil(c, state).await,
        SetupKind::Tor => tor(c, state, setup.config_path.as_deref()).await,
    }
}

/// Step 1: install, where a package is known; else the official download page.
async fn install<R: SetupRunner, A: DaemonApi>(
    c: &mut Ctx<'_, R, A>,
    state: SetupState,
) -> Result<SetupState> {
    if state.state != SetupStatus::NotInstalled {
        c.skip(&format!("{} is installed", c.kind));
        return Ok(state);
    }
    let cmd = install_command(c.kind, c.run.os(), &|m| c.run.has_program(m));
    let Some(cmd) = cmd else {
        c.announce(&format!("install {} by hand", c.kind));
        return manual(format!(
            "no package to install {} on this system. Download it from {}, install it, then run \
             this command again.",
            c.kind,
            download_link(c.kind)
        ));
    };
    if !c.announce(&format!("install {} with {}", c.kind, cmd.command_line())) {
        // A dry run goes on as if it had worked.
        return Ok(SetupState::new(SetupStatus::NotRunning));
    }
    c.run
        .run(cmd.program, &cmd.args)
        .with_context(|| format!("{} failed", cmd.command_line()))?;
    c.changes
        .0
        .push(format!("installed {} ({})", c.kind, cmd.command_line()));
    // The daemon may have an old PATH; its detection also looks in the install directory.
    let state = c.wait_for(|s| s.state != SetupStatus::NotInstalled).await?;
    if state.state == SetupStatus::NotInstalled {
        return manual(format!(
            "{} was installed but the daemon does not see it. Restart the daemon, then run this \
             command again.",
            c.kind
        ));
    }
    Ok(state)
}

/// How to start the Yggdrasil service on this system (documented by the project; the
/// Windows service name is the installer's).
fn yggdrasil_start(os: &str) -> Option<(&'static str, Vec<&'static str>)> {
    match os {
        "windows" => Some(("sc.exe", vec!["start", "Yggdrasil"])),
        "linux" => Some(("systemctl", vec!["enable", "--now", "yggdrasil"])),
        "macos" => Some((
            "launchctl",
            vec!["load", "/Library/LaunchDaemons/yggdrasil.plist"],
        )),
        _ => None,
    }
}

async fn yggdrasil<R: SetupRunner, A: DaemonApi>(
    c: &mut Ctx<'_, R, A>,
    mut state: SetupState,
) -> Result<()> {
    // Start it if it does not answer. Right after an install the service may still be
    // starting, so give it a moment first.
    if state.state == SetupStatus::NotRunning && !c.opts.dry_run {
        state = c.wait_for(|s| s.state != SetupStatus::NotRunning).await?;
    }
    if state.state == SetupStatus::NotRunning {
        match yggdrasil_start(c.run.os()) {
            Some((program, args)) => {
                if c.announce(&format!("start Yggdrasil: {program} {}", args.join(" "))) {
                    c.run
                        .run(program, &args)
                        .or_else(|e| manual(format!("could not start Yggdrasil ({e}); start its service yourself, then run this command again")))?;
                    c.changes.0.push("started the Yggdrasil service".into());
                    state = c.wait_for(|s| s.state != SetupStatus::NotRunning).await?;
                }
            }
            None => {
                return manual("start Yggdrasil, then run this command again");
            }
        }
    } else {
        c.skip("Yggdrasil is running");
    }
    // Yggdrasil's own configuration is never edited.
    if c.opts.dry_run {
        c.announce("add the Yggdrasil network to the daemon");
        return Ok(());
    }
    if state.state == SetupStatus::NotConfigured {
        state = c.wait_for(|s| s.state == SetupStatus::Ready).await?;
    }
    if state.state != SetupStatus::Ready {
        return manual(
            state
                .missing
                .unwrap_or_else(|| "Yggdrasil is not ready yet".into())
                + " Check Yggdrasil, then run this command again.",
        );
    }
    c.announce("add the Yggdrasil network to the daemon");
    add_network(
        c,
        BackendConfig::Yggdrasil {
            interface: None,
            admin_endpoint: None,
        },
    )
    .await
}

async fn add_network<R: SetupRunner, A: DaemonApi>(
    c: &mut Ctx<'_, R, A>,
    backend: BackendConfig,
) -> Result<()> {
    let n = c
        .api
        .add(&NewNetwork { id: None, backend })
        .await
        .context("the daemon did not accept the network")?;
    c.changes.0.push(format!("added the {} network", n.id));
    if let NetworkStatus::Down { reason } = &n.status {
        c.run
            .say(&format!("note: the network is down for now: {reason}"));
    }
    Ok(())
}

// ─── Tor ────────────────────────────────────────────────────────────────────

/// The options of a torrc (and the service defaults under it) that matter here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TorSettings {
    pub control_ports: Vec<String>,
    pub control_sockets: Vec<String>,
    pub cookie_auth: Option<bool>,
    pub cookie_auth_file: Option<String>,
    pub data_directory: Option<String>,
    pub includes: bool,
}

#[derive(Default)]
struct Parsed {
    control_ports: Vec<String>,
    control_sockets: Vec<String>,
    cookie_auth: Option<bool>,
    cookie_auth_file: Option<String>,
    data_directory: Option<String>,
    includes: bool,
}

fn parse_torrc(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("%include") {
            p.includes = true;
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (line, ""),
        };
        let first = value.split_whitespace().next().unwrap_or("").to_string();
        match key.to_ascii_lowercase().as_str() {
            "controlport" => p.control_ports.push(first),
            "controlsocket" => p.control_sockets.push(first),
            "cookieauthentication" => p.cookie_auth = Some(first == "1"),
            "cookieauthfile" => p.cookie_auth_file = Some(value.trim_matches('"').to_string()),
            "datadirectory" => p.data_directory = Some(value.trim_matches('"').to_string()),
            _ => {}
        }
    }
    p
}

impl TorSettings {
    /// The torrc over the service defaults it is read with: an option in the torrc replaces
    /// the defaults' value.
    pub fn from_texts(defaults: Option<&str>, torrc: &str) -> Self {
        let d = defaults.map(parse_torrc).unwrap_or_default();
        let t = parse_torrc(torrc);
        let list = |t: Vec<String>, d: Vec<String>| if t.is_empty() { d } else { t };
        Self {
            control_ports: list(t.control_ports, d.control_ports),
            control_sockets: list(t.control_sockets, d.control_sockets),
            cookie_auth: t.cookie_auth.or(d.cookie_auth),
            cookie_auth_file: t.cookie_auth_file.or(d.cookie_auth_file),
            data_directory: t.data_directory.or(d.data_directory),
            includes: t.includes || d.includes,
        }
    }

    /// Where Tor writes its cookie: `CookieAuthFile`, else `<DataDirectory>/control_auth_cookie`
    /// (the Tor manual). None if neither is set.
    pub fn cookie_path(&self) -> Option<String> {
        if let Some(f) = &self.cookie_auth_file {
            return Some(f.clone());
        }
        let dir = self.data_directory.as_ref()?;
        // The separator of the path as written, not of the machine running this.
        let sep = if dir.contains('\\') { '\\' } else { '/' };
        Some(format!(
            "{}{sep}control_auth_cookie",
            dir.trim_end_matches(['/', '\\'])
        ))
    }

    /// A loopback TCP control port, as `127.0.0.1:port`.
    fn tcp_control(&self) -> Option<String> {
        self.control_ports.iter().find_map(|p| {
            if let Ok(port) = p.parse::<u16>() {
                return (port != 0).then(|| format!("127.0.0.1:{port}"));
            }
            let sock: std::net::SocketAddr = p.parse().ok()?;
            (sock.ip().is_loopback() && sock.port() != 0).then(|| p.clone())
        })
    }

    fn unix_control(&self) -> Option<String> {
        self.control_sockets
            .iter()
            .find(|s| s.as_str() != "0" && !s.is_empty())
            .map(|s| format!("unix:{s}"))
    }
}

/// What to do about Tor's control endpoint.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlPlan {
    /// Tor has one with cookie authentication: use it, edit nothing.
    Existing { control: String },
    /// Append these lines to the torrc.
    Append { lines: Vec<String>, control: String },
}

/// Use the control endpoint the torrc already has; add only what is missing, never a second
/// `ControlPort`.
pub fn plan_control(s: &TorSettings, os: &str) -> Result<ControlPlan> {
    if s.includes {
        return manual(
            "the torrc includes other files (%include), which this command does not read; add \
             \"ControlPort 9051\" and \"CookieAuthentication 1\" yourself unless they are set",
        );
    }
    let existing = if os == "windows" {
        s.tcp_control()
    } else {
        s.unix_control().or_else(|| s.tcp_control())
    };
    let cookie_on = s.cookie_auth == Some(true);
    match (existing, cookie_on) {
        (Some(control), true) => Ok(ControlPlan::Existing { control }),
        (Some(control), false) => Ok(ControlPlan::Append {
            lines: vec!["CookieAuthentication 1".into()],
            control,
        }),
        (None, _) => {
            if s.control_ports.iter().any(|p| p != "0") {
                return manual(
                    "Tor has a ControlPort that is not a plain loopback port (or is \"auto\"); \
                     SocketGuard cannot tell where it listens. Set \"ControlPort 9051\" instead",
                );
            }
            let mut lines = vec!["ControlPort 9051".to_string()];
            if !cookie_on {
                lines.push("CookieAuthentication 1".into());
            }
            Ok(ControlPlan::Append {
                lines,
                control: "127.0.0.1:9051".into(),
            })
        }
    }
}

/// `text` with `lines` appended: everything else byte for byte, the line ending the file
/// uses, a newline first if the file does not end with one.
pub fn append_lines(text: &str, lines: &[String]) -> String {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(eol);
    }
    for l in lines {
        out.push_str(l);
        out.push_str(eol);
    }
    out
}

/// The torrc of a standard installation, if there is one on this system. Debian's service
/// defaults (`/usr/share/tor/tor-service-defaults-torrc`) are read with it.
fn locate_torrc(r: &dyn SetupRunner, explicit: Option<&Path>) -> Result<(PathBuf, Option<String>)> {
    let defaults = |r: &dyn SetupRunner| r.read_file(Path::new(DEBIAN_DEFAULTS)).ok().flatten();
    if let Some(p) = explicit {
        return match r.read_file(p)? {
            Some(_) => Ok((p.to_path_buf(), defaults(r))),
            None => manual(format!("the torrc {} does not exist", p.display())),
        };
    }
    let candidates: Vec<PathBuf> = match r.os() {
        // Debian-family only: the file is checked by its service defaults next to it.
        "linux" if defaults(r).is_some() => vec![PathBuf::from("/etc/tor/torrc")],
        "macos" => vec![
            PathBuf::from("/opt/homebrew/etc/tor/torrc"),
            PathBuf::from("/usr/local/etc/tor/torrc"),
        ],
        _ => vec![],
    };
    for p in candidates {
        if r.read_file(&p)?.is_some() {
            let d = if r.os() == "linux" { defaults(r) } else { None };
            return Ok((p, d));
        }
    }
    manual(
        "the torrc could not be located. Run this command again with --torrc <path to your \
         torrc>. SocketGuard needs these lines in it: \"ControlPort 9051\" and \
         \"CookieAuthentication 1\"",
    )
}

const DEBIAN_DEFAULTS: &str = "/usr/share/tor/tor-service-defaults-torrc";

/// How to restart Tor after the torrc changed (None: tell the person).
fn tor_restart(r: &dyn SetupRunner) -> Option<Vec<(&'static str, Vec<&'static str>)>> {
    match r.os() {
        // Debian runs Tor as tor@default (tor.service is a wrapper around it).
        "linux"
            if r.read_file(Path::new(DEBIAN_DEFAULTS))
                .ok()
                .flatten()
                .is_some() =>
        {
            Some(vec![("systemctl", vec!["restart", "tor@default"])])
        }
        "linux" => Some(vec![("systemctl", vec!["restart", "tor"])]),
        "windows" => Some(vec![
            ("sc.exe", vec!["stop", "tor"]),
            ("sc.exe", vec!["start", "tor"]),
        ]),
        _ => None,
    }
}

fn same_path(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.replace('\\', "/");
        if cfg!(windows) {
            s.to_ascii_lowercase()
        } else {
            s
        }
    };
    norm(a) == norm(b)
}

async fn tor<R: SetupRunner, A: DaemonApi>(
    c: &mut Ctx<'_, R, A>,
    state: SetupState,
    daemon_config: Option<&str>,
) -> Result<()> {
    let config_path: PathBuf = match (&c.opts.config, daemon_config) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) => PathBuf::from(p),
        (None, None) => {
            return manual("tell the command which config file the daemon uses: --config <path>")
        }
    };
    // Tor that works with the default settings needs nothing but the network.
    if state.state == SetupStatus::Ready {
        c.skip("Tor's control port works with SocketGuard's defaults");
        c.announce("add the Tor network to the daemon");
        if c.opts.dry_run {
            return Ok(());
        }
        return add_network(c, BackendConfig::default_tor()).await;
    }

    // Locate and read the torrc.
    let (torrc, defaults) = locate_torrc(&*c.run, c.opts.torrc.as_deref())?;
    let text = c.run.read_file(&torrc)?.unwrap_or_default();
    let settings = TorSettings::from_texts(defaults.as_deref(), &text);
    let plan = plan_control(&settings, c.run.os())?;
    let cookie_path = settings.cookie_path().ok_or_else(|| {
        anyhow!(ManualStep(format!(
            "Tor's data directory is not set in {}. Add a \"DataDirectory\" line (or \
             \"CookieAuthFile\") there, then run this command again.",
            torrc.display()
        )))
    })?;
    c.run.say(&format!(
        "   Tor's cookie file, from {}: {cookie_path}",
        torrc.display()
    ));

    // Configure: only the missing lines.
    let control = match &plan {
        ControlPlan::Existing { control } => {
            c.skip(&format!(
                "Tor already has a control endpoint with cookie authentication ({control}); {} is not edited",
                torrc.display()
            ));
            control.clone()
        }
        ControlPlan::Append { lines, control } => {
            let text_lines = lines.join("\" and \"");
            if c.announce(&format!(
                "add \"{text_lines}\" to {} (a copy of the original is kept as {}.socketguard.bak)",
                torrc.display(),
                torrc.display()
            )) {
                let bak = PathBuf::from(format!("{}.socketguard.bak", torrc.display()));
                if c.run.read_file(&bak)?.is_none() {
                    c.run.write_file(&bak, &text)?;
                }
                c.run.write_file(&torrc, &append_lines(&text, lines))?;
                c.changes
                    .0
                    .push(format!("added {} to {}", lines.join(", "), torrc.display()));
                match tor_restart(&*c.run) {
                    Some(cmds) => {
                        c.run.say("   restarting Tor");
                        for (p, a) in cmds {
                            c.run.run(p, &a).or_else(|e| {
                                manual(format!(
                                    "could not restart Tor ({e}); restart it yourself, then run \
                                     this command again"
                                ))
                            })?;
                        }
                        c.changes.0.push("restarted Tor".into());
                    }
                    None => {
                        return manual(
                            "restart Tor so that it reads the changed torrc, then run this \
                             command again",
                        )
                    }
                }
            }
            control.clone()
        }
    };
    if c.opts.dry_run {
        c.announce(&format!(
            "write the Tor network (control {control}, cookie {cookie_path}) to {}",
            config_path.display()
        ));
        c.announce("add the Tor network to the daemon");
        return Ok(());
    }

    // Wait for the control port; its answer must agree with the torrc.
    let mut answer = None;
    for _ in 0..40 {
        if let Ok(a) = c.run.protocolinfo(&control) {
            answer = Some(a);
            break;
        }
        c.run.sleep(Duration::from_millis(500));
    }
    let Some(answer) = answer else {
        return manual(format!(
            "Tor does not answer on {control}. Start Tor (and check its log), then run this \
             command again."
        ));
    };
    if !answer.methods.iter().any(|m| m == "SAFECOOKIE") {
        return manual(format!(
            "Tor's control port {control} does not offer cookie authentication"
        ));
    }
    match &answer.cookie_file {
        Some(reported) if same_path(reported, &cookie_path) => {}
        other => {
            return manual(format!(
                "the control port reports the cookie file {} but the torrc says {cookie_path}. \
                 SocketGuard trusts only what the torrc says; check what is listening on {control}.",
                other.as_deref().unwrap_or("(none)")
            ))
        }
    }

    // The network goes into the config file first: the daemon accepts non-default Tor
    // settings from its API only when its config file has them.
    let backend = BackendConfig::Tor {
        control: control.clone(),
        auth: TorAuth::Cookie,
        cookie_path: Some(cookie_path.clone()),
        cookie_dir: None,
        expect_tor_uid: None,
        cookie_owner: None,
        allow_remote_control: false,
    };
    let existing = c.api.networks().await?;
    if existing.iter().any(|n| n.kind == NetworkKind::Tor) {
        return manual(
            "a Tor network exists already with other settings. Remove it (socketguard networks \
             rm tor), then run this command again",
        );
    }
    c.announce(&format!(
        "write the Tor network (control {control}, cookie {cookie_path}) to {}",
        config_path.display()
    ));
    if write_config_entry(c.run, &config_path, &backend)? {
        c.changes.0.push(format!(
            "wrote the Tor network to {}",
            config_path.display()
        ));
    }
    c.announce("add the Tor network to the daemon");
    add_network(c, backend).await?;
    if let Some(n) = c
        .api
        .networks()
        .await?
        .into_iter()
        .find(|n| n.kind == NetworkKind::Tor)
    {
        if let NetworkStatus::Down { reason } = n.status {
            return manual(format!(
                "the daemon added the network but cannot use Tor yet: {reason}. On Windows a \
                 cookie owned by Tor's service account needs \"cookie_owner\" in {}",
                config_path.display()
            ));
        }
    }
    Ok(())
}

/// Put the Tor network into the `backends` of the config file at `path`, keeping the file's
/// other keys. False if the file has it already. A different Tor entry is a manual step.
fn write_config_entry(
    r: &mut dyn SetupRunner,
    path: &Path,
    backend: &BackendConfig,
) -> Result<bool> {
    let entry = serde_json::to_value(socketguard_core::config::BackendInstanceConfig {
        id: backend.default_id(),
        backend: backend.clone(),
    })?;
    let mut doc: Value = match r.read_file(path)? {
        Some(text) => {
            let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
            match serde_json::from_str::<Value>(text) {
                Ok(v) if v.is_object() => v,
                _ => {
                    return manual(format!(
                        "{} is not a JSON object; fix it first",
                        path.display()
                    ))
                }
            }
        }
        None => json!({}),
    };
    let list = doc
        .as_object_mut()
        .expect("checked")
        .entry("backends")
        .or_insert_with(|| json!([]));
    let Some(list) = list.as_array_mut() else {
        return manual(format!("\"backends\" in {} is not a list", path.display()));
    };
    if let Some(i) = list.iter().position(|b| b["type"] == "tor") {
        let same = serde_json::from_value::<socketguard_core::config::BackendInstanceConfig>(
            list[i].clone(),
        )
        .map(|b| b.backend == *backend)
        .unwrap_or(false);
        if same {
            return Ok(false);
        }
        return manual(format!(
            "{} already has a Tor network with other settings; edit or remove it",
            path.display()
        ));
    }
    list.push(entry);
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    r.write_file(path, &text)?;
    Ok(true)
}

// ─── The real system ────────────────────────────────────────────────────────

/// [`SetupRunner`] for this machine.
pub struct System;

impl SetupRunner for System {
    fn os(&self) -> &'static str {
        std::env::consts::OS
    }

    fn is_elevated(&self) -> bool {
        elevated()
    }

    fn has_program(&self, name: &str) -> bool {
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&path).any(|d| {
            ["", ".exe", ".cmd"]
                .iter()
                .any(|e| d.join(format!("{name}{e}")).is_file())
        })
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<()> {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("cannot run {program}"))?;
        if !status.success() {
            bail!("{program} exited with {status}");
        }
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    fn write_file(&mut self, path: &Path, content: &str) -> Result<()> {
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        // Keep the permissions of a file that is replaced.
        let result = std::fs::write(&tmp, content)
            .and_then(|()| match std::fs::metadata(path) {
                Ok(m) => std::fs::set_permissions(&tmp, m.permissions()),
                Err(_) => Ok(()),
            })
            .and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.with_context(|| format!("cannot write {}", path.display()))
    }

    fn protocolinfo(&mut self, control: &str) -> Result<ControlAnswer> {
        use std::io::{BufRead, BufReader, Write};
        let timeout = Duration::from_secs(2);
        let (reader, mut writer): (Box<dyn std::io::Read>, Box<dyn Write>) =
            match control.strip_prefix("unix:") {
                #[cfg(unix)]
                Some(path) => {
                    let s = std::os::unix::net::UnixStream::connect(path)?;
                    s.set_read_timeout(Some(timeout))?;
                    (Box::new(s.try_clone()?), Box::new(s))
                }
                #[cfg(not(unix))]
                Some(_) => bail!("Unix sockets are not available here"),
                None => {
                    use std::net::ToSocketAddrs;
                    let addr = control
                        .to_socket_addrs()?
                        .find(|a| a.ip().is_loopback())
                        .context("not a loopback address")?;
                    let s = std::net::TcpStream::connect_timeout(&addr, timeout)?;
                    s.set_read_timeout(Some(timeout))?;
                    (Box::new(s.try_clone()?), Box::new(s))
                }
            };
        writer.write_all(b"PROTOCOLINFO 1\r\n")?;
        let mut answer = ControlAnswer::default();
        for line in BufReader::new(reader).lines() {
            let line = line?;
            if let Some(rest) = line
                .strip_prefix("250-AUTH ")
                .or_else(|| line.strip_prefix("250 AUTH "))
            {
                if let Some(m) = rest.split("METHODS=").nth(1) {
                    let m = m.split_whitespace().next().unwrap_or("");
                    answer.methods = m.split(',').map(str::to_string).collect();
                }
                if let Some(f) = rest.split("COOKIEFILE=\"").nth(1) {
                    answer.cookie_file = f.split('"').next().map(|s| s.replace("\\\\", "\\"));
                }
            }
            if line.starts_with("250 OK") || line.starts_with('5') {
                break;
            }
        }
        Ok(answer)
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn say(&mut self, line: &str) {
        println!("{line}");
    }

    fn confirm(&mut self, question: &str) -> bool {
        use crate::prompt::Prompter;
        crate::prompt::Stdin.confirm(question)
    }
}

#[cfg(unix)]
fn elevated() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        os: &'static str,
        elevated: bool,
        programs: Vec<&'static str>,
        files: HashMap<PathBuf, String>,
        commands: Vec<String>,
        said: Vec<String>,
        /// PROTOCOLINFO answers by control address.
        control: HashMap<String, ControlAnswer>,
        /// A command that makes the control port appear.
        answer: bool,
    }

    impl SetupRunner for Fake {
        fn os(&self) -> &'static str {
            self.os
        }
        fn is_elevated(&self) -> bool {
            self.elevated
        }
        fn has_program(&self, name: &str) -> bool {
            self.programs.contains(&name)
        }
        fn run(&mut self, program: &str, args: &[&str]) -> Result<()> {
            self.commands.push(format!("{program} {}", args.join(" ")));
            Ok(())
        }
        fn read_file(&self, path: &Path) -> Result<Option<String>> {
            Ok(self.files.get(path).cloned())
        }
        fn write_file(&mut self, path: &Path, content: &str) -> Result<()> {
            self.files.insert(path.to_path_buf(), content.to_string());
            Ok(())
        }
        fn protocolinfo(&mut self, control: &str) -> Result<ControlAnswer> {
            self.control
                .get(control)
                .cloned()
                .filter(|_| self.answer)
                .context("no answer")
        }
        fn sleep(&mut self, _: Duration) {}
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
        fn confirm(&mut self, _: &str) -> bool {
            true
        }
    }

    /// The daemon: its detection answers, the networks it has, what was added.
    struct Daemon {
        setup: RefCell<NetworkSetup>,
        networks: RefCell<Vec<Network>>,
        added: RefCell<Vec<NewNetwork>>,
    }

    fn st(state: SetupStatus) -> SetupState {
        SetupState::new(state)
    }

    fn daemon(ygg: SetupState, tor: SetupState) -> Daemon {
        Daemon {
            setup: RefCell::new(NetworkSetup {
                lan: vec![],
                yggdrasil: ygg,
                tor,
                local: st(SetupStatus::Ready),
                config_path: Some("/var/lib/sg/socketguard.json".into()),
            }),
            networks: RefCell::new(vec![]),
            added: RefCell::new(vec![]),
        }
    }

    impl DaemonApi for Daemon {
        async fn setup(&self) -> Result<NetworkSetup> {
            Ok(self.setup.borrow().clone())
        }
        async fn networks(&self) -> Result<Vec<Network>> {
            Ok(self.networks.borrow().clone())
        }
        async fn add(&self, req: &NewNetwork) -> Result<Network> {
            self.added.borrow_mut().push(req.clone());
            let kind = match req.backend {
                BackendConfig::Tor { .. } => NetworkKind::Tor,
                _ => NetworkKind::Yggdrasil,
            };
            let n = Network {
                id: req.backend.default_id(),
                kind,
                name: req.backend.default_id(),
                interface: None,
                grants_apply: true,
                status: NetworkStatus::Up,
                prefix: None,
                vlan_id: None,
            };
            self.networks.borrow_mut().push(n.clone());
            Ok(n)
        }
    }

    fn opts() -> Options {
        Options {
            yes: true,
            ..Default::default()
        }
    }

    const DEBIAN_DEFAULTS_TEXT: &str = "DataDirectory /var/lib/tor\nControlSocket /run/tor/control GroupWritable RelaxDirModeCheck\nCookieAuthentication 1\nCookieAuthFileGroupReadable 1\nCookieAuthFile /run/tor/control.authcookie\n";

    fn debian(torrc: &str) -> Fake {
        let mut f = Fake {
            os: "linux",
            elevated: true,
            programs: vec!["apt-get"],
            answer: true,
            ..Default::default()
        };
        f.files
            .insert(PathBuf::from(DEBIAN_DEFAULTS), DEBIAN_DEFAULTS_TEXT.into());
        f.files
            .insert(PathBuf::from("/etc/tor/torrc"), torrc.into());
        f
    }

    fn answer(cookie: &str) -> ControlAnswer {
        ControlAnswer {
            methods: vec!["COOKIE".into(), "SAFECOOKIE".into()],
            cookie_file: Some(cookie.into()),
        }
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn without_administrator_rights_it_refuses_but_a_dry_run_does_not_need_them() {
        let d = daemon(st(SetupStatus::NotRunning), st(SetupStatus::Ready));
        let mut f = Fake {
            os: "linux",
            ..Default::default()
        };
        let err = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.to_string().contains("sudo"), "{err}");
        assert!(f.commands.is_empty());
        let mut f = Fake {
            os: "windows",
            ..Default::default()
        };
        let err = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.to_string().contains("elevated terminal"), "{err}");

        let dry = Options {
            dry_run: true,
            ..opts()
        };
        let mut f = Fake {
            os: "linux",
            ..Default::default()
        };
        block(run(SetupKind::Yggdrasil, &dry, &mut f, &d)).unwrap();
        assert!(f.commands.is_empty());
        assert!(d.added.borrow().is_empty());
        assert!(f.said.iter().any(|l| l.contains("would: start Yggdrasil")));
    }

    #[test]
    fn yggdrasil_on_windows_installs_with_winget() {
        let mut offer = st(SetupStatus::NotInstalled);
        offer.install = Some(socketguard_core::setup::InstallOffer {
            manager: "winget".into(),
            command: "winget install --id YggdrasilNetwork.Yggdrasil --source winget -e".into(),
            link: None,
        });
        let d = daemon(offer, st(SetupStatus::Ready));
        let mut f = Fake {
            os: "windows",
            elevated: true,
            programs: vec!["winget"],
            ..Default::default()
        };
        // The fake daemon never sees the install: after running winget it is a manual step.
        let err = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.downcast_ref::<ManualStep>().is_some(), "{err}");
        assert_eq!(
            f.commands,
            ["winget install --id YggdrasilNetwork.Yggdrasil --source winget -e"]
        );
        assert!(d.added.borrow().is_empty());
    }

    #[test]
    fn a_ready_yggdrasil_is_added_with_no_fields_and_nothing_is_installed() {
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::Ready));
        let mut f = Fake {
            os: "windows",
            elevated: true,
            ..Default::default()
        };
        let changes = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap();
        assert!(f.commands.is_empty());
        assert_eq!(
            d.added.borrow()[0].backend,
            BackendConfig::Yggdrasil {
                interface: None,
                admin_endpoint: None
            }
        );
        assert_eq!(changes.list().len(), 1);
        assert!(f
            .said
            .iter()
            .any(|l| l.contains("already done: yggdrasil is installed")));
    }

    #[test]
    fn a_stopped_yggdrasil_is_started_and_without_a_package_it_is_a_manual_step() {
        let mut stopped = st(SetupStatus::NotRunning);
        stopped.missing = Some("stopped".into());
        let d = daemon(stopped, st(SetupStatus::Ready));
        let mut f = Fake {
            os: "linux",
            elevated: true,
            ..Default::default()
        };
        // Starting does not make the fake daemon see it running: a manual step, after
        // the documented start command ran.
        let err = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.downcast_ref::<ManualStep>().is_some());
        assert_eq!(f.commands, ["systemctl enable --now yggdrasil"]);

        let mut none = st(SetupStatus::NotInstalled);
        none.download_link = Some(socketguard_core::setup::YGGDRASIL_DOWNLOAD.into());
        let d = daemon(none, st(SetupStatus::Ready));
        let mut f = Fake {
            os: "linux",
            elevated: true,
            programs: vec!["apt-get"],
            ..Default::default()
        };
        let err = block(run(SetupKind::Yggdrasil, &opts(), &mut f, &d)).unwrap_err();
        let ManualStep(msg) = err.downcast_ref::<ManualStep>().unwrap();
        assert!(msg.contains("yggdrasil-network.github.io/installation.html"));
        assert!(f.commands.is_empty());
    }

    #[test]
    fn tor_on_windows_without_a_package_prints_the_download_page() {
        let mut none = st(SetupStatus::NotInstalled);
        none.download_link = Some(socketguard_core::setup::TOR_DOWNLOAD.into());
        let d = daemon(st(SetupStatus::Ready), none);
        let mut f = Fake {
            os: "windows",
            elevated: true,
            programs: vec!["winget"],
            ..Default::default()
        };
        let err = block(run(SetupKind::Tor, &opts(), &mut f, &d)).unwrap_err();
        let ManualStep(msg) = err.downcast_ref::<ManualStep>().unwrap();
        assert!(msg.contains("https://www.torproject.org/download/tor/"));
    }

    #[test]
    fn torrc_is_appended_to_idempotently_keeping_everything_else() {
        let original = "# my tor\r\nSocksPort 9050\r\nLog notice file /var/log/tor.log";
        let lines = vec![
            "ControlPort 9051".to_string(),
            "CookieAuthentication 1".to_string(),
        ];
        let once = append_lines(original, &lines);
        assert_eq!(
            once,
            "# my tor\r\nSocksPort 9050\r\nLog notice file /var/log/tor.log\r\nControlPort 9051\r\nCookieAuthentication 1\r\n"
        );
        assert!(once.starts_with(original));
        // After the edit the plan wants nothing more.
        let s = TorSettings::from_texts(None, &once);
        assert!(matches!(
            plan_control(&s, "linux").unwrap(),
            ControlPlan::Existing { .. }
        ));
        assert_eq!(
            append_lines("a\n", &lines),
            "a\nControlPort 9051\nCookieAuthentication 1\n"
        );
    }

    #[test]
    fn an_existing_control_socket_with_cookie_auth_is_used_and_nothing_is_edited() {
        let torrc = "# stock\nSocksPort 9050\n";
        let s = TorSettings::from_texts(Some(DEBIAN_DEFAULTS_TEXT), torrc);
        assert_eq!(
            plan_control(&s, "linux").unwrap(),
            ControlPlan::Existing {
                control: "unix:/run/tor/control".into()
            }
        );
        assert_eq!(
            s.cookie_path().as_deref(),
            Some("/run/tor/control.authcookie")
        );

        let mut f = debian(torrc);
        f.control.insert(
            "unix:/run/tor/control".into(),
            answer("/run/tor/control.authcookie"),
        );
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        block(run(SetupKind::Tor, &opts(), &mut f, &d)).unwrap();
        assert_eq!(
            f.files[Path::new("/etc/tor/torrc")],
            torrc,
            "torrc untouched"
        );
        assert!(!f
            .files
            .contains_key(Path::new("/etc/tor/torrc.socketguard.bak")));
        assert!(f.commands.is_empty(), "no restart");
        // The config file got the entry the daemon was then asked to add.
        let doc: Value =
            serde_json::from_str(&f.files[Path::new("/var/lib/sg/socketguard.json")]).unwrap();
        assert_eq!(doc["backends"][0]["control"], "unix:/run/tor/control");
        assert_eq!(
            doc["backends"][0]["cookie_path"],
            "/run/tor/control.authcookie"
        );
        let added = d.added.borrow();
        let BackendConfig::Tor {
            control,
            cookie_path,
            ..
        } = &added[0].backend
        else {
            panic!()
        };
        assert_eq!(control, "unix:/run/tor/control");
        assert_eq!(cookie_path.as_deref(), Some("/run/tor/control.authcookie"));
    }

    #[test]
    fn a_missing_control_port_is_appended_once_with_a_backup_and_never_duplicated() {
        // No defaults file: not Debian, so the torrc is given explicitly, with its data dir.
        let torrc = "DataDirectory /var/lib/tor\nSocksPort 9050\n";
        let mut f = Fake {
            os: "linux",
            elevated: true,
            answer: true,
            ..Default::default()
        };
        f.files
            .insert(PathBuf::from("/opt/tor/torrc"), torrc.into());
        f.control.insert(
            "127.0.0.1:9051".into(),
            answer("/var/lib/tor/control_auth_cookie"),
        );
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        let o = Options {
            torrc: Some(PathBuf::from("/opt/tor/torrc")),
            ..opts()
        };
        block(run(SetupKind::Tor, &o, &mut f, &d)).unwrap();
        let edited = &f.files[Path::new("/opt/tor/torrc")];
        assert_eq!(
            edited,
            "DataDirectory /var/lib/tor\nSocksPort 9050\nControlPort 9051\nCookieAuthentication 1\n"
        );
        assert_eq!(f.files[Path::new("/opt/tor/torrc.socketguard.bak")], torrc);
        assert_eq!(f.commands, ["systemctl restart tor"]);

        // A torrc with a ControlPort already gets only the missing cookie line.
        let s = TorSettings::from_texts(None, "ControlPort 9051\n");
        assert_eq!(
            plan_control(&s, "linux").unwrap(),
            ControlPlan::Append {
                lines: vec!["CookieAuthentication 1".into()],
                control: "127.0.0.1:9051".into()
            }
        );
        // ControlPort auto, or a non-loopback one, is not guessed at.
        let s = TorSettings::from_texts(None, "ControlPort auto\n");
        assert!(plan_control(&s, "linux").is_err());
        let s = TorSettings::from_texts(None, "ControlPort 0.0.0.0:9051\n");
        assert!(plan_control(&s, "linux").is_err());
    }

    #[test]
    fn the_cookie_path_comes_from_the_torrc_and_a_different_one_on_the_wire_stops_setup() {
        let torrc = "DataDirectory /var/lib/tor\nControlPort 9051\nCookieAuthentication 1\n";
        let mut f = Fake {
            os: "linux",
            elevated: true,
            answer: true,
            ..Default::default()
        };
        f.files.insert(PathBuf::from("/t/torrc"), torrc.into());
        // Something else listens and names a file of its choosing.
        f.control
            .insert("127.0.0.1:9051".into(), answer("/tmp/evil/cookie"));
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        let o = Options {
            torrc: Some(PathBuf::from("/t/torrc")),
            ..opts()
        };
        let err = block(run(SetupKind::Tor, &o, &mut f, &d)).unwrap_err();
        let ManualStep(msg) = err.downcast_ref::<ManualStep>().unwrap();
        assert!(
            msg.contains("/tmp/evil/cookie") && msg.contains("/var/lib/tor/control_auth_cookie")
        );
        assert!(d.added.borrow().is_empty());
        assert!(!f
            .files
            .contains_key(Path::new("/var/lib/sg/socketguard.json")));
    }

    #[test]
    fn without_a_data_directory_or_a_torrc_it_stops_with_a_manual_step() {
        let mut f = Fake {
            os: "linux",
            elevated: true,
            ..Default::default()
        };
        f.files.insert(
            PathBuf::from("/t/torrc"),
            "ControlPort 9051\nCookieAuthentication 1\n".into(),
        );
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        let o = Options {
            torrc: Some(PathBuf::from("/t/torrc")),
            ..opts()
        };
        let err = block(run(SetupKind::Tor, &o, &mut f, &d)).unwrap_err();
        assert!(err.to_string().contains("DataDirectory"));
        // No torrc at a standard place and none given.
        let mut f = Fake {
            os: "windows",
            elevated: true,
            ..Default::default()
        };
        let err = block(run(SetupKind::Tor, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.to_string().contains("--torrc"));
    }

    #[test]
    fn the_config_file_is_required_when_the_daemon_does_not_say() {
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        d.setup.borrow_mut().config_path = None;
        let mut f = debian("");
        let err = block(run(SetupKind::Tor, &opts(), &mut f, &d)).unwrap_err();
        assert!(err.to_string().contains("--config"));
        // With it, setup goes on.
        f.control.insert(
            "unix:/run/tor/control".into(),
            answer("/run/tor/control.authcookie"),
        );
        let o = Options {
            config: Some(PathBuf::from("/etc/sg/socketguard.json")),
            ..opts()
        };
        block(run(SetupKind::Tor, &o, &mut f, &d)).unwrap();
        assert!(f.files.contains_key(Path::new("/etc/sg/socketguard.json")));
    }

    #[test]
    fn the_config_entry_keeps_other_keys_and_a_different_tor_entry_is_refused() {
        let backend = BackendConfig::Tor {
            control: "127.0.0.1:9051".into(),
            auth: TorAuth::Cookie,
            cookie_path: Some("/c".into()),
            cookie_dir: None,
            expect_tor_uid: None,
            cookie_owner: None,
            allow_remote_control: false,
        };
        let mut f = Fake::default();
        let path = Path::new("/c.json");
        f.files.insert(
            path.to_path_buf(),
            r#"{"poll_interval_secs": 7, "backends": [{"id":"ula","type":"ula"}]}"#.into(),
        );
        assert!(write_config_entry(&mut f, path, &backend).unwrap());
        let doc: Value = serde_json::from_str(&f.files[path]).unwrap();
        assert_eq!(doc["poll_interval_secs"], 7);
        assert_eq!(doc["backends"].as_array().unwrap().len(), 2);
        // Again: nothing to do.
        assert!(!write_config_entry(&mut f, path, &backend).unwrap());
        let other = BackendConfig::default_tor();
        assert!(write_config_entry(&mut f, path, &other).is_err());
    }

    #[test]
    fn a_dry_run_changes_nothing() {
        let torrc = "DataDirectory /var/lib/tor\n";
        let mut f = Fake {
            os: "linux",
            elevated: false,
            ..Default::default()
        };
        f.files.insert(PathBuf::from("/t/torrc"), torrc.into());
        let d = daemon(st(SetupStatus::Ready), st(SetupStatus::NotConfigured));
        let o = Options {
            dry_run: true,
            torrc: Some(PathBuf::from("/t/torrc")),
            ..opts()
        };
        block(run(SetupKind::Tor, &o, &mut f, &d)).unwrap();
        assert_eq!(f.files.len(), 1);
        assert_eq!(f.files[Path::new("/t/torrc")], torrc);
        assert!(f.commands.is_empty());
        assert!(d.added.borrow().is_empty());
        assert!(f
            .said
            .iter()
            .any(|l| l.contains("would: add \"ControlPort 9051\"")));
    }
}
