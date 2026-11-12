//! `service install` and the install record (ADR 0050): what was found and created is
//! written to `setup-log.json` next to the config file as it happens, and removal reverses
//! exactly that record (see `uninstall`). A thing that existed before is never removed.

use crate::access::{ensure_group, GroupManager};
use crate::host::{require_admin, Host};
use crate::report::Report;
use crate::service::ServiceManager;
use anyhow::{Context, Result};
use socketguard_core::install_log::{self, Change, Entry};
use std::path::{Path, PathBuf};

/// The install record file.
pub struct Record {
    path: PathBuf,
}

impl Record {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn for_config(config: &Path) -> Self {
        Self::new(socketguard_core::paths::setup_log_path(config))
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        install_log::read_file(&self.path).map_err(anyhow::Error::msg)
    }
    pub fn write(&self, entries: &[Entry]) -> Result<()> {
        install_log::write_file(&self.path, entries).map_err(anyhow::Error::msg)
    }
    pub fn push(&self, e: Entry) -> Result<()> {
        let mut all = self.entries()?;
        all.push(e);
        self.write(&all)
    }
    /// Append `e` unless an entry with a matching change exists: a second install must not
    /// overwrite what the first one found.
    pub fn push_once(&self, same: impl Fn(&Change) -> bool, e: Entry) -> Result<()> {
        let mut all = self.entries()?;
        if all.iter().any(|x| same(&x.change)) {
            return Ok(());
        }
        all.push(e);
        self.write(&all)
    }
    /// Change the first matching entry.
    pub fn update(
        &self,
        same: impl Fn(&Change) -> bool,
        f: impl FnOnce(&mut Change),
    ) -> Result<()> {
        let mut all = self.entries()?;
        if let Some(e) = all.iter_mut().find(|e| same(&e.change)) {
            f(&mut e.change);
            self.write(&all)?;
        }
        Ok(())
    }
}

/// Create `dir` and its missing parents, protect what was created and return it (outermost
/// first). Existing directories are left alone.
pub fn ensure_dir(dir: &Path, shared: bool) -> Result<Vec<PathBuf>> {
    let mut missing = vec![];
    let mut cur = dir;
    while !cur.exists() {
        missing.push(cur.to_path_buf());
        match cur.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(p) => cur = p,
            None => break,
        }
    }
    missing.reverse();
    for d in &missing {
        std::fs::create_dir(d).with_context(|| format!("cannot create {}", d.display()))?;
        crate::state::protect_dir(d, shared)
            .with_context(|| format!("cannot protect {}", d.display()))?;
    }
    Ok(missing)
}

/// The directories of the config file and the database exist, with their protection; the
/// ones created here are recorded (only those).
pub fn prepare_dirs(config: &Path, db: &Path, record: &Record) -> Result<Vec<PathBuf>> {
    let cdir = config.parent().filter(|p| !p.as_os_str().is_empty());
    let ddir = db.parent().filter(|p| !p.as_os_str().is_empty());
    let mut created = vec![];
    if let Some(c) = cdir {
        created.extend(ensure_dir(c, true)?);
    }
    if let Some(d) = ddir {
        // The database file protects itself; a directory of its own is owner-only.
        created.extend(ensure_dir(d, cdir == Some(d))?);
    }
    for d in &created {
        let p = d.display().to_string();
        record.push_once(
            |c| matches!(c, Change::DirectoryCreated { path } if *path == p),
            Entry::now(Change::DirectoryCreated { path: p.clone() }),
        )?;
    }
    Ok(created)
}

// ─── macOS: the pf anchor ───────────────────────────────────────────────────

static RECORD_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Where the running daemon keeps the install record (set once at start).
pub fn set_record_path(config: &Path) {
    let _ = RECORD_PATH.set(socketguard_core::paths::setup_log_path(config));
}

/// The install record of the running daemon; None without a record path (tests).
pub fn record() -> Option<Record> {
    RECORD_PATH.get().map(|p| Record::new(p.clone()))
}

/// Windows: record the value `FWPM_ENGINE_COLLECT_NET_EVENTS` had before the daemon first
/// set it. Only the first call counts, across restarts.
pub fn record_wfp_option_once(prior: Option<u32>) {
    let Some(path) = RECORD_PATH.get() else {
        return;
    };
    let rec = Record::new(path.clone());
    let r = rec.push_once(
        |c| matches!(c, Change::WfpEngineOption { .. }),
        Entry::now(Change::WfpEngineOption {
            option: "FWPM_ENGINE_COLLECT_NET_EVENTS".into(),
            prior,
        }),
    );
    if let Err(e) = r {
        tracing::warn!("Could not record the WFP engine option: {e:#}");
    }
}

/// Record a directory the daemon made for a child process (ADR 0052), once. Uninstall keeps
/// it with the data and `--purge` removes it. A daemon without a record path (tests) does
/// nothing.
pub fn record_owned_directory_once(dir: &Path) {
    let Some(path) = RECORD_PATH.get() else {
        return;
    };
    let p = dir.display().to_string();
    let r = Record::new(path.clone()).push_once(
        |c| matches!(c, Change::OwnedDirectory { path } if *path == p),
        Entry::now(Change::OwnedDirectory { path: p.clone() }),
    );
    if let Err(e) = r {
        tracing::warn!("Could not record the directory {p}: {e:#}");
    }
}

pub const PF_CONF: &str = "/etc/pf.conf";
pub const PF_ANCHOR_LINE: &str = "anchor \"socketguard\"";

fn has_anchor(text: &str) -> bool {
    text.lines().any(|l| l.trim().starts_with(PF_ANCHOR_LINE))
}

fn pf_enabled(host: &mut dyn Host) -> Result<bool> {
    Ok(host
        .run("pfctl", &["-s", "info"])?
        .stdout
        .contains("Status: Enabled"))
}

fn write_keep_mode(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("socketguard-tmp");
    std::fs::write(&tmp, text)?;
    if let Ok(m) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, m.permissions());
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

/// Add `anchor "socketguard"` to the pf configuration and load it, and enable pf, only where
/// missing; record what was found and done.
pub fn ensure_pf_anchor(host: &mut dyn Host, conf: &Path, record: &Record) -> Result<()> {
    let text = std::fs::read_to_string(conf).unwrap_or_default();
    let had_line = has_anchor(&text);
    let was_enabled = pf_enabled(host)?;
    let same = |c: &Change| matches!(c, Change::PfAnchor { .. });
    // The first record says what the host looked like before SocketGuard.
    record.push_once(
        same,
        Entry::now(Change::PfAnchor {
            conf: conf.display().to_string(),
            line: PF_ANCHOR_LINE.into(),
            line_added: false,
            pf_enabled_before: was_enabled,
            pf_enabled_by_us: false,
        }),
    )?;
    if !had_line {
        let mut new = text.clone();
        if !new.is_empty() && !new.ends_with('\n') {
            new.push('\n');
        }
        new.push_str(PF_ANCHOR_LINE);
        new.push('\n');
        write_keep_mode(conf, &new)?;
        record.update(same, |c| {
            if let Change::PfAnchor { line_added, .. } = c {
                *line_added = true;
            }
        })?;
        host.run_ok("pfctl", &["-f", &conf.display().to_string()])?;
        host.say(&format!(
            "Added {PF_ANCHOR_LINE} to {} and loaded it.",
            conf.display()
        ));
    }
    if !was_enabled {
        host.run_ok("pfctl", &["-e"])?;
        record.update(same, |c| {
            if let Change::PfAnchor {
                pf_enabled_by_us, ..
            } = c
            {
                *pf_enabled_by_us = true;
            }
        })?;
        host.say("Enabled pf.");
    }
    Ok(())
}

/// Reverse a [`Change::PfAnchor`].
pub fn undo_pf_anchor(
    host: &mut dyn Host,
    conf: &Path,
    line: &str,
    line_added: bool,
    enabled_by_us: bool,
) -> Result<()> {
    if line_added {
        if let Ok(text) = std::fs::read_to_string(conf) {
            let new = install_log::remove_lines(&text, &[line.to_string()]);
            if new != text {
                write_keep_mode(conf, &new)?;
                host.run_ok("pfctl", &["-f", &conf.display().to_string()])?;
            }
        }
    }
    if enabled_by_us && pf_enabled(host)? {
        host.run_ok("pfctl", &["-d"])?;
    }
    Ok(())
}

// ─── service install ────────────────────────────────────────────────────────

pub struct InstallPlan<'a> {
    /// The binary the service runs.
    pub exe: &'a Path,
    pub config: &'a Path,
    pub db: &'a Path,
    pub no_start: bool,
    pub pf_conf: &'a Path,
}

/// `service install [--no-start]`. Safe to repeat.
pub fn service_install(
    host: &mut dyn Host,
    mgr: &mut dyn ServiceManager,
    groups: &mut dyn GroupManager,
    plan: &InstallPlan,
) -> Result<()> {
    require_admin(host, "installing the SocketGuard service")?;
    let record = Record::for_config(plan.config);
    prepare_dirs(plan.config, plan.db, &record)?;
    ensure_group(host, groups, &record)?;
    // The managed networks' children run as this account; without it they run as the
    // daemon's own and say so, so a failure here is not fatal.
    if let Err(e) = crate::account::ensure(host, &record) {
        host.say(&format!(
            "Could not create the account {}: {e:#}. Managed networks will run as the daemon's account.",
            crate::account::NAME
        ));
    }
    if host.os() == "macos" {
        ensure_pf_anchor(host, plan.pf_conf, &record)?;
    }
    mgr.install(plan.exe, !plan.no_start)?;
    let (name, manager) = (mgr.service_name(), mgr.manager().to_string());
    record.push_once(
        |c| matches!(c, Change::ServiceRegistered { .. }),
        Entry::now(Change::ServiceRegistered {
            name: name.clone(),
            manager,
        }),
    )?;
    host.say(&format!(
        "SocketGuard is installed as the service {name}{}.",
        if plan.no_start {
            " (not started)"
        } else {
            " and running"
        }
    ));
    Ok(())
}

/// What undoing an entry needs from the system besides commands.
pub trait Platform {
    /// Windows: set the WFP engine option `FWPM_ENGINE_COLLECT_NET_EVENTS` back.
    fn restore_wfp_option(&mut self, prior: u32) -> Result<()>;
}

pub struct SystemPlatform;

impl Platform for SystemPlatform {
    fn restore_wfp_option(&mut self, prior: u32) -> Result<()> {
        #[cfg(windows)]
        {
            crate::firewall::wfp::restore_collect_net_events(prior)
        }
        #[cfg(not(windows))]
        {
            let _ = prior;
            anyhow::bail!("the WFP engine option exists on Windows only")
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub struct FakePlatform {
    pub restored: Vec<u32>,
}

#[cfg(any(test, feature = "test-support"))]
impl Platform for FakePlatform {
    fn restore_wfp_option(&mut self, prior: u32) -> Result<()> {
        self.restored.push(prior);
        Ok(())
    }
}

/// Reverse one record entry (not directories: `uninstall` handles those after the data).
/// Returns what happened, as report items.
pub fn undo_entry(
    host: &mut dyn Host,
    mgr: &mut dyn ServiceManager,
    groups: &mut dyn GroupManager,
    platform: &mut dyn Platform,
    e: &Entry,
) -> Report {
    let mut r = Report::default();
    match &e.change {
        Change::ServiceRegistered { name, .. } => {
            let before = mgr.status();
            let removed = mgr.uninstall();
            // Windows only marks a service for deletion; it disappears once the last handle
            // to it closes. Give that a moment before calling it left behind.
            let mut after = mgr.status();
            for _ in 0..20 {
                if !matches!(&after, Ok(s) if s.installed) || removed.is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                after = mgr.status();
            }
            match (before, removed, after) {
                (Ok(before), Ok(()), Ok(after)) => {
                    if after.installed {
                        r.left(format!("service {name}"), "still registered after removal");
                    } else if before.installed {
                        r.removed(format!("service {name}"));
                    } else {
                        r.absent(format!("service {name}"));
                    }
                }
                (_, Err(err), _) | (Err(err), _, _) | (_, _, Err(err)) => {
                    r.left(format!("service {name}"), format!("{err:#}"))
                }
            }
        }
        Change::AccessGroup { name, created } => {
            let what = format!("group {name}");
            if !created {
                r.kept(what, "it existed before SocketGuard");
            } else {
                match groups.exists(name) {
                    Ok(false) => r.absent(what),
                    Ok(true) => match groups.delete(name).and_then(|()| groups.exists(name)) {
                        Ok(false) => r.removed(what),
                        Ok(true) => r.left(what, "still exists after deletion"),
                        Err(err) => r.left(what, format!("{err:#}")),
                    },
                    Err(err) => r.left(what, format!("{err:#}")),
                }
            }
        }
        Change::PfAnchor {
            conf,
            line,
            line_added,
            pf_enabled_before,
            pf_enabled_by_us,
        } => {
            let what = format!("pf anchor line in {conf}");
            if !line_added && !pf_enabled_by_us {
                r.kept(
                    what,
                    "it was there before SocketGuard, and pf was already enabled",
                );
            } else {
                match undo_pf_anchor(host, Path::new(conf), line, *line_added, *pf_enabled_by_us) {
                    Ok(()) => {
                        r.removed(what);
                        if *pf_enabled_by_us && !pf_enabled_before {
                            r.removed("pf enabled by SocketGuard (disabled again)");
                        }
                    }
                    Err(err) => r.left(what, format!("{err:#}")),
                }
            }
        }
        Change::WfpEngineOption { option, prior } => {
            let what = format!("WFP engine option {option}");
            match prior {
                None => r.kept(
                    what,
                    "its earlier value could not be read, so it is not changed",
                ),
                Some(p) => match platform.restore_wfp_option(*p) {
                    Ok(()) => r.removed(format!("{what} (set back to {p})")),
                    Err(err) => r.left(what, format!("{err:#}")),
                },
            }
        }
        Change::UnprivilegedAccount { name, created } => {
            r.extend(crate::account::undo(host, name, *created))
        }
        Change::WintunDriver { present_before } => {
            r.extend(crate::wintun::undo(host, *present_before))
        }
        Change::Legacy => r.kept(
            "an entry of a removed feature",
            "entry of a removed feature; nothing to undo",
        ),
        Change::DirectoryCreated { .. } | Change::OwnedDirectory { .. } => {}
    }
    r
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sg-inst-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::FakeGroups;
    use crate::host::fake::FakeHost;
    use crate::service::FakeServiceManager;

    use super::tests_support::tmp;

    #[test]
    fn install_records_what_it_created_and_is_idempotent() {
        let d = tmp();
        let config = d.join("etc").join("socketguard.json");
        let db = d.join("var").join("socketguard.db");
        let mut host = FakeHost::new("linux");
        // The unprivileged account is missing at first, then there.
        host.answer_in_order(
            "getent passwd",
            vec![
                crate::host::Output {
                    code: 2,
                    ..Default::default()
                },
                crate::host::Output::default(),
            ],
        );
        let mut mgr = FakeServiceManager::default();
        let mut groups = FakeGroups::default();
        let plan = InstallPlan {
            exe: Path::new("/bin/sg"),
            config: &config,
            db: &db,
            no_start: false,
            pf_conf: &d.join("pf.conf"),
        };
        service_install(&mut host, &mut mgr, &mut groups, &plan).unwrap();
        service_install(&mut host, &mut mgr, &mut groups, &plan).unwrap();
        let rec = Record::for_config(&config).entries().unwrap();
        let kinds: Vec<String> = rec
            .iter()
            .map(|e| match &e.change {
                Change::DirectoryCreated { .. } => "dir".into(),
                Change::AccessGroup { created, .. } => format!("group created={created}"),
                Change::ServiceRegistered { .. } => "service".into(),
                Change::UnprivilegedAccount { created, .. } => {
                    format!("account created={created}")
                }
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "dir",
                "dir",
                "group created=true",
                "account created=true",
                "service"
            ],
            "{kinds:?}"
        );
        assert!(host.ran("useradd"));
        assert!(mgr.running && mgr.installed);
        assert_eq!(groups.calls, ["create socketguard"]);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn existing_directories_are_not_recorded() {
        let d = tmp();
        let config = d.join("socketguard.json");
        let rec = Record::for_config(&config);
        assert!(prepare_dirs(&config, &d.join("socketguard.db"), &rec)
            .unwrap()
            .is_empty());
        assert!(rec.entries().unwrap().is_empty());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn install_needs_administrator_rights_and_changes_nothing_without() {
        let d = tmp();
        let config = d.join("new").join("socketguard.json");
        let mut host = FakeHost::new("linux");
        host.elevated = false;
        let mut mgr = FakeServiceManager::default();
        let mut groups = FakeGroups::default();
        let plan = InstallPlan {
            exe: Path::new("/bin/sg"),
            config: &config,
            db: &d.join("new").join("x.db"),
            no_start: true,
            pf_conf: &d.join("pf.conf"),
        };
        assert!(service_install(&mut host, &mut mgr, &mut groups, &plan).is_err());
        assert!(!d.join("new").exists());
        assert!(mgr.calls.is_empty() && groups.calls.is_empty());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pf_anchor_is_added_and_enabled_only_when_missing_and_undone_exactly() {
        let d = tmp();
        let conf = d.join("pf.conf");
        std::fs::write(&conf, "scrub-anchor \"x\"\nanchor \"other\"\n").unwrap();
        let rec = Record::new(d.join("setup-log.json"));
        let mut host = FakeHost::new("macos");
        host.answer("pfctl -s info", 0, "Status: Disabled\n");
        ensure_pf_anchor(&mut host, &conf, &rec).unwrap();
        ensure_pf_anchor(&mut host, &conf, &rec).unwrap();
        let text = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(text.matches(PF_ANCHOR_LINE).count(), 1, "{text}");
        assert!(host.ran("pfctl -e"));
        let entries = rec.entries().unwrap();
        assert_eq!(entries.len(), 1);
        let Change::PfAnchor {
            line_added,
            pf_enabled_before,
            pf_enabled_by_us,
            ..
        } = &entries[0].change
        else {
            panic!()
        };
        assert!(*line_added && !*pf_enabled_before && *pf_enabled_by_us);

        let mut mgr = FakeServiceManager::default();
        let mut groups = FakeGroups::default();
        let mut plat = FakePlatform::default();
        host.commands.clear();
        host.answer("pfctl -s info", 0, "Status: Enabled\n");
        host.exit.retain(|(p, _)| p != "pfctl -s info");
        host.answer("pfctl -s info", 0, "Status: Enabled\n");
        let r = undo_entry(&mut host, &mut mgr, &mut groups, &mut plat, &entries[0]);
        assert!(r.complete(), "{}", r.render());
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "scrub-anchor \"x\"\nanchor \"other\"\n"
        );
        assert!(host.ran("pfctl -d"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_pf_anchor_that_was_there_is_left_alone() {
        let d = tmp();
        let conf = d.join("pf.conf");
        std::fs::write(&conf, "anchor \"socketguard\"\n").unwrap();
        let rec = Record::new(d.join("setup-log.json"));
        let mut host = FakeHost::new("macos");
        host.answer("pfctl -s info", 0, "Status: Enabled\n");
        ensure_pf_anchor(&mut host, &conf, &rec).unwrap();
        assert!(!host.ran("pfctl -e") && !host.ran("pfctl -f"));
        let e = rec.entries().unwrap();
        let (mut mgr, mut groups, mut plat) = (
            FakeServiceManager::default(),
            FakeGroups::default(),
            FakePlatform::default(),
        );
        let r = undo_entry(&mut host, &mut mgr, &mut groups, &mut plat, &e[0]);
        assert!(r.complete());
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "anchor \"socketguard\"\n"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn undo_keeps_a_group_that_existed_and_restores_the_wfp_option() {
        let mut host = FakeHost::new("linux");
        let mut mgr = FakeServiceManager::default();
        let mut groups = FakeGroups::default();
        groups.groups.insert("socketguard".into(), vec![]);
        let mut plat = FakePlatform::default();
        let g = Entry::now(Change::AccessGroup {
            name: "socketguard".into(),
            created: false,
        });
        let r = undo_entry(&mut host, &mut mgr, &mut groups, &mut plat, &g);
        assert!(groups.groups.contains_key("socketguard"), "never removed");
        assert!(r.complete());
        let g = Entry::now(Change::AccessGroup {
            name: "socketguard".into(),
            created: true,
        });
        undo_entry(&mut host, &mut mgr, &mut groups, &mut plat, &g);
        assert!(!groups.groups.contains_key("socketguard"));
        let w = Entry::now(Change::WfpEngineOption {
            option: "COLLECT_NET_EVENTS".into(),
            prior: Some(0),
        });
        undo_entry(&mut host, &mut mgr, &mut groups, &mut plat, &w);
        assert_eq!(plat.restored, [0]);
    }
}
