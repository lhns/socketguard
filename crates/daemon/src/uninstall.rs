//! `socketguard-daemon uninstall` (ADR 0050): stop the service, disable, undo the install
//! record, remove the service, then (only on request) the data. Data is deleted by name,
//! never recursively; the one exception is a directory the record names as created for a
//! child process of ours, strictly inside the state directory.

use crate::access::GroupManager;
use crate::host::{require_admin, Host};
use crate::install::{undo_entry, Platform, Record};
use crate::report::Report;
use crate::service::ServiceManager;
use anyhow::{bail, Result};
use socketguard_core::install_log::{Change, Entry};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    pub purge: bool,
    pub keep_data: bool,
    /// Do not ask (the data question is then decided by `purge` / `keep_data` alone).
    pub yes: bool,
    pub export: Option<PathBuf>,
    /// Go on although disable left something.
    pub force: bool,
}

pub struct UninstallPaths {
    pub config: PathBuf,
    pub db: PathBuf,
    /// The Unix socket, if the API uses one.
    pub socket: Option<PathBuf>,
    /// The default state directory: the only place an owned directory may be removed from.
    pub state_dir: PathBuf,
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
type ExportFn<'a> = Box<dyn FnMut(&Path) -> BoxFut<'a, Result<()>> + 'a>;

pub struct Deps<'a> {
    pub host: &'a mut dyn Host,
    pub mgr: &'a mut dyn ServiceManager,
    pub groups: &'a mut dyn GroupManager,
    pub platform: &'a mut dyn Platform,
    /// Whether a daemon still answers on the API socket.
    pub api_reachable: &'a dyn Fn() -> bool,
    /// `disable` (with `force`: by name when the database is missing).
    pub disable: Box<dyn FnOnce(bool) -> BoxFut<'a, Report> + 'a>,
    /// Write an export of the settings to the file.
    pub export: ExportFn<'a>,
}

/// Whether `p` is strictly inside `root` (compared as written; both absolute).
pub fn strictly_inside(p: &Path, root: &Path) -> bool {
    p != root
        && p.is_absolute()
        && p.starts_with(root)
        && !p
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

const DATA_QUESTION: &str = "Also delete settings and keys? Onion addresses cannot be recovered; \
the export does not contain the onion private keys. [y/N]";

pub async fn uninstall(
    deps: Deps<'_>,
    opts: &UninstallOptions,
    paths: &UninstallPaths,
) -> Result<Report> {
    let Deps {
        host,
        mgr,
        groups,
        platform,
        api_reachable,
        disable,
        mut export,
    } = deps;
    require_admin(host, "uninstalling SocketGuard")?;
    if opts.purge && opts.keep_data {
        bail!("--purge and --keep-data contradict each other");
    }

    // 1. Stop the service; a daemon that still answers is not ours to stop here.
    mgr.stop()?;
    if api_reachable() {
        bail!(
            "a SocketGuard daemon still answers on the API socket; stop it first (it is not the installed service)"
        );
    }

    let mut report = Report::default();
    let record = Record::for_config(&paths.config);
    let entries = record.entries()?;

    // 2. Disable.
    let disabled = disable(opts.force).await;
    let incomplete = !disabled.complete();
    report.extend(disabled);
    if incomplete && !opts.force {
        report.note(
            "Stopped before removing anything else; fix what is LEFT, or run again with --force.",
        );
        return Ok(report);
    }

    // 3. Undo the record, newest first. Directories wait until the data is gone.
    let mut kept_entries: Vec<Entry> = vec![];
    let mut dirs: Vec<Entry> = vec![];
    let mut service_seen = false;
    for e in entries.iter().rev() {
        match &e.change {
            Change::DirectoryCreated { .. } | Change::OwnedDirectory { .. } => dirs.push(e.clone()),
            other => {
                service_seen |= matches!(other, Change::ServiceRegistered { .. });
                let r = undo_entry(host, mgr, groups, platform, e);
                if !r.complete() {
                    kept_entries.push(e.clone());
                }
                report.extend(r);
            }
        }
    }
    // 4. The service registration goes even when nothing recorded it.
    if !service_seen {
        let e = Entry::now(Change::ServiceRegistered {
            name: mgr.service_name(),
            manager: mgr.manager().into(),
        });
        report.extend(undo_entry(host, mgr, groups, platform, &e));
    }

    // 5. Data.
    let mut delete = opts.purge;
    if !opts.purge && !opts.keep_data && host.interactive() && !opts.yes {
        delete = host.confirm(DATA_QUESTION);
        if delete && opts.export.is_none() && host.confirm("Write an export of the settings first?")
        {
            let target = PathBuf::from(format!(
                "socketguard-export-{}.json",
                chrono::Utc::now().format("%Y%m%d-%H%M%S")
            ));
            report.note(format!("export: {}", target.display()));
            match export(&target).await {
                Ok(()) => host.say(&format!("Wrote {}", target.display())),
                Err(e) => {
                    report.left("export", format!("{e:#}; the data is kept"));
                    delete = false;
                }
            }
        }
    }
    if delete {
        if let Some(target) = &opts.export {
            if let Err(e) = export(target).await {
                report.left(
                    format!("export to {}", target.display()),
                    format!("{e:#}; the data is kept"),
                );
                delete = false;
            } else {
                host.say(&format!("Wrote {}", target.display()));
            }
        }
    } else if let Some(target) = &opts.export {
        // An export on request, without deleting.
        match export(target).await {
            Ok(()) => host.say(&format!("Wrote {}", target.display())),
            Err(e) => report.left(format!("export to {}", target.display()), format!("{e:#}")),
        }
    }

    let mut data_files = vec![];
    if delete {
        data_files = named_files(paths);
        for f in &data_files {
            remove_named(&mut report, f);
        }
    } else {
        report.kept(
            "settings and keys (database, config)",
            "kept; remove them with `uninstall --purge`",
        );
    }

    // Owned directories (a child process's data), then the directories we created.
    for e in &dirs {
        match &e.change {
            Change::OwnedDirectory { path } => {
                let p = Path::new(path);
                if !delete {
                    report.kept(
                        format!("directory {path}"),
                        "holds node keys; kept with the data",
                    );
                    kept_entries.push(e.clone());
                } else if !strictly_inside(p, &paths.state_dir) {
                    report.left(
                        format!("directory {path}"),
                        format!(
                            "refused: not strictly inside the state directory {}",
                            paths.state_dir.display()
                        ),
                    );
                    kept_entries.push(e.clone());
                } else {
                    match std::fs::remove_dir_all(p) {
                        Ok(()) => report.removed(format!("directory {path} (with its contents)")),
                        Err(x) if x.kind() == std::io::ErrorKind::NotFound => {
                            report.absent(format!("directory {path}"))
                        }
                        Err(x) => report.left(format!("directory {path}"), x.to_string()),
                    }
                }
            }
            Change::DirectoryCreated { path } => match std::fs::remove_dir(path) {
                Ok(()) => report.removed(format!("directory {path}")),
                Err(x) if x.kind() == std::io::ErrorKind::NotFound => {
                    report.absent(format!("directory {path}"))
                }
                Err(x) => {
                    kept_entries.push(e.clone());
                    if delete {
                        report.left(
                            format!("directory {path}"),
                            format!("not removed (it is not empty or in use; only named files are deleted): {x}"),
                        );
                    } else {
                        report.kept(format!("directory {path}"), "it holds the kept data");
                    }
                }
            },
            _ => {}
        }
    }

    // The record itself: gone with the data, else it keeps what is still to undo.
    let rec_path = record.path().to_path_buf();
    if delete && !data_files.contains(&rec_path) {
        remove_named(&mut report, &rec_path);
    }
    if !delete || !kept_entries.is_empty() {
        kept_entries.sort_by(|a, b| a.time.cmp(&b.time));
        if rec_path.parent().is_some_and(Path::exists) {
            if kept_entries.is_empty() {
                let _ = std::fs::remove_file(&rec_path);
            } else {
                record.write(&kept_entries)?;
            }
        }
    }
    Ok(report)
}

/// The files `--purge` deletes, by name.
pub fn named_files(paths: &UninstallPaths) -> Vec<PathBuf> {
    let mut out = vec![];
    let db = paths.db.to_string_lossy().into_owned();
    for suffix in ["", "-wal", "-shm"] {
        out.push(PathBuf::from(format!("{db}{suffix}")));
    }
    if let (Some(dir), Some(name)) = (paths.db.parent(), paths.db.file_name()) {
        let prefix = format!("{}.pre-v1", name.to_string_lossy());
        out.extend(list_prefixed(dir, &prefix));
    }
    out.push(paths.config.clone());
    if let Some(dir) = paths.config.parent() {
        out.extend(list_prefixed(dir, "socketguard.tmp-"));
    }
    out.push(socketguard_core::paths::setup_log_path(&paths.config));
    if let Some(s) = &paths.socket {
        out.push(s.clone());
    }
    out
}

fn list_prefixed(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

fn remove_named(report: &mut Report, f: &Path) {
    match std::fs::remove_file(f) {
        Ok(()) => report.removed(format!("file {}", f.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => report.left(format!("file {}", f.display()), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::FakeGroups;
    use crate::host::fake::FakeHost;
    use crate::install::{tests_support::tmp, FakePlatform};
    use crate::report::Outcome;
    use crate::service::FakeServiceManager;
    use std::cell::RefCell;

    struct World {
        d: PathBuf,
        config: PathBuf,
        db: PathBuf,
        state: PathBuf,
    }

    fn world() -> World {
        let d = tmp();
        let etc = d.join("etc");
        let state = d.join("var");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let config = etc.join("socketguard.json");
        let db = state.join("socketguard.db");
        for f in [
            &config,
            &db,
            &state.join("socketguard.db-wal"),
            &state.join("socketguard.db-shm"),
            &state.join("socketguard.db.pre-v1"),
            &state.join("socketguard.db.pre-v1.2"),
            &etc.join("socketguard.tmp-1-abc"),
            &etc.join("unrelated.txt"),
            &state.join("unrelated-too.txt"),
        ] {
            std::fs::write(f, "x").unwrap();
        }
        World {
            d,
            config,
            db,
            state,
        }
    }

    fn paths(w: &World) -> UninstallPaths {
        UninstallPaths {
            config: w.config.clone(),
            db: w.db.clone(),
            socket: None,
            state_dir: w.state.clone(),
        }
    }

    fn record(w: &World, changes: Vec<Change>) {
        Record::for_config(&w.config)
            .write(&changes.into_iter().map(Entry::now).collect::<Vec<_>>())
            .unwrap();
    }

    async fn run(
        w: &World,
        host: &mut FakeHost,
        mgr: &mut FakeServiceManager,
        groups: &mut FakeGroups,
        opts: UninstallOptions,
        disable_report: Report,
        order: &RefCell<Vec<String>>,
    ) -> Result<Report> {
        let mut plat = FakePlatform::default();
        let exported = RefCell::new(vec![]);
        let deps = Deps {
            host,
            mgr,
            groups,
            platform: &mut plat,
            api_reachable: &|| false,
            disable: Box::new(|force| {
                order.borrow_mut().push(format!("disable force={force}"));
                Box::pin(async move { disable_report })
            }),
            export: Box::new(|p| {
                exported.borrow_mut().push(p.to_path_buf());
                order.borrow_mut().push("export".into());
                let p = p.to_path_buf();
                Box::pin(async move { std::fs::write(p, "{}").map_err(Into::into) })
            }),
        };
        uninstall(deps, &opts, &paths(w)).await
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn purge_deletes_exactly_the_named_files_and_directories_only_when_recorded_and_empty() {
        let w = world();
        record(
            &w,
            vec![
                Change::DirectoryCreated {
                    path: w.state.display().to_string(),
                },
                Change::DirectoryCreated {
                    path: w.d.join("etc").display().to_string(),
                },
                Change::AccessGroup {
                    name: "socketguard".into(),
                    created: true,
                },
                Change::ServiceRegistered {
                    name: "fake-service".into(),
                    manager: "fake".into(),
                },
            ],
        );
        let mut host = FakeHost::new("linux");
        let mut mgr = FakeServiceManager {
            installed: true,
            running: true,
            ..Default::default()
        };
        let mut groups = FakeGroups::default();
        groups.groups.insert("socketguard".into(), vec![]);
        let order = RefCell::new(vec![]);
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                purge: true,
                yes: true,
                ..Default::default()
            },
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        let text = report.render();
        // The unrelated files stay, so both recorded directories are not empty: LEFT, not deleted.
        assert_eq!(names(&w.state), ["unrelated-too.txt"], "{text}");
        // The record stays while a recorded directory is LEFT, so a later run can finish.
        assert_eq!(
            names(&w.d.join("etc")),
            ["setup-log.json", "unrelated.txt"],
            "{text}"
        );
        assert!(
            !report.complete(),
            "a directory with a stranger's file is reported:\n{text}"
        );
        assert_eq!(mgr.calls.first().map(String::as_str), Some("stop"));
        assert!(!mgr.installed);
        assert!(groups.groups.is_empty());
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn empty_recorded_directories_are_removed_and_unrecorded_ones_stay() {
        let w = world();
        std::fs::remove_file(w.d.join("etc").join("unrelated.txt")).unwrap();
        std::fs::remove_file(w.state.join("unrelated-too.txt")).unwrap();
        // Only the state directory is recorded as created by us.
        record(
            &w,
            vec![Change::DirectoryCreated {
                path: w.state.display().to_string(),
            }],
        );
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        let order = RefCell::new(vec![]);
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                purge: true,
                yes: true,
                ..Default::default()
            },
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        assert!(report.complete(), "{}", report.render());
        assert!(!w.state.exists());
        assert!(w.d.join("etc").exists(), "not recorded, so not removed");
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn non_interactive_without_flags_keeps_the_data_and_the_record_of_directories() {
        let w = world();
        record(
            &w,
            vec![Change::DirectoryCreated {
                path: w.state.display().to_string(),
            }],
        );
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        let order = RefCell::new(vec![]);
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions::default(),
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        assert!(report.complete(), "{}", report.render());
        assert!(w.db.exists() && w.config.exists());
        assert!(host.questions.is_empty(), "no prompt without a terminal");
        let left = Record::for_config(&w.config).entries().unwrap();
        assert_eq!(left.len(), 1, "a later purge still knows the directory");
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn an_interactive_run_asks_offers_an_export_and_deletes_only_on_yes() {
        let w = world();
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        host.interactive = true;
        host.answers_yes = true;
        let order = RefCell::new(vec![]);
        // The export lands in the working directory by default; give the test its own.
        let before = std::env::current_dir().unwrap();
        std::env::set_current_dir(&w.d).unwrap();
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions::default(),
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        std::env::set_current_dir(before).unwrap();
        assert!(host.questions[0].contains("Also delete settings and keys?"));
        assert!(host.questions[0].contains("Onion addresses cannot be recovered"));
        assert!(host.questions[1].contains("export"));
        assert_eq!(*order.borrow(), ["disable force=false", "export"]);
        assert!(!w.db.exists() && !w.config.exists(), "{}", report.render());
        std::fs::remove_dir_all(w.d).unwrap();

        let w = world();
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        host.interactive = true;
        let order = RefCell::new(vec![]);
        run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions::default(),
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        assert!(w.db.exists(), "default is no");
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn disable_runs_after_the_stop_and_a_left_item_stops_everything_unless_forced() {
        let w = world();
        record(
            &w,
            vec![Change::ServiceRegistered {
                name: "fake-service".into(),
                manager: "fake".into(),
            }],
        );
        let mut left = Report::default();
        left.left("address fd00::1 on lo", "busy");
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager {
                installed: true,
                ..Default::default()
            },
            FakeGroups::default(),
        );
        let order = RefCell::new(vec![]);
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                purge: true,
                ..Default::default()
            },
            left.clone(),
            &order,
        )
        .await
        .unwrap();
        assert!(!report.complete());
        assert!(
            mgr.installed,
            "the service registration stays when disable left something"
        );
        assert!(w.db.exists());
        let report = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                purge: true,
                force: true,
                ..Default::default()
            },
            left,
            &order,
        )
        .await
        .unwrap();
        assert!(!mgr.installed && !w.db.exists());
        assert!(!report.complete(), "still non-zero: the address is LEFT");
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn a_daemon_that_still_answers_and_a_missing_administrator_right_refuse() {
        let w = world();
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        host.elevated = false;
        let order = RefCell::new(vec![]);
        assert!(run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions::default(),
            Report::default(),
            &order
        )
        .await
        .is_err());
        assert!(mgr.calls.is_empty());
        host.elevated = true;
        let mut plat = FakePlatform::default();
        let deps = Deps {
            host: &mut host,
            mgr: &mut mgr,
            groups: &mut groups,
            platform: &mut plat,
            api_reachable: &|| true,
            disable: Box::new(|_| Box::pin(async { panic!("must not disable") })),
            export: Box::new(|_| Box::pin(async { Ok(()) })),
        };
        let err = uninstall(deps, &UninstallOptions::default(), &paths(&w))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("still answers"));
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[tokio::test]
    async fn owned_directories_go_on_purge_only_inside_the_state_directory() {
        let w = world();
        let tor = w.state.join("tor");
        std::fs::create_dir_all(tor.join("keys")).unwrap();
        std::fs::write(tor.join("keys").join("k"), "k").unwrap();
        let outside = w.d.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious"), "p").unwrap();
        let changes = vec![
            Change::OwnedDirectory {
                path: tor.display().to_string(),
            },
            Change::OwnedDirectory {
                path: outside.display().to_string(),
            },
            Change::OwnedDirectory {
                path: w.state.display().to_string(),
            },
        ];
        // keep-data: everything stays.
        record(&w, changes.clone());
        let (mut host, mut mgr, mut groups) = (
            FakeHost::new("linux"),
            FakeServiceManager::default(),
            FakeGroups::default(),
        );
        let order = RefCell::new(vec![]);
        let r = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                keep_data: true,
                ..Default::default()
            },
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        assert!(r.complete() && tor.join("keys").join("k").exists());
        // purge
        let r = run(
            &w,
            &mut host,
            &mut mgr,
            &mut groups,
            UninstallOptions {
                purge: true,
                ..Default::default()
            },
            Report::default(),
            &order,
        )
        .await
        .unwrap();
        let text = r.render();
        assert!(!tor.exists(), "{text}");
        assert!(
            outside.join("precious").exists(),
            "outside the state dir is refused:\n{text}"
        );
        assert!(w.state.exists(), "the state directory itself is refused");
        assert_eq!(r.left_items().len(), 2, "{text}");
        assert!(r
            .items
            .iter()
            .any(|i| matches!(&i.outcome, Outcome::Left(w) if w.contains("refused"))));
        std::fs::remove_dir_all(w.d).unwrap();
    }

    #[test]
    fn strictly_inside_rejects_the_root_and_dotdot() {
        let root = std::env::temp_dir().join("socketguard");
        assert!(strictly_inside(&root.join("tor"), &root));
        assert!(!strictly_inside(&root, &root));
        assert!(!strictly_inside(&root.join("..").join("x"), &root));
        assert!(!strictly_inside(&std::env::temp_dir().join("other"), &root));
        assert!(!strictly_inside(Path::new("tor"), &root));
    }
}
