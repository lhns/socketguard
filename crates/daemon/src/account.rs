//! The unprivileged account the managed networks' children run as (ADR 0052): a system
//! account `socketguard-net` that `service install` creates on Linux and macOS (Windows
//! uses LocalService, which exists), and uninstall removes again when it created it.
//!
//! Two halves: finding the account at run time ([`Accounts`]) and creating and removing it
//! through the [`Host`] (tested with the fake host).

use crate::host::Host;
use crate::install::Record;
use crate::report::Report;
use anyhow::{bail, Result};
use socketguard_core::install_log::{Change, Entry};

pub const NAME: &str = "socketguard-net";

/// The numeric ids of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

/// What the daemon asks the system about accounts.
pub trait Accounts: Send + Sync {
    fn lookup(&self, name: &str) -> Option<Ids>;
    /// The daemon's own uid, and whether it may start processes as another account.
    fn daemon(&self) -> (u32, bool);
}

/// The accounts of this machine.
pub struct SystemAccounts;

impl Accounts for SystemAccounts {
    #[cfg(unix)]
    fn lookup(&self, name: &str) -> Option<Ids> {
        let cname = std::ffi::CString::new(name).ok()?;
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call; `buf` is the scratch space
        // getpwnam_r documents.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut out,
            )
        };
        (rc == 0 && !out.is_null()).then_some(Ids {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
        })
    }

    #[cfg(not(unix))]
    fn lookup(&self, _name: &str) -> Option<Ids> {
        None
    }

    #[cfg(unix)]
    fn daemon(&self) -> (u32, bool) {
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        (uid, uid == 0)
    }

    /// Windows: the second value is whether the daemon is SYSTEM, which may start a process
    /// as LocalService (a daemon started by hand from a user account may not).
    #[cfg(windows)]
    fn daemon(&self) -> (u32, bool) {
        let system = crate::networks::tor_control::winacl::current_user_sid()
            .is_ok_and(|sid| sid == "S-1-5-18");
        (0, system)
    }

    #[cfg(not(any(unix, windows)))]
    fn daemon(&self) -> (u32, bool) {
        (0, false)
    }
}

/// A scripted [`Accounts`] for tests.
#[cfg(any(test, feature = "test-support"))]
pub struct FakeAccounts {
    pub account: Option<Ids>,
    pub daemon_uid: u32,
    pub root: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl FakeAccounts {
    /// The account exists and the daemon is root.
    pub fn present() -> Self {
        Self {
            account: Some(Ids { uid: 990, gid: 990 }),
            daemon_uid: 0,
            root: true,
        }
    }
    pub fn absent() -> Self {
        Self {
            account: None,
            ..Self::present()
        }
    }

    /// The account exists and has the ids of the test process itself, so giving a
    /// directory to it works without being root; the daemon counts as root.
    pub fn own() -> Self {
        #[cfg(unix)]
        // SAFETY: geteuid and getegid have no preconditions.
        let ids = unsafe {
            Ids {
                uid: libc::geteuid(),
                gid: libc::getegid(),
            }
        };
        #[cfg(not(unix))]
        let ids = Ids { uid: 990, gid: 990 };
        Self {
            account: Some(ids),
            daemon_uid: ids.uid,
            root: true,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Accounts for FakeAccounts {
    fn lookup(&self, name: &str) -> Option<Ids> {
        (name == NAME).then_some(self.account).flatten()
    }
    fn daemon(&self) -> (u32, bool) {
        (self.daemon_uid, self.root)
    }
}

fn exists(host: &mut dyn Host) -> Result<bool> {
    Ok(match host.os() {
        "macos" => host
            .run("dscl", &[".", "-read", &format!("/Users/{NAME}")])?
            .ok(),
        _ => host.run("getent", &["passwd", NAME])?.ok(),
    })
}

/// The first number from `lo` up that is not in `taken` (the output of `dscl -list`, the
/// number is the last column).
fn free_id(taken: &str, lo: u32) -> u32 {
    let used: Vec<u32> = taken
        .lines()
        .filter_map(|l| l.split_whitespace().last()?.parse().ok())
        .collect();
    (lo..).find(|n| !used.contains(n)).expect("ids run out")
}

/// macOS (untested on a real Mac): a hidden role account with no login, in the range of
/// system accounts, with a group of its own.
fn create_macos(host: &mut dyn Host) -> Result<()> {
    let users = host.run_ok("dscl", &[".", "-list", "/Users", "UniqueID"])?;
    let groups = host.run_ok("dscl", &[".", "-list", "/Groups", "PrimaryGroupID"])?;
    let id = free_id(&format!("{}\n{}", users.stdout, groups.stdout), 300).to_string();
    let user = format!("/Users/{NAME}");
    let group = format!("/Groups/{NAME}");
    host.run_ok("dscl", &[".", "-create", &group])?;
    host.run_ok("dscl", &[".", "-create", &group, "PrimaryGroupID", &id])?;
    host.run_ok("dscl", &[".", "-create", &user])?;
    for (key, value) in [
        ("UserShell", "/usr/bin/false"),
        ("RealName", "SocketGuard network helper"),
        ("UniqueID", id.as_str()),
        ("PrimaryGroupID", id.as_str()),
        ("NFSHomeDirectory", "/var/empty"),
        ("IsHidden", "1"),
    ] {
        host.run_ok("dscl", &[".", "-create", &user, key, value])?;
    }
    Ok(())
}

/// Create the account if it is missing and record what was found; a no-op on Windows.
/// Recorded before the creation, so an interrupted install is still undone.
pub fn ensure(host: &mut dyn Host, record: &Record) -> Result<()> {
    if host.os() == "windows" {
        return Ok(());
    }
    let same = |c: &Change| matches!(c, Change::UnprivilegedAccount { name, .. } if name == NAME);
    if exists(host)? {
        record.push_once(
            same,
            Entry::now(Change::UnprivilegedAccount {
                name: NAME.into(),
                created: false,
            }),
        )?;
        return Ok(());
    }
    record.push_once(
        same,
        Entry::now(Change::UnprivilegedAccount {
            name: NAME.into(),
            created: true,
        }),
    )?;
    match host.os() {
        "macos" => create_macos(host)?,
        _ => {
            host.run_ok(
                "useradd",
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    NAME,
                ],
            )?;
        }
    }
    if !exists(host)? {
        bail!("the account {NAME} does not exist after creating it");
    }
    host.say(&format!(
        "Created the system account {NAME} for the managed networks."
    ));
    Ok(())
}

fn delete(host: &mut dyn Host) -> Result<()> {
    match host.os() {
        "macos" => {
            host.run_ok("dscl", &[".", "-delete", &format!("/Users/{NAME}")])?;
            // The group is ours too; a missing one is fine.
            let _ = host.run("dscl", &[".", "-delete", &format!("/Groups/{NAME}")])?;
        }
        _ => {
            host.run_ok("userdel", &[NAME])?;
        }
    }
    Ok(())
}

/// Reverse a [`Change::UnprivilegedAccount`]: the account goes only if SocketGuard
/// created it.
pub fn undo(host: &mut dyn Host, name: &str, created: bool) -> Report {
    let mut r = Report::default();
    let what = format!("account {name}");
    if !created {
        r.kept(what, "it existed before SocketGuard");
        return r;
    }
    if name != NAME {
        r.kept(what, "not an account SocketGuard creates");
        return r;
    }
    match exists(host) {
        Ok(false) => r.absent(what),
        Ok(true) => match delete(host).and_then(|()| exists(host)) {
            Ok(false) => r.removed(what),
            Ok(true) => r.left(what, "still exists after deletion"),
            Err(e) => r.left(what, format!("{e:#}")),
        },
        Err(e) => r.left(what, format!("{e:#}")),
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::install::tests_support::tmp;

    fn record() -> (Record, std::path::PathBuf) {
        let d = tmp();
        (Record::new(d.join("setup-log.json")), d)
    }

    fn changes(r: &Record) -> Vec<Change> {
        r.entries().unwrap().into_iter().map(|e| e.change).collect()
    }

    #[test]
    fn a_missing_account_is_created_on_linux_and_recorded() {
        let (rec, d) = record();
        let mut host = FakeHost::new("linux");
        // Missing before, there after useradd.
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
        ensure(&mut host, &rec).unwrap();
        assert!(host.ran(
            "useradd --system --user-group --no-create-home --home-dir /nonexistent \
             --shell /usr/sbin/nologin socketguard-net"
        ));
        assert_eq!(
            changes(&rec),
            [Change::UnprivilegedAccount {
                name: NAME.into(),
                created: true
            }]
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn an_account_that_existed_is_recorded_as_not_ours() {
        let (rec, d) = record();
        let mut host = FakeHost::new("linux");
        ensure(&mut host, &rec).unwrap();
        ensure(&mut host, &rec).unwrap();
        assert!(!host.ran("useradd"));
        assert_eq!(
            changes(&rec),
            [Change::UnprivilegedAccount {
                name: NAME.into(),
                created: false
            }]
        );
        let r = undo(&mut host, NAME, false);
        assert!(r.complete() && !host.ran("userdel"), "{}", r.render());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn windows_needs_no_account() {
        let (rec, d) = record();
        let mut host = FakeHost::new("windows");
        ensure(&mut host, &rec).unwrap();
        assert!(host.commands.is_empty() && changes(&rec).is_empty());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn macos_gets_a_role_account_in_the_first_free_id() {
        let (rec, d) = record();
        let mut host = FakeHost::new("macos");
        host.answer(
            "dscl . -list /Users UniqueID",
            0,
            "root 0\n_foo 300\n_bar 301\n",
        );
        host.answer(
            "dscl . -list /Groups PrimaryGroupID",
            0,
            "wheel 0\n_baz 302\n",
        );
        host.answer_in_order(
            "dscl . -read /Users/socketguard-net",
            vec![
                crate::host::Output {
                    code: 56,
                    ..Default::default()
                },
                crate::host::Output::default(),
            ],
        );
        ensure(&mut host, &rec).unwrap();
        assert!(host.ran("dscl . -create /Users/socketguard-net UniqueID 303"));
        assert!(host.ran("dscl . -create /Groups/socketguard-net PrimaryGroupID 303"));
        assert!(host.ran("dscl . -create /Users/socketguard-net UserShell /usr/bin/false"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn undo_removes_only_an_account_we_created() {
        let mut host = FakeHost::new("linux");
        host.answer_in_order(
            "getent passwd",
            vec![
                crate::host::Output::default(),
                crate::host::Output {
                    code: 2,
                    ..Default::default()
                },
            ],
        );
        let r = undo(&mut host, NAME, true);
        assert!(r.complete(), "{}", r.render());
        assert!(host.ran("userdel socketguard-net"));

        // Already gone.
        let mut host = FakeHost::new("linux");
        host.answer("getent passwd", 2, "");
        let r = undo(&mut host, NAME, true);
        assert!(r.complete() && !host.ran("userdel"));

        // Still there after userdel: reported as left.
        let mut host = FakeHost::new("linux");
        let r = undo(&mut host, NAME, true);
        assert!(!r.complete(), "{}", r.render());
    }
}
