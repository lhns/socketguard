//! The access group (ADR 0050, ADR 0032): members of `SocketGuard Users` (Windows) or
//! `socketguard` (elsewhere) may use the API without administrator rights. These are
//! the administrator commands behind `socketguard-daemon access ...`, over a
//! [`GroupManager`] so they are tested with a fake.
//!
//! The daemon looks the group up when it binds its endpoint, so a group created after the
//! daemon started is picked up at the next start; membership applies from the account's
//! next sign-in (the access token is built then).

use crate::host::{require_admin, Host};
use crate::install::Record;
use crate::transport::{UNIX_GROUP, WINDOWS_GROUP};
use anyhow::{bail, Result};
use socketguard_core::install_log::{Change, Entry};

/// The group of this system.
pub fn group_name(os: &str) -> &'static str {
    if os == "windows" {
        WINDOWS_GROUP
    } else {
        UNIX_GROUP
    }
}

pub trait GroupManager {
    fn exists(&mut self, group: &str) -> Result<bool>;
    fn create(&mut self, group: &str) -> Result<()>;
    fn delete(&mut self, group: &str) -> Result<()>;
    fn add(&mut self, group: &str, account: &str) -> Result<()>;
    fn remove(&mut self, group: &str, account: &str) -> Result<()>;
    fn members(&mut self, group: &str) -> Result<Vec<String>>;
}

/// The commands of one system's tools, run through a [`Host`].
pub struct Tools<'a, H: Host> {
    pub host: &'a mut H,
}

impl<H: Host> GroupManager for Tools<'_, H> {
    fn exists(&mut self, group: &str) -> Result<bool> {
        Ok(match self.host.os() {
            "windows" => self.host.run("net", &["localgroup", group])?.ok(),
            "macos" => self
                .host
                .run("dscl", &[".", "-read", &format!("/Groups/{group}")])?
                .ok(),
            _ => self.host.run("getent", &["group", group])?.ok(),
        })
    }

    fn create(&mut self, group: &str) -> Result<()> {
        match self.host.os() {
            "windows" => self.host.run_ok("net", &["localgroup", group, "/add"])?,
            "macos" => self
                .host
                .run_ok("dseditgroup", &["-o", "create", "-q", group])?,
            _ => self.host.run_ok("groupadd", &["--system", group])?,
        };
        Ok(())
    }

    fn delete(&mut self, group: &str) -> Result<()> {
        match self.host.os() {
            "windows" => self.host.run_ok("net", &["localgroup", group, "/delete"])?,
            "macos" => self
                .host
                .run_ok("dseditgroup", &["-o", "delete", "-q", group])?,
            _ => self.host.run_ok("groupdel", &[group])?,
        };
        Ok(())
    }

    fn add(&mut self, group: &str, account: &str) -> Result<()> {
        match self.host.os() {
            "windows" => self
                .host
                .run_ok("net", &["localgroup", group, account, "/add"])?,
            "macos" => self
                .host
                .run_ok("dseditgroup", &["-o", "edit", "-a", account, "-t", "user", group])?,
            _ => self.host.run_ok("usermod", &["-aG", group, account])?,
        };
        Ok(())
    }

    fn remove(&mut self, group: &str, account: &str) -> Result<()> {
        match self.host.os() {
            "windows" => self
                .host
                .run_ok("net", &["localgroup", group, account, "/delete"])?,
            "macos" => self
                .host
                .run_ok("dseditgroup", &["-o", "edit", "-d", account, "-t", "user", group])?,
            _ => self.host.run_ok("gpasswd", &["-d", account, group])?,
        };
        Ok(())
    }

    fn members(&mut self, group: &str) -> Result<Vec<String>> {
        let out = match self.host.os() {
            "windows" => self.host.run_ok("net", &["localgroup", group])?,
            "macos" => self
                .host
                .run_ok("dscl", &[".", "-read", &format!("/Groups/{group}"), "GroupMembership"])?,
            _ => self.host.run_ok("getent", &["group", group])?,
        };
        Ok(parse_members(self.host.os(), &out.stdout))
    }
}

/// The accounts named in the output of the system's group listing.
pub fn parse_members(os: &str, text: &str) -> Vec<String> {
    match os {
        // "Alias name ...\nComment ...\n\nMembers\n\n-----\nalice\nbob\n\nThe command completed..."
        "windows" => {
            let mut lines = text.lines();
            for l in lines.by_ref() {
                if l.starts_with("-----") {
                    break;
                }
            }
            lines
                .map(str::trim)
                .take_while(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        }
        // "GroupMembership: alice bob"
        "macos" => text
            .split_once(':')
            .map(|(_, m)| m.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        // "socketguard:x:998:alice,bob"
        _ => text
            .trim()
            .rsplit(':')
            .next()
            .map(|m| {
                m.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// `access group ensure`: create the group if missing and record whether it existed. A
/// second run never overwrites the first record (a group SocketGuard created stays "created").
pub fn ensure_group(
    host: &mut dyn Host,
    groups: &mut dyn GroupManager,
    record: &Record,
) -> Result<bool> {
    let name = group_name(host.os());
    let existed = groups.exists(name)?;
    if !existed {
        groups.create(name)?;
        host.say(&format!(
            "Created the group \"{name}\". Restart the SocketGuard service so it picks the group up."
        ));
    } else {
        host.say(&format!("The group \"{name}\" exists already."));
    }
    record.push_once(
        |c| matches!(c, Change::AccessGroup { name: n, .. } if n == name),
        Entry::now(
            None,
            Change::AccessGroup {
                name: name.to_string(),
                created: !existed,
            },
        ),
    )?;
    Ok(!existed)
}

fn check_account(account: &str) -> Result<()> {
    if account.trim().is_empty()
        || account.starts_with('-')
        || account.contains(['/', ',', '"', '\n', '\r'])
    {
        bail!("{account:?} is not an account name");
    }
    Ok(())
}

pub const SIGN_IN_NOTE: &str =
    "Membership applies from the account's next sign-in; the account must sign out and in again.";

/// `access allow <account>`.
pub fn allow(
    host: &mut dyn Host,
    groups: &mut dyn GroupManager,
    record: &Record,
    account: &str,
) -> Result<()> {
    require_admin(host, "changing who may use SocketGuard")?;
    check_account(account)?;
    ensure_group(host, groups, record)?;
    let name = group_name(host.os());
    if groups.members(name)?.iter().any(|m| m.eq_ignore_ascii_case(account)) {
        host.say(&format!("{account} is a member of \"{name}\" already."));
        return Ok(());
    }
    groups.add(name, account)?;
    host.say(&format!("{account} may now use SocketGuard. {SIGN_IN_NOTE}"));
    Ok(())
}

/// `access deny <account>`.
pub fn deny(
    host: &mut dyn Host,
    groups: &mut dyn GroupManager,
    account: &str,
) -> Result<()> {
    require_admin(host, "changing who may use SocketGuard")?;
    check_account(account)?;
    let name = group_name(host.os());
    if !groups.exists(name)? || !groups.members(name)?.iter().any(|m| m.eq_ignore_ascii_case(account)) {
        host.say(&format!("{account} is not a member of \"{name}\"."));
        return Ok(());
    }
    groups.remove(name, account)?;
    host.say(&format!(
        "{account} may no longer use SocketGuard. Sessions already signed in keep access until they sign out."
    ));
    Ok(())
}

/// `access list`: the accounts that may use SocketGuard without administrator rights.
pub fn list(host: &mut dyn Host, groups: &mut dyn GroupManager) -> Result<()> {
    let name = group_name(host.os());
    if !groups.exists(name)? {
        host.say(&format!(
            "The group \"{name}\" does not exist; only administrators can use SocketGuard (`socketguard-daemon access group ensure`)."
        ));
        return Ok(());
    }
    let members = groups.members(name)?;
    host.say(&format!("Group \"{name}\":"));
    if members.is_empty() {
        host.say("  (no members; only administrators can use SocketGuard)");
    }
    for m in members {
        host.say(&format!("  {m}"));
    }
    Ok(())
}

/// A [`GroupManager`] that only remembers, for tests of the code around it.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct FakeGroups {
    pub groups: std::collections::BTreeMap<String, Vec<String>>,
    pub calls: Vec<String>,
}

#[cfg(any(test, feature = "test-support"))]
impl GroupManager for FakeGroups {
    fn exists(&mut self, g: &str) -> Result<bool> {
        Ok(self.groups.contains_key(g))
    }
    fn create(&mut self, g: &str) -> Result<()> {
        self.calls.push(format!("create {g}"));
        self.groups.insert(g.to_string(), vec![]);
        Ok(())
    }
    fn delete(&mut self, g: &str) -> Result<()> {
        self.calls.push(format!("delete {g}"));
        self.groups.remove(g);
        Ok(())
    }
    fn add(&mut self, g: &str, a: &str) -> Result<()> {
        self.calls.push(format!("add {g} {a}"));
        self.groups.entry(g.to_string()).or_default().push(a.to_string());
        Ok(())
    }
    fn remove(&mut self, g: &str, a: &str) -> Result<()> {
        self.calls.push(format!("remove {g} {a}"));
        if let Some(m) = self.groups.get_mut(g) {
            m.retain(|x| x != a);
        }
        Ok(())
    }
    fn members(&mut self, g: &str) -> Result<Vec<String>> {
        Ok(self.groups.get(g).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;

    fn record() -> (Record, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("sg-acc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        (Record::new(d.join("setup-log.json")), d)
    }

    #[test]
    fn ensure_creates_once_and_remembers_that_it_created() {
        let (rec, d) = record();
        let mut host = FakeHost::new("linux");
        let mut g = FakeGroups::default();
        assert!(ensure_group(&mut host, &mut g, &rec).unwrap());
        assert!(!ensure_group(&mut host, &mut g, &rec).unwrap());
        assert_eq!(g.calls, ["create socketguard"]);
        let e = rec.entries().unwrap();
        assert_eq!(e.len(), 1, "the second run does not overwrite the first record");
        assert!(matches!(&e[0].change, Change::AccessGroup { created: true, .. }));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_group_that_existed_is_recorded_as_such() {
        let (rec, d) = record();
        let mut host = FakeHost::new("windows");
        let mut g = FakeGroups::default();
        g.groups.insert("SocketGuard Users".into(), vec![]);
        assert!(!ensure_group(&mut host, &mut g, &rec).unwrap());
        assert!(g.calls.is_empty());
        assert!(matches!(
            &rec.entries().unwrap()[0].change,
            Change::AccessGroup { created: false, name } if name == "SocketGuard Users"
        ));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn allow_and_deny_are_idempotent_and_need_administrator_rights() {
        let (rec, d) = record();
        let mut host = FakeHost::new("linux");
        let mut g = FakeGroups::default();
        allow(&mut host, &mut g, &rec, "alice").unwrap();
        allow(&mut host, &mut g, &rec, "alice").unwrap();
        assert_eq!(g.groups["socketguard"], ["alice"]);
        assert!(host.said.iter().any(|l| l.contains("sign-in")));
        deny(&mut host, &mut g, "alice").unwrap();
        deny(&mut host, &mut g, "alice").unwrap();
        assert!(g.groups["socketguard"].is_empty());
        host.elevated = false;
        let err = allow(&mut host, &mut g, &rec, "bob").unwrap_err();
        assert!(format!("{err}").contains("administrator"), "{err}");
        assert!(deny(&mut host, &mut g, "bob").is_err());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_commands_of_each_system() {
        for (os, create, add) in [
            ("linux", "groupadd --system socketguard", "usermod -aG socketguard alice"),
            ("macos", "dseditgroup -o create -q socketguard", "dseditgroup -o edit -a alice -t user socketguard"),
            ("windows", "net localgroup SocketGuard Users /add", "net localgroup SocketGuard Users alice /add"),
        ] {
            let mut host = FakeHost::new(os);
            let name = group_name(os);
            {
                let mut t = Tools { host: &mut host };
                t.create(name).unwrap();
                t.add(name, "alice").unwrap();
            }
            assert_eq!(host.commands, [create, add], "{os}");
        }
    }

    #[test]
    fn member_listings_are_parsed() {
        assert_eq!(parse_members("linux", "socketguard:x:998:alice,bob\n"), ["alice", "bob"]);
        assert!(parse_members("linux", "socketguard:x:998:\n").is_empty());
        assert_eq!(parse_members("macos", "GroupMembership: alice bob\n"), ["alice", "bob"]);
        assert_eq!(
            parse_members(
                "windows",
                "Alias name     SocketGuard Users\r\nComment\r\n\r\nMembers\r\n\r\n-------\r\nPC\\alice\r\nPC\\bob\r\n\r\nThe command completed successfully.\r\n"
            ),
            ["PC\\alice", "PC\\bob"]
        );
    }
}
