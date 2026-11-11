//! The daemon binary's command line (ADR 0050). No options library: the grammar is small.
//!
//! ```text
//! socketguard-daemon                              run the daemon
//! socketguard-daemon --disable [--force]          remove rules, addresses, onion services
//! socketguard-daemon service install [--no-start] | uninstall | start | stop | status [--json] | run
//! socketguard-daemon access group ensure | allow <account> | deny <account> | list
//! socketguard-daemon uninstall [--purge] [--keep-data] [--yes] [--export <file>] [--force]
//! ```

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCmd {
    Install { no_start: bool },
    Uninstall,
    Start,
    Stop,
    Status { json: bool },
    /// Windows: started by the service control manager.
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessCmd {
    GroupEnsure,
    Allow(String),
    Deny(String),
    List,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run,
    Disable { force: bool },
    Service(ServiceCmd),
    Access(AccessCmd),
    Uninstall {
        purge: bool,
        keep_data: bool,
        yes: bool,
        force: bool,
        export: Option<PathBuf>,
    },
    Help,
}

pub const USAGE: &str = "\
usage: socketguard-daemon [command]

  (no command)                    run the daemon
  --disable [--force]             remove the firewall rules, addresses and onion services
  service install [--no-start]    register and start the SocketGuard service
  service uninstall|start|stop    (administrator)
  service status [--json]         installed? running?
  access group ensure             create the access group
  access allow|deny <account>     let an account use SocketGuard without administrator rights
  access list
  uninstall [--purge] [--keep-data] [--yes] [--export <file>] [--force]
";

pub fn parse(args: &[String]) -> Result<Command, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let unknown = |x: &str| format!("unknown argument {x:?}\n\n{USAGE}");
    match a.as_slice() {
        [] => Ok(Command::Run),
        ["-h" | "--help" | "help"] => Ok(Command::Help),
        ["--disable", rest @ ..] => {
            let mut force = false;
            for r in rest {
                match *r {
                    "--force" => force = true,
                    x => return Err(unknown(x)),
                }
            }
            Ok(Command::Disable { force })
        }
        ["service", "install", rest @ ..] => {
            let mut no_start = false;
            for r in rest {
                match *r {
                    "--no-start" => no_start = true,
                    x => return Err(unknown(x)),
                }
            }
            Ok(Command::Service(ServiceCmd::Install { no_start }))
        }
        ["service", "status", rest @ ..] => {
            let mut json = false;
            for r in rest {
                match *r {
                    "--json" => json = true,
                    x => return Err(unknown(x)),
                }
            }
            Ok(Command::Service(ServiceCmd::Status { json }))
        }
        ["service", "uninstall"] => Ok(Command::Service(ServiceCmd::Uninstall)),
        ["service", "start"] => Ok(Command::Service(ServiceCmd::Start)),
        ["service", "stop"] => Ok(Command::Service(ServiceCmd::Stop)),
        ["service", "run"] => Ok(Command::Service(ServiceCmd::Run)),
        ["access", "group", "ensure"] => Ok(Command::Access(AccessCmd::GroupEnsure)),
        ["access", "allow", who] => Ok(Command::Access(AccessCmd::Allow(who.to_string()))),
        ["access", "deny", who] => Ok(Command::Access(AccessCmd::Deny(who.to_string()))),
        ["access", "list"] => Ok(Command::Access(AccessCmd::List)),
        ["uninstall", rest @ ..] => {
            let (mut purge, mut keep_data, mut yes, mut force, mut export) =
                (false, false, false, false, None);
            let mut it = rest.iter();
            while let Some(r) = it.next() {
                match *r {
                    "--purge" => purge = true,
                    "--keep-data" => keep_data = true,
                    "--yes" | "-y" => yes = true,
                    "--force" => force = true,
                    "--export" => {
                        export = Some(PathBuf::from(
                            it.next().ok_or("--export needs a file name")?,
                        ))
                    }
                    x => return Err(unknown(x)),
                }
            }
            if purge && keep_data {
                return Err("--purge and --keep-data contradict each other".into());
            }
            Ok(Command::Uninstall { purge, keep_data, yes, force, export })
        }
        [x, ..] => Err(unknown(x)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Command, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn the_grammar() {
        assert_eq!(p("").unwrap(), Command::Run);
        assert_eq!(p("--disable --force").unwrap(), Command::Disable { force: true });
        assert_eq!(
            p("service install --no-start").unwrap(),
            Command::Service(ServiceCmd::Install { no_start: true })
        );
        assert_eq!(p("service status --json").unwrap(), Command::Service(ServiceCmd::Status { json: true }));
        assert_eq!(p("access allow alice").unwrap(), Command::Access(AccessCmd::Allow("alice".into())));
        assert_eq!(
            p("uninstall --purge --yes --export out.json").unwrap(),
            Command::Uninstall { purge: true, keep_data: false, yes: true, force: false, export: Some("out.json".into()) }
        );
        assert!(p("uninstall --purge --keep-data").is_err());
        assert!(p("uninstall --export").is_err());
        assert!(p("--disable --nope").is_err());
        assert!(p("frobnicate").is_err());
    }
}
