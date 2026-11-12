//! The daemon binary's command line (ADR 0050). No options library: the grammar is small.
//!
//! ```text
//! socketguard-daemon                              run the daemon
//! socketguard-daemon --portable [--owner-pid <pid>] [--allow-user <sid>]   portable mode (Windows)
//! socketguard-daemon --disable [--force]          remove rules, addresses, onion services
//! socketguard-daemon service install [--no-start] | uninstall | start | stop | status [--json] | run
//! socketguard-daemon access group ensure | allow <account> | deny <account> | list
//! socketguard-daemon uninstall [--purge] [--keep-data] [--yes] [--export <file>] [--force]
//! ```

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCmd {
    Install {
        no_start: bool,
    },
    Uninstall,
    Start,
    Stop,
    Status {
        json: bool,
    },
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
    /// Run the daemon; the options belong to portable mode (ADR 0054).
    Run(crate::portable::RunOptions),
    Disable {
        force: bool,
    },
    Service(ServiceCmd),
    Access(AccessCmd),
    Uninstall {
        purge: bool,
        keep_data: bool,
        yes: bool,
        force: bool,
        export: Option<PathBuf>,
    },
    /// Hidden: print what `uninstall --purge` deletes at the fixed installed paths of a system
    /// (this one by default), for the package builders and tests (`footprint::print_list`).
    PurgeList {
        os: Option<String>,
    },
    /// Hidden: the daemon's own start of a child that must end with the daemon (Unix).
    ChildGuard {
        /// Where to record the program's pid (see `children::pidfile`).
        pid_file: Option<PathBuf>,
        program: String,
        args: Vec<String>,
    },
    Help,
}

pub const USAGE: &str = "\
usage: socketguard-daemon [command]

  (no command)                    run the daemon
  --portable                      run from this folder, leaving nothing behind (Windows; or a
                                  file called portable next to the program)
  --owner-pid <pid>               portable: stop, removing everything, when that process ends
  --allow-user <sid>              portable: let that account use the API pipe
  --disable [--force]             remove the firewall rules, addresses and onion services
  service install [--no-start]    register and start the SocketGuard service
  service uninstall|start|stop    (administrator)
  service status [--json]         installed? running?
  access group ensure             create the access group
  access allow|deny <account>     let an account use SocketGuard without administrator rights
  access list
  uninstall [--purge] [--keep-data] [--yes] [--export <file>] [--force]
";

/// `--owner-pid <pid>` and `--allow-user <sid>` (portable mode), taken out of `args`.
fn take_run_options(args: &[String]) -> Result<(crate::portable::RunOptions, Vec<String>), String> {
    let mut opts = crate::portable::RunOptions::default();
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        match name {
            "--owner-pid" => {
                let v = inline
                    .or_else(|| it.next().cloned())
                    .ok_or("--owner-pid needs a process id")?;
                opts.owner_pid = Some(
                    v.parse()
                        .map_err(|_| format!("--owner-pid {v:?} is not a process id"))?,
                );
            }
            "--allow-user" => {
                opts.allow_user = Some(
                    inline
                        .or_else(|| it.next().cloned())
                        .ok_or("--allow-user needs a SID")?,
                );
            }
            _ => rest.push(a.clone()),
        }
    }
    Ok((opts, rest))
}

/// Why `cmd` cannot be used in portable mode, if it cannot: it would change the host
/// (a service, a group, an install record) or is the installed service's entry point.
pub fn portable_refusal(cmd: &Command) -> Option<&'static str> {
    match cmd {
        Command::Run(_)
        | Command::Help
        | Command::Disable { .. }
        | Command::ChildGuard { .. }
        | Command::PurgeList { .. } => None,
        Command::Service(ServiceCmd::Status { .. }) => None,
        Command::Service(_) => Some("portable mode registers no service"),
        Command::Access(_) => Some("portable mode creates no access group"),
        Command::Uninstall { .. } => {
            Some("there is nothing installed: delete the folder to remove portable SocketGuard")
        }
    }
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let (opts, args) = take_run_options(args)?;
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let unknown = |x: &str| format!("unknown argument {x:?}\n\n{USAGE}");
    let has_opts = opts != crate::portable::RunOptions::default();
    if has_opts && !a.is_empty() {
        return Err(format!(
            "--owner-pid and --allow-user only go with running the daemon\n\n{USAGE}"
        ));
    }
    match a.as_slice() {
        [] => Ok(Command::Run(opts)),
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
        ["child-guard", "--pid-file", file, "--", program, rest @ ..] => Ok(Command::ChildGuard {
            pid_file: Some(PathBuf::from(file)),
            program: program.to_string(),
            args: rest.iter().map(|s| s.to_string()).collect(),
        }),
        ["child-guard", "--", program, rest @ ..] => Ok(Command::ChildGuard {
            pid_file: None,
            program: program.to_string(),
            args: rest.iter().map(|s| s.to_string()).collect(),
        }),
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
        ["uninstall", "--print-purge-list"] => Ok(Command::PurgeList { os: None }),
        ["uninstall", "--print-purge-list", "--os", os] => Ok(Command::PurgeList {
            os: Some(os.to_string()),
        }),
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
            Ok(Command::Uninstall {
                purge,
                keep_data,
                yes,
                force,
                export,
            })
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
        assert_eq!(p("").unwrap(), Command::Run(Default::default()));
        assert_eq!(
            p("--owner-pid 42 --allow-user S-1-5-21-1-2-3-1001").unwrap(),
            Command::Run(crate::portable::RunOptions {
                owner_pid: Some(42),
                allow_user: Some("S-1-5-21-1-2-3-1001".into())
            })
        );
        assert_eq!(
            p("--owner-pid=7").unwrap(),
            Command::Run(crate::portable::RunOptions {
                owner_pid: Some(7),
                allow_user: None
            })
        );
        assert!(p("--owner-pid x").is_err());
        assert!(p("--owner-pid").is_err());
        assert!(p("--owner-pid 1 --disable").is_err());
        assert_eq!(
            p("--disable --force").unwrap(),
            Command::Disable { force: true }
        );
        assert_eq!(
            p("service install --no-start").unwrap(),
            Command::Service(ServiceCmd::Install { no_start: true })
        );
        assert_eq!(
            p("service status --json").unwrap(),
            Command::Service(ServiceCmd::Status { json: true })
        );
        assert_eq!(
            p("access allow alice").unwrap(),
            Command::Access(AccessCmd::Allow("alice".into()))
        );
        assert_eq!(
            p("uninstall --purge --yes --export out.json").unwrap(),
            Command::Uninstall {
                purge: true,
                keep_data: false,
                yes: true,
                force: false,
                export: Some("out.json".into())
            }
        );
        assert_eq!(
            p("child-guard -- /bin/y -useconffile c").unwrap(),
            Command::ChildGuard {
                pid_file: None,
                program: "/bin/y".into(),
                args: vec!["-useconffile".into(), "c".into()]
            }
        );
        assert_eq!(
            p("child-guard --pid-file /run/y.child -- /bin/y").unwrap(),
            Command::ChildGuard {
                pid_file: Some("/run/y.child".into()),
                program: "/bin/y".into(),
                args: vec![]
            }
        );
        assert!(p("child-guard").is_err());
        assert!(p("uninstall --purge --keep-data").is_err());
        assert!(p("uninstall --export").is_err());
        assert!(p("--disable --nope").is_err());
        assert!(p("frobnicate").is_err());
    }

    #[test]
    fn portable_mode_refuses_what_changes_the_host() {
        assert!(portable_refusal(&p("").unwrap()).is_none());
        assert!(portable_refusal(&p("--disable").unwrap()).is_none());
        assert!(portable_refusal(&p("service status").unwrap()).is_none());
        for refused in [
            "service install",
            "service uninstall",
            "service start",
            "service run",
            "access group ensure",
            "access allow alice",
            "uninstall --yes",
        ] {
            assert!(
                portable_refusal(&p(refused).unwrap()).is_some(),
                "{refused}"
            );
        }
    }
}
