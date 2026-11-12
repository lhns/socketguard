use socketguard_daemon::args::{self, Command, ServiceCmd};
use socketguard_daemon::{commands, run};
use std::process::ExitCode;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("cannot start the async runtime")
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match args::parse(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let code = match cmd {
        Command::Help => {
            print!("{}", args::USAGE);
            0
        }
        Command::Run => {
            let rt = runtime();
            match run::resolve_for_run()
                .and_then(|r| rt.block_on(run::run(r, run::signal_shutdown())))
            {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("socketguard-daemon: {e:#}");
                    1
                }
            }
        }
        Command::ChildGuard {
            pid_file,
            program,
            args,
        } => child_guard(pid_file.as_deref(), &program, &args),
        Command::Service(ServiceCmd::Run) => service_run(),
        Command::Service(c) => commands::service_cmd(c),
        Command::Disable { force } => runtime().block_on(commands::disable_cmd(force)),
        Command::Access(c) => commands::access_cmd(c),
        Command::Uninstall {
            purge,
            keep_data,
            yes,
            force,
            export,
        } => runtime().block_on(commands::uninstall_cmd(
            socketguard_daemon::uninstall::UninstallOptions {
                purge,
                keep_data,
                yes,
                force,
                export,
            },
        )),
    };
    ExitCode::from(code as u8)
}

#[cfg(unix)]
fn child_guard(pid_file: Option<&std::path::Path>, program: &str, args: &[String]) -> i32 {
    socketguard_daemon::children::guard::run(pid_file, program, args)
}

#[cfg(not(unix))]
fn child_guard(_: Option<&std::path::Path>, _: &str, _: &[String]) -> i32 {
    eprintln!("`child-guard` is for Unix; Windows uses a job object");
    2
}

/// Started by the Windows service control manager: the daemon runs until the control
/// manager asks it to stop, and then shuts down exactly as on Ctrl+C. Nothing depends on
/// the working directory (System32 for a service).
#[cfg(windows)]
fn service_run() -> i32 {
    let result = socketguard_daemon::service::windows_scm::dispatch(|mut stop| {
        let resolved = run::resolve_for_run()?;
        runtime().block_on(run::run(resolved, async move {
            let _ = stop.wait_for(|s| *s).await;
        }))
    });
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("socketguard-daemon: {e:#}");
            1
        }
    }
}

#[cfg(not(windows))]
fn service_run() -> i32 {
    eprintln!("`service run` is the Windows service entry point; use `service start` here");
    2
}
