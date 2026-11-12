use socketguard_daemon::args::{self, Command, ServiceCmd};
use socketguard_daemon::{commands, portable, run};
use std::process::ExitCode;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("cannot start the async runtime")
}

fn main() -> ExitCode {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // `--portable` (ADR 0054) is read before anything else, like the marker file.
    socketguard_core::portable::strip_flag(&mut argv);
    let cmd = match args::parse(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = socketguard_core::portable::ensure_supported() {
        eprintln!("socketguard-daemon: {e}");
        return ExitCode::from(2);
    }
    if socketguard_core::portable::is_portable() {
        if let Some(why) = args::portable_refusal(&cmd) {
            eprintln!("socketguard-daemon: {why}");
            return ExitCode::from(2);
        }
    }
    let code = match cmd {
        Command::Help => {
            print!("{}", args::USAGE);
            0
        }
        Command::Run(opts) => {
            let rt = runtime();
            let started = portable::prepare(&opts).and_then(|()| {
                let resolved = run::resolve_for_run()?;
                if socketguard_core::portable::is_portable() {
                    rt.block_on(run::run(resolved, portable::stop_requested()))
                } else {
                    rt.block_on(run::run(resolved, run::signal_shutdown()))
                }
            });
            match started {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("socketguard-daemon: {e:#}");
                    1
                }
            }
        }
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

/// Started by the Windows service control manager: the daemon runs until the control
/// manager asks it to stop, and then shuts down exactly as on Ctrl+C. Nothing depends on
/// the working directory (System32 for a service). It does not run beside a portable
/// daemon (ADR 0054).
#[cfg(windows)]
fn service_run() -> i32 {
    let result = socketguard_daemon::service::windows_scm::dispatch(|mut stop| {
        portable::refuse_beside_portable(portable::portable_daemon_running())?;
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
