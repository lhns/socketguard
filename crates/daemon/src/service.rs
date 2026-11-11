//! Registering SocketGuard as a system service (ADR 0050): a Windows service, a systemd
//! unit or a launchd daemon, started with the system. Stopping the service removes no rules
//! or addresses (ADR 0026).
//!
//! Every action sits behind [`ServiceManager`]; the systemd and launchd managers are
//! generic over [`Host`] (commands) and write into a directory they are given, so their
//! command sequences are tested with a fake on any system. The Windows manager talks to the
//! service control manager through the `windows-service` crate.

use crate::host::Host;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The Windows service name (and its display name).
pub const WINDOWS_SERVICE: &str = "SocketGuard";
pub const SYSTEMD_UNIT: &str = "socketguard.service";
pub const SYSTEMD_DIR: &str = "/etc/systemd/system";
pub const LAUNCHD_LABEL: &str = "de.lhns.socketguard";
pub const LAUNCHD_DIR: &str = "/Library/LaunchDaemons";

/// The unit file, from the same text as `deploy/systemd/socketguard.service`.
const UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/socketguard.service");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
}

pub trait ServiceManager {
    /// The name the install record keeps (`systemd`, `launchd`, `windows-scm`).
    fn manager(&self) -> &'static str;
    /// The name of the service as the system knows it.
    fn service_name(&self) -> String;
    /// Register `exe` as the service and (unless `start` is false) start it. Registering
    /// again updates the registration; it never fails because it exists.
    fn install(&mut self, exe: &Path, start: bool) -> Result<()>;
    /// Stop and remove the registration. Nothing to do when it is absent.
    fn uninstall(&mut self) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    /// Stopping removes no rules or addresses.
    fn stop(&mut self) -> Result<()>;
    fn status(&mut self) -> Result<ServiceStatus>;
}

/// The unit file for the binary at `exe`.
pub fn unit_text(exe: &Path) -> String {
    UNIT_TEMPLATE
        .lines()
        .map(|l| {
            if l.starts_with("ExecStart=") {
                format!("ExecStart={}", exe.display())
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The launchd property list for the binary at `exe`.
pub fn plist_text(exe: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n\
  <key>ProgramArguments</key>\n\
  <array><string>{}</string></array>\n\
  <key>RunAtLoad</key><true/>\n\
  <key>KeepAlive</key><true/>\n\
</dict>\n\
</plist>\n",
        xml_escape(&exe.display().to_string())
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn write_atomic(path: &Path, content: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)
        .and_then(|()| std::fs::rename(&tmp, path))
        .with_context(|| format!("writing {}", path.display()))
}

// ─── systemd ────────────────────────────────────────────────────────────────

pub struct Systemd<'a, H: Host> {
    pub host: &'a mut H,
    pub unit_dir: PathBuf,
}

impl<H: Host> Systemd<'_, H> {
    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(SYSTEMD_UNIT)
    }
}

impl<H: Host> ServiceManager for Systemd<'_, H> {
    fn manager(&self) -> &'static str {
        "systemd"
    }
    fn service_name(&self) -> String {
        SYSTEMD_UNIT.to_string()
    }
    fn install(&mut self, exe: &Path, start: bool) -> Result<()> {
        write_atomic(&self.unit_path(), &unit_text(exe))?;
        self.host.run_ok("systemctl", &["daemon-reload"])?;
        if start {
            // `enable --now` also starts a stopped unit and leaves a running one alone.
            self.host
                .run_ok("systemctl", &["enable", "--now", SYSTEMD_UNIT])?;
        } else {
            self.host.run_ok("systemctl", &["enable", SYSTEMD_UNIT])?;
        }
        Ok(())
    }
    fn uninstall(&mut self) -> Result<()> {
        let present = self.unit_path().exists();
        if present {
            // Failures of stop and disable on a unit that is not loaded are not errors.
            let _ = self.host.run("systemctl", &["stop", SYSTEMD_UNIT]);
            let _ = self.host.run("systemctl", &["disable", SYSTEMD_UNIT]);
            std::fs::remove_file(self.unit_path())
                .with_context(|| format!("removing {}", self.unit_path().display()))?;
            self.host.run_ok("systemctl", &["daemon-reload"])?;
        }
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        self.host.run_ok("systemctl", &["start", SYSTEMD_UNIT])?;
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        // Nothing to stop when the unit is not there (a second uninstall).
        if self.unit_path().exists() {
            self.host.run_ok("systemctl", &["stop", SYSTEMD_UNIT])?;
        }
        Ok(())
    }
    fn status(&mut self) -> Result<ServiceStatus> {
        let installed = self.unit_path().exists();
        let running = installed
            && self
                .host
                .run("systemctl", &["is-active", "--quiet", SYSTEMD_UNIT])?
                .ok();
        Ok(ServiceStatus { installed, running })
    }
}

// ─── launchd ────────────────────────────────────────────────────────────────

pub struct Launchd<'a, H: Host> {
    pub host: &'a mut H,
    pub dir: PathBuf,
}

impl<H: Host> Launchd<'_, H> {
    pub fn plist_path(&self) -> PathBuf {
        self.dir.join(format!("{LAUNCHD_LABEL}.plist"))
    }
    fn target() -> String {
        format!("system/{LAUNCHD_LABEL}")
    }
    fn loaded(&mut self) -> bool {
        self.host
            .run("launchctl", &["print", &Self::target()])
            .map(|o| o.ok())
            .unwrap_or(false)
    }
}

impl<H: Host> ServiceManager for Launchd<'_, H> {
    fn manager(&self) -> &'static str {
        "launchd"
    }
    fn service_name(&self) -> String {
        LAUNCHD_LABEL.to_string()
    }
    fn install(&mut self, exe: &Path, start: bool) -> Result<()> {
        let plist = self.plist_path();
        let changed = std::fs::read_to_string(&plist).ok().as_deref()
            != Some(plist_text(exe).as_str());
        write_atomic(&plist, &plist_text(exe))?;
        // The property list is `RunAtLoad`, so bootstrapping starts it; a changed list needs
        // the old one booted out first.
        if self.loaded() && changed {
            self.host.run_ok("launchctl", &["bootout", &Self::target()])?;
        }
        if !self.loaded() {
            if start {
                self.host.run_ok(
                    "launchctl",
                    &["bootstrap", "system", &plist.display().to_string()],
                )?;
            } else {
                // Registered by the plist alone; it starts at the next boot.
                self.host.say(&format!(
                    "Not started; {} runs it at the next boot (or: socketguard-daemon service start).",
                    plist.display()
                ));
            }
        }
        Ok(())
    }
    fn uninstall(&mut self) -> Result<()> {
        if self.loaded() {
            self.host.run_ok("launchctl", &["bootout", &Self::target()])?;
        }
        match std::fs::remove_file(self.plist_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("removing the launchd property list"),
        }
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        if self.loaded() {
            self.host
                .run_ok("launchctl", &["kickstart", &Self::target()])?;
        } else {
            let plist = self.plist_path().display().to_string();
            self.host.run_ok("launchctl", &["bootstrap", "system", &plist])?;
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        // KeepAlive restarts a killed job, so stopping unloads it; the plist stays and the
        // job is back at the next boot or `service start`.
        if self.loaded() {
            self.host.run_ok("launchctl", &["bootout", &Self::target()])?;
        }
        Ok(())
    }
    fn status(&mut self) -> Result<ServiceStatus> {
        let installed = self.plist_path().exists();
        let running = installed && self.loaded();
        Ok(ServiceStatus { installed, running })
    }
}

// ─── fake ───────────────────────────────────────────────────────────────────

/// A [`ServiceManager`] that only remembers, for tests of the code around it.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct FakeServiceManager {
    pub installed: bool,
    pub running: bool,
    /// Every call, in order.
    pub calls: Vec<String>,
    pub fail_stop: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl ServiceManager for FakeServiceManager {
    fn manager(&self) -> &'static str {
        "fake"
    }
    fn service_name(&self) -> String {
        "fake-service".into()
    }
    fn install(&mut self, exe: &Path, start: bool) -> Result<()> {
        self.calls.push(format!("install {} start={start}", exe.display()));
        self.installed = true;
        if start {
            self.running = true;
        }
        Ok(())
    }
    fn uninstall(&mut self) -> Result<()> {
        self.calls.push("uninstall".into());
        self.installed = false;
        self.running = false;
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        self.calls.push("start".into());
        anyhow::ensure!(self.installed, "not installed");
        self.running = true;
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        self.calls.push("stop".into());
        anyhow::ensure!(!self.fail_stop, "cannot stop");
        self.running = false;
        Ok(())
    }
    fn status(&mut self) -> Result<ServiceStatus> {
        Ok(ServiceStatus {
            installed: self.installed,
            running: self.running,
        })
    }
}

// ─── this system ────────────────────────────────────────────────────────────

/// Run `f` with the service manager of this system.
pub fn with_system_manager<T>(
    host: &mut crate::host::SystemHost,
    f: impl FnOnce(&mut dyn ServiceManager) -> Result<T>,
) -> Result<T> {
    #[cfg(windows)]
    {
        let _ = host;
        f(&mut windows_scm::WindowsScm)
    }
    #[cfg(target_os = "linux")]
    {
        f(&mut Systemd {
            host,
            unit_dir: PathBuf::from(SYSTEMD_DIR),
        })
    }
    #[cfg(target_os = "macos")]
    {
        f(&mut Launchd {
            host,
            dir: PathBuf::from(LAUNCHD_DIR),
        })
    }
}

/// Whether the service is registered, as far as can be told without running anything:
/// for `GET /api/status`.
pub fn installed_hint() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        Some(Path::new(SYSTEMD_DIR).join(SYSTEMD_UNIT).exists())
    }
    #[cfg(target_os = "macos")]
    {
        Some(Path::new(LAUNCHD_DIR).join(format!("{LAUNCHD_LABEL}.plist")).exists())
    }
    #[cfg(windows)]
    {
        windows_scm::WindowsScm.status().ok().map(|s| s.installed)
    }
}

// ─── Windows ────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub mod windows_scm {
    //! The service control manager, through the `windows-service` crate: a LocalSystem
    //! service, started automatically, restarted on failure, whose binary is this
    //! executable with `service run`.

    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager as Scm, ServiceManagerAccess};

    pub struct WindowsScm;

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    fn connect(access: ServiceManagerAccess) -> Result<Scm> {
        Scm::local_computer(None::<&str>, access).context("cannot open the service control manager")
    }

    fn does_not_exist(e: &windows_service::Error) -> bool {
        matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST))
    }

    fn info(exe: &Path) -> ServiceInfo {
        ServiceInfo {
            name: OsString::from(WINDOWS_SERVICE),
            display_name: OsString::from("SocketGuard"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.to_path_buf(),
            launch_arguments: vec![OsString::from("service"), OsString::from("run")],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        }
    }

    impl ServiceManager for WindowsScm {
        fn manager(&self) -> &'static str {
            "windows-scm"
        }
        fn service_name(&self) -> String {
            WINDOWS_SERVICE.to_string()
        }

        fn install(&mut self, exe: &Path, start: bool) -> Result<()> {
            let scm = connect(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
            let access = ServiceAccess::all();
            let service = match scm.open_service(WINDOWS_SERVICE, access) {
                Ok(s) => {
                    // Registered already: bring it to the wanted configuration.
                    s.change_config(&info(exe))?;
                    s
                }
                Err(e) if does_not_exist(&e) => scm.create_service(&info(exe), access)?,
                Err(e) => return Err(e.into()),
            };
            service.set_description("Per-application firewall and addresses (SocketGuard)")?;
            // Restart on failure; the counter resets after a day without one.
            service.update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(2),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(10),
                    },
                    ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(30),
                    },
                ]),
            })?;
            if start && service.query_status()?.current_state == ServiceState::Stopped {
                service.start::<&str>(&[])?;
            }
            Ok(())
        }

        fn uninstall(&mut self) -> Result<()> {
            let scm = connect(ServiceManagerAccess::CONNECT)?;
            let service = match scm.open_service(
                WINDOWS_SERVICE,
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
            ) {
                Ok(s) => s,
                Err(e) if does_not_exist(&e) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            if service.query_status()?.current_state != ServiceState::Stopped {
                let _ = service.stop();
                wait_for(&service, ServiceState::Stopped)?;
            }
            service.delete()?;
            Ok(())
        }

        fn start(&mut self) -> Result<()> {
            let scm = connect(ServiceManagerAccess::CONNECT)?;
            let service = scm
                .open_service(WINDOWS_SERVICE, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
                .context("the SocketGuard service is not installed (socketguard-daemon service install)")?;
            if service.query_status()?.current_state == ServiceState::Stopped {
                service.start::<&str>(&[])?;
            }
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            let scm = connect(ServiceManagerAccess::CONNECT)?;
            let service = match scm.open_service(
                WINDOWS_SERVICE,
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            ) {
                Ok(s) => s,
                Err(e) if does_not_exist(&e) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            if service.query_status()?.current_state != ServiceState::Stopped {
                let _ = service.stop();
                wait_for(&service, ServiceState::Stopped)?;
            }
            Ok(())
        }

        fn status(&mut self) -> Result<ServiceStatus> {
            let scm = connect(ServiceManagerAccess::CONNECT)?;
            match scm.open_service(WINDOWS_SERVICE, ServiceAccess::QUERY_STATUS) {
                Ok(s) => Ok(ServiceStatus {
                    installed: true,
                    running: s.query_status()?.current_state != ServiceState::Stopped,
                }),
                Err(e) if does_not_exist(&e) => Ok(ServiceStatus {
                    installed: false,
                    running: false,
                }),
                Err(e) => Err(e.into()),
            }
        }
    }

    fn wait_for(service: &windows_service::service::Service, want: ServiceState) -> Result<()> {
        for _ in 0..60 {
            if service.query_status()?.current_state == want {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        anyhow::bail!("the service did not reach the state {want:?} within 30 s")
    }

    // ── the service entry ──

    windows_service::define_windows_service!(ffi_service_main, service_main);

    static RUN: std::sync::OnceLock<Box<dyn Fn(tokio::sync::watch::Receiver<bool>) -> Result<()> + Send + Sync>> =
        std::sync::OnceLock::new();

    /// Hand control to the service dispatcher: `run_daemon` is called on the service thread
    /// with a receiver that turns true when the control manager asks the service to stop.
    /// It must shut the daemon down gracefully, as Ctrl+C does.
    pub fn dispatch(
        run_daemon: impl Fn(tokio::sync::watch::Receiver<bool>) -> Result<()> + Send + Sync + 'static,
    ) -> Result<()> {
        let _ = RUN.set(Box::new(run_daemon));
        windows_service::service_dispatcher::start(WINDOWS_SERVICE, ffi_service_main)
            .context("not started by the service control manager (use `service install`, or run the daemon without arguments)")
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            eprintln!("[socketguard] service failed: {e:#}");
        }
    }

    fn run_service() -> Result<()> {
        use windows_service::service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceStatus as Status,
        };
        use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(WINDOWS_SERVICE, handler)?;
        let status = |state, accept, code, wait: u64| Status {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(wait),
            process_id: None,
        };
        status_handle.set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            10,
        ))?;
        status_handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
            0,
        ))?;
        let result = (RUN.get().expect("dispatch sets it"))(stop_rx);
        let code = if result.is_ok() { 0 } else { 1 };
        status_handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(code),
            0,
        ))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg-svc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_unit_names_the_installed_binary_and_nothing_else_changes() {
        let t = unit_text(Path::new("/opt/sg/socketguard-daemon"));
        assert!(t.contains("ExecStart=/opt/sg/socketguard-daemon\n"));
        assert!(t.contains("Restart=on-failure"));
        assert!(!t.contains("/usr/local/bin"));
        assert!(!t.contains("WorkingDirectory"), "state must not depend on a working directory");
    }

    #[test]
    fn systemd_install_is_idempotent_and_uninstall_when_absent_is_quiet() {
        let d = dir();
        let mut host = FakeHost::new("linux");
        {
            let mut m = Systemd {
                host: &mut host,
                unit_dir: d.clone(),
            };
            m.uninstall().unwrap(); // absent: nothing happens
            assert_eq!(m.status().unwrap(), ServiceStatus { installed: false, running: false });
            m.install(Path::new("/bin/sg"), true).unwrap();
            m.install(Path::new("/bin/sg"), true).unwrap();
            assert!(m.status().unwrap().installed);
            m.uninstall().unwrap();
            m.uninstall().unwrap();
            assert!(!m.unit_path().exists());
        }
        assert_eq!(
            host.commands,
            [
                "systemctl daemon-reload",
                "systemctl enable --now socketguard.service",
                "systemctl daemon-reload",
                "systemctl enable --now socketguard.service",
                "systemctl is-active --quiet socketguard.service",
                "systemctl stop socketguard.service",
                "systemctl disable socketguard.service",
                "systemctl daemon-reload",
            ]
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn systemd_no_start_only_enables() {
        let d = dir();
        let mut host = FakeHost::new("linux");
        Systemd {
            host: &mut host,
            unit_dir: d.clone(),
        }
        .install(Path::new("/bin/sg"), false)
        .unwrap();
        assert_eq!(
            host.commands,
            ["systemctl daemon-reload", "systemctl enable socketguard.service"]
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn launchd_bootstraps_once_and_boots_out_before_removing() {
        let d = dir();
        let mut host = FakeHost::new("macos");
        // Not loaded at first (print fails); loaded after the bootstrap.
        host.answer_in_order(
            "launchctl print",
            vec![
                crate::host::Output { code: 113, ..Default::default() }, // install #1: loaded()
                crate::host::Output { code: 113, ..Default::default() }, // install #1: !loaded()
                crate::host::Output::default(),                          // install #2: loaded() (unchanged)
                crate::host::Output::default(),                          // install #2: !loaded()
                crate::host::Output::default(),                          // uninstall: loaded()
            ],
        );
        {
            let mut m = Launchd {
                host: &mut host,
                dir: d.clone(),
            };
            m.install(Path::new("/usr/local/bin/socketguard-daemon"), true).unwrap();
            let plist = std::fs::read_to_string(m.plist_path()).unwrap();
            assert!(plist.contains("<key>RunAtLoad</key><true/>"));
            assert!(plist.contains("<key>KeepAlive</key><true/>"));
            m.install(Path::new("/usr/local/bin/socketguard-daemon"), true).unwrap();
            m.uninstall().unwrap();
            assert!(!m.plist_path().exists());
            m.uninstall().unwrap();
        }
        let bootstraps = host.commands.iter().filter(|c| c.starts_with("launchctl bootstrap system ")).count();
        assert_eq!(bootstraps, 1, "{:?}", host.commands);
        assert!(host.commands.iter().any(|c| c == "launchctl bootout system/de.lhns.socketguard"));
        std::fs::remove_dir_all(d).unwrap();
    }
}
