//! Portable mode (ADR 0054): SocketGuard run from a folder on Windows, leaving nothing on the
//! host once its process has ended. One function decides it for the daemon, the CLI and the
//! window: [`is_portable`].

use crate::config::BackendConfig;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The file next to the programs that turns portable mode on.
pub const MARKER: &str = "portable";
/// The folder, next to the programs, that holds everything portable mode writes.
pub const DATA_DIR: &str = "data";
/// The API pipe of a portable daemon. Differs from the service's pipe so tools can tell the
/// two apart and the installed service can refuse to run beside it.
pub const API_PIPE: &str = r"\\.\pipe\socketguard-portable";
/// The command-line switch.
pub const FLAG: &str = "--portable";

static REQUESTED: AtomicBool = AtomicBool::new(false);

/// `--portable` was given (see [`strip_flag`]).
pub fn request() {
    REQUESTED.store(true, Ordering::SeqCst);
}

/// Remove `--portable` from `args` and remember it. Returns whether it was there.
pub fn strip_flag(args: &mut Vec<String>) -> bool {
    let found = remove_flag(args);
    if found {
        request();
    }
    found
}

fn remove_flag(args: &mut Vec<String>) -> bool {
    let before = args.len();
    args.retain(|a| a != FLAG);
    args.len() != before
}

/// The directory of the running executable.
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

/// Whether the marker file or `--portable` asks for portable mode, on any system.
pub fn requested() -> bool {
    if REQUESTED.load(Ordering::SeqCst) {
        return true;
    }
    static MARKER_FOUND: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MARKER_FOUND.get_or_init(|| exe_dir().is_some_and(|d| d.join(MARKER).is_file()))
}

/// Portable mode is on: asked for, on Windows (the only system that has it).
pub fn is_portable() -> bool {
    cfg!(windows) && requested()
}

/// The refusal for systems without portable mode, to print before anything else happens.
pub fn ensure_supported() -> Result<(), String> {
    if requested() && !cfg!(windows) {
        return Err(format!(
            "portable mode exists on Windows only (found {FLAG} or a file named \"{MARKER}\" next to the program)"
        ));
    }
    Ok(())
}

/// What the last run left, in `data\`, for the window to read after the daemon has exited.
pub const LAST_EXIT_FILE: &str = "last-exit.log";

/// The line the daemon writes to [`LAST_EXIT_FILE`]: `<unix seconds> clean...` or
/// `<unix seconds> LEFT: <thing>; <thing>`.
pub fn last_exit_line(unix_secs: u64, left: &[String]) -> String {
    if left.is_empty() {
        format!("{unix_secs} clean: rules and addresses removed")
    } else {
        format!("{unix_secs} LEFT: {}", left.join("; "))
    }
}

/// The inverse of [`last_exit_line`]: when it was written and what was left (empty: clean).
pub fn parse_last_exit(text: &str) -> Option<(u64, Vec<String>)> {
    let line = text.lines().rev().find(|l| !l.trim().is_empty())?;
    let (secs, rest) = line.trim().split_once(' ')?;
    let secs: u64 = secs.parse().ok()?;
    let left = match rest.strip_prefix("LEFT: ") {
        Some(items) => items.split("; ").map(str::to_string).collect(),
        None => Vec::new(),
    };
    Some((secs, left))
}

/// `<exe dir>\data`.
pub fn data_dir_in(exe_dir: &Path) -> PathBuf {
    exe_dir.join(DATA_DIR)
}

/// The data folder of the running portable program.
pub fn data_dir() -> Option<PathBuf> {
    exe_dir().map(|d| data_dir_in(&d))
}

/// Whether `SOCKETGUARD_CONFIG` is set and therefore being ignored (the daemon says so).
pub fn ignored_config_override() -> Option<String> {
    std::env::var("SOCKETGUARD_CONFIG")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Whether a network of this kind may be configured in portable mode: only the ones that
/// need no trusted configuration (ADR 0054). An existing (unmanaged) Tor or Yggdrasil node
/// is refused: the folder is writable by the user, so what points at software outside it
/// would let a user process steer something that runs with administrator rights.
///
/// The managed Tor and Yggdrasil (ADR 0052) extend this once their config flag exists.
pub fn allowed_in_portable(backend: &BackendConfig) -> Result<(), String> {
    match backend {
        BackendConfig::Ula { .. } | BackendConfig::Slaac { .. } | BackendConfig::Dhcpv6 { .. } => {
            Ok(())
        }
        BackendConfig::Tor { .. } => Err(
            "an existing Tor node cannot be added in portable mode: only networks that need no \
             trusted configuration are offered here (Local, LAN)"
                .into(),
        ),
        BackendConfig::Yggdrasil { .. } => Err(
            "an existing Yggdrasil node cannot be added in portable mode: only networks that \
             need no trusted configuration are offered here (Local, LAN)"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_is_removed_from_the_arguments() {
        let mut a: Vec<String> = ["--portable", "status"].map(String::from).to_vec();
        assert!(remove_flag(&mut a));
        assert_eq!(a, ["status"]);
        assert!(!remove_flag(&mut a));
    }

    #[test]
    fn the_last_exit_line_round_trips() {
        assert_eq!(parse_last_exit(&last_exit_line(9, &[])), Some((9, vec![])));
        let left = vec!["address fd00::1 on Ethernet".to_string(), "x".to_string()];
        assert_eq!(
            parse_last_exit(&format!("{}\n", last_exit_line(9, &left))),
            Some((9, left))
        );
        assert_eq!(parse_last_exit(""), None);
        assert_eq!(parse_last_exit("garbage"), None);
    }

    #[test]
    fn data_lives_next_to_the_programs() {
        assert_eq!(
            data_dir_in(Path::new(r"D:\SocketGuard")),
            Path::new(r"D:\SocketGuard").join("data")
        );
    }

    #[test]
    fn only_local_and_lan_networks_are_allowed() {
        let ula = BackendConfig::default();
        assert!(allowed_in_portable(&ula).is_ok());
        let slaac = BackendConfig::Slaac {
            interface: "Ethernet".into(),
            prefix: None,
        };
        assert!(allowed_in_portable(&slaac).is_ok());
        assert!(allowed_in_portable(&BackendConfig::Dhcpv6 {
            interface: "Ethernet".into()
        })
        .is_ok());
        let ygg = BackendConfig::Yggdrasil {
            interface: None,
            admin_endpoint: None,
        };
        let msg = allowed_in_portable(&ygg).unwrap_err();
        assert!(
            msg.contains("Yggdrasil") && msg.contains("portable"),
            "{msg}"
        );
        let tor: BackendConfig = serde_json::from_str(r#"{"type":"tor"}"#).unwrap();
        assert!(allowed_in_portable(&tor).unwrap_err().contains("Tor"));
    }
}
