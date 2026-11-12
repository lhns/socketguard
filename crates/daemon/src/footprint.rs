//! What `uninstall --purge` deletes by name, as one list (docs/footprint.md, ADR 0057).
//!
//! The daemon deletes from this list at run time ([`purge_items`], used by
//! `uninstall::named_files`). The Debian postrm cannot run the daemon (the binary is gone at
//! purge), so `installer/linux/build.sh` asks the built daemon for the list of the fixed
//! installed paths (`socketguard-daemon uninstall --print-purge-list`) and embeds it in the
//! script. The tests in `tests/footprint_list.rs` check the list against
//! `deploy/ci/footprint-check.*` and docs/footprint.md.

use crate::uninstall::UninstallPaths;
use socketguard_core::config::{API_SOCKET_LINUX, API_SOCKET_MACOS};
use socketguard_core::paths::locations_for;
use std::path::{Path, PathBuf};

/// One thing purge removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A file, by name.
    File(PathBuf),
    /// The files of `dir` whose name starts with `prefix` (temp files a crash left).
    Prefixed { dir: PathBuf, prefix: String },
    /// A directory with everything in it: the data of a network's child process.
    Tree(PathBuf),
    /// A directory, removed only when it is empty.
    Dir(PathBuf),
    /// The account the children run as, removed only when the install record says the
    /// install created it.
    AccountIfCreated(String),
}

/// The prefix of the temp files next to the config (`socketguard.tmp-<pid>-<uuid>`).
pub const TEMP_PREFIX: &str = "socketguard.tmp-";

/// What purge removes, for `paths` on the system `os` (`std::env::consts::OS`).
pub fn purge_items(paths: &UninstallPaths, os: &str) -> Vec<Item> {
    let mut out = vec![];
    let db = paths.db.to_string_lossy().into_owned();
    for suffix in ["", "-wal", "-shm"] {
        out.push(Item::File(PathBuf::from(format!("{db}{suffix}"))));
    }
    out.push(Item::File(paths.config.clone()));
    let config_dir = paths.config.parent().map(Path::to_path_buf);
    if let Some(dir) = &config_dir {
        out.push(Item::Prefixed {
            dir: dir.clone(),
            prefix: TEMP_PREFIX.into(),
        });
    }
    out.push(Item::File(socketguard_core::paths::setup_log_path(
        &paths.config,
    )));
    if let Some(s) = &paths.socket {
        out.push(Item::File(s.clone()));
    }
    // The data of the networks' child processes (ADR 0052): Tor, Yggdrasil and, on Unix, the
    // pid files.
    out.push(Item::Tree(
        paths.state_dir.join(crate::networks::tor_child::DIR),
    ));
    out.push(Item::Tree(
        paths.state_dir.join(crate::networks::ygg_child::DIR),
    ));
    if os != "windows" {
        out.push(Item::Tree(paths.state_dir.join(crate::children::RUN_DIR)));
    }
    if let Some(dir) = config_dir {
        out.push(Item::Dir(dir));
    }
    if !out.contains(&Item::Dir(paths.state_dir.clone())) {
        out.push(Item::Dir(paths.state_dir.clone()));
    }
    if os != "windows" {
        out.push(Item::AccountIfCreated(crate::account::NAME.into()));
    }
    out
}

/// The default installed paths of `os`, whatever the environment says (a `portable` file or
/// `SOCKETGUARD_CONFIG` on the machine that asks does not matter): the paths a package
/// installs to.
pub fn fixed_paths(os: &str) -> UninstallPaths {
    let l = locations_for(os, None);
    let socket = match os {
        "windows" => None,
        "macos" => Some(PathBuf::from(API_SOCKET_MACOS)),
        _ => Some(PathBuf::from(API_SOCKET_LINUX)),
    };
    UninstallPaths {
        config: l.config(),
        db: l.db(),
        socket,
        state_dir: l.state_dir,
    }
}

/// `path` written with the separator of `os`, whatever system builds the text.
fn render_path(path: &Path, os: &str) -> String {
    let s = path.to_string_lossy();
    if os == "windows" {
        s.replace('/', "\\")
    } else {
        s.replace('\\', "/")
    }
}

/// The list as text, one item per line: `file <path>`, `glob <pattern>`, `tree <path>`,
/// `dir <path>`, `account-if-created <name>`. Paths are in the style of `os`.
pub fn render(items: &[Item], os: &str) -> String {
    let sep = if os == "windows" { '\\' } else { '/' };
    let mut text = String::new();
    for item in items {
        match item {
            Item::File(p) => text.push_str(&format!("file {}\n", render_path(p, os))),
            Item::Prefixed { dir, prefix } => {
                text.push_str(&format!("glob {}{sep}{prefix}*\n", render_path(dir, os)))
            }
            Item::Tree(p) => text.push_str(&format!("tree {}\n", render_path(p, os))),
            Item::Dir(p) => text.push_str(&format!("dir {}\n", render_path(p, os))),
            Item::AccountIfCreated(n) => text.push_str(&format!("account-if-created {n}\n")),
        }
    }
    text
}

/// What `uninstall --print-purge-list` prints for `os`.
pub fn print_list(os: &str) -> String {
    render(&purge_items(&fixed_paths(os), os), os)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Debian postrm used to delete exactly this (by a list of its own).
    #[test]
    fn linux_list_is_what_the_debian_postrm_always_deleted() {
        assert_eq!(
            print_list("linux"),
            "\
file /var/lib/socketguard/socketguard.db
file /var/lib/socketguard/socketguard.db-wal
file /var/lib/socketguard/socketguard.db-shm
file /etc/socketguard/socketguard.json
glob /etc/socketguard/socketguard.tmp-*
file /etc/socketguard/setup-log.json
file /run/socketguard.sock
tree /var/lib/socketguard/tor
tree /var/lib/socketguard/yggdrasil
tree /var/lib/socketguard/run
dir /etc/socketguard
dir /var/lib/socketguard
account-if-created socketguard-net
"
        );
    }

    #[test]
    fn windows_and_macos_lists_use_their_own_style() {
        let w = print_list("windows");
        assert!(
            w.contains("file C:\\ProgramData\\SocketGuard\\socketguard.db-wal\n"),
            "{w}"
        );
        assert!(
            w.contains("tree C:\\ProgramData\\SocketGuard\\tor\n"),
            "{w}"
        );
        assert!(!w.contains('/'), "{w}");
        assert!(!w.contains("account-if-created"), "{w}");
        assert!(!w.contains("run"), "{w}");
        let m = print_list("macos");
        assert!(m.contains("file /var/run/socketguard.sock\n"), "{m}");
        assert_eq!(
            m.matches("dir /Library/Application Support/SocketGuard\n")
                .count(),
            1,
            "{m}"
        );
        assert!(!m.contains('\\'), "{m}");
    }
}
