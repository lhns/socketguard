//! The list of what purge removes (`footprint::print_list`, `uninstall --print-purge-list`)
//! against the two places that describe the host from outside: `deploy/ci/footprint-check.*`
//! (hand-written, independent of the daemon) and docs/footprint.md. One way: everything the
//! daemon removes must be looked for by the checker of that system and described in the
//! document; the checkers may know more.

use socketguard_daemon::footprint::print_list;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_file(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Regex-escape the dots of a file name, as the checkers write them.
fn escaped(name: &str) -> String {
    name.replace('.', "\\.")
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap()
}

/// What the line `kind rest` must look like in the checker for `os` (a text that occurs in
/// it), and in docs/footprint.md. The checker texts are matched where the item is declared (a
/// quoted pattern of its table, or the call that looks for a directory), not anywhere: their
/// self-tests name the same patterns.
fn needles(os: &str, kind: &str, rest: &str) -> (String, String) {
    let win = os == "windows";
    let sep = if win { "\\\\" } else { "/" };
    // `"name|/socketguard\.json$"` in footprint-check.sh, `'\socketguard\.json$'` in the .ps1.
    let pattern = |name: &str, end: &str| {
        if win {
            format!("'{sep}{name}{end}'")
        } else {
            format!("|{sep}{name}{end}\"")
        }
    };
    match kind {
        "file" | "glob" => {
            let name = basename(rest).trim_end_matches('*');
            let checker = if name.ends_with(".sock") {
                // Looked for by its whole path.
                format!("'^{}$'", escaped(rest))
            } else {
                // The checker matches the end of a path; temp files only by their prefix.
                pattern(&escaped(name), if kind == "glob" { "" } else { "$" })
            };
            (checker, name.to_string())
        }
        "tree" => {
            let name = basename(rest);
            (pattern(name, "$"), format!("<state dir>/{name}"))
        }
        "dir" => {
            let checker = if win {
                // The checker looks for `\ProgramData\SocketGuard`, whatever the drive.
                let tail = rest.split_once(':').map_or(rest, |(_, t)| t);
                format!("$paths '(?i){}$'", tail.replace('\\', "\\\\"))
            } else {
                format!("\"$paths\" '^{rest}$'")
            };
            let doc = if win {
                rest.replace("C:\\ProgramData", "%ProgramData%")
            } else {
                rest.to_string()
            };
            (checker, doc)
        }
        "account-if-created" => (rest.to_string(), rest.to_string()),
        other => panic!("unknown kind {other:?}"),
    }
}

#[test]
fn everything_purge_removes_is_checked_from_outside_and_documented() {
    let doc = repo_file("docs/footprint.md");
    let mut missing = vec![];
    for os in ["linux", "macos", "windows"] {
        let checker = repo_file(if os == "windows" {
            "deploy/ci/footprint-check.ps1"
        } else {
            "deploy/ci/footprint-check.sh"
        });
        let list = print_list(os);
        assert!(list.lines().count() >= 9, "{os}: {list}");
        for line in list.lines() {
            let (kind, rest) = line.split_once(' ').unwrap_or_else(|| panic!("{line:?}"));
            let (in_checker, in_doc) = needles(os, kind, rest);
            if !checker.contains(&in_checker) {
                missing.push(format!(
                    "{os}: the checker never looks for `{line}` ({in_checker})"
                ));
            }
            if !doc.contains(&in_doc) {
                missing.push(format!(
                    "{os}: docs/footprint.md does not mention `{line}` ({in_doc})"
                ));
            }
        }
    }
    assert!(missing.is_empty(), "\n{}", missing.join("\n"));
}

/// The command prints the installed paths of the system whatever is next to the binary and
/// in the environment: it runs from the build tree, which may hold a `portable` marker.
#[test]
fn the_print_command_ignores_a_portable_marker_and_environment_overrides() {
    let exe = Path::new(env!("CARGO_BIN_EXE_socketguard-daemon"));
    let dir: PathBuf = std::env::temp_dir().join(format!("sg-purge-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join(exe.file_name().unwrap());
    std::fs::copy(exe, &copy).unwrap();
    std::fs::write(dir.join("portable"), "marker").unwrap();

    let run = |args: &[&str]| {
        let out = Command::new(&copy)
            .args(args)
            .env("SOCKETGUARD_CONFIG", dir.join("elsewhere").join("sg.json"))
            .env("SOCKETGUARD_THIRD_PARTY", dir.join("tp"))
            .env("ProgramData", dir.join("pd"))
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        run(&["uninstall", "--print-purge-list"]),
        print_list(std::env::consts::OS)
    );
    for os in ["linux", "macos", "windows"] {
        assert_eq!(
            run(&["uninstall", "--print-purge-list", "--os", os]),
            print_list(os)
        );
    }
    let linux = run(&["uninstall", "--print-purge-list", "--os", "linux"]);
    assert!(
        linux.starts_with("file /var/lib/socketguard/socketguard.db\n"),
        "{linux}"
    );
    assert!(
        !linux.contains("elsewhere") && !linux.contains("pd"),
        "{linux}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
