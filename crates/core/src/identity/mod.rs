//! App identity (ADR 0027 and its amendment): which program a listening socket belongs to.
//!
//! Identity is derived from facts the daemon observes about the process, never from
//! anything stored in the file system, so it survives upgrades and restarts. Everything an
//! unprivileged process controls (argv, the `comm` name) is treated as hostile: it may pick
//! its own identity, but only one that no trusted app has (see the markers below).

use crate::model::AppId;
use crate::types::ListeningSocket;
use sha2::{Digest, Sha256};

/// The operating system whose conventions normalize a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }
}

/// Normalize an executable path so it is stable across upgrades: Linux appends
/// ` (deleted)` to /proc/pid/exe when the binary was replaced; Windows paths are
/// case-insensitive.
pub fn normalize_exe_path(path: &str, platform: Platform) -> String {
    match platform {
        Platform::Windows => path.to_lowercase(),
        Platform::Linux => path.strip_suffix(" (deleted)").unwrap_or(path).to_string(),
        Platform::Macos => path.to_string(),
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// The identity of an app and what to show for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    pub id: AppId,
    /// Display name: script or service name for interpreters, else the process name.
    pub name: String,
    /// Normalized script / jar / module / main class / service name.
    pub interpreter_arg: Option<String>,
    /// Why this identity is special, for the frontends.
    pub note: Option<String>,
    /// An OS component rather than one of the user's programs.
    pub system: bool,
}

/// Whether the process is part of the operating system (a service or a system process), by
/// the facts the monitor reads: the executable, the process name, the owner and (Linux)
/// whether a systemd service unit runs it. `system_root` is `%SystemRoot%` on Windows.
///
/// - Windows: the executable lies under the system root, or it is `System`, `svchost.exe`
///   or `services.exe`.
/// - Linux: an owner below uid 1000 whose process runs in a service unit or from a system
///   directory.
/// - macOS: the executable lies under `/System` or `/usr/libexec`.
pub fn is_system_process(
    platform: Platform,
    ls: &ListeningSocket,
    system_root: Option<&str>,
) -> bool {
    let exe = ls
        .exe_path
        .as_deref()
        .map(|p| normalize_exe_path(p, platform));
    let under = |dir: &str| exe.as_deref().is_some_and(|e| e.starts_with(dir));
    match platform {
        Platform::Windows => {
            let root = system_root
                .unwrap_or("C:\\Windows")
                .trim_end_matches('\\')
                .to_lowercase();
            let name = ls.process_name.to_lowercase();
            under(&format!("{root}\\"))
                || matches!(name.as_str(), "system" | "svchost.exe" | "services.exe")
        }
        Platform::Linux => {
            let low_uid = ls
                .uid
                .as_deref()
                .and_then(|u| u.parse::<u32>().ok())
                .is_some_and(|u| u < 1000);
            low_uid
                && (ls.in_service_unit
                    || ["/usr/sbin/", "/usr/lib/", "/lib/", "/sbin/"]
                        .iter()
                        .any(|d| under(d)))
        }
        Platform::Macos => under("/System/") || under("/usr/libexec/"),
    }
}

mod interpreters;
use interpreters::{host_of, target_of, Target};

// ─── The identity ────────────────────────────────────────────────────────────

/// The first 128 bits of SHA-256 over `parts`, as 32 hex characters.
fn hex32(parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\0").as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `path` names a location by itself (no working directory needed).
fn is_absolute(path: &str, platform: Platform) -> bool {
    match platform {
        Platform::Windows => {
            let b = path.as_bytes();
            // A UNC path or `X:\`; `\dir` is relative to the current drive.
            path.starts_with("\\\\")
                || path.starts_with("//")
                || (b.len() >= 3 && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
        }
        _ => path.starts_with('/'),
    }
}

/// `path` under `cwd`, with `.` and `..` components folded lexically (symlinks are not
/// resolved: the daemon may not see the same file system).
fn resolve_against(cwd: &str, path: &str, platform: Platform) -> String {
    let sep = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    // `\dir\x` on Windows: rooted on the drive of the working directory.
    let drive = cwd.get(..2).filter(|d| d.as_bytes()[1] == b':');
    let full = match drive {
        Some(d) if platform == Platform::Windows && path.starts_with(['\\', '/']) => {
            format!("{d}{path}")
        }
        _ => format!("{cwd}{sep}{path}"),
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split(['/', '\\']) {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let root = match platform {
        Platform::Windows if cwd.starts_with("\\\\") || cwd.starts_with("//") => "\\\\",
        Platform::Windows => "",
        _ => "/",
    };
    format!("{root}{}", parts.join(&sep.to_string()))
}

/// App identity (ADR 0027): the id is the first 32 hex characters (128 bits) of SHA-256 over
///
/// - the normalized executable path (or, with the `noexe` marker, the process name),
/// - what the interpreter runs: kind and name of the script, module, jar, class or
///   service, or the marker `inline` (code on the command line) or `ambiguous` (an
///   unrecognized option precedes the script: the whole argument vector),
/// - the owning uid,
/// - the marker `foreign-mntns` for a process in another mount namespace.
///
/// The executable path is normalized first so that toolchain upgrades keep the identity.
/// A relative script, jar or dll path is resolved against the process's working directory;
/// without it the marker `ambiguous-cwd` keeps the identity apart from the absolute form.
pub fn app_identity(ls: &ListeningSocket) -> AppIdentity {
    app_identity_on(Platform::current(), ls)
}

/// [`app_identity`] with the platform's conventions chosen explicitly.
pub(crate) fn app_identity_on(platform: Platform, ls: &ListeningSocket) -> AppIdentity {
    if ls.unidentified {
        // Nothing is known about the owner, so the port is the identity: each such socket
        // is its own app and grants never carry over from one to another (ADR 0046).
        let name = format!("unknown:{}/{}", ls.protocol, ls.port);
        return AppIdentity {
            id: hex32(&["v4", "unknown", &name]),
            name,
            interpreter_arg: None,
            note: Some("unidentified".to_string()),
            system: false,
        };
    }
    let process_name = ls.process_name.as_str();
    let exe = ls
        .exe_path
        .as_deref()
        .map(|p| normalize_exe_path(p, platform));
    let exe_name = exe.as_deref().map(file_name).unwrap_or(process_name);
    let args: Option<&[String]> = ls.cmdline.as_deref().map(|c| c.get(1..).unwrap_or(&[]));

    let target = match (host_of(exe_name), args) {
        (Some(host), Some(args)) => target_of(host, args),
        // The command line is hidden, so what the interpreter runs is unknown.
        (Some(_), None) => Target::Ambiguous,
        (None, _) => Target::Nothing,
    };

    let case = |s: &str| match platform {
        Platform::Windows => s.to_lowercase(),
        _ => s.to_string(),
    };
    let mut notes: Vec<&str> = Vec::new();
    let mut markers: Vec<String> = Vec::new();
    let (interpreter_arg, run_key) = match &target {
        Target::Nothing => (None, String::new()),
        Target::Arg(kind, v) => {
            let mut key = v.clone();
            if matches!(*kind, "script" | "jar" | "dll") && !is_absolute(v, platform) {
                match ls.cwd.as_deref().filter(|c| is_absolute(c, platform)) {
                    Some(cwd) => key = resolve_against(cwd, v, platform),
                    None => {
                        notes.push("relative path, working directory unknown");
                        markers.push("ambiguous-cwd".into());
                    }
                }
            }
            (Some(v.clone()), format!("{kind}:{}", case(&key)))
        }
        Target::Inline => {
            notes.push("inline code");
            (None, "inline".to_string())
        }
        Target::Ambiguous => {
            notes.push("unrecognized arguments");
            let argv = args.map(|a| a.join("\u{1}")).unwrap_or_default();
            let tag = if args.is_some() {
                "ambiguous"
            } else {
                "nocmdline"
            };
            (None, format!("{tag}:{}", hex32(&[&case(&argv)])))
        }
    };
    let key_exe = match &exe {
        Some(e) => e.clone(),
        None => {
            notes.push("no executable path");
            markers.push("noexe".into());
            normalize_exe_path(process_name, platform)
        }
    };
    if ls.foreign_mntns {
        notes.push("foreign mount namespace");
        markers.push("foreign-mntns".into());
    }
    let uid = ls
        .uid
        .as_deref()
        .map(|u| format!("uid:{u}"))
        .unwrap_or_else(|| "uid:?".into());
    let id = hex32(&["v4", &key_exe, &run_key, &markers.join(","), &uid]);

    let name = interpreter_arg
        .as_deref()
        .map(file_name)
        .filter(|n| !n.is_empty())
        .unwrap_or(process_name)
        .to_string();
    AppIdentity {
        id,
        name,
        interpreter_arg,
        note: (!notes.is_empty()).then(|| notes.join(", ")),
        system: is_system_process(platform, ls, std::env::var("SystemRoot").ok().as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::interpreters::Host;
    use super::*;
    use crate::types::Protocol;

    pub(super) fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn sock(exe: Option<&str>, name: &str, cmd: Option<&[&str]>) -> ListeningSocket {
        ListeningSocket {
            pid: 1,
            process_name: name.into(),
            port: 80,
            protocol: Protocol::Tcp,
            bind_address: "::".parse().unwrap(),
            exe_path: exe.map(Into::into),
            cmdline: cmd.map(args),
            uid: Some("1000".into()),
            foreign_mntns: false,
            cwd: None,
            unidentified: false,
            in_service_unit: false,
        }
    }

    pub(super) fn ident(exe: &str, cmd: &[&str]) -> AppIdentity {
        app_identity_on(Platform::Linux, &sock(Some(exe), file_name(exe), Some(cmd)))
    }

    fn t(host: Host, a: &[&str]) -> Target {
        target_of(host, &args(a))
    }

    #[test]
    fn plain_binary_uses_the_process_name() {
        let a = ident("/usr/sbin/nginx", &["nginx", "-g", "daemon off;"]);
        assert_eq!(a.name, "nginx");
        assert_eq!(a.interpreter_arg, None);
        assert_eq!(a.note, None);
        assert_eq!(a.id.len(), 32);
        assert!(a.id.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable: same input, same id, whatever the arguments.
        assert_eq!(a.id, ident("/usr/sbin/nginx", &["nginx"]).id);
        assert_ne!(a.id, ident("/usr/sbin/apache2", &["apache2"]).id);
    }

    #[test]
    fn python_scripts_are_separate_apps() {
        let a = ident(
            "/usr/bin/python3.12",
            &["python3", "-u", "/srv/a/server.py", "--port", "1"],
        );
        let b = ident("/usr/bin/python3.12", &["python3", "/srv/b/server.py"]);
        assert_eq!(a.interpreter_arg.as_deref(), Some("/srv/a/server.py"));
        assert_eq!(a.name, "server.py");
        assert_ne!(a.id, b.id);
        assert_eq!(
            a.id,
            ident("/usr/bin/python3.12", &["python3", "/srv/a/server.py"]).id
        );
        let m = ident(
            "/usr/bin/python3",
            &["python3", "-m", "http.server", "8080"],
        );
        assert_eq!(m.interpreter_arg.as_deref(), Some("http.server"));
        assert_eq!(m.name, "http.server");
        // A module is not a script of the same name.
        let s = ident("/usr/bin/python3", &["python3", "http.server"]);
        assert_ne!(m.id, s.id);
        let c = ident("/usr/bin/python3", &["python3", "-c", "print(1)"]);
        assert_eq!(c.interpreter_arg, None);
        assert_eq!(c.name, "python3");
        assert_eq!(c.note.as_deref(), Some("inline code"));
    }

    #[test]
    fn java_jar_and_main_class() {
        let jar = ident(
            "/usr/lib/jvm/bin/java",
            &["java", "-Xmx1g", "-jar", "/opt/app/app.jar", "--x"],
        );
        assert_eq!(jar.interpreter_arg.as_deref(), Some("/opt/app/app.jar"));
        assert_eq!(jar.name, "app.jar");
        let class = ident(
            "/usr/lib/jvm/bin/java",
            &[
                "java",
                "-cp",
                "/lib/a.jar",
                "-Dx=1",
                "com.example.Main",
                "arg",
            ],
        );
        assert_eq!(class.interpreter_arg.as_deref(), Some("com.example.Main"));
        assert_eq!(class.name, "com.example.Main");
        assert_ne!(jar.id, class.id);
    }

    #[test]
    fn svchost_service_argument() {
        let p = Platform::Windows;
        let exe = r"C:\Windows\System32\svchost.exe";
        let mk = |cmd: &[&str]| {
            let mut s = sock(Some(exe), "svchost.exe", Some(cmd));
            s.uid = Some("S-1-5-18".into());
            app_identity_on(p, &s)
        };
        let dns = mk(&[
            "svchost.exe",
            "-k",
            "NetworkService",
            "-p",
            "-s",
            "Dnscache",
        ]);
        assert_eq!(dns.interpreter_arg.as_deref(), Some("Dnscache"));
        assert_eq!(dns.name, "Dnscache");
        let other = mk(&["svchost.exe", "-k", "netsvcs", "-s", "Schedule"]);
        assert_ne!(dns.id, other.id);
        let bare = mk(&["svchost.exe", "-k", "x"]);
        assert_eq!(bare.interpreter_arg, None);
        assert_eq!(bare.name, "svchost.exe");
    }

    #[test]
    fn dotnet_dll_and_other_hosts() {
        let d = ident(
            "/usr/bin/dotnet",
            &["dotnet", "exec", "/app/Web.dll", "--urls", "x"],
        );
        assert_eq!(d.interpreter_arg.as_deref(), Some("/app/Web.dll"));
        let d2 = ident("/usr/bin/dotnet", &["dotnet", "/app/Web.dll"]);
        assert_eq!(d2.interpreter_arg.as_deref(), Some("/app/Web.dll"));
        assert_eq!(d.id, d2.id);
        // A host option's value is not the app.
        let decoy = ident(
            "/usr/bin/dotnet",
            &["dotnet", "--depsfile", "/trusted/Web.dll", "/evil/Evil.dll"],
        );
        assert_eq!(decoy.interpreter_arg.as_deref(), Some("/evil/Evil.dll"));
        let run = ident("/usr/bin/dotnet", &["dotnet", "run"]);
        assert_eq!(run.interpreter_arg, None);
        assert!(run.note.is_some());
        let n = ident("/usr/bin/node", &["node", "--inspect", "server.js"]);
        assert_eq!(n.interpreter_arg.as_deref(), Some("server.js"));
        let deno = ident("/usr/bin/deno", &["deno", "run", "-A", "main.ts"]);
        assert_eq!(deno.interpreter_arg.as_deref(), Some("main.ts"));
        let rb = ident("/usr/bin/ruby", &["ruby", "app.rb"]);
        assert_eq!(rb.interpreter_arg.as_deref(), Some("app.rb"));
    }

    #[test]
    fn hidden_command_line_of_an_interpreter_is_ambiguous() {
        let none = app_identity_on(Platform::Linux, &sock(Some("/usr/bin/node"), "node", None));
        let bare = ident("/usr/bin/node", &["node"]);
        assert_eq!(none.interpreter_arg, None);
        assert_ne!(none.id, bare.id);
        assert!(none.note.is_some());
        // A non-interpreter does not care.
        let a = app_identity_on(
            Platform::Linux,
            &sock(Some("/usr/sbin/nginx"), "nginx", None),
        );
        assert_eq!(a.id, ident("/usr/sbin/nginx", &["nginx"]).id);
    }

    #[test]
    fn windows_paths_are_case_insensitive() {
        let mk = |name: &str, exe: &str, cmd: &[&str]| {
            app_identity_on(Platform::Windows, &sock(Some(exe), name, Some(cmd)))
        };
        let a = mk(
            "Python.exe",
            r"C:\Python312\Python.exe",
            &["python.exe", r"C:\Srv\App.py"],
        );
        let b = mk(
            "python.exe",
            r"c:\python312\python.exe",
            &["python.exe", r"c:\srv\app.py"],
        );
        assert_eq!(a.id, b.id);
        assert_eq!(a.name, "App.py");
        let l1 = app_identity_on(Platform::Linux, &sock(Some("/opt/App"), "x", None));
        let l2 = app_identity_on(Platform::Linux, &sock(Some("/opt/app"), "x", None));
        assert_ne!(l1.id, l2.id);
    }

    #[test]
    fn linux_deleted_suffix_is_stripped() {
        let a = app_identity_on(
            Platform::Linux,
            &sock(Some("/usr/sbin/nginx"), "nginx", None),
        );
        let b = app_identity_on(
            Platform::Linux,
            &sock(Some("/usr/sbin/nginx (deleted)"), "nginx", None),
        );
        assert_eq!(a.id, b.id);
        assert_eq!(
            normalize_exe_path("/usr/sbin/nginx (deleted)", Platform::Linux),
            "/usr/sbin/nginx"
        );
        assert_eq!(
            normalize_exe_path(r"C:\Windows\Foo.EXE", Platform::Windows),
            r"c:\windows\foo.exe"
        );
        // A script-hosting interpreter that was upgraded keeps its app.
        let old = ident("/usr/bin/python3.11", &["python3", "/srv/x.py"]);
        let up = app_identity_on(
            Platform::Linux,
            &sock(
                Some("/usr/bin/python3.11 (deleted)"),
                "python3",
                Some(&["python3", "/srv/x.py"]),
            ),
        );
        assert_eq!(old.id, up.id);
    }

    fn at(cwd: Option<&str>, platform: Platform, exe: &str, cmd: &[&str]) -> AppIdentity {
        let mut s = sock(Some(exe), file_name(exe), Some(cmd));
        s.cwd = cwd.map(Into::into);
        app_identity_on(platform, &s)
    }

    #[test]
    fn relative_scripts_resolve_against_the_working_directory() {
        let rel = |cwd| {
            at(
                cwd,
                Platform::Linux,
                "/usr/bin/node",
                &["node", "server.js"],
            )
        };
        // The same relative name in two directories is two apps ...
        assert_ne!(rel(Some("/srv/a")).id, rel(Some("/srv/b")).id);
        // ... and it is the app that runs the absolute path.
        let abs = at(
            None,
            Platform::Linux,
            "/usr/bin/node",
            &["node", "/srv/a/server.js"],
        );
        assert_eq!(rel(Some("/srv/a")).id, abs.id);
        let dots = at(
            Some("/srv/a/x"),
            Platform::Linux,
            "/usr/bin/node",
            &["node", "../././server.js"],
        );
        assert_eq!(dots.id, abs.id);
        // Display stays as given.
        assert_eq!(
            rel(Some("/srv/a")).interpreter_arg.as_deref(),
            Some("server.js")
        );
        assert_eq!(rel(Some("/srv/a")).note, None);
    }

    #[test]
    fn a_relative_script_without_a_working_directory_never_merges_with_the_absolute_form() {
        let unknown = at(
            None,
            Platform::Linux,
            "/usr/bin/node",
            &["node", "/srv/a/server.js"],
        );
        let rel = at(
            None,
            Platform::Linux,
            "/usr/bin/node",
            &["node", "server.js"],
        );
        assert_ne!(rel.id, unknown.id);
        assert!(rel
            .note
            .as_deref()
            .unwrap()
            .contains("working directory unknown"));
        // A relative cwd is as good as none.
        let odd = at(
            Some("srv"),
            Platform::Linux,
            "/usr/bin/node",
            &["node", "server.js"],
        );
        assert_eq!(odd.id, rel.id);
        // The cwd does not matter for absolute scripts or modules.
        let abs_cwd = at(
            Some("/tmp"),
            Platform::Linux,
            "/usr/bin/node",
            &["node", "/srv/a/server.js"],
        );
        assert_eq!(abs_cwd.id, unknown.id);
        let m1 = at(
            Some("/a"),
            Platform::Linux,
            "/usr/bin/python3",
            &["python3", "-m", "http.server"],
        );
        let m2 = at(
            Some("/b"),
            Platform::Linux,
            "/usr/bin/python3",
            &["python3", "-m", "http.server"],
        );
        assert_eq!(m1.id, m2.id);
    }

    #[test]
    fn windows_relative_scripts_use_the_working_directory_case_insensitively() {
        let w = |cwd, script| {
            at(
                Some(cwd),
                Platform::Windows,
                r"C:\Python\python.exe",
                &["python.exe", script],
            )
        };
        assert_eq!(
            w(r"C:\Srv\App", "run.py").id,
            w(r"c:\srv\app", r"..\app\RUN.py").id
        );
        assert_eq!(w(r"C:\Srv", "run.py").id, w(r"D:\x", r"C:\Srv\run.py").id);
        assert_ne!(w(r"C:\Srv", "run.py").id, w(r"C:\Other", "run.py").id);
        // `\dir\run.py` is rooted on the drive of the working directory ...
        assert_eq!(
            w(r"C:\x", r"\Srv\run.py").id,
            w(r"C:\y", r"C:\Srv\run.py").id
        );
        assert_ne!(w(r"C:\x", r"\Srv\run.py").id, w(r"D:\x", r"\Srv\run.py").id);
        // ... and without a working directory it is as unknown as any relative path.
        let unknown = at(
            None,
            Platform::Windows,
            r"C:\P\python.exe",
            &["python.exe", r"\Srv\run.py"],
        );
        assert!(unknown.note.unwrap().contains("unknown"));
    }

    // ─── Forgery resistance ──────────────────────────────────────────────

    #[test]
    fn argv_decoys_do_not_pick_the_script() {
        // The decoy is an option's value or sits next to inline code.
        assert_eq!(
            t(
                Host::Node,
                &["--eval=console.log(1)", "/srv/trusted/app.js"]
            ),
            Target::Inline
        );
        assert_eq!(
            t(Host::Node, &["--eval", "x", "/srv/trusted/app.js"]),
            Target::Inline
        );
        assert_eq!(
            t(Host::Python, &["-W", "/srv/trusted/app.py", "-c", "evil"]),
            Target::Inline
        );
        assert_eq!(t(Host::Ruby, &["-e'puts 1'", "trusted.rb"]), Target::Inline);
        assert_eq!(
            t(
                Host::Java,
                &[
                    "--add-modules",
                    "com.victim.Main",
                    "-cp",
                    "evil.jar",
                    "Evil"
                ]
            ),
            Target::Arg("class", "Evil".into())
        );
        // Inline code never has the script identity.
        let evil = ident(
            "/usr/bin/node",
            &["node", "--eval=1", "/srv/trusted/app.js"],
        );
        let good = ident("/usr/bin/node", &["node", "/srv/trusted/app.js"]);
        assert_ne!(evil.id, good.id);
        assert_eq!(evil.interpreter_arg, None);
        assert_eq!(evil.note.as_deref(), Some("inline code"));
    }

    #[test]
    fn unknown_options_make_the_candidate_ambiguous() {
        assert_eq!(
            t(Host::Python, &["--mystery", "/srv/trusted/app.py"]),
            Target::Ambiguous
        );
        let evil = ident(
            "/usr/bin/python3",
            &["python3", "--mystery", "/srv/trusted/app.py"],
        );
        let good = ident("/usr/bin/python3", &["python3", "/srv/trusted/app.py"]);
        assert_ne!(evil.id, good.id);
        assert_eq!(evil.interpreter_arg, None);
        assert_eq!(evil.note.as_deref(), Some("unrecognized arguments"));
        // Different ambiguous command lines are different apps.
        let other = ident(
            "/usr/bin/python3",
            &["python3", "--mystery", "/srv/other/app.py"],
        );
        assert_ne!(evil.id, other.id);
        // Same one twice is the same app.
        assert_eq!(
            evil.id,
            ident(
                "/usr/bin/python3",
                &["python3", "--mystery", "/srv/trusted/app.py"]
            )
            .id
        );
        // Without a script, unknown options still do not look like a bare interpreter.
        assert_eq!(t(Host::Node, &["--mystery"]), Target::Ambiguous);
    }

    #[test]
    fn uid_separates_users() {
        let mut a = sock(Some("/usr/sbin/nginx"), "nginx", None);
        let mut b = a.clone();
        a.uid = Some("0".into());
        b.uid = Some("1000".into());
        assert_ne!(
            app_identity_on(Platform::Linux, &a).id,
            app_identity_on(Platform::Linux, &b).id
        );
        b.uid = None;
        assert_ne!(
            app_identity_on(Platform::Linux, &a).id,
            app_identity_on(Platform::Linux, &b).id
        );
    }

    #[test]
    fn a_missing_exe_never_collides_with_a_path() {
        let mut spoof = sock(None, "nginx", None);
        spoof.uid = Some("0".into());
        let mut real = sock(Some("/usr/sbin/nginx"), "nginx", None);
        real.uid = Some("0".into());
        // Even a spoofed comm that equals the real exe's path.
        let mut path_comm = sock(None, "/usr/sbin/nginx", None);
        path_comm.uid = Some("0".into());
        let s = app_identity_on(Platform::Linux, &spoof);
        assert_ne!(s.id, app_identity_on(Platform::Linux, &real).id);
        assert_ne!(
            app_identity_on(Platform::Linux, &path_comm).id,
            app_identity_on(Platform::Linux, &real).id
        );
        assert_eq!(s.note.as_deref(), Some("no executable path"));
        let other = app_identity_on(Platform::Linux, &sock(None, "other", None));
        assert_ne!(s.id, other.id);
        assert_eq!(s.name, "nginx");
    }

    #[test]
    fn a_foreign_mount_namespace_never_collides_with_the_host() {
        let host = sock(Some("/usr/sbin/nginx"), "nginx", None);
        let mut forged = host.clone();
        forged.foreign_mntns = true;
        let f = app_identity_on(Platform::Linux, &forged);
        assert_ne!(f.id, app_identity_on(Platform::Linux, &host).id);
        assert_eq!(f.note.as_deref(), Some("foreign mount namespace"));
        // Stable across restarts: nothing random in it.
        assert_eq!(f.id, app_identity_on(Platform::Linux, &forged).id);
        // And it is per user.
        let mut other_user = forged.clone();
        other_user.uid = Some("1001".into());
        assert_ne!(f.id, app_identity_on(Platform::Linux, &other_user).id);
    }

    fn unknown(proto: Protocol, port: u16) -> ListeningSocket {
        let mut s = ListeningSocket::new(0, port, proto, "::".parse().unwrap())
            .with_process_name("unknown");
        s.unidentified = true;
        s
    }

    #[test]
    fn an_unidentified_socket_is_an_app_per_protocol_and_port() {
        let a = app_identity_on(Platform::Windows, &unknown(Protocol::Tcp, 8080));
        assert_eq!(a.name, "unknown:tcp/8080");
        assert_eq!(a.note.as_deref(), Some("unidentified"));
        assert!(!a.system);
        // Stable, and separate per port and protocol, so grants never carry over.
        assert_eq!(
            a.id,
            app_identity_on(Platform::Linux, &unknown(Protocol::Tcp, 8080)).id
        );
        assert_ne!(
            a.id,
            app_identity_on(Platform::Windows, &unknown(Protocol::Tcp, 8081)).id
        );
        assert_ne!(
            a.id,
            app_identity_on(Platform::Windows, &unknown(Protocol::Udp, 8080)).id
        );
        // And not the id of any identified process called "unknown".
        let mut named = sock(None, "unknown", None);
        named.port = 8080;
        assert_ne!(a.id, app_identity_on(Platform::Windows, &named).id);
    }

    #[test]
    fn system_components_by_platform() {
        let win = |exe: Option<&str>, name: &str| {
            let mut s = sock(exe, name, None);
            s.uid = None;
            is_system_process(Platform::Windows, &s, Some("C:\\Windows"))
        };
        assert!(win(
            Some("C:\\Windows\\System32\\svchost.exe"),
            "svchost.exe"
        ));
        assert!(win(
            Some("c:\\windows\\system32\\services.exe"),
            "services.exe"
        ));
        assert!(win(None, "System"));
        assert!(win(None, "svchost.exe"));
        assert!(!win(Some("C:\\Program Files\\App\\app.exe"), "app.exe"));
        assert!(!win(Some("C:\\WindowsApps\\app.exe"), "app.exe"));

        let lin = |exe: Option<&str>, uid: &str, unit: bool| {
            let mut s = sock(exe, "x", None);
            s.uid = Some(uid.into());
            s.in_service_unit = unit;
            is_system_process(Platform::Linux, &s, None)
        };
        assert!(lin(Some("/opt/x/bin/x"), "0", true), "a service unit");
        assert!(
            lin(Some("/usr/sbin/sshd"), "0", false),
            "a system directory"
        );
        assert!(lin(Some("/usr/lib/systemd/systemd-resolved"), "101", false));
        assert!(
            !lin(Some("/usr/sbin/sshd"), "1000", true),
            "a user's process"
        );
        assert!(!lin(Some("/home/me/app"), "0", false));

        let mac = |exe: &str| is_system_process(Platform::Macos, &sock(Some(exe), "x", None), None);
        assert!(mac("/System/Library/CoreServices/x"));
        assert!(mac("/usr/libexec/rapportd"));
        assert!(!mac("/Applications/App.app/x"));
    }
}
