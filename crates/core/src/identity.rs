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
}

// ─── Interpreter command lines ───────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Host {
    Python,
    Node,
    Bun,
    Deno,
    Ruby,
    Perl,
    Php,
    Java,
    Dotnet,
    Svchost,
}

/// Known interpreters and hosts, matched on the lowercased executable name without `.exe`.
fn host_of(exe_name: &str) -> Option<Host> {
    let lower = exe_name.to_lowercase();
    let name = lower.strip_suffix(".exe").unwrap_or(&lower);
    if name == "python" || name == "pythonw" {
        return Some(Host::Python);
    }
    if let Some(ver) = name.strip_prefix("python") {
        if ver.starts_with(|c: char| c.is_ascii_digit())
            && ver.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(Host::Python);
        }
    }
    match name {
        "node" => Some(Host::Node),
        "bun" => Some(Host::Bun),
        "ruby" => Some(Host::Ruby),
        "perl" => Some(Host::Perl),
        "php" => Some(Host::Php),
        "deno" => Some(Host::Deno),
        "java" | "javaw" => Some(Host::Java),
        "dotnet" => Some(Host::Dotnet),
        "svchost" => Some(Host::Svchost),
        _ => None,
    }
}

/// What an interpreter command line runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Nothing recognizable runs (a REPL, `--version`): the interpreter itself.
    Nothing,
    /// A script, module, jar, class or service, by kind and name.
    Arg(&'static str, String),
    /// Code on the command line (or stdin), not a file.
    Inline,
    /// An option we do not know precedes the candidate, so what runs cannot be told.
    Ambiguous,
}

/// The option grammar of one interpreter. Anything not listed makes the command line
/// ambiguous, because an unknown option might swallow the next argument and the first
/// plain argument after it would then not be the script.
#[derive(Default)]
struct Opts {
    /// Options with a value: the next argument, `--opt=value`, and for short options the
    /// attached `-Xvalue`.
    value: &'static [&'static str],
    /// Options that run code from the command line.
    inline: &'static [&'static str],
    /// Options whose value is the thing that runs: (option, kind).
    target: &'static [(&'static str, &'static str)],
    /// Options with a value that make the command line unrecognizable (php -S).
    opaque: &'static [&'static str],
    /// Known options without a value.
    flags: &'static [&'static str],
    /// Prefixes of known options that never take a separate value (`-Xmx1g`, `--no-x`).
    flag_prefixes: &'static [&'static str],
    /// Letters of a cluster of single-letter flags (`-lane`); a cluster that ends in one
    /// of `cluster_inline` runs code (`-pe`).
    cluster_letters: &'static str,
    cluster_inline: &'static str,
    /// First arguments that are subcommands: skipped, or running inline code.
    skip_subcommands: &'static [&'static str],
    inline_subcommands: &'static [&'static str],
    /// The kind of the first plain argument.
    kind: &'static str,
}

const PYTHON: Opts = Opts {
    value: &["-W", "-X", "-Q", "--check-hash-based-pycs"],
    inline: &["-c"],
    target: &[("-m", "module")],
    flags: &[
        "-B",
        "-b",
        "-bb",
        "-d",
        "-E",
        "-h",
        "-?",
        "-i",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-q",
        "-R",
        "-s",
        "-S",
        "-u",
        "-v",
        "-vv",
        "-V",
        "-VV",
        "-x",
        "--help",
        "--version",
    ],
    cluster_letters: "BbdEhiIOPqRsSuvVx",
    cluster_inline: "c",
    kind: "script",
    ..NO_OPTS
};

const NODE: Opts = Opts {
    value: &[
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "-C",
        "--conditions",
        "--env-file",
        "--watch-path",
        "--title",
        "--max-old-space-size",
        "--max-semi-space-size",
        "--max-http-header-size",
        "--stack-size",
        "--disable-warning",
        "--input-type",
        "--redirect-warnings",
        "--inspect-port",
        "--icu-data-dir",
        "--openssl-config",
        "--tls-cipher-list",
        "--unhandled-rejections",
        "--diagnostic-dir",
        "--report-dir",
        "--cpu-prof-dir",
        "--heap-prof-dir",
        "--test-name-pattern",
        "--test-reporter",
    ],
    inline: &["-e", "--eval", "-p", "--print", "-pe"],
    flags: &[
        "--inspect",
        "--inspect-brk",
        "--inspect-wait",
        "--enable-source-maps",
        "--expose-gc",
        "--expose_gc",
        "--harmony",
        "--use-strict",
        "--trace-warnings",
        "--trace-deprecation",
        "--trace-uncaught",
        "--throw-deprecation",
        "--pending-deprecation",
        "--preserve-symlinks",
        "--preserve-symlinks-main",
        "--abort-on-uncaught-exception",
        "--experimental-vm-modules",
        "--experimental-strip-types",
        "--experimental-transform-types",
        "--watch",
        "--check",
        "-c",
        "--interactive",
        "-i",
        "--test",
        "--prof",
        "--zero-fill-buffers",
        "--force-fips",
        "--enable-fips",
        "--frozen-intrinsics",
        "--version",
        "-v",
        "--help",
        "-h",
    ],
    flag_prefixes: &["--no-"],
    cluster_letters: "p",
    cluster_inline: "e",
    kind: "script",
    ..NO_OPTS
};

const BUN: Opts = Opts {
    value: &[
        "-r",
        "--preload",
        "--import",
        "--cwd",
        "-c",
        "--config",
        "--env-file",
        "--port",
        "--tsconfig-override",
        "--define",
        "-d",
        "--loader",
        "-l",
        "--install",
        "--inspect-port",
    ],
    inline: &["-e", "--eval", "-p", "--print"],
    flags: &[
        "--hot",
        "--watch",
        "--smol",
        "--bun",
        "-b",
        "--silent",
        "--inspect",
        "--inspect-brk",
        "--inspect-wait",
        "--version",
        "-v",
        "--help",
        "-h",
        "--prefer-offline",
        "--prefer-latest",
    ],
    flag_prefixes: &["--no-"],
    skip_subcommands: &["run"],
    kind: "script",
    ..NO_OPTS
};

const DENO: Opts = Opts {
    value: &[
        "-c",
        "--config",
        "--import-map",
        "--lock",
        "--cert",
        "--location",
        "--seed",
        "--port",
        "--tunnel",
    ],
    flags: &[
        "-A",
        "--allow-all",
        "-q",
        "--quiet",
        "-L",
        "-r",
        "--reload",
        "--watch",
        "--check",
        "--cached-only",
        "--inspect",
        "--inspect-brk",
        "--inspect-wait",
        "--version",
        "-V",
        "--help",
        "-h",
        "--unstable",
        "--prompt",
    ],
    flag_prefixes: &["--no-", "--allow-", "--deny-", "--unstable-"],
    skip_subcommands: &["run", "serve"],
    inline_subcommands: &["eval", "repl"],
    kind: "script",
    ..NO_OPTS
};

const RUBY: Opts = Opts {
    value: &[
        "-I",
        "-r",
        "-C",
        "-E",
        "-F",
        "--encoding",
        "--external-encoding",
    ],
    inline: &["-e"],
    flags: &[
        "-a",
        "-c",
        "-d",
        "--debug",
        "-l",
        "-n",
        "-p",
        "-s",
        "-S",
        "-v",
        "--verbose",
        "--version",
        "-w",
        "-y",
        "-h",
        "--help",
        "--jit",
        "--yjit",
        "--rjit",
    ],
    flag_prefixes: &["-W", "-0", "-x", "-K", "-i", "--disable", "--enable"],
    cluster_letters: "acdlnpsSvwyh",
    cluster_inline: "e",
    kind: "script",
    ..NO_OPTS
};

const PERL: Opts = Opts {
    value: &["-I", "-M", "-m"],
    inline: &["-e", "-E"],
    flags: &[
        "-a", "-c", "-n", "-p", "-s", "-S", "-t", "-T", "-u", "-U", "-v", "-w", "-W", "-X", "-h",
        "-f",
    ],
    flag_prefixes: &["-C", "-i", "-F", "-l", "-0", "-x", "-V", "-d", "-D"],
    cluster_letters: "acnpsStTuUvwWXh",
    cluster_inline: "eE",
    kind: "script",
    ..NO_OPTS
};

const PHP: Opts = Opts {
    value: &["-d", "-c", "-z"],
    // -B/-R/-F/-E run code per input line.
    inline: &["-r", "-B", "-R", "-F", "-E"],
    target: &[("-f", "script")],
    opaque: &["-S", "-t"],
    flags: &[
        "-n",
        "-q",
        "-a",
        "-h",
        "-?",
        "-i",
        "-m",
        "-v",
        "-w",
        "-e",
        "--ini",
        "--version",
        "--help",
    ],
    kind: "script",
    ..NO_OPTS
};

const JAVA: Opts = Opts {
    value: &[
        "-cp",
        "-classpath",
        "--class-path",
        "-p",
        "--module-path",
        "--upgrade-module-path",
        "--add-modules",
        "--add-opens",
        "--add-exports",
        "--add-reads",
        "--patch-module",
        "--limit-modules",
        "--enable-native-access",
        "--source",
    ],
    target: &[("-jar", "jar"), ("-m", "module"), ("--module", "module")],
    flags: &[
        "-server",
        "-client",
        "-ea",
        "-da",
        "-esa",
        "-dsa",
        "-enableassertions",
        "-disableassertions",
        "-enablesystemassertions",
        "-disablesystemassertions",
        "-showversion",
        "--show-version",
        "-version",
        "--version",
        "-help",
        "--help",
        "-?",
        "--enable-preview",
        "-verbose",
    ],
    flag_prefixes: &[
        "-D",
        "-X",
        "-agentlib:",
        "-agentpath:",
        "-javaagent:",
        "-verbose:",
        "-splash:",
        "-ea:",
        "-da:",
        "-enableassertions:",
        "-disableassertions:",
    ],
    kind: "class",
    ..NO_OPTS
};

const DOTNET: Opts = Opts {
    value: &[
        "--depsfile",
        "--runtimeconfig",
        "--additionalprobingpath",
        "--additional-deps",
        "--fx-version",
        "--roll-forward",
    ],
    skip_subcommands: &["exec"],
    kind: "dll",
    ..NO_OPTS
};

const NO_OPTS: Opts = Opts {
    value: &[],
    inline: &[],
    target: &[],
    opaque: &[],
    flags: &[],
    flag_prefixes: &[],
    cluster_letters: "",
    cluster_inline: "",
    skip_subcommands: &[],
    inline_subcommands: &[],
    kind: "script",
};

fn is_cluster(a: &str, letters: &str) -> bool {
    a.len() > 2 && a[1..].chars().all(|c| letters.contains(c))
}

fn is_inline_cluster(a: &str, o: &Opts) -> bool {
    let body = &a[1..];
    let Some(last) = body.chars().last() else {
        return false;
    };
    body.len() > 1
        && o.cluster_inline.contains(last)
        && body[..body.len() - last.len_utf8()]
            .chars()
            .all(|c| o.cluster_letters.contains(c))
}

/// Walk `args` (argv without `argv[0]`) with the option grammar `o`. Returns what runs and
/// how many arguments were looked at.
fn scan(args: &[String], o: &Opts) -> (Target, usize) {
    let mut unknown = false;
    let mut skipped_subcommand = false;
    let mut i = 0;
    let end = |unknown: bool| {
        if unknown {
            Target::Ambiguous
        } else {
            Target::Nothing
        }
    };
    let plain = |unknown: bool, kind: &'static str, v: &str| {
        if unknown {
            Target::Ambiguous
        } else {
            Target::Arg(kind, v.to_string())
        }
    };
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            return match args.get(i) {
                Some(t) => (plain(unknown, o.kind, t), i + 1),
                None => (end(unknown), i),
            };
        }
        if a == "-" {
            return (Target::Inline, i); // a script on stdin
        }
        if !a.starts_with('-') {
            if !skipped_subcommand && o.inline_subcommands.contains(&a) {
                return (Target::Inline, i);
            }
            if !skipped_subcommand && o.skip_subcommands.contains(&a) {
                skipped_subcommand = true;
                continue;
            }
            return (plain(unknown, o.kind, a), i);
        }

        let long = a.starts_with("--");
        let (name, attached_value) = if long {
            match a.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a, None),
            }
        } else {
            (a, None)
        };
        // `-Xvalue`: a short option with its value attached.
        let short_attached = |list: &[&str]| -> bool {
            !long
                && list
                    .iter()
                    .any(|opt| opt.len() == 2 && a.len() > 2 && a.starts_with(opt))
        };

        if o.inline.contains(&name) || short_attached(o.inline) {
            return (Target::Inline, i);
        }
        if let Some((_, kind)) = o.target.iter().find(|(opt, _)| *opt == name) {
            return match (attached_value, args.get(i)) {
                (Some(v), _) => (plain(unknown, kind, v), i),
                (None, Some(v)) => (plain(unknown, kind, v), i + 1),
                (None, None) => (Target::Ambiguous, i),
            };
        }
        if !long {
            if let Some((_, kind)) = o
                .target
                .iter()
                .find(|(opt, _)| opt.len() == 2 && a.len() > 2 && a.starts_with(opt))
            {
                return (plain(unknown, kind, &a[2..]), i);
            }
        }
        if o.opaque.contains(&name) {
            unknown = true;
            if attached_value.is_none() {
                i += 1;
            }
            continue;
        }
        if short_attached(o.opaque) {
            unknown = true;
            continue;
        }
        if o.value.contains(&name) {
            if attached_value.is_none() {
                i += 1;
            }
            continue;
        }
        if short_attached(o.value) {
            continue;
        }
        if !long && is_inline_cluster(a, o) {
            return (Target::Inline, i);
        }
        if o.flags.contains(&a) || (long && attached_value.is_some()) {
            continue;
        }
        if o.flag_prefixes.iter().any(|p| a.starts_with(p)) {
            continue;
        }
        if !long && is_cluster(a, o.cluster_letters) {
            continue;
        }
        unknown = true;
    }
    (end(unknown), i)
}

/// `-s <name>` of svchost: the service it hosts.
fn svchost_target(args: &[String]) -> Target {
    match args
        .iter()
        .position(|a| a == "-s")
        .and_then(|i| args.get(i + 1))
    {
        Some(s) if !s.is_empty() => Target::Arg("service", s.clone()),
        _ => Target::Nothing,
    }
}

/// The target of a dotnet command line: `[exec] [host options] app.dll`.
fn dotnet_target(args: &[String]) -> Target {
    match scan(args, &DOTNET) {
        (Target::Arg(_, v), _) if v.to_ascii_lowercase().ends_with(".dll") => Target::Arg("dll", v),
        // `dotnet run`, `dotnet watch`, ...: not an app of its own.
        (Target::Arg(..), _) => Target::Ambiguous,
        (t, _) => t,
    }
}

fn target_of(host: Host, args: &[String]) -> Target {
    let opts = match host {
        Host::Python => &PYTHON,
        Host::Node => &NODE,
        Host::Bun => &BUN,
        Host::Deno => &DENO,
        Host::Ruby => &RUBY,
        Host::Perl => &PERL,
        Host::Php => &PHP,
        Host::Java => &JAVA,
        Host::Dotnet => return dotnet_target(args),
        Host::Svchost => return svchost_target(args),
    };
    let (target, used) = scan(args, opts);
    // A response file may hold any options.
    if host == Host::Java && args[..used].iter().any(|a| a.starts_with('@')) {
        return Target::Ambiguous;
    }
    target
}

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
    let full = format!("{cwd}{sep}{path}");
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
pub fn app_identity_on(platform: Platform, ls: &ListeningSocket) -> AppIdentity {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;

    fn args(a: &[&str]) -> Vec<String> {
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
        }
    }

    fn ident(exe: &str, cmd: &[&str]) -> AppIdentity {
        app_identity_on(Platform::Linux, &sock(Some(exe), file_name(exe), Some(cmd)))
    }

    fn t(host: Host, a: &[&str]) -> Target {
        target_of(host, &args(a))
    }

    fn script(v: &str) -> Target {
        Target::Arg("script", v.into())
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
    }

    #[test]
    fn python_version_names() {
        for n in [
            "python",
            "python3",
            "python3.12",
            "pythonw",
            "Python.EXE",
            "python3.12.exe",
        ] {
            assert!(host_of(n).is_some(), "{n}");
        }
        for n in ["pythonista", "python-config", "nodejs"] {
            assert!(host_of(n).is_none(), "{n}");
        }
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
    fn python_forms() {
        assert_eq!(t(Host::Python, &["-u", "app.py", "-c"]), script("app.py"));
        assert_eq!(
            t(Host::Python, &["-Xutf8", "-Wignore", "app.py"]),
            script("app.py")
        );
        assert_eq!(
            t(Host::Python, &["-X", "dev", "-W", "error", "app.py"]),
            script("app.py")
        );
        assert_eq!(
            t(
                Host::Python,
                &["--check-hash-based-pycs", "always", "app.py"]
            ),
            script("app.py")
        );
        assert_eq!(
            t(Host::Python, &["-m", "http.server", "-c"]),
            Target::Arg("module", "http.server".into())
        );
        assert_eq!(
            t(Host::Python, &["-mhttp.server"]),
            Target::Arg("module", "http.server".into())
        );
        assert_eq!(t(Host::Python, &["-Bc", "x"]), Target::Inline);
        assert_eq!(t(Host::Python, &["-uB", "app.py"]), script("app.py"));
        assert_eq!(t(Host::Python, &["-c", "x", "app.py"]), Target::Inline);
        assert_eq!(t(Host::Python, &["-"]), Target::Inline);
        assert_eq!(t(Host::Python, &["--", "app.py"]), script("app.py"));
        assert_eq!(t(Host::Python, &["-u"]), Target::Nothing);
    }

    #[test]
    fn node_bun_deno_forms() {
        assert_eq!(
            t(Host::Node, &["-r", "dotenv/config", "app.js"]),
            script("app.js")
        );
        assert_eq!(
            t(
                Host::Node,
                &["--require=x", "--inspect=0.0.0.0:9229", "app.js"]
            ),
            script("app.js")
        );
        assert_eq!(
            t(
                Host::Node,
                &["--import", "./hook.mjs", "--no-warnings", "app.js"]
            ),
            script("app.js")
        );
        assert_eq!(
            t(Host::Node, &["--loader", "x", "-C", "dev", "app.js"]),
            script("app.js")
        );
        assert_eq!(t(Host::Node, &["-p", "1+1", "app.js"]), Target::Inline);
        assert_eq!(t(Host::Node, &["-pe", "1", "app.js"]), Target::Inline);
        assert_eq!(t(Host::Node, &["--print=1", "app.js"]), Target::Inline);
        assert_eq!(
            t(Host::Bun, &["run", "--hot", "server.ts"]),
            script("server.ts")
        );
        assert_eq!(t(Host::Bun, &["server.ts"]), script("server.ts"));
        assert_eq!(
            t(Host::Bun, &["-r", "./preload.ts", "server.ts"]),
            script("server.ts")
        );
        assert_eq!(t(Host::Bun, &["-e", "1", "server.ts"]), Target::Inline);
        assert_eq!(
            t(Host::Deno, &["run", "--allow-net=0.0.0.0", "-A", "main.ts"]),
            script("main.ts")
        );
        assert_eq!(
            t(Host::Deno, &["run", "--config", "deno.json", "main.ts"]),
            script("main.ts")
        );
        assert_eq!(
            t(Host::Deno, &["run", "-c", "decoy.ts", "main.ts"]),
            script("main.ts")
        );
        assert_eq!(t(Host::Deno, &["eval", "main.ts"]), Target::Inline);
        assert_eq!(t(Host::Deno, &["main.ts"]), script("main.ts"));
    }

    #[test]
    fn ruby_perl_php_forms() {
        assert_eq!(
            t(Host::Ruby, &["-I", "lib", "-r", "json", "app.rb"]),
            script("app.rb")
        );
        assert_eq!(t(Host::Ruby, &["-Ilib", "-W0", "app.rb"]), script("app.rb"));
        assert_eq!(t(Host::Ruby, &["-C", "/srv", "app.rb"]), script("app.rb"));
        assert_eq!(t(Host::Ruby, &["-e", "1", "app.rb"]), Target::Inline);
        assert_eq!(t(Host::Ruby, &["-lane", "1", "app.rb"]), Target::Inline);
        assert_eq!(t(Host::Ruby, &["-w", "app.rb"]), script("app.rb"));
        assert_eq!(t(Host::Perl, &["-w", "-Ilib", "app.pl"]), script("app.pl"));
        assert_eq!(
            t(Host::Perl, &["-I", "lib", "-M", "strict", "app.pl"]),
            script("app.pl")
        );
        assert_eq!(t(Host::Perl, &["-MPOSIX", "app.pl"]), script("app.pl"));
        assert_eq!(t(Host::Perl, &["-e", "1", "app.pl"]), Target::Inline);
        assert_eq!(t(Host::Perl, &["-E", "say 1", "app.pl"]), Target::Inline);
        assert_eq!(t(Host::Perl, &["-pe", "1", "app.pl"]), Target::Inline);
        assert_eq!(t(Host::Php, &["-r", "1", "app.php"]), Target::Inline);
        assert_eq!(
            t(Host::Php, &["-d", "memory_limit=1G", "app.php"]),
            script("app.php")
        );
        assert_eq!(
            t(Host::Php, &["-c", "/etc/php.ini", "-f", "app.php", "x"]),
            script("app.php")
        );
        assert_eq!(t(Host::Php, &["-dx=1", "-f", "a.php"]), script("a.php"));
        // The built-in server has no script: it is told apart by its whole command line.
        assert_eq!(
            t(Host::Php, &["-S", "0.0.0.0:80", "-t", "/srv/a"]),
            Target::Ambiguous
        );
        let a = ident("/usr/bin/php", &["php", "-S", "0.0.0.0:80", "-t", "/srv/a"]);
        let b = ident("/usr/bin/php", &["php", "-S", "0.0.0.0:80", "-t", "/srv/b"]);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn java_forms() {
        assert_eq!(
            t(
                Host::Java,
                &["-Xmx1g", "-Dk=v", "-jar", "app.jar", "-jar", "x"]
            ),
            Target::Arg("jar", "app.jar".into())
        );
        assert_eq!(
            t(
                Host::Java,
                &["--module-path", "mods", "-m", "app.mod/app.Main"]
            ),
            Target::Arg("module", "app.mod/app.Main".into())
        );
        assert_eq!(
            t(Host::Java, &["--module=app.mod", "x"]),
            Target::Arg("module", "app.mod".into())
        );
        assert_eq!(
            t(Host::Java, &["-classpath", "a:b", "-ea", "com.x.Main"]),
            Target::Arg("class", "com.x.Main".into())
        );
        assert_eq!(
            t(Host::Java, &["--add-opens=a/b=ALL-UNNAMED", "com.x.Main"]),
            Target::Arg("class", "com.x.Main".into())
        );
        assert_eq!(
            t(
                Host::Java,
                &["-javaagent:/a.jar", "-XX:+UseG1GC", "com.x.Main"]
            ),
            Target::Arg("class", "com.x.Main".into())
        );
        assert_eq!(
            t(Host::Java, &["@args.txt", "com.x.Main"]),
            Target::Ambiguous
        );
        assert_eq!(
            t(
                Host::Java,
                &[
                    "--add-reads",
                    "m=x",
                    "--patch-module",
                    "m=p",
                    "-p",
                    "mods",
                    "Main"
                ]
            ),
            Target::Arg("class", "Main".into())
        );
    }

    // ─── Process facts: uid, executable, mount namespace ─────────────────

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
}
