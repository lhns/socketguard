//! Command-line grammars of the interpreters and hosts whose scripts are separate apps
//! (python, node, java, svchost, ...): what an interpreter command line runs.
//!
//! Anything an unprivileged process controls (argv) is hostile, so every grammar errs
//! toward `Ambiguous`: an option we do not know might swallow the next argument.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Host {
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
pub(super) fn host_of(exe_name: &str) -> Option<Host> {
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
pub(super) enum Target {
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

pub(super) fn target_of(host: Host, args: &[String]) -> Target {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tests::{args, ident};

    fn t(host: Host, a: &[&str]) -> Target {
        target_of(host, &args(a))
    }

    fn script(v: &str) -> Target {
        Target::Arg("script", v.into())
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
}
