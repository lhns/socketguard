# ADR 0027: Domain Model: Apps, Networks, Addresses, Peers and Grants

## Status

Accepted. Supersedes ADRs 0009 and 0016-0024, the schema and migration parts of ADR 0005, and the stale-socket deletion of ADR 0007.

Amended below; read the amendments in order.

## Date

2026-11-09

## Context

ADRs 0016-0024 layered per-backend policy, a Disabled mode (later removed), ACL groups, socket groups and group inheritance. ACL subjects were raw IP strings, and policy resolution was copy-pasted four times in `engine.rs`. ADR 0009's socket ID used `DefaultHasher`, which is not stable across Rust versions, and keyed on process name, so two Python scripts were one service. The UI ADRs (0019-0024) describe components for concepts that no longer exist.

## Decision

Six nouns replace the old model:

| Noun | Meaning | Replaces |
|---|---|---|
| **App** | A program. Key: SHA-256 of `exe_path`; for known interpreters and hosts (python, node, java, dotnet, ruby, svchost, ...) also the normalized script or service argument. Falls back to `process_name`. Cmdline is captured on all platforms. | `socket_id`, grouping by process name |
| **Network** | User-facing name for an instance of a pluggable network (ADR 0037): Local (ULA), LAN (SLAAC/DHCPv6), Yggdrasil, Tor (onion), later WireGuard | Backend instance as shown to users |
| **Address** | (app, network, port set, locator). The locator is network-specific: an IPv6 address (stored as interface ID) on IP networks, a `.onion` name on Tor | `SocketAddress`, `SocketGroupAddress`, socket groups |
| **Peer** | A label plus credentials (ADR 0028) | Raw `allowed_ip` strings |
| **Peer group** | A named set of peers | ACL groups |
| **Grant** | (app [+port] [+network], subject = peer, peer group or Anyone) | The `Policy` enum |

- **Grants, not policies.** No grants means closed; a grant to Anyone means open and needs confirmation in both frontends. There is no inactive or disabled state.
- **D1, one address mechanism.** An address belongs to one app on one network and serves a set of that app's ports. A global setting picks the default for new apps: one address per app, or one per port. In either mode the user can split a port onto its own address or merge ports onto one. There is no separate group concept.
- **Local means "this machine only".** The ULA prefix is a random `fd00::/8` /48 private to this host and never advertised, and `iif lo` is always allowed (ADR 0026), so grants on Local would have no effect. The API rejects them with 400 and a message saying Local is this machine only, and frontends show Local addresses without a grant list. ULA sits on loopback by default; if a user puts the ULA network on a LAN interface, it behaves like any IP network and grants apply.
- **Networks are pluggable, the model is not IPv6-only.** Each network kind implements the `Network` trait (ADR 0037): it creates and removes locators and enforces grants for the credential types it understands. IP networks enforce through the shared firewall seam (ADR 0029); Tor through its control port.
- **Address stability.** On IP networks the interface ID is stored. When a prefix changes, the address is rebuilt from the new prefix and the same interface ID. Grants reference apps, not addresses, so they are unaffected. On Tor the stored service key keeps the `.onion` name stable.
- **Apps are persistent records.** ADR 0007's stale-socket deletion no longer deletes apps, since that would drop their grants. An app's addresses persist while its App record exists, whether or not it is listening; they stay inside the protected scope, so nothing is reachable without a grant. They are removed only by an explicit `apps rm` or by `disable`. There is no automatic expiry.
- **D2, clean break.** Schema v1: apps, addresses (+ ports), peers, peer_credentials, peer_groups (+ members), grants, settings, plus the activity table (ADR 0034). Versioned with `PRAGMA user_version`. An old database is renamed to `socketguard.db.pre-v1`; there is no migration code.
- **One producer** turns this model into the desired firewall state (ADR 0029).

## Consequences

- Fewer concepts: groups of sockets become address port sets, groups of sources become peer groups.
- App identity survives restarts, toolchain upgrades and PID changes, and separates interpreter-hosted services.
- Upgrading drops existing sockets, ACLs and groups; the old DB is kept for reference only.
- Interpreter detection needs a maintained list of known hosts and per-host argument normalization.

## Amendment (2026-11-09): identity cannot be forged by a local process

A review showed that an unprivileged process could pick an identity it should not have (and so inherit the grants of a trusted app, getting its port served on that app's address). Everything the process controls is now treated as hostile. Identity is still upgrade-stable: it is derived from the path of the executable, never from its inode or content, and an upgrade that replaces the binary keeps the id.

The id is the first 32 hex characters (128 bits; see the second review below) of SHA-256 over: the normalized executable path, what the interpreter runs, the owning user, and markers. Markers are folded into the hash, so a process that triggers one can never produce the id of a process that does not.

- **Owning user.** The effective uid on Linux (`/proc/<pid>/status`) and macOS, the owner SID on Windows. The same binary under another user is another app.
- **Interpreter arguments.** Per-interpreter option tables (python, node, bun, deno, ruby, perl, php, java, dotnet) know which options take a value, so an option value is never mistaken for the script. `--opt=value` and attached short forms (`-Wignore`, `-e'code'`) are understood.
  - Code on the command line (`-c`, `-e`, `--eval`, `-p`, php `-r`, ...) or a script on stdin: marker `inline`, no script argument.
  - An option the table does not know precedes the first plain argument, an `@argfile` (java), or the command line is hidden: marker `ambiguous`; the identity includes a hash of the whole argument vector, so it matches neither the clean script form nor any other command line.
  - The kind of target (script, module, jar, class, dll, service) is part of the identity, so `python -m foo` and `python foo` differ.
- **Missing executable path.** The process name is spoofable (`prctl`, `exec -a`), so the identity uses marker `noexe` plus the name and the uid.
- **Foreign mount namespace (Linux).** If `/proc/<pid>/ns/mnt` differs from the daemon's (or either cannot be read), `/proc/<pid>/exe` may be a bind mount that names a trusted path. Marker `foreign-mntns`. The namespace inode is not used, so the identity stays stable across restarts.
- **Unattributable sockets** (no owning process, pid 0, or process names that cannot be resolved) get no app and no addresses; the first one is logged at debug level. A socket held by several processes with different executable or uid is skipped as ambiguous; with the same executable and uid any holder will do.

`App.identity_note` carries the reason (`inline code`, `unrecognized arguments`, `no executable path`, `foreign mount namespace`) for the CLI and UI. Schema v3 stores it.

**Consequence for existing installs:** the uid and the new hash layout re-key every app. Apps from a v2 database stay as inert records; their programs reappear as new, pending apps and need their grants again. The migration cannot recompute ids because the uid was never stored.

## Amendment (second security review): wider ids, relative paths resolved

- **128-bit ids.** The id is now 32 hex characters (the hash input is prefixed `v4`). 64 bits made a chosen-prefix collision between a hostile program's identity and a trusted app's feasible for an attacker with a few GPU-days. This re-keys every app again: they reappear as new, pending apps and need their grants again. Accepted before release.
- **Relative script paths are resolved against the process's working directory.** `ListeningSocket.cwd` carries it (`/proc/<pid>/cwd` on Linux, sysinfo `cwd()` on Windows and macOS). A relative script, jar or dll path (`node server.js`) is joined to it and `.` / `..` components are folded lexically, so the same relative name in two directories is two apps and `node server.js` in `/srv/a` is the same app as `node /srv/a/server.js`. The display name and `interpreter_arg` stay as given. Windows treats only `X:\...` and UNC paths as absolute; `\dir` is relative to the current drive.
- **Unknown working directory.** If the cwd cannot be read (or is not absolute) for a relative path, the marker `ambiguous-cwd` is folded into the hash (identity note "relative path, working directory unknown"), so it never merges with the absolute form. The marker is named `ambiguous-cwd`, not `ambiguous`, to stay apart from the `ambiguous` argument-vector tag above.
