# ADR 0052: SocketGuard Ships and Runs Its Own Tor and Yggdrasil

## Status

Accepted. Supersedes the install and configure steps of ADR 0048 (detection and the zero-input add stay). Builds on ADR 0040, 0050 and 0051.

## Date

2026-11-11

## Context

ADR 0048 made a network one click when its software was already there, and otherwise installed it through a package manager and edited its configuration. That touched system-wide installs, could not cover Tor on Windows (no package, and the cookie path is an administrator setting), and left windows in which a freshly installed node was open (ADR 0051). The owner wants networks to work without installing anything and without touching what is already installed.

Facts established for this decision (2026-11-11):

- Two Yggdrasil nodes in one network namespace do not work as they are: each adapter claims `200::/7`, replies of the second node leave through the first and are dropped. Source-based policy routing fixes it on Linux; Windows and macOS are untested.
- Yggdrasil publishes installers only (deb, pkg, msi), no bare binaries; it builds from a tag with `./build` and Go. It is LGPLv3 with an exception for combined works; unmodified binaries run as a separate process need the licence text and the source made available. On Windows it needs `wintun.dll`, whose licence allows shipping the unmodified DLL alongside software that uses its API; its driver is shared system-wide with other Wintun users.
- The Tor Project publishes the Tor Expert Bundle per system with signed checksums (Windows x86_64, Linux x86_64 and aarch64, macOS x86_64 and aarch64). Tor is 3-clause BSD; the bundle carries the notices of Tor, libevent, OpenSSL and zlib.
- Tor can be owned by the process that starts it (`__OwningControllerProcess`, `TAKEOWNERSHIP`), pick its control port (`ControlPort auto`, `ControlPortWriteToFile`) and write its cookie where it is told (`CookieAuthFile`).

## Decision

- **Managed networks.** A Tor or Yggdrasil network can be `managed`: SocketGuard runs its own copy as a child process with its own data directory, ports and adapter, under its state directory. It is the default when a network is added. A managed network needs no input and no administrator settings, so any member of the access group may add one.
- **Existing software, as it is.** A system-wide node that is detected and usable without changes can be added instead ("use my existing one"). SocketGuard never installs, starts, stops or reconfigures software it did not ship. The `networks setup` command, its package and `torrc` steps and its undo are removed; the install record of ADR 0050 stays.
- **Where the binaries come from.** Versions, download locations and checksums are pinned in one file in the repository. The release build fetches the Tor Expert Bundle and verifies it against the signed checksum file with the Tor Project's key pinned by fingerprint; it builds Yggdrasil from the pinned tag and takes `wintun.dll` from wintun.net by checksum. Nothing is downloaded at install time or at runtime. The files are shipped in the installer's directory, not embedded in SocketGuard's binaries, with their licence texts; the source of the Yggdrasil build is linked from the release.
- **What is shipped.** For Tor: the `tor` binary and the libraries it needs, no pluggable transports. For Yggdrasil: the `yggdrasil` binary and on Windows `wintun.dll`; SocketGuard speaks the admin protocol itself. Systems: Windows x86_64, Linux and macOS x86_64 and aarch64. A build without the files says so on the network card.
- **Tor child.** Started with a generated `torrc`: its own data directory, no SOCKS port, a control endpoint only SocketGuard can reach (a Unix socket in a protected directory; on Windows a loopback port chosen by Tor and written to a protected file), cookie authentication with the cookie file at a path SocketGuard chose. The path comes from SocketGuard's own configuration, never from the wire, which is what ADR 0040 requires. Tor exits when the daemon does.
- **Yggdrasil child.** SocketGuard generates the node key, so the node's address and subnet are known before the process exists; the block of ADR 0051 is applied and verified first. Its configuration is generated: own adapter name, no admin endpoint that other local users can reach, Yggdrasil's defaults for discovery, and the peers the user entered. The key is part of SocketGuard's state.
- **One Yggdrasil node per host for now.** A managed Yggdrasil network is not started while another node runs on the host, and says why. Policy routing for a second node is left for later.
- **Privileges.** Children run with as little as the system allows: Tor as an unprivileged account (a dedicated system account on Linux and macOS, LocalService on Windows); Yggdrasil drops to that account after creating its adapter where it can (not on Windows). What cannot be dropped is stated in `docs/footprint.md`.
- **Lifecycle.** A child starts only when its network is enabled and its block is in force, is restarted when it dies, and stops when SocketGuard is turned off, the network is removed or the daemon stops. A managed network therefore has no exposure on leaving.
- **Footprint.** Data directories of the children are "owned directories" in the install record: kept on an uninstall that keeps data (they hold the node key and Tor's state), removed on purge. The Wintun driver is shared: SocketGuard records whether it was present before, and on purge removes it only if it was not and nothing else uses it.
- **Versions** of the shipped Tor and Yggdrasil are shown in `status`.

## Consequences

- Tor and Yggdrasil work on all three systems with one click and nothing to install; Tor on Windows needs no configuration file.
- SocketGuard's releases now carry third-party security updates: a Tor or Yggdrasil fix needs a SocketGuard release. The pinned file makes the update a one-line change, and the release notes name the versions.
- A managed Yggdrasil node is a new identity; it does not share the key of a node the user already runs, and the two cannot run at the same time yet.
- Installers grow by roughly 15 to 25 MB.
- Without pluggable transports the managed Tor cannot use bridges.
- The package-install flow of ADR 0048 lasted one day; its detection and cards remain.

## Amendment (2026-11-12): trust in the pid file, the account decision, the child guard

- **Pid files are the daemon's alone.** A child's pid and start time are kept in `<state dir>/run/<network id>.pid` (a directory only the daemon can write), never in a directory a child owns: a compromised child could otherwise have made the daemon, running as root, end any process at the next start. A leftover is ended only when its start time and its executable path both match what the daemon started.
- **The account is decided once, before anything depends on it.** On Windows the daemon tries the LocalService logon first; on failure the child runs as the daemon's account, and the data-directory ACL, the expected owner of the cookie and the status all follow that answer.
- **Unix: `child-guard`.** `-user` clears the parent-death signal, so Yggdrasil is started through `socketguard-daemon child-guard -- <program> <args>`: a root parent that holds the daemon's pipe as its stdin and ends the program when the pipe closes (the daemon died, `kill -9` included) or its parent changes. The pid file names the guard, whose executable is the daemon's.
- **A node that never answers on its admin socket** is restarted without one after a deadline (20 s), so a network does not stay "starting"; its card then says peer information is unavailable.
## Amendment (2026-11-12): what the implementation showed

- **How Tor is tied to the daemon.** Not through `TAKEOWNERSHIP`: that ties Tor to one control connection, and SocketGuard's are short. Tor is started with `__OwningControllerProcess` and, per system, a job object or the parent-death signal.
- **Dropping privileges** is done by the daemon before it starts the child, not by a `User` line in Tor's configuration.
- **Yggdrasil on Linux and macOS can outlive a killed daemon**, because dropping privileges clears the parent-death link. The rules stay in force, and the next start ends the leftover process. Closing this gap is wanted; until then it is listed in `docs/footprint.md`.
- **The signing key** that is pinned is the Tor Browser Developers primary key; the fingerprint on the signatures is its subkey.
- **No location database** is shipped: Tor bootstraps and serves onion services without it.

## Amendment (2026-11-12): bridges for the managed Tor; a link to public Yggdrasil peers

- **Bridges.** The obfs4 transport helper from the same verified Tor bundle is shipped. Bridges are off by default. The user pastes bridge lines obtained from the Tor Project into the managed Tor network's settings; SocketGuard ships no bridge list and fetches none. A bridge line is accepted only if it has the form of a bridge line for a shipped transport; it can never add another option to Tor's configuration (ADR 0040).
- **Public peers.** Next to the peers of a managed Yggdrasil network there is a link to the project's public peers page. SocketGuard does not fetch or ship a list, and adds no peer on its own.
