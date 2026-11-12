# ADR 0050: Installed as a Service, with Fixed Paths and an Uninstall That Leaves Nothing

## Status

Accepted. Fulfils the uninstaller that ADR 0026 names as a release blocker. Changes where ADR 0038's config file lives by default.

## Date

2026-11-11

## Context

`docs/footprint.md` lists what SocketGuard puts on a host. Several items have no removal path (database, config, groups, service unit, the pf anchor line, a WFP engine option, DHCPv6 leases), and the removal that exists is unsafe: config and database default to the working directory, so `--disable` run elsewhere finds an empty state, deletes the rules and leaves the addresses unprotected. There is no installer, and outside Linux no service, so the daemon is started by hand and a frontend needs administrator rights.

## Decision

- **Fixed locations.** Config and database live in one system directory per platform (Windows `%ProgramData%\SocketGuard`, Linux `/etc/socketguard` and `/var/lib/socketguard`, macOS `/Library/Application Support/SocketGuard`). `SOCKETGUARD_CONFIG` and `db_path` still override. Nothing defaults to the working directory any more. A daemon that finds state in the old place moves it once and says so.
- **Every install and removal action is a command of the daemon binary** (`service install|uninstall|start|stop`, `uninstall`). Packages only call these commands, so the logic is tested in one place.
- **Service.** A Windows service, a systemd unit and a launchd daemon, started with the system. Stopping the service removes nothing (ADR 0026).
- **Install record.** Install writes what it found and what it created (group existed or not, pf anchor line and pf state, the WFP engine option's prior value) to the same log network setup uses. Removal reverses exactly that record and nothing else.
- **Disable is safe.** It opens the existing database and never creates one. Without it, it refuses; `--force` removes what can be found by name (provider, table, anchor) and reports what it could not check. It includes services known only to the Tor ledger, and it reports truthfully and exits non-zero when something is left.
- **Uninstall** = stop the service, refuse if a daemon still answers, disable, undo the install record and the network setup log, remove the service and, where it created them, the groups. It keeps the database and config unless told otherwise: asked when a person runs it, kept when run silently, deleted by `--purge` (and by `apt purge`). Before deleting it offers an export, because the database holds the onion keys. It deletes named files only, never a directory tree it did not create.
- **An upgrade is not an uninstall.** Package scripts must tell the two apart; disable and purge never run on an upgrade.
- **Access.** A group (`SocketGuard Users` on Windows, `socketguard` elsewhere) may use the API without administrator rights. The Windows installer offers to add the installing account; Linux and macOS packages add nobody, and the frontends offer "allow my account" with elevation.
- **DHCPv6.** The client identifier is stored and stable, and an address that is given up is released to the server.
- **Packages.** A WiX MSI for Windows, deb and rpm for Linux, a pkg for macOS, built by a release workflow. Unsigned for now; signing is added by providing certificates.
- **Proof.** After uninstall with purge, a check looks for every item in `docs/footprint.md` from outside and must find none. It runs in CI for each package.

## Consequences

- A frontend connects to a running service without elevation; the test wrapper around the daemon is no longer needed.
- Uninstalling from a package manager keeps settings and keys; removing them is a separate, explicit step.
- Unsigned installers show a warning on Windows and are blocked by default on macOS until signing is set up.
- Linux and macOS installers are verified only in CI.
- Existing hand-started installations change location once.

## Amendment (2026-11-11): details settled while building it

- **Install record.** The log of ADR 0048 is one list of typed, reversible entries in `crates/core/src/install_log.rs`, shared by the daemon binary and the CLI. Install adds `service_registered`, `access_group` (created or existed), `directory_created`, `pf_anchor` and `wfp_engine_option`; entries are written when the thing happens and are never overwritten by a second run.
- **Owned directories.** When SocketGuard later runs Tor or Yggdrasil itself, the data directory it creates for that child process is recorded as `owned_directory`. `uninstall --purge` may remove such a directory as a tree, but only if its path is strictly inside the state directory; a recorded path outside it is refused and reported. A keep-data uninstall leaves it. Every other deletion is by name.
- **Disable reports per item** (`removed`, `already absent`, `kept`, `LEFT` with the reason) and exits non-zero when anything is LEFT. `--disable` needs the database at the resolved path and refuses, changing nothing, when it is missing; a missing config file alone only produces a note. `--disable --force` removes the rules by name.
- **Exit codes** of the daemon commands: 0 done, 1 something failed or is LEFT, 2 usage error.

## Amendment (2026-11-12): what the first real installs showed

- **macOS socket.** The default API socket on macOS is `/var/run/socketguard.sock`; `/run` does not exist there.
- **An upgrade restarts the daemon** onto the new binary on every system; `service install` does that when the service is already present.
- **The state directory's protection is inherited** by the files created in it on Windows, so the administrator who uninstalls can read what the service wrote.
- **Packages pass the choice explicitly:** removal calls `uninstall --keep-data`, and only `apt purge` or `uninstall --purge` deletes data.
- **Verified by CI on real machines:** MSI on Windows Server, deb on Ubuntu, pkg on macOS (Apple Silicon). The rpm is only built and checked; its service steps have not run.
