# What SocketGuard puts on a host, and what removes it

The rule: everything SocketGuard creates has a named removal path, and removing SocketGuard leaves nothing behind. This file is the map. A row marked **gap** breaks the rule today; the other rows name the command that removes the item (ADR 0050).

Stopping the daemon removes nothing on purpose: rules and addresses stay so the host fails closed (ADR 0026, ADR 0030). Removal is always explicit: `disable` (API, CLI, `socketguard-daemon --disable`) or `socketguard-daemon uninstall`.

`socketguard-daemon uninstall` stops the service, disables (refusing to go on while something is LEFT, unless `--force`), reverses the install record in `setup-log.json` newest first, removes the service, and, only on request (`--purge`, or "yes" to the question it asks on a terminal), deletes the data files by name. It prints per item *removed*, *already absent*, *kept* or *LEFT* and exits non-zero if anything it owns is LEFT. `deploy/ci/footprint-check.{sh,ps1}` checks the list below from outside.

## Firewall

| Item | System | Survives stop / reboot | Removed by | How to check |
|---|---|---|---|---|
| WFP provider `{534F434B-4755-4152-4400-000000000001}`, sublayer `…0002`, filters named "SocketGuard …" (persistent) | Windows | yes / yes | `--disable`, `--disable --force` (by name, without the database), `uninstall` | `netsh wfp show filters`, search for `534f434b` |
| Engine option `FWPM_ENGINE_COLLECT_NET_EVENTS = 1` | Windows | yes / unknown | `uninstall` sets it back to the value the daemon found (recorded once, before it first set it); not reset by a plain disable. Gap: not checkable from outside | |
| `table inet socketguard` with counters, NFLOG group 7 | Linux | yes / no | `--disable`, `--disable --force`, `uninstall` | `nft list table inet socketguard` |
| Legacy `table ip6 socketguard` | Linux | yes / no | `--disable` and `--disable --force` (also deleted), `uninstall` | `nft list table ip6 socketguard` |
| pf anchor `socketguard` | macOS | yes / no | `--disable`, `--disable --force`, `uninstall` (`pfctl -a socketguard -F all`) | `pfctl -a socketguard -sr` |
| `anchor "socketguard"` in `/etc/pf.conf`, pf enabled | macOS | yes / yes | added by `service install` only if missing and recorded; `uninstall` removes the line only if it added it and disables pf only if it enabled it | `grep socketguard /etc/pf.conf`, `pfctl -s info` |

No Windows Firewall rules, iptables rules or rule files on disk are created.

## Addresses

| Item | System | Survives stop / reboot | Removed by | How to check |
|---|---|---|---|---|
| `/128` IPv6 addresses on interfaces (Local ULA on loopback, LAN, Yggdrasil, DHCPv6), tracked in `owned_addresses` | all | yes / Linux and macOS no, Windows unknown | `--disable`, `uninstall`, forgetting an app, removing a network, releasing a reservation, the sweep at start | `ip -6 addr`, `ifconfig`, `Get-NetIPAddress -AddressFamily IPv6` |
| Addresses of a network that is no longer configured | all | yes | the owned-address table records the interface, so `--disable` removes them too; a stuck one is reported as LEFT and keeps the rules |  |
| Addresses when the database was lost or replaced | all | yes | **gap:** never found. `--disable` without the database refuses; `--disable --force` removes the rules by name and says addresses could not be checked | |
| DHCPv6 leases on the server | all | yes / yes | a RELEASE is sent when an address is given up (retired, removed, disable, uninstall), using the stored client id and lease record. **Gap:** a lease stays until it expires when the server is unreachable or the release is lost | the server's lease table |

No routes, sysctls or registry values are changed.

## Tor and Yggdrasil

| Item | Survives stop / reboot | Removed by |
|---|---|---|
| Onion services created with `ADD_ONION … Detach` (in Tor's memory) | yes / until Tor restarts | `DEL_ONION` on disable, uninstall, forgetting an app, removing the network |
| Services known only to the ledger (`tor_owned_services`) or tombstones | yes | `--disable` and `uninstall` remove them too. With Tor unreachable they are listed as LEFT and the command exits non-zero |
| Onion service keys and generated client keys in the database | yes | deleted with their rows; otherwise with the database (`uninstall --purge`). The export does not contain onion private keys |
| Yggdrasil | nothing is changed in the node or its configuration | |

## Files

Default locations (ADR 0050): Windows `%ProgramData%\SocketGuard`, Linux `/etc/socketguard` (config, setup log) and `/var/lib/socketguard` (database), macOS `/Library/Application Support/SocketGuard`. `SOCKETGUARD_CONFIG` and `db_path` override. Nothing is written to the working directory.

| Item | Where | Removed by |
|---|---|---|
| Database `socketguard.db` (keys, ledger, settings), `-wal`, `-shm` | `db_path` | `uninstall --purge` |
| Archived old databases `<db>.pre-v1[.N]` | next to the database | `uninstall --purge` |
| Config `socketguard.json`, written when a network is added or removed | `SOCKETGUARD_CONFIG` or the config directory | `uninstall --purge` (with `--keep-data` the Tor entry written by `networks setup` is still removed) |
| Temp file `socketguard.tmp-<pid>-<uuid>` | next to the config | removed on error; left after a crash: `uninstall --purge` |
| Install record and setup log `setup-log.json` | next to the config | `uninstall --purge`; kept (with the entries still to undo) otherwise |
| `.socketguard.bak` backup of Tor's `torrc` | next to the `torrc` | `networks setup tor --undo`, `uninstall` |
| Directories created by SocketGuard | the config and state directories | `uninstall`, only if the install record says SocketGuard created them and they are empty |
| Unix socket `/run/socketguard.sock` | | graceful stop; `uninstall --purge` |
| Named pipe `\\.\pipe\socketguard` | Windows | process exit |
| UI storage: webview profile of `com.socketguard.desktop`, localStorage `socketguard.columns` | per user | the UI's "Remove SocketGuard" flow clears the signed-in user's own storage. **Gap:** the profiles of other users on the machine cannot be removed by an elevated system command; they stay under each user's profile (see the paths in the UI section below) |

No log or PID files are written. Telemetry is exported only when the `OTEL_*` variables are set.

## System integration

| Item | State |
|---|---|
| Group `socketguard` (Unix), `SocketGuard Users` (Windows) | created by `service install` / `access group ensure` if missing; `uninstall` removes it only if the install record says SocketGuard created it, never one that existed before. Members are added with `access allow` |
| Windows service `SocketGuard` (auto start, LocalSystem, restart on failure) | `service install`; removed by `service uninstall` and `uninstall` |
| systemd unit `/etc/systemd/system/socketguard.service` | `service install`; removed by `service uninstall` and `uninstall` |
| launchd daemon `/Library/LaunchDaemons/de.lhns.socketguard.plist` | `service install`; removed by `service uninstall` and `uninstall` |
| Registry keys, scheduled tasks, autostart entries, environment variables | none |

## Network setup (ADR 0048)

Everything `socketguard networks setup` changes is recorded in `setup-log.json` next to the config file and reversed by `socketguard networks setup <kind> --undo`, or by `socketguard-daemon uninstall` (which never uninstalls packages; it prints the command).

| Item | Removal |
|---|---|
| Packages it installed through the package manager (never ones that were already there) | `--undo --uninstall-packages`; plain `--undo` and `uninstall` only print the command |
| Services it started or enabled | `--undo` / `uninstall` restores the previous state |
| Lines appended to Tor's `torrc` and the one-time `.socketguard.bak` | `--undo` / `uninstall` removes exactly those lines and the backup |
| Tor network entry in the config file | `--undo`, `uninstall`, or removing the network |
| `setup-log.json` | `uninstall --purge` |

## Failures of the removal paths themselves

- **`--disable` from the wrong directory** can no longer happen: config and database have fixed locations. If the database is not at the resolved location, `--disable` refuses, names the paths it looked at, exits non-zero and changes nothing.
- **Partial disable keeps the rules.** If one address cannot be removed, the rules stay (fail closed), the command says which addresses are left and exits non-zero; a running daemon retries.
- **An invalid Tor network no longer aborts `--disable`:** the other networks are processed and the Tor services are reported as LEFT.
- **No Windows test of the real WFP removal.** CI has no Windows job; the Windows service, the WFP removal and the engine option are covered by fakes and by the footprint check run after each package. The Linux and macOS service and package steps are verified only in CI.
