# What SocketGuard puts on a host, and what removes it

The rule: everything SocketGuard creates has a named removal path, and removing SocketGuard leaves nothing behind. This file is the map. A row marked **gap** breaks the rule today.

Stopping the daemon removes nothing on purpose: rules and addresses stay so the host fails closed (ADR 0026, ADR 0030). Removal is always explicit: `disable` (API, CLI, `socketguard-daemon --disable`) or, once it exists, uninstall.

## Firewall

| Item | System | Survives stop / reboot | Removed by | How to check |
|---|---|---|---|---|
| WFP provider `{534F434B-4755-4152-4400-000000000001}`, sublayer `…0002`, filters named "SocketGuard …" (persistent) | Windows | yes / yes | disable | `netsh wfp show filters`, search for `534f434b` |
| Engine option `FWPM_ENGINE_COLLECT_NET_EVENTS = 1` | Windows | yes / unknown | **gap: nothing resets it** | |
| `table inet socketguard` with counters, NFLOG group 7 | Linux | yes / no | disable | `nft list table inet socketguard` |
| Legacy `table ip6 socketguard` | Linux | yes / no | only the next apply, **gap: not disable** | |
| pf anchor `socketguard` | macOS | yes / no | disable (`pfctl -a socketguard -F all`) | `pfctl -a socketguard -sr` |
| `anchor "socketguard"` in `/etc/pf.conf`, pf enabled | macOS | yes / yes | **gap: set up by hand, nothing undoes it** | |

No Windows Firewall rules, iptables rules or rule files on disk are created.

## Addresses

| Item | System | Survives stop / reboot | Removed by | How to check |
|---|---|---|---|---|
| `/128` IPv6 addresses on interfaces (Local ULA on loopback, LAN, Yggdrasil, DHCPv6), tracked in `owned_addresses` | all | yes / Linux and macOS no, Windows unknown | disable, forgetting an app, removing a network, releasing a reservation, the sweep at start | `ip -6 addr`, `ifconfig`, `Get-NetIPAddress -AddressFamily IPv6` |
| Addresses of a network that is no longer configured | all | yes | **gap: "cannot remove"** | |
| Addresses when the database was lost or replaced | all | yes | **gap: never found** | |
| DHCPv6 leases on the server (a new client id at every start) | all | yes / yes | **gap: a release is never sent** | the server's lease table |

No routes, sysctls or registry values are changed.

## Tor and Yggdrasil

| Item | Survives stop / reboot | Removed by |
|---|---|---|
| Onion services created with `ADD_ONION … Detach` (in Tor's memory) | yes / until Tor restarts | `DEL_ONION` on disable, forgetting an app, removing the network |
| Services known only to the ledger or tombstones | yes | a running daemon only; **gap: `--disable` misses them and reports success when Tor is down** |
| Onion service keys and generated client keys in the database | yes | deleted with their rows; otherwise with the database |
| Yggdrasil | nothing is changed in the node or its configuration | |

## Files

| Item | Where | Removed by |
|---|---|---|
| Database `socketguard.db` (keys, ledger, settings), `-wal`, `-shm` | `db_path`, default: the daemon's working directory | **gap: nothing** |
| Archived old databases `<db>.pre-v1[.N]` | next to the database | **gap: nothing** |
| Config `socketguard.json`, written when a network is added or removed | `SOCKETGUARD_CONFIG` or the working directory | **gap: nothing** |
| Temp file `socketguard.tmp-<pid>-<uuid>` | next to the config | removed on error; **gap: left after a crash** |
| Unix socket `/run/socketguard.sock` | | graceful stop; replaced at start |
| Named pipe `\\.\pipe\socketguard` | Windows | process exit |
| UI storage: webview profile of `com.socketguard.desktop`, localStorage `socketguard.columns` | per user | **gap: nothing** |

No log, PID or lock files are written. Telemetry is exported only when the `OTEL_*` variables are set.

## System integration

| Item | State |
|---|---|
| Groups `socketguard` (Unix), `SocketGuard Users` (Windows) | expected, created by hand; **gap: no removal** |
| systemd unit, `/var/lib/socketguard` | installed by hand; **gap: no uninstall** |
| Windows service, launchd service, installer | do not exist |
| Registry keys, scheduled tasks, autostart entries, environment variables | none |

## Network setup (ADR 0048, being built)

| Item | Removal |
|---|---|
| Packages installed through the package manager (Yggdrasil, Tor) | **gap: no undo specified** |
| Services started | **gap** |
| Lines added to Tor's `torrc`, with a backup copy | **gap** |
| Tor network entry in the config file | removing the network |

## Failures of the removal paths themselves

- **`--disable` from the wrong directory.** Config and database default to the working directory. Run elsewhere, it creates an empty database, finds no addresses, and still deletes the firewall rules: the real addresses stay on the interfaces with nothing denying them, and the real database is not marked disabled.
- **Partial disable keeps the rules.** If one address cannot be removed, the rules stay and only a running daemon retries.
- **`--disable` can abort early** when the Tor settings in the config do not validate, before anything is removed.
- **No Windows test.** CI has no Windows job; the WFP removal has never been checked by a test.

## What closes the gaps

1. Fixed, absolute locations for the database and config per system, so every tool finds the same state.
2. `disable` that does not depend on the database: remove by name (provider, table, anchor) and by the address ledger, refuse when it cannot find the state it would need, and report truthfully what was and was not removed.
3. `purge`/uninstall: disable, then delete database, archives, config, socket directory, UI storage, groups, service units, the pf anchor line, and reset the WFP engine option; undo what network setup changed (torrc lines from the backup; offer to uninstall packages it installed, recorded in a setup log).
4. DHCPv6: a stable client id and a release when an address is given up.
5. A check that proves it: after `purge`, list every item in this file from outside and find none. Run it in CI on Linux and macOS and in a Windows job.
