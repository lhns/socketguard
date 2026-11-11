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

## Network setup (ADR 0048)

Everything `socketguard networks setup` changes is recorded in `setup-log.json` next to the config file and reversed by `socketguard networks setup <kind> --undo`.

| Item | Removal |
|---|---|
| Packages it installed through the package manager (never ones that were already there) | `--undo --uninstall-packages`; plain `--undo` only prints the command |
| Services it started or enabled | `--undo` restores the previous state; `--undo --stop-service-only` stops only the service and keeps the network and its block |
| Lines appended to Tor's `torrc` (a one-time `.socketguard.bak` is kept) | `--undo` removes exactly those lines; **gap: the backup file stays** |
| Tor network entry in the config file | `--undo`, or removing the network |
| `setup-log.json` | **gap: nothing deletes it** |

## Windows of exposure (ADR 0051)

The invariant: a network SocketGuard adds, installs or manages never makes the host reachable outside its rules, at any moment. Each case, and whether it is closed.

| Case | State | By what, or why open |
|---|---|---|
| Yggdrasil installed by someone else and running, before it is added | **open, by design** | Not a network SocketGuard manages yet. The network card says so ("Yggdrasil is running but not managed", `exposed` in `GET /api/networks/setup`). |
| Between starting the node and the network being added | closed | `networks setup yggdrasil` adds the network first and starts nothing until the block is verified (`yggdrasil_block` in `GET /api/networks/setup`). It installs nothing. |
| Setup stops half way | closed | The network and its block stay; the message says so and how to undo. Running setup again says "already a network; nothing to do": start the service by hand or undo. |
| Network added before the node was ever seen | closed on the interface only, if the interface exists (WFP) or is named (nftables, pf) | Its address is unknown, so only the interface is closed: setup names the adapter (Windows: `Yggdrasil`) or refuses to start the service. `closed` is false with the reason until the node answers once. |
| Node stopped, restarted, adapter missing, renamed or recreated | closed | The node's own `/128` and `/64` are denied as destinations on any interface (`overlay:<network>:addr`, `:subnet`), remembered in the settings table (`ygg_node:<network>`) from the first time they are known. |
| A second node, not managed by SocketGuard, on the same host | untouched | Only the managed node's addresses are denied. |
| Network removed, "turn off", uninstall while the node keeps running | **open, by choice** | The block is removed with them. `GET /api/exposure` is shown first, with the programs that become reachable and an offer to stop the service setup started. Removing a running node's network needs `confirm_exposed` (CLI `--yes`). |
| Linux: boot before the daemon applies its ruleset | partly closed | `Before=network-pre.target`, `Wants=network-pre.target` and `Before=yggdrasil.service` order the daemon first, but `Type=simple` orders on process start, not on the first apply; the rules are in force a moment later. The remembered node addresses are applied in that first ruleset. |
| macOS: boot before the anchor is loaded | **open** | No launchd service exists yet; nothing orders the node after SocketGuard, and pf rules do not survive a reboot. |
| Windows: boot | closed | WFP filters are persistent. |
| Tor, LAN, SLAAC, DHCPv6 | nothing to close | Tor adds a control port on loopback with cookie authentication only and exposes nothing inbound before SocketGuard publishes a service. SocketGuard's own LAN addresses are denied before they are added (the ruleset covers an address before it goes on an interface). |
| Windows: node first seen, adapter appears before the next pass | **open, short** | WFP binds filters to an adapter's LUID, so no filter exists for an adapter that does not exist. The address block covers the node once its address is known; until then (and for non-Yggdrasil traffic on that adapter) the window lasts from the adapter's creation to the next reconcile and `interfaces_changed` re-apply. `yggdrasil_block.interface_blocked` is therefore false on Windows for a missing adapter, and setup refuses to start the service on that basis. |

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
