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
| Unix socket `/run/socketguard.sock` (macOS `/var/run/socketguard.sock`) | | graceful stop; `uninstall --purge` |
| Named pipe `\\.\pipe\socketguard` | Windows | process exit |
| UI storage: webview profile of `com.socketguard.desktop`, localStorage `socketguard.columns` | per user | the UI's "Remove SocketGuard" flow clears the signed-in user's own storage. **Gap:** the profiles of other users on the machine cannot be removed by an elevated system command; they stay under each user's profile (paths below) |

Per-user UI storage (the webview profile of `com.socketguard.desktop`; the UI's "Remove SocketGuard" flow empties the signed-in user's profile through `clear_local_ui_settings`, which leaves the empty folder): Windows `%LOCALAPPDATA%\com.socketguard.desktop\EBWebView`; Linux `~/.local/share/com.socketguard.desktop`; macOS `~/Library/WebKit/com.socketguard.desktop` and `~/Library/Caches/com.socketguard.desktop` (the Linux and macOS paths come from the webview defaults and are not verified).

No log or PID files are written. Telemetry is exported only when the `OTEL_*` variables are set.

## System integration

| Item | State |
|---|---|
| Group `socketguard` (Unix), `SocketGuard Users` (Windows) | created by `service install` / `access group ensure` if missing; `uninstall` removes it only if the install record says SocketGuard created it, never one that existed before. Members are added with `access allow` |
| Windows service `SocketGuard` (auto start, LocalSystem, restart on failure) | `service install`; removed by `service uninstall` and `uninstall` |
| systemd unit `/etc/systemd/system/socketguard.service` | `service install`; removed by `service uninstall` and `uninstall` |
| launchd daemon `/Library/LaunchDaemons/de.lhns.socketguard.plist` | `service install`; removed by `service uninstall` and `uninstall` |
| Registry keys, scheduled tasks, autostart entries, environment variables | none |

## Package files (ADR 0050, docs/packaging.md)

What the installers put on a host besides the items above, and who removes it. The rule for the
data above (kept on remove, deleted on purge) applies to every package.

| Item | System | Removed by |
|---|---|---|
| `C:\Program Files\SocketGuard\` (three exes, `third_party\`), the folder on the system `PATH` (`Software\lhns\SocketGuard` marker keys), Start menu shortcut `SocketGuard`, Add/Remove Programs entry, Windows Installer cache | Windows | the MSI (Apps & features, `msiexec /x`); the MSI never touches the data |
| `/usr/bin/{socketguard-daemon,socketguard,socketguard-ui}`, `/usr/share/applications/socketguard.desktop`, the icon, `/usr/share/doc/socketguard/`, `/usr/lib/socketguard/third_party/`, the dpkg or rpm database entry | Linux | `apt remove` / `dnf remove`; `apt purge` also deletes the data by name (rpm: `uninstall --purge` first) |
| `/usr/local/bin/{socketguard-daemon,socketguard}`, `/Applications/SocketGuard.app`, `/usr/local/lib/socketguard/`, the package receipt `de.lhns.socketguard` | macOS | **gap by nature of a pkg:** `uninstall` removes everything else; these are deleted by hand and `pkgutil --forget` (documented in the README); the CI test does it and checks the rest |

## Network setup (ADR 0048)

Everything `socketguard networks setup` changes is recorded in `setup-log.json` next to the config file and reversed by `socketguard networks setup <kind> --undo`, or by `socketguard-daemon uninstall` (which never uninstalls packages; it prints the command).

| Item | Removal |
|---|---|
| Packages it installed through the package manager (never ones that were already there) | `--undo --uninstall-packages`; plain `--undo` and `uninstall` only print the command |
| Services it started or enabled | `--undo` / `uninstall` restores the previous state; `--undo --stop-service-only` stops only the service and keeps the network and its block |
| Lines appended to Tor's `torrc` and the one-time `.socketguard.bak` | `--undo` / `uninstall` removes exactly those lines and the backup |
| Tor network entry in the config file | `--undo`, `uninstall`, or removing the network |
| `setup-log.json` | `uninstall --purge` |

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

- **`--disable` from the wrong directory** can no longer happen: config and database have fixed locations. If the database is not at the resolved location, `--disable` refuses, names the paths it looked at, exits non-zero and changes nothing.
- **Partial disable keeps the rules.** If one address cannot be removed, the rules stay (fail closed), the command says which addresses are left and exits non-zero; a running daemon retries.
- **An invalid Tor network no longer aborts `--disable`:** the other networks are processed and the Tor services are reported as LEFT.
- **The removal paths run for real in CI** (`.github/workflows/packages.yml`, ADR 0050): the MSI job installs, grants a port range through WFP, upgrades, removes and purges on a Windows runner, the deb job does the same with nftables on an Ubuntu VM with systemd, the pkg job with pf and launchd on macOS, and each ends with `deploy/ci/footprint-check.*` looking from outside. Not covered: the engine option `FWPM_ENGINE_COLLECT_NET_EVENTS` (not readable from outside; net events are collected, which shows it is set), the rpm service steps (CI only installs it in a container without systemd) and other users' webview profiles.
