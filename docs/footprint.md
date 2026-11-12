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
| An existing Yggdrasil or Tor node ("your own") | nothing is changed in the node or its configuration | |
| SocketGuard's own Tor and Yggdrasil | see "Managed Tor and Yggdrasil" below | |

## Files

Default locations (ADR 0050): Windows `%ProgramData%\SocketGuard`, Linux `/etc/socketguard` (config, setup log) and `/var/lib/socketguard` (database), macOS `/Library/Application Support/SocketGuard`. `SOCKETGUARD_CONFIG` and `db_path` override. Nothing is written to the working directory.

| Item | Where | Removed by |
|---|---|---|
| Database `socketguard.db` (keys, ledger, settings), `-wal`, `-shm` | `db_path` | `uninstall --purge` |
| Archived old databases `<db>.pre-v1[.N]` | next to the database | `uninstall --purge` |
| Config `socketguard.json`, written when a network is added or removed | `SOCKETGUARD_CONFIG` or the config directory | `uninstall --purge` |
| Temp file `socketguard.tmp-<pid>-<uuid>` | next to the config | removed on error; left after a crash: `uninstall --purge` |
| Install record and setup log `setup-log.json` | next to the config | `uninstall --purge`; kept (with the entries still to undo) otherwise |
| Directories created by SocketGuard | the config and state directories | `uninstall`, only if the install record says SocketGuard created them and they are empty |
| Unix socket `/run/socketguard.sock` (macOS `/var/run/socketguard.sock`) | | graceful stop; `uninstall --purge` |
| Named pipe `\\.\pipe\socketguard` | Windows | process exit |
| UI storage: webview profile of `com.socketguard.desktop`, localStorage `socketguard.columns` | per user | the UI's "Remove SocketGuard" flow clears the signed-in user's own storage. **Gap:** the profiles of other users on the machine cannot be removed by an elevated system command; they stay under each user's profile (paths below) |

Per-user UI storage (the webview profile of `com.socketguard.desktop`; the UI's "Remove SocketGuard" flow empties the signed-in user's profile through `clear_local_ui_settings`, which leaves the empty folder): Windows `%LOCALAPPDATA%\com.socketguard.desktop\EBWebView`; Linux `~/.local/share/com.socketguard.desktop`; macOS `~/Library/WebKit/com.socketguard.desktop` and `~/Library/Caches/com.socketguard.desktop` (the Linux and macOS paths come from the webview defaults and are not verified).

No log files are written (children log into the daemon's log). A pid file `<state dir>/run/<network id>.pid` is written for each managed child on Linux and macOS (pid and start time; the directory is created by the daemon, mode 0700, a child's own directories never hold it; the file is mode 0600, written fresh and never through a link, and believed only when a regular file of the daemon's own user in a directory only the daemon can write; a process is ended at the next start only when its start time and its executable path both match what the daemon started). Telemetry is exported only when the `OTEL_*` variables are set.

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

## Managed Tor and Yggdrasil (ADR 0052)

SocketGuard ships Tor, Yggdrasil and (Windows) `wintun.dll` and runs them as child processes. It installs no package, starts no system service of theirs and edits no configuration of software it did not ship (`socketguard networks setup` no longer exists). A managed network adds the items below.

| Item | System | Survives stop / reboot | Removed by |
|---|---|---|---|
| Child process `tor` (own data directory, no SOCKS port, control endpoint only SocketGuard reads) | all | no: it ends with the daemon (Windows job object, Linux parent-death signal, Tor's own owning-controller check; macOS: a pid file in `<state dir>/run` and a check at the next start) | turning SocketGuard off, removing the network, stopping the daemon |
| Child process `yggdrasil` (own key, own adapter) | all | no: it ends with the daemon (Windows job object). Unix: Yggdrasil changes its user id after creating the adapter, which drops the parent-death signal, so the daemon starts it through `socketguard-daemon child-guard`, a small root parent that holds the node's stdin pipe open to the daemon and ends the node when the pipe closes (the daemon died, `kill -9` included) or its parent changes. If the guard itself is killed, the next start of the daemon finds the leftover through the two pid files in `<state dir>/run` (the guard's and the node's; pid, start time and executable path must match) and ends it before starting its own | turning SocketGuard off, removing the network, stopping the daemon |
| Tor data directory `<state dir>/tor` (state, cookie, control socket; on Unix with the account the state directory itself gets the execute bit for others so that `socketguard-net` can reach it, no read or write) | all | yes | kept by an uninstall that keeps data; `uninstall --purge` removes the tree (install record kind `owned_directory`, path must be inside the state directory) |
| Pid files `<state dir>/run/<network id>.pid` (Unix; pid and start time of a managed child; directory mode 0700, the daemon's own) | Linux, macOS | yes | removed when the child ends; the directory goes with the state directory (`uninstall --purge`) |
| Yggdrasil directory `<state dir>/yggdrasil` (generated `yggdrasil.conf` with the node's private key, mode 0600 and the daemon's own; `run/` with the admin socket, owned by `socketguard-net`) | all | yes | removing the network deletes the whole directory; otherwise as the Tor directory (`uninstall --purge`) |
| The node's private key in the database (setting `ygg_key:<network>`, also the remembered node `ygg_node:<network>`) | all | yes | removing the network; otherwise with the database (`uninstall --purge`) |
| System account `socketguard-net` | Linux, macOS | yes | `service install` creates it if missing and records it; `uninstall` removes it only when it was created by SocketGuard. Without it children run as the daemon's account and `status` says so |
| Adapter `SocketGuard` (Windows), `sgygg0` (Linux), a `utun` (macOS, named by the system; SocketGuard finds it by the node's address) | all | no: it disappears when `yggdrasil` exits | stopping the child; the footprint check lists a leftover `SocketGuard` or `sgygg0` (a leftover `utun` is not named, the check sees the process instead) |
| Wintun driver in the driver store | Windows | yes | **shared with other software.** The install record keeps whether it was present before the first managed start (read from `pnputil /enum-drivers` and recorded before Yggdrasil first starts); `uninstall --purge` removes it (`pnputil /delete-driver`, never `/force`) only if it was absent before and Windows accepts the removal, otherwise it is reported as *kept*, "shared with other software" |
| Shipped third-party files (`third_party/` next to the daemon or in the package location, with `licenses/` and `VERSIONS`) | all | yes | the package (`uninstall`, `apt purge`, `msiexec /x`) |

What privilege cannot be dropped:

- **Yggdrasil on Windows** runs as the account of the daemon (the service account, LocalSystem): there is no way to drop privileges after the adapter is created. On Linux and macOS it creates the adapter as root and then drops to `socketguard-net` (`-user`).
- **Tor** runs as `socketguard-net` (Unix) or LocalService (Windows). If the daemon is started by hand without the right to start a process as LocalService, or the account does not exist, Tor runs as the daemon's account and `status` says so.
- The daemon itself keeps its privileges: it manages the firewall and the addresses.

## Windows of exposure (ADR 0051)

The invariant: a network SocketGuard adds, installs or manages never makes the host reachable outside its rules, at any moment. Each case, and whether it is closed.

| Case | State | By what, or why open |
|---|---|---|
| Yggdrasil installed by someone else and running, before it is added | **open, by design** | Not a network SocketGuard manages yet. The network card says so ("Yggdrasil is running but not managed", `exposed` in `GET /api/networks/setup`). |
| SocketGuard's own Yggdrasil node, before its first start | closed | The first-sight window does not apply: SocketGuard generates the key, derives the node's address and `/64` from it and stores them as the remembered node (`ygg_node:<network>`) before anything runs. The child starts only after the ruleset with `overlay:<network>:addr` and `:subnet` was applied and verified; if the apply fails the child does not start and the status says why. The adapter name is chosen by SocketGuard, so the interface rule exists too. |
| Managed node, one other node already running on the host | closed | The child is not started (two nodes in one namespace break each other); the status says "another Yggdrasil node is running on this host". |
| Network added before an existing node was ever seen | closed on the interface only, if the interface exists (WFP) or is named (nftables, pf) | Its address is unknown, so only the interface is closed. `closed` is false with the reason until the node answers once. |
| Node stopped, restarted, adapter missing, renamed or recreated | closed | The node's own `/128` and `/64` are denied as destinations on any interface (`overlay:<network>:addr`, `:subnet`), remembered in the settings table (`ygg_node:<network>`) from the first time they are known. |
| A second node, not managed by SocketGuard, on the same host | untouched | Only the managed node's addresses are denied. |
| Network removed, "turn off", uninstall while the node keeps running | **open, by choice** | The block is removed with them. `GET /api/exposure` is shown first, with the programs that become reachable. Removing a running node's network needs `confirm_exposed` (CLI `--yes`). **Only for an existing node ("your own")**: SocketGuard's own node stops with its network and with "turn off" (and with the daemon when it stops normally), so a managed network has no exposure on leaving and needs no confirmation. A daemon that is killed leaves the node running on Linux and macOS, behind the rules, which stay in force. |
| Linux: boot before the daemon applies its ruleset | partly closed | `Before=network-pre.target`, `Wants=network-pre.target` and `Before=yggdrasil.service` order the daemon first, but `Type=simple` orders on process start, not on the first apply; the rules are in force a moment later. The remembered node addresses are applied in that first ruleset. |
| macOS: boot before the anchor is loaded | **open** | No launchd service exists yet; nothing orders the node after SocketGuard, and pf rules do not survive a reboot. |
| Windows: boot | closed | WFP filters are persistent. |
| Tor, LAN, SLAAC, DHCPv6 | nothing to close | An existing Tor adds a control port on loopback with cookie authentication only (SocketGuard's own Tor uses a Unix socket, or on Windows a loopback port chosen by Tor, in its protected directory) and exposes nothing inbound before SocketGuard publishes a service. SocketGuard's own LAN addresses are denied before they are added (the ruleset covers an address before it goes on an interface). |
| Windows: node first seen, adapter appears before the next pass | **open, short** | WFP binds filters to an adapter's LUID, so no filter exists for an adapter that does not exist. The address block covers the node once its address is known; until then (and for non-Yggdrasil traffic on that adapter) the window lasts from the adapter's creation to the next reconcile and `interfaces_changed` re-apply. `yggdrasil_block.interface_blocked` is therefore false on Windows for a missing adapter, and setup refuses to start the service on that basis. |

## Failures of the removal paths themselves

- **`--disable` from the wrong directory** can no longer happen: config and database have fixed locations. If the database is not at the resolved location, `--disable` refuses, names the paths it looked at, exits non-zero and changes nothing.
- **Partial disable keeps the rules.** If one address cannot be removed, the rules stay (fail closed), the command says which addresses are left and exits non-zero; a running daemon retries.
- **An invalid Tor network no longer aborts `--disable`:** the other networks are processed and the Tor services are reported as LEFT.
- **The removal paths run for real in CI** (`.github/workflows/packages.yml`, ADR 0050): the MSI job installs, grants a port range through WFP, upgrades, removes and purges on a Windows runner, the deb job does the same with nftables on an Ubuntu VM with systemd, the pkg job with pf and launchd on macOS, and each ends with `deploy/ci/footprint-check.*` looking from outside. Not covered: restoring the engine option `FWPM_ENGINE_COLLECT_NET_EVENTS` to *off* (`netsh wfp show options optionsfor=netevents` reads it from outside; on the CI runner it was already on before the install, so the install record says `prior: 1` and nothing changes), the address-prefix block (needs a Yggdrasil node), the rpm service steps (CI only installs it in a container without systemd) and other users' webview profiles.
