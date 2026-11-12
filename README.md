# SocketGuard

Secure by default, without NAT. Every app and every port on a host is closed until you grant
access. Access goes to *peers*, identified by a key or an address, not to bare IP strings. Each
granted port, port group or "All ports" of an app gets its own address on each network, so you
can see and share exactly what is reachable. A *reserved address* is a named address that stays
the same while the apps behind it change.

Networks: Local (this machine), LAN, Yggdrasil and Tor. SocketGuard bundles Tor and Yggdrasil and
runs them itself; nothing is installed on your system for them.

A daemon (a system service) does the work: it finds listening apps, keeps firewall rules (nftables,
pf, Windows Filtering Platform) and addresses in step with your grants, and serves a local API.
The `socketguard` command line and the desktop app are two frontends for that API.

[Install](#install) · [First steps](#first-steps) · [Networks](#networks) ·
[Uninstall](#uninstall-and-purge) · [Portable mode](#portable-mode) · [Architecture](#architecture) ·
[Platform support](#platform-support) · [Command line](#command-line) ·
[Configuration](#configuration) · [Roadmap](#roadmap-and-what-is-not-built) ·
[Building](#building-from-source) · [Testing](#testing)

## Install

Packages are attached to each [release](https://github.com/lhns/socketguard/releases) with a
`SHA256SUMS` file. They are **not signed yet**, so each system warns once. Each package installs
`socketguard-daemon`, `socketguard` and `socketguard-ui`, registers a service that starts with the
system, and starts it. Details: [docs/packaging.md](docs/packaging.md).

**Windows** (`SocketGuard-<version>-x64.msi`). Installs to `C:\Program Files\SocketGuard` and adds
it to `PATH`. A box in the installer (ticked by default) lets *your* account use SocketGuard without
administrator rights by adding it to the local group `SocketGuard Users`; **sign out and in again**
before it applies. Silent install: `msiexec /i SocketGuard-<version>-x64.msi /qn ALLOWUSER=PC\alice`
(without `ALLOWUSER` nobody is added). The app needs the Edge WebView2 Runtime (part of Windows 11).
*Unsigned:* SmartScreen shows "Windows protected your PC"; choose *More info*, *Run anyway*.

**Portable (Windows)** (`SocketGuard-portable-windows-x64.zip`): see [Portable mode](#portable-mode).

**Debian, Ubuntu** (`socketguard_<version>-1_amd64.deb`): `sudo apt install ./socketguard_*.deb`.
**Fedora, RHEL** (`socketguard-<version>-1.x86_64.rpm`): `sudo dnf install ./socketguard-*.rpm`.
Both need systemd. The unit is `Type=notify` and ordered before the network: the service is ready,
and `systemctl start` returns, once its rules are applied. Nobody is added to the `socketguard` group: run
`sudo socketguard-daemon access allow $USER` (or use the app's "allow my account"), then **sign out
and in again**.

**macOS** (`SocketGuard-<version>-arm64.pkg` for Apple silicon, `-x86_64.pkg` for Intel). Installs the
programs and `SocketGuard.app` and starts a launchd daemon. *Unsigned:* macOS refuses to open a
downloaded pkg; use *Open* from its context menu, or *System Settings > Privacy & Security > Open
Anyway*. Then `sudo socketguard-daemon access allow $USER` and sign out and in.

Upgrading is installing the newer package; settings and rules stay and the service restarts.

## First steps

Nothing is reachable until you grant it, so start by letting one peer reach one app.

**In the desktop app.** The *Apps* page lists what listens on this host; all of it is closed. Open
an app, choose *Add access* on "All ports" or on one port, pick who (a peer you add by key or
address, or a peer group) and confirm. The app now has an address on each network that takes the
grant; the inspector shows it and, per network, whether the peer is `verified` by key or `IP only`.
*Reserved* holds named addresses, *Peers* the peers and groups, *Activity* the feed (including
blocked attempts), *Settings* the networks and whole-host protection.

**On the command line.**

```bash
socketguard init                              # first run: networks, remote-admin grants, protect-host
socketguard networks list                     # what is configured; `networks detect` shows what can be added
socketguard apps list
socketguard peers add --label alice <ygg-key> # bare values: 64 hex = Yggdrasil key, IP/CIDR = address
socketguard grant nginx:80 alice              # an app[:port[/proto]]; or group:team, or anyone (asks)
socketguard apps show nginx                   # its addresses, ports, grants and their reach
socketguard share nginx                       # the connection strings to give to alice
socketguard activity --blocked --follow       # what was refused
socketguard revoke nginx:80 alice
```

`socketguard --help` lists everything: tags (`tags`), port groups (`port-groups`), reserved addresses
(`reservations`, `addresses`), peer groups (`groups`), batch `grant`/`revoke`, `export`/`apply`,
`protect-host`, `disable`/`enable`. `--json` prints the API types as JSON; apps, peers and groups can be
named by id, unique id prefix or name. Reach is shown per network as `verified`, `whole subnet`,
`IP only`, `open` or `not reachable`. See [Command line](#command-line), [docs/api.md](docs/api.md) and ADR 0033.

## Networks

| Network | Addresses | Identity of sources |
|---|---|---|
| Local | ULA on loopback, this machine only | none |
| LAN | from the LAN's `/64` (SLAAC, DHCPv6) | IP only |
| Yggdrasil | `/128`s from the node's `300::/64` | verified by key |
| Tor | one onion service per address | verified by Tor client key |

Tor and Yggdrasil are **managed** by default: SocketGuard runs its own copy as a child process with
its own data, so nothing on your system is installed or changed, and the copies stop when SocketGuard
stops (ADR 0052).

```bash
socketguard networks add tor
socketguard networks add yggdrasil --peer tls://host:port      # --peer is repeatable
socketguard networks peers yggdrasil --add tls://host:port --rm tls://old:1
```

If you already run a node, add it as it is with `--existing` (the app calls it "Use my existing
one"): `socketguard networks add yggdrasil --existing`, or `socketguard networks add tor --existing`
(with `--control` and `--password-env` if needed). An existing node keeps its own configuration;
SocketGuard never installs, starts or reconfigures software it did not ship. `socketguard networks
detect` and the app's Settings page show what this machine offers. Tor access control is described
in [ADR 0040](docs/adr/0040-onion-service-lifecycle-consolidated.md).

## Uninstall and purge

Removing SocketGuard stops the service and takes its firewall rules, addresses and service
registration off the host but **keeps** settings and keys. A purge deletes those too.

- Windows: Apps & features or `msiexec /x` removes; for a purge run
  `socketguard-daemon uninstall --purge` first (administrator terminal), or use the app's
  "Remove SocketGuard...".
- Debian/Ubuntu: `apt remove socketguard` removes, `apt purge socketguard` purges.
- Fedora/RHEL: `dnf remove socketguard` removes; run `sudo socketguard-daemon uninstall --purge` before
  erasing it to purge.
- macOS: a pkg has no uninstaller. Run `sudo socketguard-daemon uninstall` (`--purge` also deletes
  settings and keys), then delete `/Applications/SocketGuard.app`, `/usr/local/bin/socketguard*` and
  `/usr/local/lib/socketguard`, and `sudo pkgutil --forget de.lhns.socketguard`.

`uninstall` also takes `--keep-data`, `--yes`, `--export <file>` and `--force`. Stopping the daemon
removes nothing on purpose, so a stopped host stays closed; `socketguard disable` (or
`socketguard-daemon --disable` while it is stopped) removes the rules and addresses and keeps them off
until `socketguard enable`. [docs/footprint.md](docs/footprint.md) lists everything SocketGuard puts
on a host and what removes it.

## Portable mode

`SocketGuard-portable-windows-x64.zip` (ADR 0054). Unzip anywhere, even to a removable drive, and
run `socketguard-ui.exe`; it asks for administrator rights at every start. Everything it keeps is in
the `data` folder next to the programs; no service, group or installed files. A file named
`portable` next to the daemon, or `socketguard-daemon --portable`, selects the mode.

**The trade-off.** Protection ends with the window: rules and addresses are removed when you close
SocketGuard, sign out or shut down. A crash or a kill leaves the machine open, as it was before
SocketGuard started, **not closed**. Use the MSI to protect a computer permanently. Portable mode
does not start beside the installed service, offers only Local, LAN and the managed Tor and
Yggdrasil, and trusts the folder: anything running as you can change what then runs with
administrator rights, so keep it where only you can write. Delete the folder to remove it. To try
the UI or CLI against a daemon without installing, use this mode.

## Architecture

```
  desktop app (Tauri) --+
                        +--> local API ---------> socketguard-daemon (system service)
  socketguard (CLI) ----+    Unix socket or       |
                             named pipe           |  monitor   listening sockets -> apps
                                                  |  engine    apps + grants + peers -> desired state
                                                  |  state     SQLite database, activity log
                                                  |  ruleset --> firewall: nftables | pf | WFP
                                                  |  iface     addresses on the OS interfaces
                                                  |  networks  Local, LAN (SLAAC, DHCPv6),
                                                  |            Yggdrasil, Tor
                                                  v
                  host: firewall rules, addresses, and the child processes of the
                        managed networks (SocketGuard's own Tor and Yggdrasil)
```

The frontends only speak the local API; they hold no state. The daemon applies the stored state
when it starts and leaves it in place when it stops (portable mode excepted).

| Path | Contents |
|---|---|
| `crates/core/` | Domain model (apps, peers, grants, reach), config, API types |
| `crates/daemon/` | The daemon: monitor, engine, SQLite state, ruleset producer, firewall backends, interface addresses, networks (Local, LAN, Yggdrasil, DHCPv6, Tor), local API, telemetry |
| `crates/client/` | Typed client for the local API, shared by the CLI and the app |
| `crates/cli/` | The `socketguard` command line |
| `ui/`, `ui/src-tauri/` | Desktop app: React frontend and its Tauri v2 Rust backend |
| `installer/` | MSI (WiX), portable zip, deb and rpm (nfpm), macOS pkg; `installer/payload/` receives the bundled Tor and Yggdrasil |
| `deploy/` | `bundle/` (pinned third-party programs), `ci/`, `e2e/` (Docker tests), `otel/` (telemetry stack), `systemd/` |
| `test/` | Package tests run by `packages.yml` |
| `docs/` | API, packaging, footprint, manual checks, `adr/` |

## Platform support

| | Windows | Linux | macOS |
|---|---|---|---|
| Firewall | Windows Filtering Platform | nftables (`inet` table) | pf anchor |
| Service | Windows service | systemd unit | launchd daemon |
| Installer | MSI, x86_64 | deb and rpm, x86_64 | pkg, arm64 and x86_64 |
| Portable | zip, x86_64 | no | no |
| Managed Tor | yes | yes | yes |
| Managed Yggdrasil | yes (Wintun adapter) | yes (needs `/dev/net/tun`) | yes (`utun`) |
| CI | Windows runner: unit tests; MSI and portable zip installed and run, real WFP filters | Ubuntu 22.04 VM: deb with systemd, netns tests (real nftables); Fedora containers: rpm, and one with systemd; nightly Docker e2e | arm64 and Intel runners: unit tests, `pfctl` check, pkg installed with launchd; smoke test |

Only built, never run: no Linux aarch64 or Windows arm64 package exists (the bundle script can fetch
their Tor and Yggdrasil, but no job builds them). Nothing is signed or notarized. On CI runners the
managed Yggdrasil adapter depends on the runner (tun device, Wintun driver); the tests then report a
skip with the reason instead of passing. The Docker tests run on Linux only.

Not verified: Windows 10 (the WebView2 Runtime arriving through Windows Update is unchecked), the
installer dialogs (CI installs silently; the checklist is [docs/manual-checks.md](docs/manual-checks.md)),
a standard user elevating with an administrator's credentials, Linux distributions other than
Ubuntu 22.04 and Fedora, and signing. Details: [docs/packaging.md](docs/packaging.md); the boot gap
before the rules are applied is listed in [docs/footprint.md](docs/footprint.md).

## Command line

The essentials; every command is in [docs/cli.md](docs/cli.md) and `socketguard --help`.
`--json` prints the API types; `--socket PATH` picks another daemon.

```bash
socketguard status                         # daemon, networks, protect-host, counts
socketguard apps list | show nginx         # what listens; addresses, ports, grants and reach
socketguard grant nginx:80 alice           # app[:port[/proto]] to a peer; or group:team, or anyone
socketguard grant ftpd:port-group=passive alice
socketguard grant tag:dev group:team       # a tag: every member, now and later
socketguard grant reservation:web alice    # a reserved address: its bound rows, All ports
socketguard grant --app web --app api --port 80 --port 443 --to alice --network lan --dry-run
socketguard revoke nginx:80 alice          # or: revoke <grant-id>
socketguard grants --peer alice            # also --app, --tag, --reservation, --group
socketguard peers add --label alice <key>  # 64 hex = Yggdrasil key, IP/CIDR, 52 base32 = Tor client key
socketguard peers tor-key bob              # generate a Tor client key; `share` prints the client line
socketguard groups add team alice bob
socketguard tags add dev --match 'python*' # apps matching join, now and when they start
socketguard port-groups add 21/tcp 50000-51000/tcp -n passive --app ftpd
socketguard addresses list                 # automatic and reserved addresses
socketguard reservations add web nginx:80 tag:dev   # bind rows; then grant reservation:web
socketguard networks add tor | add yggdrasil --peer tls://host:port | add yggdrasil --existing
socketguard networks list | detect | peers yggdrasil --add URI --rm URI | rm ID
socketguard share nginx                    # connection strings for the peer
socketguard activity --blocked -f          # what was refused
socketguard protect-host on eth0           # close the host's other listeners on eth0
socketguard exposure                       # what Yggdrasil would expose without SocketGuard
socketguard export -o sg.toml | apply -f sg.toml --dry-run
socketguard disable | enable | shutdown    # rules off/on; shutdown is portable mode
socketguard-daemon service install | access allow $USER | uninstall [--purge] | --disable | --portable
```

## Configuration

The daemon reads one JSON file, `socketguard.json`. Networks added with `socketguard networks add`
are written back to it; the other keys are edited by hand and need a daemon restart. Every key is
optional.

| Where | Windows | Linux | macOS | Portable |
|---|---|---|---|---|
| Config file, setup log | `%ProgramData%\SocketGuard` | `/etc/socketguard` | `/Library/Application Support/SocketGuard` | `data\` next to the programs |
| Database | same folder | `/var/lib/socketguard` | same folder | `data\` |

`$SOCKETGUARD_CONFIG` replaces the config file path (portable mode ignores it); a relative `db_path`
is taken against the config file's folder. Nothing uses the working directory.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `backends` | array | one Local network | The networks (below). `id` is optional: the type, or `type-interface` for `slaac` and `dhcpv6`. At most one each of `ula`, `yggdrasil`, `tor` |
| `backend` | object | none | Single-network form, used if `backends` is absent |
| `api_socket` | string | `/run/socketguard.sock`; macOS `/var/run/socketguard.sock` | Unix socket of the local API; ignored on Windows |
| `api_pipe` | string | `\\.\pipe\socketguard` | Named pipe of the local API; ignored elsewhere |
| `poll_interval_secs` | number | `2` | How often listening sockets are read |
| `db_path` | string | empty: `socketguard.db` in the database folder above | SQLite file, absolute or relative to the config folder |
| `log_level` | string | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `process_filter` | object | `{"mode": "denylist", "patterns": []}` (nothing excluded) | `mode` is `allowlist` or `denylist`; `patterns` are case-insensitive globs (`*`, `?`) on the process name. An empty allowlist admits nothing |

Entries of `backends` (`"type"` selects the kind):

| `type` | Key | Type | Default | Meaning |
|---|---|---|---|---|
| `ula` (Local) | `interface` | string | loopback: `lo`, `lo0`, `Loopback Pseudo-Interface 1` | Interface that holds the addresses |
| `slaac` (LAN) | `interface` | string | required | Interface on the router's LAN |
| | `prefix` | string | discovered (also `"auto"`) | IPv6 `/64` to use |
| `dhcpv6` (LAN) | `interface` | string | required | Interface on the DHCPv6 server's LAN |
| `yggdrasil` | `managed` | bool | `false` | Run SocketGuard's own node; excludes `interface` and `admin_endpoint` |
| | `peers` | string array | `[]` | Managed only: URIs (`tcp`, `tls`, `quic`, `ws`, `wss`, `socks`, `sockstls`) |
| | `interface` | string | found at runtime | Existing node: its interface |
| | `admin_endpoint` | string | `yggdrasilctl`'s default | Existing node: admin socket, e.g. `unix:///var/run/yggdrasil.sock` |
| `tor` | `managed` | bool | `false` | Run SocketGuard's own Tor; none of the keys below may be set |
| | `control` | string | `127.0.0.1:9051` | Existing Tor: `host:port` or `unix:/path`. Administrator |
| | `auth` | string or object | `"cookie"` | `"cookie"` (SAFECOOKIE), `"cookie_insecure"`, `{"password": "..."}`, `"none"` (Unix socket only). Administrator |
| | `cookie_path` | string | none | Cookie file Tor must report. Administrator |
| | `cookie_dir` | string | folder of `cookie_path` | Folder whose owner may own the cookie. Administrator |
| | `expect_tor_uid` | number | none | Unix control socket: the uid Tor must run as. Administrator |
| | `cookie_owner` | string | none | Windows: SID that may own the cookie, besides SYSTEM and Administrators. Administrator |
| | `allow_remote_control` | bool | `false` | Accept a control address that is not loopback. Administrator |

**Administrator only.** The API is open to every member of the access group, so it accepts a Tor
network only with default settings or settings already in the file. The Tor control settings above
(ADR 0040) therefore belong in the file, which only an administrator can write.

Environment variables:

| Variable | Read by | Meaning |
|---|---|---|
| `SOCKETGUARD_CONFIG` | daemon and its commands | Config file path |
| `SOCKETGUARD_SOCKET` | CLI, app | Socket or pipe of the daemon to talk to |
| `SOCKETGUARD_THIRD_PARTY` | daemon | Extra folder to look in for the bundled Tor and Yggdrasil |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_{TRACES,LOGS,METRICS}_ENDPOINT` | daemon | Export telemetry over OTLP when set; `deploy/otel/` has a local stack |
| `OTEL_SDK_DISABLED`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | daemon | Standard OpenTelemetry settings |
| `SOCKETGUARD_FORCE_REMOVE` | deb and rpm remove scripts | `1` passes `--force` and ignores a failed removal |
| `SOCKETGUARD_TRUST_PIPE_SERVER` | CLI, app (Windows) | `1` accepts a pipe not owned by SYSTEM or Administrators; development only |
| `SOCKETGUARD_ALLOW_UNPROTECTED_DB` | daemon (Windows) | `1` runs although the database ACL could not be set; development only |
| `SOCKETGUARD_BUNDLE_CACHE` | `deploy/bundle/fetch.sh` | Download cache |
| `SOCKETGUARD_NETNS_TESTS`, `SOCKETGUARD_PF_CHECK` | tests | Enable the netns tests (Linux, root) and the `pfctl` check (macOS, root) |

## Roadmap and what is not built

Not built, and not promised. Each item is recorded in an ADR.

- WireGuard as a network on an existing interface, and an opt-in mTLS gateway: only the credential
  kinds `wg_key` and `tls_spki` exist ([ADR 0036](docs/adr/0036-future-directions.md)). Key-verified
  access therefore exists on Yggdrasil and Tor only.
- IPv4 per-app addresses: IPv4 gets whole-host protection only (ADR 0036, 0026). Also not built:
  out-of-process network plugins, mDNS/DNS-SD names, dynamic DNS, pflog capture on macOS.
- More than one Yggdrasil node per host: SocketGuard's own node and one you already run cannot run
  at the same time ([ADR 0052](docs/adr/0052-bundled-tor-and-yggdrasil.md),
  [0051](docs/adr/0051-nothing-socketguard-adds-opens-the-host.md)).
- Pluggable transports and bridges for the managed Tor (ADR 0052). The ADR's later amendment
  describes obfs4 bridge lines, but nothing in this tree ships or reads them.
- Port remapping on a reserved address, and per-client access on one onion address
  ([ADR 0047](docs/adr/0047-addresses-on-demand-reservations-port-groups.md)). Inside a reservation,
  Tor access is all or nothing.
- Keeping the last ruleset across a reboot, loaded before the daemon. By choice (ADR 0051): if the
  daemon cannot start, nothing is filtered and the machine stays reachable for repair. On Linux the
  network waits for the daemon's first ruleset; on macOS the gap at boot stays.
- Signed installers: no Authenticode, Developer ID or notarization yet
  ([docs/packaging.md](docs/packaging.md)). No Linux aarch64 or Windows arm64 packages.

## Building from source

Prerequisites: Rust ([rustup](https://rustup.rs)) and Node.js; on Windows the Visual Studio Build
Tools; at runtime `nft` on Linux and `pfctl` on macOS. On a fresh clone run `cd ui && npm install`
once, then:

```bash
./build.sh                 # release build: frontend, then all crates
./build.sh --debug         # debug build
./build.sh --with-bundled  # also fetch the pinned Tor, Yggdrasil and Wintun next to the build
```

`--with-bundled` needs network access, git and Go (`deploy/bundle/fetch.sh`). Binaries land in
`target/<profile>/`: `socketguard-daemon`, `socketguard` and `socketguard-ui`. Always use
`./build.sh`, not `cargo build` or `npm run build` alone.

## Testing

- `cargo test --workspace --exclude socketguard-ui`, and `cd ui && npm run lint && npm run typecheck
  && npm test`: unit, golden, engine, API and UI tests. CI (`.github/workflows/ci.yml`; Forgejo has
  its own in `.forgejo/`) also runs the UI crate, the netns tests as root and
  `deploy/ci/macos-smoke.sh`.
- `SOCKETGUARD_NETNS_TESTS=1 cargo test -p socketguard-daemon --test netns`: real nftables in network
  namespaces (Linux, root).
- `deploy/e2e/ygg-e2e.sh`, `tor-e2e.sh` and the `managed-*` scripts: Docker end-to-end tests with real
  Yggdrasil and Tor.
- The package tests in `test/` run in `.github/workflows/packages.yml`; checklist for the dialogs CI
  cannot click: [docs/manual-checks.md](docs/manual-checks.md).

## Where the decisions live

- [docs/adr/](docs/adr/): architecture decisions; the current design is ADR 0026 onward.
- [docs/footprint.md](docs/footprint.md): what SocketGuard puts on a host and what removes it.
- [docs/api.md](docs/api.md): the local API, its endpoint and who may use it.
- [docs/packaging.md](docs/packaging.md): packages, install, upgrade and removal per platform.
- [docs/manual-checks.md](docs/manual-checks.md): manual installer checks per release.

## Licence

Apache License 2.0, see [LICENSE](LICENSE). The installers ship unmodified Tor, Yggdrasil and, on
Windows, Wintun; their licences and sources are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and, installed, in `third_party/licenses/`.
Versions and checksums are pinned in `deploy/bundle/versions.toml`.
