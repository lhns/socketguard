# Packages and releases (ADR 0050)

Every package only calls commands of the daemon binary, so the logic is tested once and the
packages stay thin. Definitions: `installer/windows/` (WiX), `installer/linux/` (nfpm),
`installer/macos/` (pkgbuild). CI: `.github/workflows/packages.yml` builds each, installs it on a
real runner and checks the host from outside with `deploy/ci/footprint-check.*`;
`release.yml` reuses it.

**One staged tree per system (ADR 0057).** `./build.sh --stage [dir]` (default `dist/stage`; the
directory is emptied first) builds in release mode and fetches the pinned Tor, Yggdrasil and
Wintun (`deploy/bundle/fetch.sh`, ADR 0052), and leaves everything a package of the host system and
architecture ships in one flat directory:

    dist/stage/
      socketguard-daemon  socketguard  socketguard-ui       (.exe on Windows)
      LICENSE  THIRD_PARTY_NOTICES.md
      third_party/
        tor/               the Tor binary, its libraries, pluggable_transports/lyrebird
        yggdrasil/         yggdrasil, and wintun.dll on Windows
        licenses/<name>.txt
        VERSIONS           what `socketguard status` reports

`third_party/` has its modes fixed (everyone reads and runs, only the owner writes) because the
children run as an unprivileged account. The `portable` marker is **not** in the stage: only the zip
step makes it, so no other package can carry it (`test/msi.ps1` checks the install directory has
none). The package builders wrap the stage and take nothing else:

| Builder | Takes | Result |
|---|---|---|
| `installer/windows/build.ps1 -Version v -Stage dir -Out f.msi` | the three exes, `LICENSE`, `THIRD_PARTY_NOTICES.md`, every file of `third_party\` (a WiX fragment with one component per file is generated) | `C:\Program Files\SocketGuard\` with `third_party\` and `licenses\` |
| `installer/windows/portable.ps1 -Stage dir -Out f.zip` | the exes and `third_party\`; adds the `portable` marker, `LICENSE.txt`, `NOTICE.txt`, `README.txt` | the portable folder |
| `installer/linux/build.sh version dir [outdir]` | the three programs, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `third_party/` as a `type: tree` | deb and rpm; `/usr/lib/socketguard/third_party/`; the deb's postrm is generated here (below) |
| `installer/macos/build.sh version dir [outdir]` | the same, into the pkg payload | `/usr/local/lib/socketguard/third_party/`, the app and `/usr/local/bin` |

A package is built a second time with the next patch version (`deploy/ci/version.sh --next`) from
the same stage, for the upgrade test.

The stage also runs the product: the daemon finds `third_party` next to its executable (then at the
package location of its platform, then in `$SOCKETGUARD_THIRD_PARTY`), so `dist/stage/socketguard-daemon`
works in place. `./build.sh --with-bundled` stays for development runs from `target/<profile>`: it
fetches into `target/<profile>/third_party` without staging.

`--stage` needs network, git, Go (the version in `versions.toml`; Yggdrasil is built from the pinned
commit) and, with `--require-signature` (CI), `gpg` for the Tor Project signature. Downloads and the
Yggdrasil source are cached in `target/bundle-cache` (`SOCKETGUARD_BUNDLE_CACHE`). In CI
`.github/actions/bundle` provides Go, gpg and a cache directory keyed on `versions.toml` (`.bundle-cache`)
before `build.sh`. Supported targets: `windows-x86_64`, `linux-x86_64`, `macos-x86_64`,
`macos-aarch64` (`fetch.sh` also knows `linux-aarch64` and `windows-aarch64`; no job builds those).
The packages depend on the system zlib (`zlib1g`, `zlib`); the Tor bundle does not carry `libz.so.1`.
Licence texts: `third_party/licenses/` holds those of the programs; `THIRD_PARTY_NOTICES.md` and
`LICENSE` are installed to `Program Files\SocketGuard\licenses` (Windows), `/usr/share/doc/socketguard/`
(Linux) and the app's `Contents/Resources` plus `/usr/local/share/doc/socketguard/` (macOS). Files
installed this way belong to the package; what SocketGuard creates at run time (a Tor data directory,
Yggdrasil keys) is in the install record (ADR 0050).

In CI each system builds once (`packages.yml`): the Windows job produces the MSI, the MSI of the next
version (artifact `msi-next`, not in the release) and the zip; the `msi` and `portable` test jobs
download those finished files and run in parallel. Only finished packages travel between jobs, never
the stage (an artifact upload drops the execute bits).

The repository's composite actions: `.github/actions/setup` (Rust, cargo cache, Node, npm cache and
`npm ci`, and the Linux desktop build dependencies), `setup-wix`, `setup-nfpm`, `bundle`.

| | Install | Upgrade | Remove | Purge |
|---|---|---|---|---|
| **MSI** (Windows, per machine) | `service install`; `access allow <ALLOWUSER>` when given | the same, after the old version is removed without `uninstall`; the service is restarted | `uninstall --keep-data --yes` | `socketguard-daemon uninstall --purge` (the MSI never deletes data) |
| **deb** | postinst `configure`: `service install` | the same (`configure` runs again); a running daemon is restarted | prerm `remove`: `uninstall --keep-data --yes` | postrm `purge`: deletes the named files, `<state>/tor`, `<state>/yggdrasil`, `<state>/run`, and `socketguard-net` when the install record says the install created it (`apt purge`) |
| **rpm** | `%post`: `service install` | the same (`$1` is 2); restarted | `%preun` with `$1` = 0: `uninstall --keep-data --yes` | none: run `socketguard-daemon uninstall --purge` before erasing |
| **pkg** (macOS) | postinstall: `service install` | the same; restarted | no uninstaller: `sudo socketguard-daemon uninstall`, then delete the files (README) | `sudo socketguard-daemon uninstall --purge` |

An upgrade is never an uninstall: `uninstall` and `--disable` do not run on one, in any package.
The deb and the rpm tell them apart by the maintainer-script argument (`remove` / `$1 = 0`), the
MSI by `REMOVE AND NOT UPGRADINGPRODUCTCODE` (the one feature can only be removed whole).

`service install` restarts a daemon that is already running (systemd `restart`, launchd
`kickstart -k`), so the process after an upgrade is the new binary. The Windows installer stops the
service before replacing the file (`ServiceControl`, stop only) and `service install` starts it.

## Windows

- Per machine, `C:\Program Files\SocketGuard`, the three binaries, `third_party\` (Tor, Yggdrasil,
  `wintun.dll`, their licence texts, `VERSIONS`), `licenses\` (`LICENSE.txt`, `THIRD_PARTY_NOTICES.md`), the install folder appended to
  the system `PATH`, a Start menu shortcut for the app, an Add/Remove Programs entry.
  `UpgradeCode` `F3E0B72B-FD6F-4C59-878D-68BA159A16B3` must never change.
- **Who may use SocketGuard.** The dialog has a box, ticked by default: "Let *account* manage
  SocketGuard without administrator rights". The account is the one that started the installer,
  read by the interface sequence (which runs as that user even when the install is elevated with an
  administrator's credentials). Silent installs add nobody unless
  `msiexec /i SocketGuard.msi /qn ALLOWUSER=PC\alice` (public property `ALLOWUSER`). The account
  must sign out and in again before the group applies.
- **WebView2.** The app needs the Microsoft Edge WebView2 Runtime. Windows 11 ships it; that Windows
  10 receives it through Windows Update and Edge is from memory, not checked. Tauri's own bundler
  defaults to downloading a bootstrapper at install time (`WebviewInstallMode::default()` is
  `DownloadBootstrapper { silent: true }` in tauri-utils 2.8.3, `config.rs`), which a firewall's installer should not do; the MSI instead looks
  for the runtime (`pv` under `EdgeUpdate\Clients\{F3017226-...}`, machine or user) and the dialog
  says when it is missing. The service and the CLI do not need it.
- **A removal that leaves something fails** (the daemon exits 1: persistent filters would outlive
  the program that can remove them) and is rolled back. `msiexec /x SocketGuard.msi FORCEREMOVE=1`
  adds `--force` and ignores the failure.
- Log: `msiexec /i SocketGuard.msi /l*v install.log`; the daemon's own output for each action is
  in it.
- Unsigned: SmartScreen shows "Windows protected your PC / Unknown publisher"; *More info*, *Run
  anyway*.

## Windows, portable zip (ADR 0054)

- `installer/windows/portable.ps1 -Stage dist/stage -Out dist/SocketGuard-portable-windows-x64.zip`
  builds one folder from the stage: the three programs, `third_party\` (Tor, Yggdrasil, `wintun.dll`,
  licences, `VERSIONS`), and what only the zip has: the `portable` marker, README, LICENSE and NOTICE.
  It is built in the same Windows job as the MSI, from the same stage.
- No installer ran, so nothing set up an account for the children: Tor and Yggdrasil run as
  the account of the elevated portable daemon (the card says "the account running portable
  SocketGuard"), and `data\tor` and `data\yggdrasil` have a protected access list that the read
  access of the allowed user on `data\` does not reach.
- Whether the Wintun driver was in the driver store before the first Yggdrasil start is kept
  in `data\session.json`. A clean exit removes the driver (`pnputil /delete-driver`, never `/force`)
  only if it was absent, after the children have ended; a kill leaves it, and the next clean exit
  from the same folder removes it.
- `test/portable.ps1` proves it on the runner (see below). Run it only on a throwaway machine.

## Linux

- One tool for both formats: **nfpm** (one YAML, per-format scripts and dependencies; a single
  static binary, pinned and checksum-verified in CI). `cargo-deb` plus `cargo-generate-rpm` would be
  two descriptions of the same thing and a Rust toolchain step each.
- Files: `/usr/bin/{socketguard-daemon,socketguard,socketguard-ui}`, a `.desktop` file, an icon.
  The systemd unit is **not** a package file: `service install` writes it from the text the daemon
  embeds (`deploy/systemd/socketguard.service`) with `ExecStart=/usr/bin/socketguard-daemon`, so a
  second copy cannot drift.
- Dependencies: nftables, iproute2, conntrack, libwebkit2gtk-4.1, GTK 3, zlib (Fedora names in the rpm).
- Documentation: `/usr/share/doc/socketguard/{LICENSE,THIRD_PARTY_NOTICES.md}`; the licence texts of
  the bundled programs are in `third_party/licenses/`.
- No systemd (a container): the install scripts print a note and do nothing, the remove scripts do
  nothing; run `socketguard-daemon service install` where systemd runs.
- `SOCKETGUARD_FORCE_REMOVE=1` makes the remove scripts pass `--force` and ignore a failure.
- The deb `postrm` cannot run the daemon (the file is gone at purge). `installer/linux/build.sh`
  runs the staged daemon's `uninstall --print-purge-list --os linux` (hidden; one item per line:
  `file`, `glob`, `tree`, `dir`, `account-if-created`; the list is `crates/daemon/src/footprint.rs`,
  which `uninstall --purge` itself deletes from) and embeds it in `installer/linux/scripts/deb-postrm.in`,
  whose loop is the whole interpreter. The account lookup in the install record stays in the script.
  `crates/daemon/tests/footprint_list.rs` (a cargo test, so it runs in `ci.yml` on all three systems)
  checks that every item the daemon lists for Linux, macOS and Windows is looked for by
  `deploy/ci/footprint-check.*` and described in `docs/footprint.md`.
- Built on Ubuntu 22.04 (glibc 2.35) so the binaries run on it and on newer systems.

## macOS

- `pkgbuild` and `productbuild`. `/usr/local/bin/{socketguard-daemon,socketguard}` and
  `/Applications/SocketGuard.app` (with `LICENSE` and `THIRD_PARTY_NOTICES.md` in `Contents/Resources`, and
  again in `/usr/local/share/doc/socketguard`), assembled by hand (the binary, `Info.plist`, `icon.icns`, an
  ad-hoc signature). Tauri's bundler would need `@tauri-apps/cli`, a `bundle` section and a second
  build path beside `build.sh` for the same two files. The app finds the CLI and the daemon in
  `/usr/local/bin` (`sibling_candidates` in `ui/src-tauri/src/main.rs`); the launchd plist names
  `/usr/local/bin/socketguard-daemon`, a stable path.
- A pkg has no uninstaller. **To remove:** `sudo socketguard-daemon uninstall` (add `--purge` to
  delete settings and keys), then
  `sudo rm -rf /Applications/SocketGuard.app /usr/local/bin/socketguard-daemon /usr/local/bin/socketguard /usr/local/lib/socketguard /usr/local/share/doc/socketguard`
  and `sudo pkgutil --forget de.lhns.socketguard`. The app's "Remove SocketGuard..." runs the first
  command.
- Unsigned: Gatekeeper blocks a downloaded pkg ("cannot be opened because it is from an
  unidentified developer"). Open it from the context menu (*Open*), or *System Settings > Privacy &
  Security > Open Anyway*, or `xattr -d com.apple.quarantine SocketGuard-*.pkg`.

## Releases

Push a tag `v<version>` (the workspace version in `Cargo.toml`). `release.yml` checks they match,
builds and tests all packages, and creates a **draft** release with the MSI, the portable zip, the
deb, the rpm, the pkgs (arm64 and x86_64) and `SHA256SUMS`. The release notes name the shipped Tor, Yggdrasil and Wintun versions (read from
`deploy/bundle/versions.toml`), link the pinned Yggdrasil source commit and the Tor version page, and
point to `THIRD_PARTY_NOTICES.md`; the same text is the job summary of a dry run. *Run workflow* on a branch is a dry run: the same files, uploaded as a workflow
artifact, no release.

### Signing and notarization (not done)

Provide these repository secrets and add the marked steps (`SIGN` comments in
`installer/macos/build.sh` and `.github/workflows/release.yml`); then pass them with
`secrets: inherit`.

| Secret | Used for |
|---|---|
| `WINDOWS_SIGNING_CERT_PFX` (base64), `WINDOWS_SIGNING_CERT_PASSWORD` | `signtool sign /fd sha256 /tr <timestamp> ...` on the three exes before `build.ps1` and on the MSI after |
| `APPLE_SIGNING_IDENTITY` ("Developer ID Application: ...") | `codesign --options runtime --timestamp` of the `.app` and `/usr/local/bin/*` |
| `APPLE_INSTALLER_IDENTITY` ("Developer ID Installer: ...") | `productbuild --sign` |
| `APPLE_CERTIFICATE_P12` (base64), `APPLE_CERTIFICATE_PASSWORD` | import both identities into a temporary keychain |
| `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID`, `APPLE_NOTARY_PASSWORD` (app-specific) | `xcrun notarytool submit ... --wait`, `xcrun stapler staple` |
| `GPG_SIGNING_KEY` (optional) | detached signature of the deb, rpm and `SHA256SUMS` |

## What CI proves, and what it does not

`packages.yml` on every push to `main`, on request, and for each release. The MSI, portable, deb and pkg jobs also have the **Tor and Yggdrasil
section** (`test/networks.sh` for the deb and the pkg, `test/networks.ps1` shared by
`test/msi.ps1` and `test/portable.ps1` on Windows; the helpers they all use are `test/lib.sh` and
`test/lib.ps1`), summarised in a line
`networks: N checks passed, M skipped` (the label the scripts print); the rpm jobs check the bundled files only (below):

- after the install: `status --json` names the bundled `tor` and `yggdrasil` with the versions of
  `third_party/VERSIONS` and the directory the daemon found; the licence texts and notices are
  installed; the unprivileged account can run the installed `tor` and `yggdrasil` (Linux, macOS:
  `socketguard-net`; Windows: a task as LocalService, plus the ACL);
- after the upgrade: `networks add tor` becomes up (bootstrapped, up to 10 minutes), tor runs as
  `socketguard-net` (Windows: NT AUTHORITY\LOCAL SERVICE, the test fails and prints `runs_as`
  otherwise); removing the network ends tor; it is added again and left for the uninstall steps;
- `networks add yggdrasil`: the node address is known and in the firewall ruleset before the adapter
  exists (Linux: `nft list table inet socketguard` against `sgygg0`, polled every 0.2 s; macOS:
  `pfctl -a socketguard -sr` against the address on a `utun`), yggdrasil runs as `socketguard-net`
  after creating the tun (Linux); Windows: the `SocketGuard` Wintun adapter holds the node address,
  and whether the admin socket answers (`peers_connected`) is reported;
- removal keeping the data: both children and the adapter are gone, `<state>/tor` and
  `<state>/yggdrasil` stay; purge: they are gone, `socketguard-net` is removed when the install
  record says the install created it, Wintun is gone from the driver store when the record says it
  was absent before (Windows); then `footprint-check` expects the host clean.

Runner-dependent: the Yggdrasil adapter needs `/dev/net/tun` (Linux; skipped with a warning when
missing), the ability to create a `utun` (macOS) and to install the Wintun driver (Windows: when no
adapter appears, the status detail is written to `ygg-adapter-error.txt` in `msi-test-output`
and the Yggdrasil assertions are SKIPPED with that reason, not faked); Tor needs the Tor network.

`.github/workflows/e2e.yml` (nightly and on request, not on push) runs the Docker tests of
`deploy/e2e/`: `ygg-e2e.sh`, `tor-e2e.sh`, `tor-bridges-e2e.sh`.

- **MSI** (Windows runner): silent install with `ALLOWUSER`; service running; the pipe answers; the
  group has the account; WFP provider, sublayer and filters present; a LAN network on a ULA /64
  with a granted port range: `netsh wfp show filters` names the range ends (a range condition is
  looked for and reported, not required) and a connection from a second local address to a granted
  port succeeds while a port outside the range is refused (`-StrictFirewall` in CI makes that a
  failure; `netsh wfp` dumps and net events are uploaded as `msi-test-output`); after the upgrade
  and Yggdrasil, a prefix block on the real engine: a connection to an address inside
  the Yggdrasil node's /64 that SocketGuard did not assign is dropped. That does not prove
  the /64 filter alone (the interface scope of the same adapter drops it too), and the granted-port
  half is SKIPPED when a local-to-local connection does not reach the permit; upgrade (restarted daemon, same
  database file, same stored state, no `uninstall`); removal (service, filters and group gone, data
  kept); `uninstall --purge` with the daemon copied aside; `footprint-check.ps1` from outside after
  each step.
- **portable zip** (Windows runner, `test/portable.ps1`): start from the unzipped folder with
  `--portable`; real WFP filters admit a granted port and block another; a clean exit and a kill
  (no SocketGuard filter may remain, the next start sweeps the addresses); portable and the
  installed service refuse to run side by side. Then, with the Tor and Yggdrasil section shared with the MSI
  test (`test/networks.ps1`): a Tor becomes up (bootstrapped, up to 10 minutes) and
  `tor.exe` runs as the same account as the portable daemon; a Yggdrasil creates the
  `SocketGuard` adapter (SKIPPED with the exact error in `ygg-adapter-error.txt` when the runner
  cannot, never faked); `data\tor` and `data\yggdrasil` are not inherited from `data\`; after the
  clean exit no child, adapter or `third_party` process is left, `session.json` is gone, the Wintun
  driver is removed if and only if the driver store did not have it before, and `footprint-check`
  agrees. Not covered: the kill with a Yggdrasil (the driver staying after it).
- **deb** (Ubuntu 22.04 VM with systemd): install, unit active and enabled, socket answers, nft
  table, upgrade restarts onto the new binary and keeps the database inode and state, Tor
  (as `socketguard-net`) and Yggdrasil (skipped without `/dev/net/tun`), remove, purge.
- **rpm** (`test/rpm.sh`): dependency resolution, file list, scriptlets and library check in a Fedora
  container without systemd (the service is not started or removed there). It also checks that the
  bundled `tor`, `yggdrasil` and the obfs4 helper are in the package, run as an unprivileged user
  (`setpriv`) and find their libraries. No Tor or Yggdrasil network runs from an rpm.
- **rpm on systemd** (`rpm-systemd` job, Fedora container with systemd as PID 1 on the Ubuntu VM, `test/rpm-systemd.sh`): install, `Type=notify` unit active with the nft table present at once, socket, a restart that brings the table back before it returns, upgrade restart onto the same database and state, `dnf remove`, then purge by command and erase.
- **pkg** (macOS runners `macos-latest` = arm64 and `macos-15-intel` = x86_64, per GitHub's runner table; same test on both): install, launchd daemon answering, pf anchor line, upgrade restart,
  Tor and Yggdrasil, `uninstall --keep-data`, `uninstall --purge` restores `/etc/pf.conf`,
  then the manual removal.

Not covered: the installer dialogs (CI installs silently; the access dialog, the WebView2 note and
the `FORCEREMOVE` path are built but never clicked or run), a standard user elevating with an
administrator's credentials, Windows 10, Linux distributions other than Ubuntu 22.04 and Fedora,
signing, and every dialog (see docs/manual-checks.md for the checklist a person runs once).
