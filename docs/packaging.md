# Packages and releases (ADR 0050)

Every package only calls commands of the daemon binary, so the logic is tested once and the
packages stay thin. Definitions: `installer/windows/` (WiX), `installer/linux/` (nfpm),
`installer/macos/` (pkgbuild). CI: `.github/workflows/packages.yml` builds each, installs it on a
real runner and checks the host from outside with `deploy/ci/footprint-check.*`;
`release.yml` reuses it.

**Bundled Tor and Yggdrasil (ADR 0052).** Each package job first runs `.github/actions/bundle`,
which calls `deploy/bundle/fetch.sh --require-signature --build-yggdrasil <os>-<arch>
installer/payload/<os>/` (Tor Expert Bundle with its Tor Project signature, Yggdrasil built from the
pinned commit with Go, `wintun.dll` on Windows; `gpg` and Go are installed on the runner when
missing, downloads are cached on `hashFiles('deploy/bundle/versions.toml')`). The build scripts then
pick the files up (`installer/payload/README.md`). They land in `C:\Program Files\SocketGuard	hird_party\`,
`/usr/lib/socketguard/third_party/` and `/usr/local/lib/socketguard/third_party/`; the daemon looks
there (and next to its executable, then `$SOCKETGUARD_THIRD_PARTY`). Modes are set so the
unprivileged account the children run as can run them: `socketguard-net` on Linux and macOS (the
Linux packages depend on `zlib1g` / `zlib` for the `libz.so.1` Tor needs), LocalService on Windows
(Program Files is readable by everyone). The CI builds Windows x86_64, Linux x86_64 (the nfpm file
says `arch: amd64`) and macOS for both architectures (an Apple silicon and an Intel runner each build and test
their own pkg). Linux aarch64 is fetchable (`fetch.sh linux-aarch64`) but no job builds or tests it.

| | Install | Upgrade | Remove | Purge |
|---|---|---|---|---|
| **MSI** (Windows, per machine) | `service install`; `access allow <ALLOWUSER>` when given | the same, after the old version is removed without `uninstall`; the service is restarted | `uninstall --keep-data --yes` | `socketguard-daemon uninstall --purge` (the MSI never deletes data) |
| **deb** | postinst `configure`: `service install` | the same (`configure` runs again); a running daemon is restarted | prerm `remove`: `uninstall --keep-data --yes` | postrm `purge`: deletes the named files, `<state>/tor`, `<state>/yggdrasil`, and `socketguard-net` when the install record says the install created it (`apt purge`) |
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

- `installer/windows/portable.ps1 -BinDir target/release -Out dist/portable/SocketGuard-portable-windows-x64.zip`
  builds one folder: the three programs, the `portable` marker, README, LICENSE and NOTICE, and
  `third_party\` (Tor, Yggdrasil, `wintun.dll`, licences, `VERSIONS`) when `installer/payload/windows/`
  holds them. The `portable` job of `packages.yml` runs the same `.github/actions/bundle` step as the
  MSI job before building the zip, so the zip carries them and managed networks work from it.
- No installer ran, so nothing set up an account for the children: managed Tor and Yggdrasil run as
  the account of the elevated portable daemon (the card says "the account running portable
  SocketGuard"), and `data\tor` and `data\yggdrasil` have a protected access list that the read
  access of the allowed user on `data\` does not reach.
- Whether the Wintun driver was in the driver store before the first managed Yggdrasil start is kept
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
- No systemd (a container): the scripts print a note and do nothing; run
  `socketguard-daemon service install` where systemd runs.
- `SOCKETGUARD_FORCE_REMOVE=1` makes the remove scripts pass `--force` and ignore a failure.
- The deb `postrm` cannot run the daemon (the file is gone at purge). It deletes the same named
  files; `the_debian_postrm_names_what_purge_deletes` (crates/daemon/src/uninstall.rs) fails when
  the list and `named_files` differ.
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
builds and tests all packages, and creates a **draft** release with the MSI, deb, rpm, pkg and
`SHA256SUMS`. The release notes name the shipped Tor, Yggdrasil and Wintun versions (read from
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

`packages.yml` on every push to `installers`, `redesign` and `main`, and for each release. Every
job also has the **managed networks section** (`test/managed.sh` on Linux and macOS, `test/msi.ps1`
on Windows), summarised in a line `managed networks: N checks passed, M skipped`:

- after the install: `status --json` names the bundled `tor` and `yggdrasil` with the versions of
  `third_party/VERSIONS` and the directory the daemon found; the licence texts and notices are
  installed; the unprivileged account can run the installed `tor` and `yggdrasil` (Linux, macOS:
  `socketguard-net`; Windows: a task as LocalService, plus the ACL);
- after the upgrade: `networks add tor` becomes up (bootstrapped, up to 5 minutes), tor runs as
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
`deploy/e2e/`: `managed-ygg-e2e.sh`, `managed-tor-e2e.sh`, `ygg-e2e.sh`, `tor-e2e.sh`.

- **MSI** (Windows runner): silent install with `ALLOWUSER`; service running; the pipe answers; the
  group has the account; WFP provider, sublayer and filters present; a LAN network on a ULA /64
  with a granted port range: one `FWP_MATCH_RANGE` filter and a connection from a second local
  address to a granted port succeeds while a port outside the range is refused (`netsh wfp`
  dumps and net events are uploaded as `msi-test-output`); upgrade (restarted daemon, same
  database file, same stored state, no `uninstall`); removal (service, filters and group gone, data
  kept); `uninstall --purge` with the daemon copied aside; `footprint-check.ps1` from outside after
  each step.
- **portable zip** (Windows runner, `test/portable.ps1`): start from the unzipped folder with
  `--portable`; real WFP filters admit a granted port and block another; a clean exit and a kill
  (no SocketGuard filter may remain, the next start sweeps the addresses); portable and the
  installed service refuse to run side by side. Then, with the managed section shared with the MSI
  test (`test/managed-helpers.ps1`): a managed Tor becomes up (bootstrapped, up to 5 minutes) and
  `tor.exe` runs as the same account as the portable daemon; a managed Yggdrasil creates the
  `SocketGuard` adapter (SKIPPED with the exact error in `ygg-adapter-error.txt` when the runner
  cannot, never faked); `data\tor` and `data\yggdrasil` are not inherited from `data\`; after the
  clean exit no child, adapter or `third_party` process is left, `session.json` is gone, the Wintun
  driver is removed if and only if the driver store did not have it before, and `footprint-check`
  agrees. Not covered: the kill with a managed Yggdrasil (the driver staying after it).
- **deb** (Ubuntu 22.04 VM with systemd): install, unit active and enabled, socket answers, nft
  table, upgrade restarts onto the new binary and keeps the database inode and state, remove, purge.
- **rpm**: dependency resolution, file list, scriptlets and library check in a Fedora container
  without systemd, plus the full life cycle in one that runs systemd. It also checks that the bundled
  `tor` and `yggdrasil` are in the package, run as an unprivileged user (`setpriv`) and find their libraries.
- **rpm on systemd** (`rpm-systemd` job, Fedora container with systemd as PID 1 on the Ubuntu VM, `test/rpm-systemd.sh`): install, unit active, socket, nft table, upgrade restart, `dnf remove`, then purge by command and erase.
- **pkg** (macOS runners `macos-latest` = arm64 and `macos-15-intel` = x86_64, per GitHub's runner table; same test on both): install, launchd daemon answering, pf anchor line, upgrade restart,
  `uninstall --purge` restores `/etc/pf.conf`, then the manual removal.

Not covered: the installer dialogs (CI installs silently; the access dialog, the WebView2 note and
the `FORCEREMOVE` path are built but never clicked or run), a standard user elevating with an
administrator's credentials, Windows 10, Linux distributions other than Ubuntu 22.04 and Fedora,
signing, and every dialog (see docs/manual-checks.md for the checklist a person runs once).
