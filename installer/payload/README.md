# Bundled third-party binaries

Every package ships Tor, Yggdrasil and (Windows) `wintun.dll` (ADR 0052). They come from **one
directory per platform**, copied wholesale, and nothing else in the package definitions names
them:

| Directory | Installed to |
|---|---|
| `installer/payload/windows/` | `C:\Program Files\SocketGuard\third_party\` |
| `installer/payload/linux/` | `/usr/lib/socketguard/third_party/` (deb and rpm) |
| `installer/payload/macos/` | `/usr/local/lib/socketguard/third_party/` |

Sub-directories are kept. `README.md` and `.gitkeep` are not installed. With the directory empty
(a development build) the package contains no `third_party` folder (the MSI declares the empty
directory; it is not created on disk) and managed networks say so on their card.

The daemon looks for `third_party` next to its executable (the Windows install, a development
build), then in the package location of its platform (`/usr/lib/socketguard/third_party` on Linux,
`/usr/local/lib/socketguard/third_party` on macOS), then in `$SOCKETGUARD_THIRD_PARTY`; the first
directory that exists wins.

## How files get there

`deploy/bundle/fetch.sh` (pins and checksums in `deploy/bundle/versions.toml`) fills the directory
before `installer/*/build.*` runs. `.github/actions/bundle` does it in CI for each package job:

    deploy/bundle/fetch.sh --require-signature --build-yggdrasil <os>-<arch> installer/payload/<os>/

(`windows-x86_64`, `linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64`; fetch.sh also
knows `windows-aarch64`, but no package is built for it.) It needs
`gpg` (the Tor Project signature on the checksum file is required in CI), Go at least the version in
`versions.toml` (Yggdrasil is built from the pinned commit), `git`, `curl`, and `unzip` on Windows
(fetch.sh falls back to PowerShell's `Expand-Archive`). Downloads and the Yggdrasil source are
cached in `target/bundle-cache` by default (`SOCKETGUARD_BUNDLE_CACHE`; CI uses `.bundle-cache`, keyed on
`versions.toml`). Nothing
downloads at install time, and nothing is committed here except this file and the `.gitkeep`s
(everything else under the platform directories is git-ignored).

The result: `tor/` (the `tor` binary, its libraries, and the obfs4 helper `tor/pluggable_transports/lyrebird`), `yggdrasil/` (`yggdrasil`, and `wintun.dll`
on Windows), `licenses/<name>.txt`, and `VERSIONS` (what `socketguard status` reports).

## What the build scripts do with them

- Windows: `installer/windows/build.ps1` generates a WiX fragment (one component per file) and
  defines `ThirdParty` for `socketguard.wxs`. Program Files is readable and runnable by every
  account, which is what LocalService (the account Tor runs as) needs.
- Portable zip: `installer/windows/portable.ps1` copies the same directory to `third_party\` in the
  zip; the children run as the account of the portable daemon (ADR 0054).
- Linux: `installer/linux/build.sh` appends a `type: tree` entry to the nfpm contents, after setting
  the modes (everyone reads and runs, only root writes): the child processes run as the system
  account `socketguard-net`. The packages depend on the system zlib (`zlib1g`, `zlib`); the Tor
  bundle does not carry `libz.so.1`.
- macOS: `installer/macos/build.sh` copies the directory into the pkg payload with the same modes
  (`pkgbuild --ownership recommended` makes root the owner).

Licence texts: `third_party/licenses/` holds those of the programs; `THIRD_PARTY_NOTICES.md` and
`LICENSE` are installed to `Program Files\SocketGuard\licenses` (Windows), `/usr/share/doc/socketguard/`
(Linux) and the app's `Contents/Resources` plus `/usr/local/share/doc/socketguard/` (macOS).

Files installed this way belong to the package: the package manager removes them on removal.
Anything SocketGuard downloads or starts at run time (a Tor data directory, Yggdrasil keys) is not
in here; those are recorded as owned directories in the install record (ADR 0050).
