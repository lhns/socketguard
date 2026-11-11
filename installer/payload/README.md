# Bundled third-party binaries

A later step bundles Tor, Yggdrasil and `wintun.dll`. Every package picks them up from **one
directory per platform**, copied wholesale, and nothing else in the package definitions names
them:

| Directory | Installed to |
|---|---|
| `installer/payload/windows/` | `C:\Program Files\SocketGuard\third_party\` |
| `installer/payload/linux/` | `/usr/lib/socketguard/third_party/` (deb and rpm) |
| `installer/payload/macos/` | `/usr/local/lib/socketguard/third_party/` |

Sub-directories are kept. `README.md` and `.gitkeep` are not installed. The directories are empty
today, so the packages contain no `third_party` folder (the MSI declares the empty directory; it is
not created on disk).

How files get there: a download step in the build (one per platform, verifying a pinned
checksum) puts them in the directory before `installer/*/build.*` runs. Nothing downloads at
install time, and nothing is committed here except this file and the `.gitkeep`s.

Each build script notices the files by itself:

- Windows: `installer/windows/build.ps1` generates a WiX fragment (one component per file) and
  defines `ThirdParty` for `socketguard.wxs`.
- Linux: `installer/linux/build.sh` appends a `type: tree` entry to the nfpm contents.
- macOS: `installer/macos/build.sh` copies the directory into the pkg payload.

Files installed this way belong to the package: the package manager removes them on removal.
Anything SocketGuard downloads or starts at run time (a Tor data directory, Yggdrasil keys) is not
in here; those are recorded as owned directories in the install record (ADR 0050).
