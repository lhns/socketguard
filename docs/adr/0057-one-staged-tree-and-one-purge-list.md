# ADR 0057: One Staged Tree per System, One Purge List

## Status

Accepted. Refines ADR 0050 (packages) and ADR 0052 (where the bundled files are laid out before packaging).

## Date

2026-11-12

## Context

Each package builder took the programs from `target/release` and the bundled Tor, Yggdrasil and Wintun from `installer/payload/<os>/`, filled by a CI action, and the Windows MSI and zip were built and tested in separate jobs that each rebuilt the product. The Debian postrm named by hand what `uninstall --purge` deletes, and a unit test compared the two. The same list was a third time in `deploy/ci/footprint-check.*` and in `docs/footprint.md`.

## Decision

- `./build.sh --stage [dir]` builds and leaves everything a package of the host system ships in one flat directory (default `dist/stage`): the three programs, `third_party/`, `LICENSE`, `THIRD_PARTY_NOTICES.md` (layout in docs/packaging.md). The builders (`installer/windows/build.ps1`, `portable.ps1`, `installer/linux/build.sh`, `installer/macos/build.sh`) take that directory and nothing else. `installer/payload/` is gone. The `portable` marker is made by the zip step only.
- A system builds once. The Windows job makes the MSI, the MSI of the next version and the zip; the test jobs download finished packages. Only finished packages travel between jobs.
- `crates/daemon/src/footprint.rs` is the one list of what `uninstall --purge` deletes by name (files, temp-file prefix, the networks' data trees, directories removed when empty, the account created by the install). `named_files` derives from it. `socketguard-daemon uninstall --print-purge-list [--os <system>]` prints the list of the fixed installed paths of a system, independent of the machine it runs on. `installer/linux/build.sh` embeds that output in the deb postrm, whose loop only interprets the line kinds.
- The footprint checkers stay hand-written and independent of the daemon. A cargo test (`crates/daemon/tests/footprint_list.rs`, run by `ci.yml`) checks one way that everything the list holds for Linux, macOS and Windows is looked for by the checker of that system and described in `docs/footprint.md`.

## Consequences

- A change to what purge removes is made in one place; the postrm cannot go out of step, and the consistency test fails until the checker and the document say the same.
- The product runs in place from the stage, so `--stage` is also the way to try a build with Tor and Yggdrasil. `--with-bundled` stays for runs from `target/<profile>`.
- The deb's list is made at build time from the daemon that goes into the package; there is no list on the host at removal and no fallback list.
- Items the daemon removes by record (the owned directories) are listed by their fixed names; a purge from a non-default state directory still removes them by the record, the postrm only the fixed ones.
