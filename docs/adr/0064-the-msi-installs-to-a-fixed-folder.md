# ADR 0064: The MSI Installs to a Fixed Folder

## Status

Accepted. Refines ADR 0050 (installed as a service, with fixed paths).

## Date

2026-11-13

## Context

The service runs as LocalSystem from the install folder, and `socketguard.exe` and the UI are
started by users from it. The MSI let the user choose that folder (the `WixUI_InstallDir` dialog,
and `INSTALLFOLDER=...` on the command line). A folder outside Program Files that ordinary users
can write to would let any of them replace the daemon and get SYSTEM.

## Decision

The folder is `%ProgramFiles%\SocketGuard`, fixed. The MSI uses the `WixUI_FeatureTree` dialog set
(plus the access-group dialog) so no folder dialog exists, and the directory ids are not all upper
case (`InstallFolder`, `ThirdPartyDir`, `LicensesDir`), so they are not public properties and a
command line cannot set them. `test/msi.ps1` installs with `INSTALLFOLDER=C:\SgElsewhere` and checks
that the files, the service and the PATH entry are under Program Files and that the folder does not
exist. Anyone who needs another location uses the portable zip (ADR 0054).

## Consequences

- The privilege escalation through a user-chosen folder is closed by construction, not by a check.
- Installing to another drive or a per-user folder is not possible with the MSI.
- A future dialog set or directory must keep non-public ids.
