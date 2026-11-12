# Build the portable zip (ADR 0054): SocketGuard-portable-windows-x64.zip, one folder that runs
# from anywhere, including a removable drive, and leaves nothing on the computer once it is closed.
#
#   installer/windows/portable.ps1 -Stage dist/stage -Out dist/SocketGuard-portable-windows-x64.zip
#
# -Stage is the staged tree (./build.sh --stage, docs/packaging.md). The zip holds its programs and
# third_party\ (Tor, Yggdrasil, wintun.dll, licences, VERSIONS) like the MSI, plus what only this
# package has: the file named `portable` next to the programs, which is what turns portable mode
# on (made here, never part of the stage, so no other package can carry it), LICENSE.txt,
# NOTICE.txt and README.txt.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Stage,
  [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'

foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe', 'LICENSE', 'third_party\VERSIONS') {
  if (-not (Test-Path -PathType Leaf (Join-Path $Stage $f))) {
    Write-Host "missing $f in $Stage (run ./build.sh --stage)"
    exit 1
  }
}

$name = 'SocketGuard-portable-windows-x64'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$dest = Join-Path $work $name
New-Item -ItemType Directory -Force -Path $dest | Out-Null

try {
  foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe') {
    Copy-Item (Join-Path $Stage $f) $dest
  }
  Copy-Item -Recurse (Join-Path $Stage 'third_party') (Join-Path $dest 'third_party')
  # The marker. Its content is not read; the text is for whoever finds it.
  Set-Content -Path (Join-Path $dest 'portable') -Encoding ascii -Value 'This file turns on SocketGuard portable mode. See README.txt.'

  Copy-Item (Join-Path $Stage 'LICENSE') (Join-Path $dest 'LICENSE.txt')
  # Bundled third-party software carries its own licences next to its files (third_party\);
  # this file says which they are.
  $notice = @(
    'SocketGuard is licensed under the Apache License 2.0 (LICENSE.txt).',
    'Programs bundled in third_party\ (when present) keep their own licences, which are',
    'in their folders there.'
  )
  Set-Content -Path (Join-Path $dest 'NOTICE.txt') -Encoding ascii -Value $notice

  $readme = @'
SocketGuard, portable
=====================

How to start
  Double-click socketguard-ui.exe. SocketGuard shows "runs from this folder and is not
  started". Press Start and allow the administrator prompt. Command line:
  socketguard.exe status   (and every other socketguard.exe command) works while it runs.

What it does on this computer
  While SocketGuard runs, it adds firewall rules (Windows Filtering Platform, named
  SocketGuard) and IPv6 addresses on your network adapters, and it listens on a private
  pipe named \\.\pipe\socketguard-portable. Everything it keeps (settings, database, logs)
  is in the data folder next to the programs. Nothing is written to ProgramData, the
  registry or any other folder, and no service or user group is created.
  The window keeps its own browser data in the ui-data folder next to it.
  One exception: if you add SocketGuard's own Yggdrasil network, Windows installs the Wintun
  network driver, which belongs to the computer. A normal exit removes it again if it was not
  there before; if SocketGuard is killed, it stays until the next normal exit from this folder.

Protection ends with the window
  The rules and addresses are removed when you close SocketGuard, sign out or shut down.
  If SocketGuard is killed or crashes, the rules are removed by Windows at once and the
  computer is open as it was before SocketGuard started - not closed. Addresses a crash
  leaves are removed the next time you start SocketGuard from this folder, or at reboot.
  This mode is for using SocketGuard on a computer for a while, not for protecting it
  permanently. Install SocketGuard (the MSI) for that.

Needs
  Administrator rights at every start. It does not start while the installed SocketGuard
  service exists on the computer, and the installed service does not start while this runs.
  The folder is writable by you, so anything running as you can change what then runs with
  administrator rights. Keep it where only you can write, or use the installed SocketGuard.

How to remove it
  Close SocketGuard, then delete this folder. Your settings are in its data folder: keep
  that folder to keep them.
'@
  Set-Content -Path (Join-Path $dest 'README.txt') -Encoding ascii -Value $readme

  $outDir = Split-Path -Parent $Out
  if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
  if (Test-Path $Out) { Remove-Item -Force $Out }
  Compress-Archive -Path $dest -DestinationPath $Out -CompressionLevel Optimal
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$built = Get-Item $Out
Write-Host "$($built.FullName)  $($built.Length) bytes"
