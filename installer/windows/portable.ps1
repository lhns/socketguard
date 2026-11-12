# Build the portable zip (ADR 0054): SocketGuard-portable-windows-x64.zip, one folder that runs
# from anywhere, including a removable drive, and leaves nothing on the computer once it is closed.
#
#   installer/windows/portable.ps1 -BinDir target/release -Out dist/SocketGuard-portable-windows-x64.zip
#
# -BinDir holds socketguard-daemon.exe, socketguard.exe and socketguard-ui.exe (./build.sh puts them
# in target/release). The file named `portable` next to the programs is what turns portable mode on.
# Files in installer/payload/windows/ are copied to third_party\ like the MSI does.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'

foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe') {
  if (-not (Test-Path -PathType Leaf (Join-Path $BinDir $f))) {
    Write-Host "missing $f in $BinDir"
    exit 1
  }
}

$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent (Split-Path -Parent $here)
$name = 'SocketGuard-portable-windows-x64'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$stage = Join-Path $work $name
New-Item -ItemType Directory -Force -Path $stage | Out-Null

try {
  foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe') {
    Copy-Item (Join-Path $BinDir $f) $stage
  }
  # The marker. Its content is not read; the text is for whoever finds it.
  Set-Content -Path (Join-Path $stage 'portable') -Encoding ascii -Value 'This file turns on SocketGuard portable mode. See README.txt.'

  $payload = Join-Path $root 'installer/payload/windows'
  if (Test-Path $payload) {
    $files = @(Get-ChildItem -LiteralPath $payload -Recurse -File | Where-Object { $_.Name -notin @('.gitkeep', 'README.md') })
    if ($files.Count -gt 0) {
      $dest = Join-Path $stage 'third_party'
      foreach ($f in $files) {
        $rel = $f.FullName.Substring((Resolve-Path $payload).Path.TrimEnd('\').Length + 1)
        $target = Join-Path $dest $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item $f.FullName $target
      }
      Write-Host "third_party payload included from $payload"
    }
  }

  Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'LICENSE.txt')
  # Bundled third-party software carries its own licences next to its files (third_party\);
  # this file says which they are.
  $notice = @(
    'SocketGuard is licensed under the Apache License 2.0 (LICENSE.txt).',
    'Programs bundled in third_party\ (when present) keep their own licences, which are',
    'in their folders there.'
  )
  Set-Content -Path (Join-Path $stage 'NOTICE.txt') -Encoding ascii -Value $notice

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
  Set-Content -Path (Join-Path $stage 'README.txt') -Encoding ascii -Value $readme

  $outDir = Split-Path -Parent $Out
  if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
  if (Test-Path $Out) { Remove-Item -Force $Out }
  Compress-Archive -Path $stage -DestinationPath $Out -CompressionLevel Optimal
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$built = Get-Item $Out
Write-Host "$($built.FullName)  $($built.Length) bytes"
