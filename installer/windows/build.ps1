# Build the Windows MSI.
#
#   installer/windows/build.ps1 -Version 0.1.0 -Stage dist/stage -Out dist/SocketGuard-0.1.0-x64.msi
#
# -Stage is the staged tree (./build.sh --stage, docs/packaging.md): socketguard-daemon.exe,
# socketguard.exe, socketguard-ui.exe, LICENSE, THIRD_PARTY_NOTICES.md and third_party\ (Tor,
# Yggdrasil, wintun.dll). Everything in third_party\ is installed under <install dir>\third_party\.
# Needs WiX v5 with the UI and Util extensions, which .github/actions/setup-wix installs.
# PowerShell because WiX only runs on Windows.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$Stage,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Arch = 'x64'
)

$ErrorActionPreference = 'Stop'

# An MSI ProductVersion is three numbers and nothing else compares. Refused rather than
# truncated: a version silently rounded to something else is an upgrade that never fires.
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
  Write-Host "not an MSI version: $Version"
  Write-Host '  fix: build the installer for a <major>.<minor>.<patch> version'
  exit 1
}
$parts = $Version -split '\.' | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
  Write-Host "out of range for an MSI version (major/minor <= 255, build <= 65535): $Version"
  exit 1
}

foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'third_party\VERSIONS') {
  if (-not (Test-Path -PathType Leaf (Join-Path $Stage $f))) {
    Write-Host "missing $f in $Stage (run ./build.sh --stage)"
    exit 1
  }
}

$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent (Split-Path -Parent $here)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Get-Id([string]$prefix, [string]$text) {
  $sha = [System.Security.Cryptography.SHA1]::Create()
  $h = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join ''
  return $prefix + $h.Substring(0, 20)
}

# A WiX fragment for the stage's third_party\: one component per file, directories nested.
function New-ThirdPartyFragment([string]$dir, [string]$outFile) {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
  [void]$sb.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
  $ids = New-Object System.Collections.Generic.List[string]
  $emit = {
    param($path, $parentId)
    foreach ($d in Get-ChildItem -LiteralPath $path -Directory) {
      $did = Get-Id 'D_' $d.FullName
      [void]$sb.AppendLine("<DirectoryRef Id=`"$parentId`"><Directory Id=`"$did`" Name=`"$($d.Name)`" /></DirectoryRef>")
      & $emit $d.FullName $did
    }
    foreach ($f in Get-ChildItem -LiteralPath $path -File) {
      $cid = Get-Id 'C_' $f.FullName
      $ids.Add($cid)
      [void]$sb.AppendLine("<Component Id=`"$cid`" Directory=`"$parentId`"><File Id=`"$(Get-Id 'F_' $f.FullName)`" Name=`"$($f.Name)`" Source=`"$($f.FullName)`" KeyPath=`"yes`" /></Component>")
    }
  }
  & $emit $dir 'ThirdPartyDir'
  [void]$sb.AppendLine('<ComponentGroup Id="ThirdParty">')
  foreach ($c in $ids) { [void]$sb.AppendLine("<ComponentRef Id=`"$c`" />") }
  [void]$sb.AppendLine('</ComponentGroup></Fragment></Wix>')
  [System.IO.File]::WriteAllText($outFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

try {
  # The licence the UI shows, derived from LICENSE rather than committed as a second copy.
  $rtf = New-Object System.Text.StringBuilder
  [void]$rtf.Append("{\rtf1\ansi\deff0{\fonttbl{\f0 Courier New;}}\fs18`r`n")
  foreach ($line in Get-Content (Join-Path $Stage 'LICENSE')) {
    $escaped = $line -replace '\\', '\\\\' -replace '\{', '\{' -replace '\}', '\}'
    [void]$rtf.Append("$escaped\par`r`n")
  }
  [void]$rtf.Append("}`r`n")
  Set-Content -Path (Join-Path $work 'license.rtf') -Value $rtf.ToString() -Encoding ascii -NoNewline

  $outDir = Split-Path -Parent $Out
  if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
  $stageAbs = (Resolve-Path $Stage).Path.TrimEnd('\')
  $icon = Join-Path $root 'ui/src-tauri/icons/icon.ico'

  $frag = Join-Path $work 'third_party.wxs'
  New-ThirdPartyFragment (Join-Path $stageAbs 'third_party') $frag

  wix build `
    -arch $Arch `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -bindpath $work `
    -d "StageDir=$stageAbs" -d "Version=$Version" -d "IconFile=$icon" `
    -o $Out `
    (Join-Path $here 'socketguard.wxs') $frag
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$built = Get-Item $Out
Write-Host "$($built.FullName)  $($built.Length) bytes"
