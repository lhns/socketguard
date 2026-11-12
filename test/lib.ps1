# Helpers the Windows package tests share (test/msi.ps1, test/portable.ps1, test/networks.ps1).
# Dot-sourced, not run. Each scenario script stays its own readable sequence.
#
# The including script defines, before calling anything here:
#   $Out         the directory the run keeps its output in
#   $Footprint   path of deploy/ci/footprint-check.ps1 (for Assert-Footprint)
#   On-Fail      (optional) a function with the script's own diagnostics and cleanup; Fail calls it

$script:section = ''
$script:okCount = 0
$script:skipped = New-Object System.Collections.Generic.List[string]

function Section([string]$t) { $script:section = $t; Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }

function Ok([string]$m) { $script:okCount++; Write-Host "  ok: $m" }

# A check this runner cannot do: said with the exact reason, shown as a CI warning and listed by
# Write-Summary, never faked.
function Skip([string]$m) {
  $script:skipped.Add($m)
  Write-Host "  SKIPPED: $m" -ForegroundColor Yellow
  Write-Host "::warning::SKIPPED: $m"
}

function Write-Summary([string]$Label) {
  Write-Host "${Label}: $($script:okCount) checks passed, $($script:skipped.Count) skipped"
  foreach ($s in $script:skipped) { Write-Host "  skipped: $s" }
}

function Fail([string]$m) {
  Write-Host "FAIL [$script:section] $m" -ForegroundColor Red
  if (Get-Command On-Fail -ErrorAction SilentlyContinue) { On-Fail }
  exit 1
}

function Wait-Until([scriptblock]$Cond, [int]$Seconds, [string]$What = '') {
  $end = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $end) {
    if (& $Cond) { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

# Run a program to completion, keep its output in $Out, return @{Code; Text}.
function Run([string]$Exe, [string[]]$Arguments, [string]$Tag, [int]$TimeoutSec = 120) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $o = $p.StandardOutput.ReadToEndAsync()
  $e = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) { Stop-Process -Id $p.Id -Force; Fail "$Exe $($Arguments -join ' ') hung" }
  $text = $o.Result + $e.Result
  if ($Tag) { Set-Content -Path (Join-Path $Out "$Tag.txt") -Value "$Exe $($Arguments -join ' ')`nexit $($p.ExitCode)`n$text" }
  return @{ Code = $p.ExitCode; Text = $text }
}

function Service-State { $s = Get-Service SocketGuard -ErrorAction SilentlyContinue; if ($s) { return "$($s.Status)" } return 'absent' }

function Try-Connect([string]$Ip, [int]$Port, [string]$From) {
  try {
    $c = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    if ($From) { $c.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($From), 0))) }
    $t = $c.ConnectAsync([System.Net.IPAddress]::Parse($Ip), $Port)
    $ok = $t.Wait(4000) -and $c.Connected
    $c.Close()
    return [bool]$ok
  } catch { return $false }
}

# deploy/ci/footprint-check.ps1 from outside; its output is kept in $Out.
function Assert-Footprint([hashtable]$Params, [string]$Tag) {
  $o = & $Footprint @Params 2>&1 | Out-String
  $code = $LASTEXITCODE
  Set-Content -Path (Join-Path $Out "footprint-$Tag.txt") -Value $o
  Write-Host $o
  if ($code -ne 0) { Fail "footprint-check exited $code" }
  Ok "footprint-check $Tag"
}
