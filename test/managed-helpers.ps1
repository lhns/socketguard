# Helpers for the managed Tor and Yggdrasil checks (ADR 0052) of test/msi.ps1 and
# test/portable.ps1. Dot-sourced: the including script defines $Cli, $Out, Run, Fail and
# Wait-Until (Cond, Seconds[, What]) and gets its own counters.
#
# Own counters and summary lines; a check the runner cannot do is SKIPPED with the exact reason
# and listed at the end, never faked.

$script:mnOk = 0
$script:mnSkipped = New-Object System.Collections.Generic.List[string]
$script:mnAdapterSeen = $false
$script:mnWintun = $null

function Mn-Ok([string]$m) { $script:mnOk++; Write-Host "  ok: $m" }
function Mn-Skip([string]$m) {
  $script:mnSkipped.Add($m)
  Write-Host "  SKIPPED: $m" -ForegroundColor Yellow
  Write-Host "::warning::managed networks: SKIPPED: $m"
}
function Mn-Net([string]$Id) {
  $r = Run $Cli @('networks', 'list', '--json') $null
  if ($r.Code -ne 0) { return $null }
  try { return @($r.Text | ConvertFrom-Json) | Where-Object { $_.id -eq $Id } | Select-Object -First 1 } catch { return $null }
}
function Mn-Describe($n) {
  if (-not $n) { return 'no such network' }
  $extra = ''
  if ($n.managed -and $n.managed.progress) { $extra = " $($n.managed.progress)%" }
  $ms = ''
  $detail = ''
  if ($n.managed) { $ms = "$($n.managed.state)"; $detail = "$($n.managed.detail)" }
  return "$($n.status.state) $($n.status.reason) [$ms$extra] $detail"
}
function Mn-Procs([string]$Name) {
  return @(Get-CimInstance Win32_Process -Filter "Name='$Name'" -ErrorAction SilentlyContinue |
      Where-Object { (-not $_.ExecutablePath) -or ($_.ExecutablePath -like '*\third_party\*') })
}
function Mn-Owner($p) {
  $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
  if ($o.ReturnValue -ne 0) { return "unknown (GetOwner returned $($o.ReturnValue))" }
  return "$($o.Domain)\$($o.User)"
}
function Mn-Adapter {
  return Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'SocketGuard' -or $_.InterfaceDescription -match 'Wintun' } | Select-Object -First 1
}
function Mn-Fail([string]$m) {
  Write-Host "managed networks: $m" -ForegroundColor Red
  Write-Host '--- socketguard networks list ---'
  Write-Host (Run $Cli @('networks', 'list') 'mn-networks-list').Text
  Write-Host (Run $Cli @('networks', 'list', '--json') 'mn-networks-json').Text
  Write-Host '--- tor, yggdrasil and the daemon ---'
  Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(tor|yggdrasil|socketguard)' } |
    Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize | Out-String | Write-Host
  Write-Host '--- adapters ---'
  Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Format-Table Name, InterfaceDescription, Status -AutoSize | Out-String | Write-Host
  Fail "managed networks: $m"
}
function Mn-WaitUp([string]$Id, [int]$Seconds) {
  $end = (Get-Date).AddSeconds($Seconds); $last = ''
  while ($true) {
    $n = Mn-Net $Id
    if ($n -and $n.status.state -eq 'up') { return $true }
    $now = Mn-Describe $n
    if ($now -ne $last) { Write-Host "  ${Id}: $now"; $last = $now }
    if ((Get-Date) -gt $end) { return $false }
    Start-Sleep -Seconds 2
  }
}
