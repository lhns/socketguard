# Helpers for the Tor and Yggdrasil checks (ADR 0052) of test/msi.ps1 and test/portable.ps1.
# Dot-sourced after test/lib.ps1 (Ok, Skip, Fail, Run, Wait-Until); the including script defines
# $Cli, and $script:MnLogBase with Daemon-Log for the daemon log.

$script:mnAdapterSeen = $false
$script:mnWintun = $null

function Mn-Net([string]$Id) {
  $r = Run $Cli @('networks', 'list', '--json') $null
  if ($r.Code -ne 0) { return $null }
  try { return @($r.Text | ConvertFrom-Json) | Where-Object { $_.id -eq $Id } | Select-Object -First 1 } catch { return $null }
}
function Mn-Describe($n) {
  if (-not $n) { return 'no such network' }
  $extra = ''
  if ($n.child -and $n.child.progress) { $extra = " $($n.child.progress)%" }
  $ms = ''
  $detail = ''
  if ($n.child) { $ms = "$($n.child.state)"; $detail = "$($n.child.detail)" }
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
  Write-Host "networks: $m" -ForegroundColor Red
  Write-Host '--- socketguard networks list ---'
  Write-Host (Run $Cli @('networks', 'list') 'mn-networks-list').Text
  Write-Host (Run $Cli @('networks', 'list', '--json') 'mn-networks-json').Text
  Write-Host '--- tor, yggdrasil and the daemon ---'
  Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(tor|yggdrasil|socketguard)' } |
    Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize | Out-String | Write-Host
  if ($script:MnLogBase) {
    Write-Host '--- daemon log (last 120 lines; carries the Tor lines and the Tor health failures) ---'
    Write-Host ((Daemon-Log $script:MnLogBase) -split "`n" | Select-Object -Last 120 | Out-String)
  }
  Write-Host '--- adapters ---'
  Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Format-Table Name, InterfaceDescription, Status -AutoSize | Out-String | Write-Host
  Fail "networks: $m"
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
