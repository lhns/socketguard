# The Windows installer, end to end, on a throwaway machine (the CI runner):
#
#   pwsh test/msi.ps1 -Msi dist/SocketGuard-0.1.0-x64.msi -MsiNext dist/SocketGuard-0.1.1-x64.msi `
#        -Out dist/msi-test
#
# Installs silently (ALLOWUSER = the current user), checks the service, the pipe, the group,
# the data directory and the firewall objects, exercises the real WFP filters once, upgrades
# to the next MSI (no `uninstall` may run: the data and rules stay and the service is
# restarted), removes the MSI (the service and rules go, the data stays), then purges with a
# copy of the daemon kept aside, and checks from outside that nothing is left.
#
# Machine-wide changes, elevated, no prompts: never run it on a machine you use.
# Everything worth reading afterwards (msiexec logs, `netsh wfp` dumps, the daemon's output) goes
# to -Out, which the workflow uploads.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [Parameter(Mandatory = $true)][string]$MsiNext,
  [Parameter(Mandatory = $true)][string]$Out,
  # The firewall exercise (listener, port range, connection attempts) only reports until this is set.
  [switch]$StrictFirewall
)

$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$MsiNext = (Resolve-Path $MsiNext).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$InstallDir = Join-Path $env:ProgramFiles 'SocketGuard'
$Daemon = Join-Path $InstallDir 'socketguard-daemon.exe'
$Cli = Join-Path $InstallDir 'socketguard.exe'
$DataDir = Join-Path $env:ProgramData 'SocketGuard'
$Aside = Join-Path ([IO.Path]::GetTempPath()) 'sg-aside'
$Footprint = Join-Path $Root 'deploy/ci/footprint-check.ps1'
$User = $env:USERNAME
$script:section = ''
$script:soft = New-Object System.Collections.Generic.List[string]

function Section([string]$t) { $script:section = $t; Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "  ok: $m" }
function Soft([string]$m) {
  if ($StrictFirewall) { Fail $m }
  $script:soft.Add("[$script:section] $m"); Write-Host "  SOFT-FAIL: $m" -ForegroundColor Yellow; Write-Host "::warning::$m"
}

# What a failed start looks like from the outside: the service reports Running before the
# daemon has initialised and writes no log, so look at the event log and run the daemon in the
# foreground for a few seconds to see its stderr.
function Dump-Diagnostics {
  Write-Host '--- diagnostics ---'
  try {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 15 -ErrorAction Stop |
      ForEach-Object { Write-Host "$($_.TimeCreated) $($_.Id) $($_.Message)" }
  } catch { Write-Host "no SCM events: $_" }
  try { Get-CimInstance Win32_Service -Filter "Name='SocketGuard'" | Format-List Name, State, ExitCode, PathName | Out-String | Write-Host } catch {}
  if (Test-Path $Daemon) {
    try {
      & sc.exe stop SocketGuard | Out-Null
      Start-Sleep -Seconds 3
      $o = Join-Path $Out 'daemon-foreground.txt'
      $p = Start-Process -FilePath $Daemon -PassThru -NoNewWindow -RedirectStandardError $o -RedirectStandardOutput "$o.out"
      Start-Sleep -Seconds 8
      if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
      Write-Host '--- daemon in the foreground (stderr) ---'
      Get-Content $o -ErrorAction SilentlyContinue | Select-Object -First 60 | Write-Host
      Get-Content "$o.out" -ErrorAction SilentlyContinue | Select-Object -First 60 | Write-Host
    } catch { Write-Host "foreground run failed: $_" }
  }
  Save-Wfp 'failure'
  try {
    Write-Host '--- who am I, and who may read the data directory ---'
    & whoami /groups | Select-String 'Label|Administrators' | Write-Host
    if (Test-Path $DataDir) { & icacls $DataDir /t 2>&1 | Write-Host }
  } catch {}
  Get-ChildItem $Out -Filter *.log | ForEach-Object { Write-Host "== $($_.Name) (tail)"; Get-Content $_.FullName -Tail 80 | Write-Host }
}

function Fail([string]$m) {
  Write-Host "FAIL [$script:section] $m" -ForegroundColor Red
  Dump-Diagnostics
  exit 1
}

function Invoke-Msi([string[]]$Arguments, [string]$Tag, [int]$Expect = 0) {
  $log = Join-Path $Out "$Tag.log"
  $all = $Arguments + @('/qn', '/l*v', $log)
  Write-Host "  msiexec $($all -join ' ')"
  $p = Start-Process -FilePath msiexec.exe -ArgumentList $all -PassThru
  if (-not $p.WaitForExit(10 * 60 * 1000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Fail "msiexec ($Tag) did not finish within 10 minutes"
  }
  if ($p.ExitCode -ne $Expect) {
    Write-Host "  exit $($p.ExitCode), expected $Expect; the lines that matter:"
    if (Test-Path $log) {
      Get-Content $log | Where-Object { $_ -match 'Return value 3|DEBUG: Error|Error \d{4}|returned actual error|WixQuietExec|socketguard|SOFTWARE\\|Failed|failed' -and $_ -notmatch 'SELECT `Message`' } |
        Select-Object -First 80 | Write-Host
    }
    Fail "msiexec ($Tag) exited $($p.ExitCode), expected $Expect"
  }
  Ok "msiexec ($Tag) exited $Expect"
}

# Run a program, keep its output in $Out, return @{Code; Text}.
function Run([string]$Exe, [string[]]$Arguments, [string]$Tag) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $o = $p.StandardOutput.ReadToEndAsync()
  $e = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(120000)) { Stop-Process -Id $p.Id -Force; Fail "$Exe $($Arguments -join ' ') hung" }
  $text = $o.Result + $e.Result
  if ($Tag) { Set-Content -Path (Join-Path $Out "$Tag.txt") -Value "$Exe $($Arguments -join ' ')`nexit $($p.ExitCode)`n$text" }
  return @{ Code = $p.ExitCode; Text = $text }
}

function Save-Wfp([string]$Tag) {
  foreach ($w in @(@('filters', "wfp-filters-$Tag.xml"), @('state', "wfp-state-$Tag.xml"), @('netevents', "wfp-netevents-$Tag.xml"))) {
    try { & netsh wfp show $w[0] file=(Join-Path $Out $w[1]) 2>&1 | Out-Null } catch { Write-Host "netsh wfp show $($w[0]) failed: $_" }
  }
}

function Wait-Until([scriptblock]$Cond, [int]$Seconds, [string]$What) {
  $end = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $end) {
    if (& $Cond) { return $true }
    Start-Sleep -Milliseconds 700
  }
  return $false
}

function Service-State { $s = Get-Service SocketGuard -ErrorAction SilentlyContinue; if ($s) { return "$($s.Status)" } return 'absent' }
function Service-Pid { $c = Get-CimInstance Win32_Service -Filter "Name='SocketGuard'" -ErrorAction SilentlyContinue; if ($c) { return [int]$c.ProcessId } return 0 }

function Assert-Footprint([hashtable]$Params, [string]$Tag) {
  $o = & $Footprint @Params 2>&1 | Out-String
  $code = $LASTEXITCODE
  Set-Content -Path (Join-Path $Out "footprint-$Tag.txt") -Value $o
  Write-Host $o
  if ($code -ne 0) { Fail "footprint-check exited $code" }
  Ok "footprint-check $Tag"
}

# ---- the firewall exercise: the first real run of the WFP code ---------------------------

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

function Invoke-FirewallExercise {
  Section 'firewall: network, listener, port range, connections'
  Write-Host (Run $Cli @('networks', 'detect') 'fw-networks-detect').Text
  Write-Host (Run $Cli @('networks', 'list', '--json') 'fw-networks-list').Text

  # A LAN network needs a /64 on an adapter. The runner has no router advertisement, so this
  # gives its first adapter a ULA /64 of its own and lets SocketGuard add /128s from it.
  # The adapter of the default route is the one `networks detect` offers as a LAN interface.
  Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex -AutoSize | Out-String | Write-Host
  $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
  $adapter = if ($route) { Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue } else { $null }
  if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback' } | Select-Object -First 1 }
  if (-not $adapter) { Soft 'no adapter that is up'; return }
  $alias = $adapter.Name
  $mine = 'fd5a:1b2c:3d4e:1::10'
  Write-Host "  adapter: $alias (index $($adapter.ifIndex), $($adapter.InterfaceDescription)); giving it $mine/64"
  try { New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $mine -PrefixLength 64 -ErrorAction Stop | Out-Null } catch { Soft "cannot add $mine to $alias`: $_"; return }
  $script:addedAddress = @($adapter.ifIndex, $mine)

  $net = Run $Cli @('networks', 'add', 'slaac', '--interface', $alias, '--id', 'lan-test') 'fw-networks-add'
  Write-Host $net.Text
  if ($net.Code -ne 0) { Soft "networks add slaac exited $($net.Code)"; return }

  # One process, two listeners: 50010 inside the granted range, 50030 outside it.
  $code = '$a=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,50010);$a.Start();' +
    '$b=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,50030);$b.Start();Start-Sleep 1200'
  $script:listener = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', $code -PassThru -WindowStyle Hidden
  $script:app = $null
  $found = Wait-Until {
    $r = Run $Cli @('apps', 'list', '--json') $null
    if ($r.Code -ne 0) { return $false }
    try { $list = $r.Text | ConvertFrom-Json } catch { return $false }
    $script:app = @($list) | Where-Object { ($_.ports | ConvertTo-Json -Compress) -match '50010' } | Select-Object -First 1
    return [bool]$script:app
  } 90 'listener app'
  $apps = Run $Cli @('apps', 'list', '--json') 'fw-apps-list'
  if (-not $found) { Soft 'the test listener never appeared in apps list'; Write-Host $apps.Text; return }
  $app = $script:app
  Ok "listener is app $($app.id) ($($app.name))"

  $pg = Run $Cli @('port-groups', 'add', '50000-50020/tcp', '--label', 'testrange', '--app', "$($app.id)", '--yes') 'fw-portgroup'
  Write-Host $pg.Text
  if ($pg.Code -ne 0) { Soft "port-groups add exited $($pg.Code)"; return }
  $gr = Run $Cli @('grant', "$($app.id):port-group=testrange", 'anyone', '--yes') 'fw-grant'
  Write-Host $gr.Text
  if ($gr.Code -ne 0) { Soft "grant exited $($gr.Code)"; return }

  # The app's address on the network: from `apps show`, an address in the adapter's /64.
  $addr = $null
  $got = Wait-Until {
    $show = Run $Cli @('apps', 'show', "$($app.id)", '--json') 'fw-apps-show'
    if ($show.Text -match '(fd5a:1b2c:3d4e:1:[0-9a-f:]+)') { $m = $Matches[1]; if ($m -ne $mine) { $script:addr = $m; return $true } }
    return $false
  } 40 'app address'
  $addr = $script:addr
  Write-Host "  app address: $addr"

  # The range must be in a SocketGuard filter, as one range condition and not 21 filters.
  $has = Wait-Until {
    & netsh wfp show filters file=(Join-Path $Out 'wfp-filters-granted.xml') 2>&1 | Out-Null
    $path = Join-Path $Out 'wfp-filters-granted.xml'
    if (-not (Test-Path $path)) { return $false }
    $script:xml = [IO.File]::ReadAllText($path)
    return ($script:xml -match 'SocketGuard') -and ($script:xml -match '>50000<') -and ($script:xml -match '>50020<')
  } 40 'range filter'
  if ($has) {
    Ok 'netsh wfp show filters has SocketGuard filters naming 50000 and 50020'
    if ($script:xml -match 'FWP_MATCH_RANGE|FWP_RANGE_TYPE') { Ok 'with a range condition' } else { Soft 'no FWP_MATCH_RANGE / FWP_RANGE_TYPE next to the ports' }
  } else {
    Soft 'no SocketGuard filter with the 50000-50020 range after the grant'
    if ($StrictFirewall) { Fail 'no WFP range filter' }
  }

  if ($addr) {
    $reachIn = Try-Connect $addr 50010 $mine
    $reachOut = Try-Connect $addr 50030 $mine
    Write-Host "  from $mine to ${addr}: granted port 50010 reachable=$reachIn; port 50030 (not granted) reachable=$reachOut"
    if (-not $reachIn) { Soft 'the granted port was not reachable' }
    if ($reachOut) { Soft 'the port outside the range was reachable' }
    if ($StrictFirewall -and (-not $reachIn -or $reachOut)) { Fail 'the firewall did not behave' }
  } else { Soft 'the app got no address on the network' }
  Save-Wfp 'granted'
  if ($script:listener -and -not $script:listener.HasExited) { Stop-Process -Id $script:listener.Id -Force -ErrorAction SilentlyContinue }
  if ($script:addedAddress) { Remove-NetIPAddress -InterfaceIndex $script:addedAddress[0] -IPAddress $script:addedAddress[1] -Confirm:$false -ErrorAction SilentlyContinue }
}

# ---- the run ---------------------------------------------------------------------------------

Section 'install'
if (Test-Path $InstallDir) { Fail "$InstallDir exists already; this test needs a clean machine" }
Invoke-Msi @('/i', $Msi, "ALLOWUSER=$User") 'install'

Section 'after install'
foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe') {
  if (-not (Test-Path (Join-Path $InstallDir $f))) { Fail "$f not installed" }
}
Ok 'the three binaries are in Program Files'
if (-not (Wait-Until { (Service-State) -eq 'Running' } 60 'service')) { Fail "service is $(Service-State), not Running" }
Ok 'service SocketGuard is Running'
$cfg = (Get-CimInstance Win32_Service -Filter "Name='SocketGuard'")
Write-Host "  service: $($cfg.PathName) start=$($cfg.StartMode) account=$($cfg.StartName)"
$pidBefore = Service-Pid
if (-not (Wait-Until { (Run $Cli @('status', '--json') 'status').Code -eq 0 } 90 'pipe')) { Fail "socketguard status --json does not answer: $((Run $Cli @('status','--json') 'status').Text)" }
Ok 'socketguard status --json answers over the pipe'
$grp = (& net localgroup 'SocketGuard Users' 2>&1) | Out-String
if ($grp -notmatch [regex]::Escape($User)) { Fail "SocketGuard Users does not contain $User`n$grp" }
Ok "SocketGuard Users contains $User"
if (-not (Test-Path (Join-Path $DataDir 'socketguard.db'))) { Fail 'no socketguard.db in ProgramData\SocketGuard' }
Ok 'ProgramData\SocketGuard has the database'
$dbCreated = (Get-Item (Join-Path $DataDir 'socketguard.db')).CreationTimeUtc
$st = Run $Daemon @('service', 'status', '--json') 'service-status'
if ($st.Text -notmatch '"installed":\s*true' -or $st.Text -notmatch '"running":\s*true') { Fail "service status --json: $($st.Text)" }
Ok 'daemon service status --json: installed and running'
$sysPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($sysPath -notlike "*$InstallDir*") { Fail 'the install folder is not on the system PATH' }
Ok 'install folder is on the system PATH'
if (-not (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'SocketGuard.lnk'))) { Fail 'no Start menu shortcut' }
Ok 'Start menu shortcut'
$arp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'SocketGuard'
if (-not $arp) { Fail 'no Add/Remove Programs entry' }
Ok "Add/Remove Programs entry, version $($arp.DisplayVersion)"
Save-Wfp 'installed'
# The WFP objects appear when the daemon first applies; the pipe answering means it started.
Assert-Footprint @{ Expect = 'present'; Require = @('wfp-provider', 'wfp-sublayer', 'named-pipe') } 'present'

try { Invoke-FirewallExercise } catch { Soft "firewall exercise threw: $_" }

Section 'upgrade'
# A marker that only the data survives: the port group of the exercise (when it got that far).
$pgBefore = (Run $Cli @('port-groups', 'list', '--json') 'pg-before').Text
New-Item -ItemType Directory -Force -Path $Aside | Out-Null
Copy-Item $Daemon (Join-Path $Aside 'socketguard-daemon.exe') -Force
$pidBefore = Service-Pid
Invoke-Msi @('/i', $MsiNext, "ALLOWUSER=$User") 'upgrade'
if (-not (Wait-Until { (Service-State) -eq 'Running' } 60 'service')) { Fail "after the upgrade the service is $(Service-State)" }
Ok 'service Running after the upgrade'
$pidAfter = Service-Pid
if ($pidAfter -eq $pidBefore -or $pidAfter -eq 0) { Fail "the daemon was not restarted by the upgrade (pid $pidBefore -> $pidAfter)" }
Ok "daemon restarted (pid $pidBefore -> $pidAfter)"
$log = Get-Content (Join-Path $Out 'upgrade.log') -Raw
if ($log -match 'Action start [^:]*: CA\.Uninstall') { Fail 'the upgrade ran the uninstall action' }
Ok 'the upgrade did not run the uninstall action'
$arp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'SocketGuard'
if (@($arp).Count -ne 1) { Fail "expected one Add/Remove Programs entry after the upgrade, found $(@($arp).Count)" }
Ok "one Add/Remove Programs entry, version $($arp.DisplayVersion)"
if ((Get-Item (Join-Path $DataDir 'socketguard.db')).CreationTimeUtc -ne $dbCreated) { Fail 'the database was recreated by the upgrade' }
Ok 'the database file is the same one (creation time unchanged)'
if (-not (Wait-Until { (Run $Cli @('status', '--json') 'status-upgrade').Code -eq 0 } 90 'pipe')) { Fail 'status does not answer after the upgrade' }
$pgAfter = (Run $Cli @('port-groups', 'list', '--json') 'pg-after').Text
if ($pgBefore -ne $pgAfter) { Fail "port groups changed over the upgrade:`nbefore: $pgBefore`nafter: $pgAfter" }
Ok 'the stored state is the same after the upgrade'
Assert-Footprint @{ Expect = 'present'; Require = @('wfp-provider', 'wfp-sublayer', 'named-pipe') } 'present-upgraded'

Section 'uninstall the MSI'
Invoke-Msi @('/x', $MsiNext) 'uninstall'
if ((Service-State) -ne 'absent') { Fail "service is still $(Service-State)" }
Ok 'service gone'
if (Test-Path $InstallDir) {
  $left = Get-ChildItem $InstallDir -Recurse -File
  if ($left) { Fail "$InstallDir still holds: $(($left | ForEach-Object Name) -join ', ')" }
}
Ok 'Program Files\SocketGuard is empty or gone'
if ([Environment]::GetEnvironmentVariable('Path', 'Machine') -like '*SocketGuard*') { Fail 'the system PATH still names SocketGuard' }
if (-not (Test-Path (Join-Path $DataDir 'socketguard.db'))) { Fail 'the MSI removal deleted the database' }
Ok 'the data is kept'
Save-Wfp 'uninstalled'
Assert-Footprint @{ Expect = 'absent'; AllowData = $true } 'absent-keep-data'

Section 'purge with the daemon kept aside'
$export = Join-Path $Out 'export.json'
$pu = Run (Join-Path $Aside 'socketguard-daemon.exe') @('uninstall', '--purge', '--yes', '--export', $export) 'purge'
Write-Host $pu.Text
if ($pu.Code -ne 0) { Fail "uninstall --purge exited $($pu.Code)" }
Ok 'uninstall --purge --yes exited 0'
Save-Wfp 'purged'
Assert-Footprint @{ Expect = 'absent' } 'absent'

Section 'done'
if ($script:soft.Count -gt 0) {
  Write-Host 'Soft failures (the firewall exercise only reports until -StrictFirewall):'
  $script:soft | ForEach-Object { Write-Host "  $_" }
}
Write-Host 'OK'
