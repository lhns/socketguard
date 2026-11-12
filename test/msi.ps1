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
  # The engine option FWPM_ENGINE_COLLECT_NET_EVENTS: what netsh can say about it, and what the
  # daemon recorded about the value it found (the install record).
  foreach ($o in @('?', 'optionsfor=netevents', 'optionsfor=engine')) {
    try { "== netsh wfp show options $o`n" + ((& netsh wfp show options $o 2>&1) | Out-String) | Out-File -Append (Join-Path $Out "wfp-options-$Tag.txt") } catch {}
  }
  $log = Join-Path $DataDir 'setup-log.json'
  if (Test-Path $log) { Copy-Item $log (Join-Path $Out "setup-log-$Tag.json") -ErrorAction SilentlyContinue }
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

# ---- managed networks (ADR 0052): the bundled Tor and Yggdrasil ------------------------------
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

# The installed files, what `status` says about them, and that LocalService (the account Tor
# runs as) can run what is in Program Files.
function Assert-Bundled {
  Section 'managed networks: the bundled files'
  $tp = Join-Path $InstallDir 'third_party'
  foreach ($f in 'tor\tor.exe', 'yggdrasil\yggdrasil.exe', 'yggdrasil\wintun.dll', 'VERSIONS', 'licenses\tor.txt', 'licenses\yggdrasil.txt', 'licenses\wintun.txt') {
    if (-not (Test-Path (Join-Path $tp $f))) { Mn-Fail "missing $tp\$f" }
  }
  Mn-Ok "third_party has tor.exe, yggdrasil.exe, wintun.dll, VERSIONS and the licence texts"
  foreach ($f in 'LICENSE.txt', 'THIRD_PARTY_NOTICES.md') {
    if (-not (Test-Path (Join-Path $InstallDir "licenses\$f"))) { Mn-Fail "missing $InstallDir\licenses\$f" }
  }
  Mn-Ok 'licenses\LICENSE.txt and licenses\THIRD_PARTY_NOTICES.md are installed'

  $st = Run $Cli @('status', '--json') 'mn-status'
  try { $j = $st.Text | ConvertFrom-Json } catch { Mn-Fail "status --json is not JSON: $($st.Text)" }
  Write-Host "  status.bundled: $($j.bundled | ConvertTo-Json -Compress -Depth 5)"
  if (-not $j.bundled.dir) { Mn-Fail 'status shows no bundled directory' }
  if ((Resolve-Path $j.bundled.dir).Path.TrimEnd('\') -ne (Resolve-Path $tp).Path.TrimEnd('\')) { Mn-Fail "the daemon found its third_party at '$($j.bundled.dir)', expected $tp" }
  Mn-Ok "the daemon found $tp"
  foreach ($name in 'tor', 'yggdrasil') {
    $got = @($j.bundled.versions | Where-Object { $_.name -eq $name })
    if ($got.Count -ne 1) { Mn-Fail "status does not name the bundled $name" }
    $line = Get-Content (Join-Path $tp 'VERSIONS') | Where-Object { $_ -match "^$name\s+(\S+)" } | Select-Object -First 1
    if (-not $line -or ($line -split '\s+')[1] -ne $got[0].version) { Mn-Fail "$name`: status says '$($got[0].version)', VERSIONS says '$line'" }
    Mn-Ok "$name $($got[0].version) (as in VERSIONS)"
  }

  # Inherited from Program Files: Users may read and run it. Then the real test, as LocalService.
  $tor = Join-Path $tp 'tor\tor.exe'
  $rx = (Get-Acl $tor).Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match 'Users|LOCAL SERVICE|Everyone|Authenticated' -and
    (([int]$_.FileSystemRights -band 0x1200A9) -eq 0x1200A9)
  }
  if (-not $rx) { Mn-Fail "no ACL entry lets Users or LocalService read and run $tor`n$((& icacls $tor) -join "`n")" }
  Mn-Ok "$tor is readable and runnable by $(($rx | ForEach-Object { $_.IdentityReference.Value }) -join ', ')"
  $work = 'C:\Windows\Temp\sg-localservice'
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  & icacls $work /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
  $cmd = Join-Path $work 'run.cmd'
  Set-Content -Path $cmd -Encoding ascii -Value "@echo off`r`n`"$tor`" --version > `"$work\tor.txt`" 2>&1`r`n`"$(Join-Path $tp 'yggdrasil\yggdrasil.exe')`" -version > `"$work\ygg.txt`" 2>&1`r`necho done > `"$work\done.txt`"`r`n"
  $ran = $false
  try {
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$cmd`""
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount
    Register-ScheduledTask -TaskName 'sg-localservice-check' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'sg-localservice-check'
    $ran = Wait-Until { Test-Path (Join-Path $work 'done.txt') } 60 'task'
  } catch { Write-Host "  scheduled task as LocalService failed: $_" }
  finally { Unregister-ScheduledTask -TaskName 'sg-localservice-check' -Confirm:$false -ErrorAction SilentlyContinue }
  if (-not $ran) {
    Mn-Skip "could not run tor.exe as LocalService with a scheduled task (the task did not finish); the ACL check above stands"
  } else {
    Copy-Item "$work\*" $Out -ErrorAction SilentlyContinue
    $t = Get-Content "$work\tor.txt" -Raw; $y = Get-Content "$work\ygg.txt" -Raw
    if ($t -notmatch 'Tor version') { Mn-Fail "tor.exe --version as LocalService printed: $t" }
    Mn-Ok "LocalService runs the installed tor.exe: $($t.Trim())"
    if ($y -notmatch '\d+\.\d+') { Mn-Fail "yggdrasil.exe -version as LocalService printed: $y" }
    Mn-Ok "LocalService runs the installed yggdrasil.exe: $($y.Trim())"
  }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

function Invoke-ManagedNetworks {
  Section 'managed networks: Tor'
  $r = Run $Cli @('networks', 'add', 'tor', '--id', 'tor') 'mn-add-tor'
  Write-Host $r.Text
  if ($r.Code -ne 0) { Mn-Fail "networks add tor exited $($r.Code)" }
  Write-Host '  waiting for the bootstrap (up to 5 minutes)'
  if (-not (Mn-WaitUp 'tor' 300)) { Mn-Fail 'the managed Tor network is not up after 5 minutes' }
  Mn-Ok 'the managed Tor network is up (bootstrapped)'
  $procs = Mn-Procs 'tor.exe'
  if ($procs.Count -eq 0) { Mn-Fail 'the network is up but no tor.exe from third_party is running' }
  $owner = Mn-Owner $procs[0]
  $n = Mn-Net 'tor'
  Write-Host "  tor.exe (pid $($procs[0].ProcessId)) owner: $owner; the network card says runs_as = '$($n.managed.runs_as)', version $($n.managed.version)"
  if ($owner -notmatch 'LOCAL SERVICE') { Mn-Fail "tor.exe runs as $owner, not NT AUTHORITY\LOCAL SERVICE (runs_as: '$($n.managed.runs_as)')" }
  Mn-Ok 'tor.exe runs as NT AUTHORITY\LOCAL SERVICE'
  if ("$($n.managed.runs_as)" -notmatch 'LocalService|LOCAL SERVICE') { Mn-Fail "runs_as is '$($n.managed.runs_as)'" }
  Mn-Ok "the network card says it runs as $($n.managed.runs_as)"
  if (-not (Wait-Until { Test-Path (Join-Path $DataDir 'tor') } 20 'tor dir')) { Mn-Fail "no $DataDir\tor" }

  $r = Run $Cli @('networks', 'rm', 'tor', '--yes') 'mn-rm-tor'
  Write-Host $r.Text
  if ($r.Code -ne 0) { Mn-Fail "networks rm tor exited $($r.Code)" }
  if (-not (Wait-Until { (Mn-Procs 'tor.exe').Count -eq 0 } 60 'tor gone')) { Mn-Fail 'tor.exe still runs 60 s after the network was removed' }
  Mn-Ok 'removing the network ends tor.exe'
  # Added again and left configured: the uninstall steps look at what a stop keeps and a purge removes.
  $r = Run $Cli @('networks', 'add', 'tor', '--id', 'tor') 'mn-add-tor-again'
  if ($r.Code -ne 0) { Mn-Fail "networks add tor (again) exited $($r.Code): $($r.Text)" }
  if (-not (Wait-Until { (Mn-Procs 'tor.exe').Count -gt 0 } 60 'tor again')) { Mn-Fail 'tor.exe did not start again' }
  if (-not (Wait-Until { Test-Path (Join-Path $DataDir 'tor') } 20 'tor dir')) { Mn-Fail "no $DataDir\tor after adding the network again" }
  Mn-Ok "added again; $DataDir\tor exists"

  Section 'managed networks: Yggdrasil'
  $r = Run $Cli @('networks', 'add', 'yggdrasil', '--id', 'ygg') 'mn-add-ygg'
  Write-Host $r.Text
  if ($r.Code -ne 0) { Mn-Fail "networks add yggdrasil exited $($r.Code)" }
  Write-Host '  waiting for the adapter (the Wintun driver is installed by wintun.dll on the first adapter; up to 2 minutes)'
  $seen = Wait-Until { [bool](Mn-Adapter) } 120 'adapter'
  $n = Mn-Net 'ygg'
  Write-Host "  ygg: $(Mn-Describe $n)"
  if ($n -and "$($n.managed.state)" -eq 'unavailable') { Mn-Fail "the Yggdrasil files are not part of this build: $(Mn-Describe $n)" }
  if (-not $seen) {
    $why = Mn-Describe $n
    Set-Content -Path (Join-Path $Out 'ygg-adapter-error.txt') -Value ("no adapter after 120 s`n$why`n" + ($n | ConvertTo-Json -Depth 6) + "`n" + ((Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Format-Table Name, InterfaceDescription, Status -AutoSize | Out-String)) + "`n" + ((& pnputil /enum-drivers 2>&1 | Select-String -Pattern 'wintun' -Context 3, 3 | Out-String)))
    Mn-Skip "managed Yggdrasil: no adapter 'SocketGuard' on this runner after 120 s. Status: $why. Details in ygg-adapter-error.txt"
    return
  }
  $script:mnAdapterSeen = $true
  $ad = Mn-Adapter
  Mn-Ok "the adapter exists: $($ad.Name) ($($ad.InterfaceDescription), $($ad.Status))"
  if (-not (Mn-WaitUp 'ygg' 120)) { Mn-Fail 'the managed Yggdrasil network is not up 2 minutes after the adapter appeared' }
  Mn-Ok 'the managed Yggdrasil network is up'
  $n = Mn-Net 'ygg'
  $addr = "$($n.managed.address)"
  if (-not $addr) { Mn-Fail 'the network card shows no node address' }
  $onAdapter = Wait-Until {
    $ips = @(Get-NetIPAddress -InterfaceIndex (Mn-Adapter).ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue)
    $null -ne ($ips | Where-Object { [System.Net.IPAddress]::Parse(($_.IPAddress -split '%')[0]).Equals([System.Net.IPAddress]::Parse($addr)) })
  } 30 'address on adapter'
  if (-not $onAdapter) { Mn-Fail "the adapter does not hold the node address $addr" }
  Mn-Ok "the adapter holds the node address $addr"
  $yp = Mn-Procs 'yggdrasil.exe'
  if ($yp.Count -eq 0) { Mn-Fail 'no yggdrasil.exe from third_party is running' }
  Write-Host "  yggdrasil.exe owner: $(Mn-Owner $yp[0]) (Windows cannot drop privileges after the adapter exists); runs_as: '$($n.managed.runs_as)'"
  # Is the admin socket usable? peers_connected is known when it is; otherwise the valve engaged.
  if ($null -ne $n.managed.peers_connected) {
    Mn-Ok "the admin socket works: peers_connected = $($n.managed.peers_connected) (no peers are configured here)"
  } else {
    Write-Host "  peers_connected is unknown: the admin endpoint did not answer or the valve engaged. Detail: '$($n.managed.detail)'" -ForegroundColor Yellow
    Write-Host '::warning::managed networks: Yggdrasil admin socket: peer information unavailable on this runner'
    $script:mnSkipped.Add("Yggdrasil admin socket: peers_connected unknown (detail: '$($n.managed.detail)')")
  }
}

# ---- the run ---------------------------------------------------------------------------------

Section 'install'
if (Test-Path $InstallDir) { Fail "$InstallDir exists already; this test needs a clean machine" }
Save-Wfp 'before'
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

Assert-Bundled

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

Invoke-ManagedNetworks
# What the install record says about the Wintun driver, read before the purge deletes it.
try {
  $rec = Get-Content (Join-Path $DataDir 'setup-log.json') -Raw | ConvertFrom-Json
  $script:mnWintun = @($rec.entries | Where-Object { $_.type -eq 'wintun_driver' }) | Select-Object -First 1
} catch { Write-Host "  cannot read the install record: $_" }

Section 'uninstall the MSI'
Invoke-Msi @('/x', $MsiNext) 'uninstall'
if ((Service-State) -ne 'absent') { Fail "service is still $(Service-State)" }
Ok 'service gone'
if (-not (Wait-Until { ((Mn-Procs 'tor.exe').Count -eq 0) -and ((Mn-Procs 'yggdrasil.exe').Count -eq 0) } 60 'children')) { Mn-Fail 'tor.exe or yggdrasil.exe still runs after the removal' }
Mn-Ok 'tor.exe and yggdrasil.exe are stopped'
if ($script:mnAdapterSeen -and -not (Wait-Until { -not (Mn-Adapter) } 30 'adapter gone')) { Mn-Fail 'the SocketGuard adapter is still there after the removal' }
if ($script:mnAdapterSeen) { Mn-Ok 'the Yggdrasil adapter is gone' }
if (-not (Test-Path (Join-Path $DataDir 'tor'))) { Mn-Fail "the removal deleted $DataDir\tor" }
if ($script:mnAdapterSeen -and -not (Test-Path (Join-Path $DataDir 'yggdrasil'))) { Mn-Fail "the removal deleted $DataDir\yggdrasil" }
Mn-Ok "the data directories of the networks are kept ($DataDir\tor$(if ($script:mnAdapterSeen) { ', yggdrasil' }))"
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
if ((Test-Path (Join-Path $DataDir 'tor')) -or (Test-Path (Join-Path $DataDir 'yggdrasil'))) { Mn-Fail "the purge left $DataDir\tor or $DataDir\yggdrasil" }
Mn-Ok 'the purge removed the data directories of the networks'
if ($script:mnWintun -and -not $script:mnWintun.present_before) {
  $drv = (& pnputil /enum-drivers 2>&1 | Out-String)
  Set-Content -Path (Join-Path $Out 'pnputil-after-purge.txt') -Value $drv
  if ($drv -match '(?i)wintun') { Mn-Fail 'the install record says Wintun was not present before; the purge left it in the driver store (pnputil-after-purge.txt)' }
  Mn-Ok 'Wintun was not present before the install and is not in the driver store after the purge'
} elseif ($script:mnWintun) {
  Write-Host '  the install record says Wintun was present before the install: the purge keeps it (not asserted)'
} else {
  Write-Host '  no wintun_driver entry in the install record (no adapter was created): nothing to assert'
}
Assert-Footprint @{ Expect = 'absent' } 'absent'

Section 'done'
Write-Host "managed networks: $($script:mnOk) checks passed, $($script:mnSkipped.Count) skipped"
foreach ($s in $script:mnSkipped) { Write-Host "  skipped: $s" }
if ($script:soft.Count -gt 0) {
  Write-Host 'Soft failures (the firewall exercise only reports until -StrictFirewall):'
  $script:soft | ForEach-Object { Write-Host "  $_" }
}
Write-Host 'OK'
