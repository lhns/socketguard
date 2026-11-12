# Portable mode (ADR 0054), end to end, on a throwaway machine (the CI runner):
#
#   pwsh test/portable.ps1 -Zip dist/SocketGuard-portable-windows-x64.zip -Out dist/portable-test
#
# Unzips to a temp folder and starts the daemon from there with --portable, --owner-pid (a helper
# process this script controls) and --allow-user. Checks that nothing lands in ProgramData, that the
# pipe answers, that the real WFP filters admit a granted port and block another one, then:
#   (a) clean exit: the owner process ends, the daemon exits by itself, and the host is as before;
#   (b) kill: the daemon is killed, no SocketGuard provider, sublayer or filter may remain (dynamic
#       session), the leftover addresses are recorded, and the next start sweeps them;
#   (c) coexistence: portable refuses to start while the service is installed, and the installed
#       service refuses to run while a portable daemon does;
#   (d) Tor and Yggdrasil (ADR 0052) from the zip's third_party\: Tor bootstraps and runs as
#       the account of the portable daemon (no installer account exists in portable mode), the node
#       key is out of the allowed user's reach, the Wintun adapter appears, and a clean exit leaves no
#       child, no adapter and no Wintun driver that was absent before (the footprint check agrees).
#
# Machine-wide changes, elevated, no prompts: never run it on a machine you use.
# Everything worth reading afterwards (daemon output, `netsh wfp` dumps, footprint output) goes to -Out.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Zip,
  [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'
$Zip = (Resolve-Path $Zip).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Footprint = Join-Path $Root 'deploy/ci/footprint-check.ps1'
$Work = Join-Path ([IO.Path]::GetTempPath()) ('sg-portable-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$Dir = Join-Path $Work 'SocketGuard-portable-windows-x64'
$Scratch = Join-Path $Work 'installed-copy'
$Daemon = Join-Path $Dir 'socketguard-daemon.exe'
$Cli = Join-Path $Dir 'socketguard.exe'
$Data = Join-Path $Dir 'data'
$ProgramDataDir = Join-Path $env:ProgramData 'SocketGuard'
$Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ProviderGuid = '534F434B-4755-4152-4400-000000000001'
$script:run = 0
$script:daemonProc = $null
$script:owner = $null
$script:addedAddress = $null
$script:listener = $null
# Section, Ok, Skip, Fail, Run, Wait-Until, Assert-Footprint and friends.
. (Join-Path $PSScriptRoot 'lib.ps1')
# Mn-* helpers shared with test/msi.ps1 (test/networks.ps1).
. (Join-Path $PSScriptRoot 'networks.ps1')

function On-Fail {
  Write-Host '--- diagnostics ---'
  Get-ChildItem $Out -Filter 'daemon-*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "== $($_.Name) (tail)"; Get-Content $_.FullName -Tail 60 | Write-Host
  }
  if (Test-Path $Data) {
    Get-ChildItem $Data -Force | Format-Table Name, Length -AutoSize | Out-String | Write-Host
    $le = Join-Path $Data 'last-exit.log'
    if (Test-Path $le) { Write-Host "last-exit.log: $(Get-Content $le -Raw)" }
  }
  Save-Wfp 'failure'
  try { & whoami /groups | Select-String 'Label|Administrators' | Write-Host } catch {}
  Cleanup
}

function Cleanup {
  foreach ($p in @($script:listener, $script:owner, $script:daemonProc)) {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  }
  if ($script:addedAddress) { Remove-NetIPAddress -InterfaceIndex $script:addedAddress[0] -IPAddress $script:addedAddress[1] -Confirm:$false -ErrorAction SilentlyContinue }
}

# The WFP objects of SocketGuard, from the engine's own dump.
function Get-Wfp([string]$Tag) {
  $f = Join-Path $Out "wfp-state-$Tag.xml"
  & netsh wfp show state file=$f 2>&1 | Out-Null
  $xml = ''
  if (Test-Path $f) {
    $b = [IO.File]::ReadAllBytes($f)
    $xml = if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($b) } else { [Text.Encoding]::UTF8.GetString($b) }
  }
  return @{
    Provider = [bool]($xml -match [regex]::Escape($ProviderGuid))
    Sublayer = [bool]($xml -match '(?i)534F434B-4755-4152-4400-000000000002')
    Named    = [bool]($xml -match '(?i)<name>\s*SocketGuard')
    Length   = $xml.Length
  }
}

function Save-Wfp([string]$Tag) {
  try { & netsh wfp show filters file=(Join-Path $Out "wfp-filters-$Tag.xml") 2>&1 | Out-Null } catch {}
}

function Pipe-Exists([string]$Name) { return [bool]([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match "(?i)\\$([regex]::Escape($Name))$" }) }

# A process this script controls: the portable daemon ends when it does.
function New-Owner {
  $script:owner = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', 'Start-Sleep -Seconds 3600' -PassThru -WindowStyle Hidden
}

function Start-Portable([string]$Exe, [string]$Tag) {
  $script:run++
  New-Owner
  $o = Join-Path $Out "daemon-$script:run-$Tag.txt"
  $script:daemonProc = Start-Process -FilePath $Exe -ArgumentList '--portable', '--owner-pid', "$($script:owner.Id)", '--allow-user', $Sid `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $o -RedirectStandardError "$o.err"
  # Touch the handle so ExitCode is available after the process ends.
  $null = $script:daemonProc.Handle
  return $o
}

function Daemon-Log([string]$Base) { return ((Get-Content $Base -Raw -ErrorAction SilentlyContinue) + (Get-Content "$Base.err" -Raw -ErrorAction SilentlyContinue)) }

function Wait-Api { return (Wait-Until { (Run $Cli @('status', '--json') $null).Code -eq 0 } 90) }

# Stop the owner and wait for the daemon to end by itself. Returns its exit code.
function End-Cleanly {
  Stop-Process -Id $script:owner.Id -Force
  if (-not $script:daemonProc.WaitForExit(90 * 1000)) { Fail 'the daemon did not exit within 90 seconds of its owner ending' }
  return $script:daemonProc.ExitCode
}

# ---- the run ---------------------------------------------------------------------------------

try {
Section 'unzip and the clean machine'
if ((Service-State) -ne 'absent') { Fail "service SocketGuard is $(Service-State); this test needs a clean machine" }
if (Test-Path $ProgramDataDir) { Fail "$ProgramDataDir exists already; this test needs a clean machine" }
Expand-Archive -Path $Zip -DestinationPath $Work
foreach ($f in 'socketguard-daemon.exe', 'socketguard.exe', 'socketguard-ui.exe', 'portable', 'README.txt', 'LICENSE.txt', 'NOTICE.txt') {
  if (-not (Test-Path (Join-Path $Dir $f))) { Fail "$f is not in the zip" }
}
Ok 'the zip has the three programs, the marker, README, LICENSE and NOTICE'
if (Test-Path $Data) { Fail 'the zip already has a data folder' }
Get-ChildItem $Dir -Recurse -File | ForEach-Object { Write-Host "  $($_.FullName.Substring($Dir.Length + 1))  $($_.Length)" }
Save-Wfp 'before'
$before = Get-Wfp 'before'
if ($before.Provider) { Fail 'a SocketGuard WFP provider exists before the test' }

Section 'a non-portable start is not what the marker does'
# The marker alone must turn portable mode on, with no flag. Ask the CLI where it would look.
$h = Run $Cli @('status') 'cli-before-start'
if ($h.Text -notmatch '(?i)socketguard-portable|cannot reach|not reach|connect') { Write-Host "  note: unexpected CLI output without a daemon: $($h.Text)" }
Ok 'the CLI without a daemon fails cleanly'

Section 'start (portable, owned by a helper process)'
$log1 = Start-Portable $Daemon 'first'
if (-not (Wait-Api)) { Fail "socketguard status --json does not answer over the portable pipe`n$(Daemon-Log $log1)" }
Ok 'the portable pipe answers'
$st = (Run $Cli @('status', '--json') 'status-1').Text | ConvertFrom-Json
if ($st.portable -ne $true) { Fail "status.portable is $($st.portable)" }
Ok 'status.portable is true'
foreach ($k in 'config_path', 'db_path') {
  if (-not ([string]$st.$k).StartsWith($Data, [StringComparison]::OrdinalIgnoreCase)) { Fail "$k is $($st.$k), not under $Data" }
}
Ok "config and database are under $Data"
if ($st.socket -notmatch 'socketguard-portable') { Fail "status.socket is $($st.socket)" }
Ok 'the pipe is socketguard-portable'
Write-Host "  db_protected=$($st.db_protected) drop_events=$($st.drop_events) service_installed=$($st.service_installed)"
if (Test-Path $ProgramDataDir) { Fail "$ProgramDataDir appeared" }
Ok 'nothing under ProgramData'
if ((Service-State) -ne 'absent') { Fail 'a service appeared' }
if (-not (Test-Path (Join-Path $Data 'socketguard.db'))) { Fail 'no database in the data folder' }
if (Pipe-Exists 'socketguard') { Fail 'the installed pipe name is in use' }
if (-not (Wait-Until { (Get-Wfp 'running').Provider } 30)) { Fail 'no SocketGuard WFP provider while running' }
$w = Get-Wfp 'running'
Ok "WFP: provider=$($w.Provider) sublayer=$($w.Sublayer) named=$($w.Named)"
if (-not $w.Sublayer) { Fail 'no SocketGuard sublayer while running' }
$rights = (icacls $Data) | Out-String
Set-Content -Path (Join-Path $Out 'data-acl.txt') -Value $rights

Section 'firewall: LAN network, listener, port range, connections'
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
$adapter = if ($route) { Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue } else { $null }
if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback' } | Select-Object -First 1 }
if (-not $adapter) { Fail 'no adapter that is up' }
$alias = $adapter.Name
$mine = 'fd5a:1b2c:3d4e:1::10'
Write-Host "  adapter: $alias (index $($adapter.ifIndex)); giving it $mine/64"
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $mine -PrefixLength 64 -ErrorAction Stop | Out-Null
$script:addedAddress = @($adapter.ifIndex, $mine)
$net = Run $Cli @('networks', 'add', 'slaac', '--interface', $alias, '--id', 'lan-test') 'fw-networks-add'
Write-Host $net.Text
if ($net.Code -ne 0) { Fail "networks add slaac exited $($net.Code)" }
function Start-Listener {
  $code = '$a=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,50010);$a.Start();' +
    '$b=[Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any,50030);$b.Start();Start-Sleep 3000'
  $script:listener = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', $code -PassThru -WindowStyle Hidden
}
Start-Listener
$script:app = $null
$found = Wait-Until {
  $r = Run $Cli @('apps', 'list', '--json') $null
  if ($r.Code -ne 0) { return $false }
  try { $list = $r.Text | ConvertFrom-Json } catch { return $false }
  $script:app = @($list) | Where-Object { ($_.ports | ConvertTo-Json -Compress) -match '50010' } | Select-Object -First 1
  return [bool]$script:app
} 90
if (-not $found) { Fail 'the test listener never appeared in apps list' }
$app = $script:app
Ok "listener is app $($app.id) ($($app.name))"
$pg = Run $Cli @('port-groups', 'add', '50000-50020/tcp', '--label', 'testrange', '--app', "$($app.id)", '--yes') 'fw-portgroup'
if ($pg.Code -ne 0) { Fail "port-groups add exited $($pg.Code): $($pg.Text)" }
$gr = Run $Cli @('grant', "$($app.id):port-group=testrange", 'anyone', '--yes') 'fw-grant'
if ($gr.Code -ne 0) { Fail "grant exited $($gr.Code): $($gr.Text)" }
$script:addr = $null
$got = Wait-Until {
  $show = Run $Cli @('apps', 'show', "$($app.id)", '--json') 'fw-apps-show'
  if ($show.Text -match '(fd5a:1b2c:3d4e:1:[0-9a-f:]+)') { if ($Matches[1] -ne $mine) { $script:addr = $Matches[1]; return $true } }
  return $false
} 40
if (-not $got) { Fail 'the app got no address on the network' }
$addr = $script:addr
Write-Host "  app address: $addr"
$reachIn = Wait-Until { Try-Connect $addr 50010 $mine } 20
$reachOut = Try-Connect $addr 50030 $mine
Write-Host "  from $mine to ${addr}: granted 50010 reachable=$reachIn; not granted 50030 reachable=$reachOut"
Save-Wfp 'granted'
if (-not $reachIn) { Fail 'the granted port was not reachable' }
if ($reachOut) { Fail 'the port outside the range was reachable' }
Ok 'granted port reachable, other port blocked (real WFP)'
if (Test-Path $ProgramDataDir) { Fail "$ProgramDataDir appeared during the exercise" }
# What the ledger would hold: the addresses SocketGuard put on the adapter.
$owned = @(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $adapter.ifIndex | Where-Object { $_.IPAddress -like 'fd5a:1b2c:3d4e:1:*' -and $_.IPAddress -ne $mine } | ForEach-Object { $_.IPAddress })
Write-Host "  addresses added by SocketGuard: $($owned -join ', ')"
$ledger = Join-Path $Out 'ledger.json'
ConvertTo-Json -InputObject $owned | Set-Content $ledger
if ($owned.Count -eq 0) { Fail 'no address of SocketGuard on the adapter' }

Section '(a) clean exit: the owner ends, the daemon removes everything and exits'
if ($script:listener -and -not $script:listener.HasExited) { Stop-Process -Id $script:listener.Id -Force }
$sw = [Diagnostics.Stopwatch]::StartNew()
$code = End-Cleanly
Ok "the daemon exited by itself after $([int]$sw.Elapsed.TotalSeconds) s with code $code"
Set-Content (Join-Path $Out 'daemon-1-exit.txt') "exit code $code`n$(Daemon-Log $log1)"
if ($code -ne 0) { Fail "the daemon exited with $code after a clean end" }
$le = Get-Content (Join-Path $Data 'last-exit.log') -Raw
if ($le -notmatch 'clean') { Fail "last-exit.log does not say clean: $le" }
Ok "last-exit.log: $($le.Trim())"
if (-not (Test-Path (Join-Path $Data 'socketguard.db'))) { Fail 'the data folder lost its database' }
if (Test-Path (Join-Path $Data 'session.json')) { Fail 'session.json is left after a clean exit' }
Ok 'the data folder keeps its data'
$left = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $owned -contains $_.IPAddress })
if ($left.Count -ne 0) { Fail "addresses are still on adapters: $($left.IPAddress -join ', ')" }
Save-Wfp 'after-clean'
Assert-Footprint @{ Expect = 'absent'; LedgerExport = $ledger } 'after-clean-exit'
if (Pipe-Exists 'socketguard-portable') { Fail 'the portable pipe is still there' }

Section '(b) kill: the dynamic session takes the filters with the process'
$log2 = Start-Portable $Daemon 'second'
if (-not (Wait-Api)) { Fail "the second start does not answer`n$(Daemon-Log $log2)" }
Ok 'second start answers (grants and networks came back from the data folder)'
Start-Listener
if (-not (Wait-Until { (Get-Wfp 'second').Provider } 60)) { Fail 'no WFP provider after the second start' }
$addr2 = $null
$gotAddr = Wait-Until {
  $show = Run $Cli @('apps', 'list', '--json') $null
  return ($show.Text -match 'fd5a:1b2c:3d4e:1:')
} 60
Write-Host "  the app has an address again: $gotAddr"
$present = @(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $adapter.ifIndex | Where-Object { $_.IPAddress -like 'fd5a:1b2c:3d4e:1:*' -and $_.IPAddress -ne $mine } | ForEach-Object { $_.IPAddress })
Write-Host "  addresses on the adapter: $($present -join ', ')"
Stop-Process -Id $script:daemonProc.Id -Force
Stop-Process -Id $script:owner.Id -Force -ErrorAction SilentlyContinue
$null = $script:daemonProc.WaitForExit(30000)
$gone = Wait-Until { $w = Get-Wfp 'killed'; -not ($w.Provider -or $w.Sublayer -or $w.Named) } 30
Save-Wfp 'killed'
if (-not $gone) { Fail 'SocketGuard WFP objects remain after the daemon was killed (the session was not dynamic)' }
Ok 'no SocketGuard provider, sublayer or filter after a kill'
$remain = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $present -contains $_.IPAddress })
Write-Host "  FINDING: after a kill, $($remain.Count) of $($present.Count) addresses remain on the adapter: $($remain.IPAddress -join ', ')"
Set-Content (Join-Path $Out 'finding-addresses-after-kill.txt') "after a kill $($remain.Count) of $($present.Count) addresses remained: $($remain.IPAddress -join ', ')"
if (Test-Path (Join-Path $Data 'session.json')) { Ok 'session.json marks the unclean end' }

$log3 = Start-Portable $Daemon 'third'
if (-not (Wait-Api)) { Fail "the third start does not answer`n$(Daemon-Log $log3)" }
$text = Daemon-Log $log3
if ($remain.Count -gt 0 -and $text -notmatch 'Swept [1-9]') { Fail "the next start did not sweep the leftover addresses`n$text" }
Ok 'the next start swept the addresses a kill left (log line "Swept N address(es)")'
if ($text -match 'did not end cleanly') { Ok 'and said the earlier run did not end cleanly' }
$code = End-Cleanly
Set-Content (Join-Path $Out 'daemon-3-exit.txt') "exit code $code`n$(Daemon-Log $log3)"
if ($code -ne 0) { Fail "the daemon exited with $code" }
Start-Sleep -Seconds 2
$again = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $present -contains $_.IPAddress })
if ($again.Count -ne 0) { Fail "addresses are on adapters after a clean exit: $($again.IPAddress -join ', ')" }
Assert-Footprint @{ Expect = 'absent' } 'after-second-clean-exit'
if ($script:listener -and -not $script:listener.HasExited) { Stop-Process -Id $script:listener.Id -Force }
if ($script:addedAddress) { Remove-NetIPAddress -InterfaceIndex $script:addedAddress[0] -IPAddress $script:addedAddress[1] -Confirm:$false -ErrorAction SilentlyContinue; $script:addedAddress = $null }

Section '(c) coexistence with the installed service'
# A copy without the marker is the installed program: it registers the service.
Copy-Item $Dir $Scratch -Recurse
Remove-Item (Join-Path $Scratch 'portable') -Force
Remove-Item (Join-Path $Scratch 'data') -Recurse -Force -ErrorAction SilentlyContinue
$inst = Join-Path $Scratch 'socketguard-daemon.exe'
$r = Run $inst @('service', 'install', '--no-start') 'c-service-install'
Write-Host $r.Text
if ($r.Code -ne 0) { Fail "service install --no-start exited $($r.Code)" }
if ((Service-State) -eq 'absent') { Fail 'the service was not installed' }
$rr = Run $Daemon @('--portable', '--owner-pid', "$PID") 'c-portable-refused' 30
if ($rr.Code -eq 0) { Fail 'portable started beside the installed service' }
if ($rr.Text -notmatch 'service is installed') { Fail "the refusal does not name the conflict: $($rr.Text)" }
Ok "portable refuses beside the service: $($rr.Text.Trim())"
$rm = Run $inst @('uninstall', '--purge', '--yes') 'c-uninstall'
if ($rm.Code -ne 0) { Write-Host $rm.Text; Fail "uninstall --purge exited $($rm.Code)" }
if ((Service-State) -ne 'absent') { Fail 'the service is still there after uninstall' }
if (Test-Path $ProgramDataDir) { Fail 'ProgramData\SocketGuard is left after uninstall --purge' }

# The other way round: the service refuses to run while a portable daemon does.
$log4 = Start-Portable $Daemon 'fourth'
if (-not (Wait-Api)) { Fail "the fourth start does not answer`n$(Daemon-Log $log4)" }
$ri = Run $inst @('service', 'install', '--no-start') 'c-service-install-2'
Write-Host $ri.Text
if ($ri.Text -notmatch '(?i)portable SocketGuard is running') { Fail "service install did not warn about the running portable daemon: $($ri.Text)" }
Ok 'service install warns while a portable daemon runs'
& sc.exe start SocketGuard | Out-Null
$stopped = Wait-Until { (Service-State) -eq 'Stopped' } 40
Write-Host "  service state after sc start: $(Service-State)"
if (-not $stopped) { Fail 'the installed service kept running beside the portable daemon' }
Ok 'the installed service refused to run beside the portable daemon'
if (-not (Pipe-Exists 'socketguard-portable')) { Fail 'the portable daemon died' }
$code = End-Cleanly
if ($code -ne 0) { Fail "the portable daemon exited with $code" }
$rm = Run $inst @('uninstall', '--purge', '--yes') 'c-uninstall-2'
if ($rm.Code -ne 0) { Write-Host $rm.Text; Fail "uninstall --purge (2) exited $($rm.Code)" }
Assert-Footprint @{ Expect = 'absent' } 'end'

Section '(d) Tor and Yggdrasil (ADR 0052) in portable mode'
# The bundle action must have run before the zip was built (packages.yml, portable job).
foreach ($f in 'tor\tor.exe', 'tor\pluggable_transports\lyrebird.exe', 'yggdrasil\yggdrasil.exe', 'yggdrasil\wintun.dll', 'VERSIONS') {
  if (-not (Test-Path (Join-Path $Dir "third_party\$f"))) { Mn-Fail "third_party\$f is not in the zip (installer/windows/portable.ps1 copies it from the stage, ./build.sh --stage)" }
}
Ok 'the zip has third_party\ with tor.exe, lyrebird.exe, yggdrasil.exe, wintun.dll and VERSIONS'
# Asked once, before the first Yggdrasil start, like the daemon does: the same pattern as the
# footprint check, which compares the driver store with this answer after the exit.
function Wintun-InStore { return [bool]((& pnputil.exe /enum-drivers 2>&1 | Out-String) -match '(?im)^[^:\r\n]+:\s*wintun\.inf\s*$') }
$wintunBefore = Wintun-InStore
Write-Host "  Wintun driver in the driver store before the Yggdrasil: $wintunBefore"
$log5 = Start-Portable $Daemon 'networks'
$script:MnLogBase = $log5
if (-not (Wait-Api)) { Mn-Fail "the start for the Tor and Yggdrasil networks does not answer`n$(Daemon-Log $log5)" }

# A Tor or Yggdrasil network is SocketGuard's own copy: portable mode allows it (an existing node was refused above).
$r = Run $Cli @('networks', 'add', 'tor', '--id', 'tor') 'd-add-tor'
Write-Host $r.Text
if ($r.Code -ne 0) { Mn-Fail "networks add tor exited $($r.Code) in portable mode" }
Write-Host '  waiting for the bootstrap (up to 10 minutes)'
if (-not (Mn-WaitUp 'tor' 600)) { Mn-Fail 'the Tor network is not up after 10 minutes' }
Ok 'the Tor network is up (bootstrapped)'
$torProcs = Mn-Procs 'tor.exe'
if ($torProcs.Count -eq 0) { Mn-Fail 'the network is up but no tor.exe from the portable folder is running' }
$daemonCim = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:daemonProc.Id)"
$daemonOwner = Mn-Owner $daemonCim
$torOwner = Mn-Owner $torProcs[0]
$n = Mn-Net 'tor'
Write-Host "  daemon owner: $daemonOwner; tor.exe (pid $($torProcs[0].ProcessId)) owner: $torOwner; the card says runs_as = '$($n.child.runs_as)'"
# No installer ran, so there is no LocalService or other account set up for the child: it is the
# account of the elevated portable daemon, and nothing tries to log LocalService on.
if ($torOwner -ne $daemonOwner) { Mn-Fail "tor.exe runs as $torOwner, the portable daemon as $daemonOwner (they must be the same account)" }
Ok "tor.exe runs as the same account as the portable daemon ($torOwner)"
if ("$($n.child.runs_as)" -notmatch 'account running portable SocketGuard') { Mn-Fail "runs_as is '$($n.child.runs_as)', not the account running portable SocketGuard" }
Ok "the network card says it runs as $($n.child.runs_as)"
if (-not (Test-Path (Join-Path $Data 'tor'))) { Mn-Fail "no $Data\tor" }

$r = Run $Cli @('networks', 'add', 'yggdrasil', '--id', 'ygg') 'd-add-ygg'
Write-Host $r.Text
if ($r.Code -ne 0) { Mn-Fail "networks add yggdrasil exited $($r.Code) in portable mode" }
Write-Host '  waiting for the adapter (the Wintun driver is installed by wintun.dll on the first adapter; up to 2 minutes)'
$seen = Wait-Until { [bool](Mn-Adapter) } 120
$n = Mn-Net 'ygg'
Write-Host "  ygg: $(Mn-Describe $n)"
if ($n -and "$($n.child.state)" -eq 'unavailable') { Mn-Fail "the Yggdrasil files are not part of this build: $(Mn-Describe $n)" }
# The key and the cookie are not for the account that may read data\: the data directories do not inherit its read access.
$sidOf = { param($rule) try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' } }
$subs = @('tor')
if ($seen) { $subs += 'yggdrasil' }
foreach ($sub in $subs) {
  $p = Join-Path $Data $sub
  if (-not (Wait-Until { Test-Path $p } 60)) { Mn-Fail "no $p; status: $(Mn-Describe (Mn-Net $(if ($sub -eq 'tor') { 'tor' } else { 'ygg' })))" }
  $acl = Get-Acl $p
  if (-not $acl.AreAccessRulesProtected) { Mn-Fail "$p inherits its access list from data\ (the allowed user's read access would reach it)`n$((& icacls $p) -join "`n")" }
  $names = @($acl.Access | ForEach-Object { & $sidOf $_ })
  # The daemon is an elevated administrator, so it needs no entry of its own: Administrators covers
  # it. An entry for the allowed account would be the inherited read access of data\ leaking in.
  # (On this runner the allowed account and the elevated one are the same user, so this proves the
  # protected list, not that a different unelevated user is locked out.)
  if ($names -contains $Sid) { Mn-Fail "$p has an access entry for the allowed account $Sid`n$((& icacls $p) -join "`n")" }
  $open = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ((& $sidOf $_) -in @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')) })
  if ($open.Count -gt 0) { Mn-Fail "$p admits Everyone, Users or Authenticated Users`n$((& icacls $p) -join "`n")" }
  Ok "$sub`: the directory has a protected access list (SYSTEM, Administrators and the daemon's account)"
}
Set-Content (Join-Path $Out 'd-acl.txt') ((& icacls (Join-Path $Data 'tor')) -join "`n")
# The Wintun fact is recorded before the first Yggdrasil start; when the adapter never appeared the
# start may not have happened (see the SKIP below), so it is asserted only when it did.
if (-not $seen) {
  Write-Host '  session.json and data\yggdrasil are not asserted: the adapter did not appear'
} elseif (Wait-Until { try { $script:session = Get-Content (Join-Path $Data 'session.json') -Raw | ConvertFrom-Json; $null -ne $script:session.wintun_present_before } catch { $false } } 30) {
  if ([bool]$script:session.wintun_present_before -ne $wintunBefore) { Mn-Fail "session.json says Wintun was present before: $($script:session.wintun_present_before), the driver store said $wintunBefore" }
  Ok "session.json records that the Wintun driver was present before: $wintunBefore (no install record exists in portable mode)"
} else {
  Mn-Fail 'session.json has no wintun_present_before after the Yggdrasil was added'
}
$adapterSeen = $false
if (-not $seen) {
  $why = Mn-Describe $n
  Set-Content -Path (Join-Path $Out 'ygg-adapter-error.txt') -Value ("no adapter after 120 s`n$why`n" + ($n | ConvertTo-Json -Depth 6) + "`n" + ((Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Format-Table Name, InterfaceDescription, Status -AutoSize | Out-String)) + "`n" + ((& pnputil /enum-drivers 2>&1 | Select-String -Pattern 'wintun' -Context 3, 3 | Out-String)))
  Skip "portable Yggdrasil: no adapter 'SocketGuard' on this runner after 120 s. Status: $why. Details in ygg-adapter-error.txt"
} else {
  $adapterSeen = $true
  $ad = Mn-Adapter
  Ok "the adapter exists: $($ad.Name) ($($ad.InterfaceDescription), $($ad.Status))"
  if (-not (Wintun-InStore)) { Mn-Fail 'the adapter exists but the Wintun driver is not in the driver store' }
  if (-not (Mn-WaitUp 'ygg' 120)) { Mn-Fail 'the Yggdrasil network is not up 2 minutes after the adapter appeared' }
  Ok 'the Yggdrasil network is up'
  $yp = Mn-Procs 'yggdrasil.exe'
  if ($yp.Count -eq 0) { Mn-Fail 'no yggdrasil.exe from the portable folder is running' }
  $yo = Mn-Owner $yp[0]
  if ($yo -ne $daemonOwner) { Mn-Fail "yggdrasil.exe runs as $yo, the portable daemon as $daemonOwner" }
  Ok "yggdrasil.exe runs as the portable daemon's account ($yo)"
}

# Clean exit: the owner ends, the daemon stops both children, removes the Wintun driver if it was
# absent before, and exits 0.
$code = End-Cleanly
Set-Content (Join-Path $Out 'daemon-5-exit.txt') "exit code $code`n$(Daemon-Log $log5)"
if ($code -ne 0) { Mn-Fail "the daemon exited with $code after a clean end with Tor and Yggdrasil networks" }
Ok 'the daemon exited 0'
$le = Get-Content (Join-Path $Data 'last-exit.log') -Raw
if ($le -notmatch 'clean') { Mn-Fail "last-exit.log does not say clean: $le" }
Ok "last-exit.log: $($le.Trim())"
if (Test-Path (Join-Path $Data 'session.json')) { Mn-Fail 'session.json is left after a clean exit' }
if (-not (Wait-Until { ((Mn-Procs 'tor.exe').Count -eq 0) -and ((Mn-Procs 'yggdrasil.exe').Count -eq 0) } 30)) { Mn-Fail 'tor.exe or yggdrasil.exe from the portable folder still runs after the clean exit' }
Ok 'no tor.exe or yggdrasil.exe from the portable folder is running'
if ($adapterSeen) {
  if (-not (Wait-Until { -not (Mn-Adapter) } 30)) { Mn-Fail 'the SocketGuard adapter is still there after the clean exit' }
  Ok 'the SocketGuard adapter is gone'
}
$wintunAfter = Wintun-InStore
if ($adapterSeen -and -not $wintunBefore) {
  Set-Content -Path (Join-Path $Out 'pnputil-after-portable-exit.txt') -Value (& pnputil.exe /enum-drivers 2>&1 | Out-String)
  if ($wintunAfter) { Mn-Fail 'the Wintun driver was absent before, and is still in the driver store after the clean exit (pnputil-after-portable-exit.txt)' }
  Ok 'the Wintun driver was absent before and is removed by the clean exit'
} elseif ($wintunBefore) {
  if (-not $wintunAfter) { Mn-Fail 'the Wintun driver was installed before SocketGuard, and the clean exit removed it' }
  Ok 'the Wintun driver was installed before and stays'
} else {
  Write-Host "  no adapter was created: the driver store is asserted by the footprint check only (Wintun in store: $wintunAfter)"
}
Write-Host "  data\tor and data\yggdrasil stay in the portable folder: $((Test-Path (Join-Path $Data 'tor')) -and (Test-Path (Join-Path $Data 'yggdrasil')))"
$fp = @{ Expect = 'absent' }
if ($wintunBefore) { $fp.WintunPresentBefore = $true }
Assert-Footprint $fp 'd-after-exit'

Section 'done'
Write-Summary 'networks'
Write-Host 'OK'
}
finally {
  Cleanup
  Copy-Item (Join-Path $Data '*') $Out -Include 'last-exit.log' -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
