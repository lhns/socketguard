# Looks from OUTSIDE (never through the SocketGuard CLI or daemon) for every item of
# docs/footprint.md that exists on Windows.
#
#   footprint-check.ps1 -Expect absent  [-LedgerExport FILE]   after uninstall --purge
#   footprint-check.ps1 -Expect present [-LedgerExport FILE]   right after install
#   footprint-check.ps1 -SelfTest                              parse embedded samples only
#
# Output: one line per item, `PRESENT <item>` or `ABSENT <item>` (or `UNKNOWN <item>` when a
# tool refused, e.g. not elevated), then a summary line. Exit 1 on any mismatch, 2 on usage.
#
# -Expect absent: every item must be ABSENT, including %ProgramData%\SocketGuard itself.
# -Expect present: only the install items are required, because the WFP objects, addresses,
#   database, pipe and setup log appear only after the first start:
#     service `SocketGuard`, local group `SocketGuard Users`, directory %ProgramData%\SocketGuard
#   Every other item is printed with its state and marked "(not required)".
#
# Ledger export (-LedgerExport): a JSON file with an array of IPv6 address strings, or an object
# with an `addresses` array of strings (the addresses the daemon owned). Each one still returned
# by Get-NetIPAddress makes the item `ledger-addresses` PRESENT. Never required.
#
# Not checkable from outside: the WFP engine option FWPM_ENGINE_COLLECT_NET_EVENTS (footprint.md
# lists it as a gap); netsh wfp show state does not export engine options. Verify it by code review.
#
# `netsh wfp show state` and `sc query` need an elevated shell for the WFP part.

param(
    [ValidateSet('absent', 'present')][string]$Expect,
    [string]$LedgerExport,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$ProviderGuid = '534F434B-4755-4152-4400-000000000001'
$SublayerGuid = '534F434B-4755-4152-4400-000000000002'

# ---- pure check functions: command output in, state out ------------------------------------

function Test-Denied([string]$Text) {
    return [bool]($Text -match '(?i)access is denied|requires elevation|administrator|FAILED 5:|error 5\b')
}

# Text of `netsh wfp show state` XML: does it mention the GUID (with or without braces)?
function Get-WfpGuidState([string]$Xml, [string]$Guid) {
    if ($Xml -match [regex]::Escape($Guid)) { return 'PRESENT' }
    return 'ABSENT'
}

# Any object whose <name> starts with SocketGuard (the filters are named "SocketGuard ...").
function Get-WfpNamedState([string]$Xml) {
    if ($Xml -match '(?i)<name>\s*SocketGuard') { return 'PRESENT' }
    return 'ABSENT'
}

# sc.exe query SocketGuard: missing is `FAILED 1060: The specified service does not exist`.
function Get-ServiceState([string]$Out) {
    if ($Out -match 'FAILED 1060') { return 'ABSENT' }
    if (Test-Denied $Out) { return 'UNKNOWN' }
    if ($Out -match '(?m)^SERVICE_NAME:\s*SocketGuard\s*$') { return 'PRESENT' }
    return 'ABSENT'
}

# net localgroup "SocketGuard Users": missing is system error 1376 / "does not exist".
function Get-GroupState([string]$Out) {
    if ($Out -match '1376|does not exist') { return 'ABSENT' }
    if ($Out -match '(?m)SocketGuard Users') { return 'PRESENT' }
    return 'ABSENT'
}

# A list of existing paths and a regex: PRESENT if any path matches.
function Get-ListedState($Paths, [string]$Regex) {
    foreach ($p in @($Paths)) { if ($p -match $Regex) { return 'PRESENT' } }
    return 'ABSENT'
}

function ConvertTo-NormalAddress([string]$Text) {
    $t = ($Text -replace '[/%].*$', '').Trim()
    try { return [System.Net.IPAddress]::Parse($t).ToString().ToLowerInvariant() }
    catch { return $t.ToLowerInvariant() }
}

# Ledger JSON text -> normalised address strings (array of strings, or object with `addresses`).
function Get-LedgerAddresses([string]$Json) {
    $v = $Json | ConvertFrom-Json
    $list = $v
    if ($null -ne $v -and $v.PSObject.Properties['addresses']) { $list = $v.addresses }
    $out = @()
    foreach ($a in @($list)) { if ($a -is [string] -and $a -match ':') { $out += ConvertTo-NormalAddress $a } }
    return $out
}

# Ledger addresses that are also in the interface address list.
function Get-LedgerStillPresent([string]$Json, $InterfaceAddresses) {
    $have = @($InterfaceAddresses | ForEach-Object { ConvertTo-NormalAddress ([string]$_) })
    return @(Get-LedgerAddresses $Json | Where-Object { $have -contains $_ } | Select-Object -Unique)
}

# ---- items and verdict ---------------------------------------------------------------------

$FileItems = @(
    @('config-json', '\\socketguard\.json$'),
    @('database', '\\socketguard\.db$'),
    @('database-wal', '\\socketguard\.db-wal$'),
    @('database-shm', '\\socketguard\.db-shm$'),
    @('setup-log', '\\setup-log\.json$'),
    @('archived-database', '\.pre-v1'),
    @('temp-file', '\\socketguard\.tmp-')
)

function New-Item2([string]$State, [string]$Name, [string]$Detail = '') {
    return [pscustomobject]@{ State = $State; Name = $Name; Detail = $Detail }
}

# Prints the lines, returns the number of mismatches.
function Write-Verdict($Items, [string]$Mode, [string[]]$Required) {
    $bad = 0; $names = @()
    foreach ($i in $Items) {
        $note = ''
        if ($Mode -eq 'present' -and $Required -notcontains $i.Name) { $note = ' (not required)' }
        elseif ($Mode -eq 'present' -and $i.State -ne 'PRESENT') { $bad++; $names += $i.Name }
        elseif ($Mode -eq 'absent' -and $i.State -ne 'ABSENT') { $bad++; $names += $i.Name }
        $detail = ''
        if ($i.Detail) { $detail = ' (' + $i.Detail + ')' }
        Write-Host ($i.State + ' ' + $i.Name + $detail + $note)
    }
    if ($Mode -eq 'absent') {
        if ($bad -eq 0) { Write-Host 'OK: nothing of SocketGuard found' }
        else { Write-Host ('FAIL: found or unverifiable: ' + ($names -join ' ')) }
    } else {
        if ($bad -eq 0) { Write-Host 'OK: all install items present' }
        else { Write-Host ('FAIL: missing or unverifiable: ' + ($names -join ' ')) }
    }
    return $bad
}

# ---- self test: no system access -----------------------------------------------------------

$script:SelfFail = $false
function Assert-Equal([string]$Label, $Expected, $Actual) {
    if ("$Expected" -eq "$Actual") { Write-Host "ok   $Label" }
    else { Write-Host "FAIL $Label : expected '$Expected', got '$Actual'"; $script:SelfFail = $true }
}

function Invoke-SelfTest {
    $xmlWith = '<wfpdiag><providers><item><providerKey>{534F434B-4755-4152-4400-000000000001}</providerKey></item></providers>' +
        '<subLayers><item><subLayerKey>{534f434b-4755-4152-4400-000000000002}</subLayerKey></item></subLayers>' +
        '<filters><item><displayData><name>SocketGuard deny 8080</name></displayData></item></filters></wfpdiag>'
    $xmlWithout = '<wfpdiag><providers><item><providerKey>{FFFFFFFF-0000-0000-0000-000000000001}</providerKey>' +
        '<displayData><name>Microsoft Windows Firewall</name></displayData></item></providers></wfpdiag>'
    Assert-Equal 'wfp-provider-present' 'PRESENT' (Get-WfpGuidState $xmlWith $ProviderGuid)
    Assert-Equal 'wfp-sublayer-present-lowercase' 'PRESENT' (Get-WfpGuidState $xmlWith $SublayerGuid)
    Assert-Equal 'wfp-named-present' 'PRESENT' (Get-WfpNamedState $xmlWith)
    Assert-Equal 'wfp-provider-absent' 'ABSENT' (Get-WfpGuidState $xmlWithout $ProviderGuid)
    Assert-Equal 'wfp-sublayer-absent' 'ABSENT' (Get-WfpGuidState $xmlWithout $SublayerGuid)
    Assert-Equal 'wfp-named-absent' 'ABSENT' (Get-WfpNamedState $xmlWithout)
    Assert-Equal 'wfp-empty' 'ABSENT' (Get-WfpNamedState '')

    $scUp = "`nSERVICE_NAME: SocketGuard `n        TYPE               : 10  WIN32_OWN_PROCESS`n        STATE              : 4  RUNNING`n"
    $scGone = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:`n`nThe specified service does not exist as an installed service.`n"
    Assert-Equal 'service-present' 'PRESENT' (Get-ServiceState $scUp)
    Assert-Equal 'service-absent' 'ABSENT' (Get-ServiceState $scGone)
    Assert-Equal 'service-denied' 'UNKNOWN' (Get-ServiceState "[SC] OpenService FAILED 5:`n`nAccess is denied.")

    $grpUp = "Alias name     SocketGuard Users`nComment        `n`nMembers`n---`nalice`nThe command completed successfully.`n"
    $grpGone = "System error 1376 has occurred.`n`nThe specified local group does not exist.`n"
    Assert-Equal 'group-present' 'PRESENT' (Get-GroupState $grpUp)
    Assert-Equal 'group-absent' 'ABSENT' (Get-GroupState $grpGone)
    Assert-Equal 'group-empty' 'ABSENT' (Get-GroupState '')

    $dir = 'C:\ProgramData\SocketGuard'
    $files = @($dir, "$dir\socketguard.json", "$dir\socketguard.db-wal", "$dir\socketguard.db.pre-v1.2", "$dir\socketguard.tmp-9-abc", "$dir\setup-log.json")
    Assert-Equal 'file-config' 'PRESENT' (Get-ListedState $files '\\socketguard\.json$')
    Assert-Equal 'file-db-not-wal' 'ABSENT' (Get-ListedState $files '\\socketguard\.db$')
    Assert-Equal 'file-wal' 'PRESENT' (Get-ListedState $files '\\socketguard\.db-wal$')
    Assert-Equal 'file-shm' 'ABSENT' (Get-ListedState $files '\\socketguard\.db-shm$')
    Assert-Equal 'file-pre-v1' 'PRESENT' (Get-ListedState $files '\.pre-v1')
    Assert-Equal 'file-tmp' 'PRESENT' (Get-ListedState $files '\\socketguard\.tmp-')
    Assert-Equal 'file-setup-log' 'PRESENT' (Get-ListedState $files '\\setup-log\.json$')
    Assert-Equal 'file-empty' 'ABSENT' (Get-ListedState @() '\\socketguard\.json$')

    $pipes = @('\\.\pipe\lsass', '\\.\pipe\socketguard', '\\.\pipe\wkssvc')
    Assert-Equal 'pipe-present' 'PRESENT' (Get-ListedState $pipes '(?i)\\socketguard$')
    Assert-Equal 'pipe-absent' 'ABSENT' (Get-ListedState @('\\.\pipe\lsass') '(?i)\\socketguard$')

    $ledgerArr = '["fd00::1", "FD00:0:0:0:0:0:0:2/128"]'
    $ledgerObj = '{"addresses": ["fd00::1"], "note": "x"}'
    $live = @('::1', 'fd00::1', 'fe80::1%12', 'fd00::2')
    Assert-Equal 'ledger-array' 'fd00::1 fd00::2' ((Get-LedgerStillPresent $ledgerArr $live) -join ' ')
    Assert-Equal 'ledger-object' 'fd00::1' ((Get-LedgerStillPresent $ledgerObj $live) -join ' ')
    Assert-Equal 'ledger-gone' '' ((Get-LedgerStillPresent $ledgerArr @('::1')) -join ' ')

    $req = @('service', 'group', 'config-dir')
    $clean = @((New-Item2 'ABSENT' 'service'), (New-Item2 'ABSENT' 'group'), (New-Item2 'ABSENT' 'config-dir'), (New-Item2 'ABSENT' 'wfp-provider'))
    Assert-Equal 'verdict-absent-clean' 0 (Write-Verdict $clean 'absent' $req | Select-Object -Last 1)
    Assert-Equal 'verdict-present-missing-required' 3 (Write-Verdict $clean 'present' $req | Select-Object -Last 1)
    $inst = @((New-Item2 'PRESENT' 'service'), (New-Item2 'PRESENT' 'group'), (New-Item2 'PRESENT' 'config-dir'), (New-Item2 'ABSENT' 'database'))
    Assert-Equal 'verdict-present-ok' 0 (Write-Verdict $inst 'present' $req | Select-Object -Last 1)
    Assert-Equal 'verdict-absent-leftover' 3 (Write-Verdict $inst 'absent' $req | Select-Object -Last 1)
    Assert-Equal 'verdict-unknown-fails' 1 (Write-Verdict @(New-Item2 'UNKNOWN' 'wfp-provider') 'absent' $req | Select-Object -Last 1)

    if ($script:SelfFail) { Write-Host 'SELF-TEST FAILED'; return 1 }
    Write-Host 'SELF-TEST PASSED'
    return 0
}

# ---- live collection (only reached outside -SelfTest) --------------------------------------

function Read-TextAuto([string]$Path) {
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode.GetString($b) }
    return [System.Text.Encoding]::UTF8.GetString($b)
}

function Invoke-Live {
    $items = @()
    $dir = Join-Path $env:ProgramData 'SocketGuard'

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('sg-wfp-' + [guid]::NewGuid().ToString('N') + '.xml')
    try {
        $netshOut = (& netsh wfp show state file=$tmp 2>&1) | Out-String
        if ((Test-Path $tmp) -and -not (Test-Denied $netshOut)) {
            $xml = Read-TextAuto $tmp
            $items += New-Item2 (Get-WfpGuidState $xml $ProviderGuid) 'wfp-provider'
            $items += New-Item2 (Get-WfpGuidState $xml $SublayerGuid) 'wfp-sublayer'
            $items += New-Item2 (Get-WfpNamedState $xml) 'wfp-filters-named-socketguard'
        } else {
            foreach ($n in 'wfp-provider', 'wfp-sublayer', 'wfp-filters-named-socketguard') { $items += New-Item2 'UNKNOWN' $n 'run elevated' }
        }
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
    }

    $items += New-Item2 (Get-ServiceState ((& sc.exe query SocketGuard 2>&1) | Out-String)) 'service'
    $items += New-Item2 (Get-GroupState ((& net.exe localgroup 'SocketGuard Users' 2>&1) | Out-String)) 'group'

    $paths = @()
    if (Test-Path $dir) { $paths += $dir; $paths += @(Get-ChildItem -LiteralPath $dir -Force | ForEach-Object { $_.FullName }) }
    $items += New-Item2 (Get-ListedState $paths '(?i)\\ProgramData\\SocketGuard$') 'config-dir'
    foreach ($e in $FileItems) { $items += New-Item2 (Get-ListedState $paths ('(?i)' + $e[1])) $e[0] }

    $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\'))
    $items += New-Item2 (Get-ListedState $pipes '(?i)\\socketguard$') 'named-pipe'

    if ($LedgerExport) {
        $live = @(Get-NetIPAddress -AddressFamily IPv6 | ForEach-Object { $_.IPAddress })
        $hits = @(Get-LedgerStillPresent (Get-Content -Raw -LiteralPath $LedgerExport) $live)
        if ($hits.Count -gt 0) { $items += New-Item2 'PRESENT' 'ledger-addresses' ($hits -join ' ') }
        else { $items += New-Item2 'ABSENT' 'ledger-addresses' }
    }
    return $items
}

# ---- main ----------------------------------------------------------------------------------

if ($SelfTest) { exit (Invoke-SelfTest | Select-Object -Last 1) }
if (-not $Expect) {
    Write-Host 'usage: footprint-check.ps1 -Expect absent|present [-LedgerExport FILE] | -SelfTest'
    exit 2
}
if ($LedgerExport -and -not (Test-Path -LiteralPath $LedgerExport)) {
    Write-Host "cannot read ledger export: $LedgerExport"
    exit 2
}

$items = Invoke-Live
$bad = Write-Verdict $items $Expect @('service', 'group', 'config-dir') | Select-Object -Last 1
if ($bad -eq 0) { exit 0 } else { exit 1 }
