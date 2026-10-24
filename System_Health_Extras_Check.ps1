# PC Health and Crash Toolkit 1.0.2 - https://ihavenoram.com - https://github.com/ihavenoram/pc-health-crash-toolkit
# MIT licence, (c) 2026 ihavenoram.com. If you publish something built on this, please credit ihavenoram.com.
<#
=========================================================
Script Name: System_Health_Extras_Check
Description: Companion health checks for an unstable or "not quite right" PC that the crash,
SSD, thermal and UI-lag scripts do not cover:
  - Disk space: every fixed volume, with the SYSTEM disk graded (ALERT < 5 GB or < 5% free,
    WARN < 15 GB or < 10%), the biggest space users when it is low, pagefile headroom, and
    whether a kernel crash dump still fits.
  - Storage controller stalls: controller resets (129), timeouts (9), controller errors (11),
    device-not-ready (15) from any storage controller driver incl. Intel RST/Optane, and disk
    I/O retries (153), by day - the freeze/stutter/RDP-drop signature, with times to line up
    against crashes.
  - Memory: installed vs usable RAM, DIMMs, commit pressure, WHEA memory-class errors and
    Windows Memory Diagnostic results.
  - Drivers / devices: Device Manager problem codes, unsigned or very old third-party drivers
    for display / storage / network / chipset, BIOS age, driver installs in the lookback
    window (with times, to line up against crash times).
  - Windows integrity: pending reboot, updates installed / failed in the window, last
    successful update, component-store corruption markers in CBS.log, OS build support.
  - Battery / power: battery wear (powercfg battery report), power plan, Fast Startup,
    sleep states, deaths during sleep and wake sources.

Output: a text report, then ONE compact JSON line between
===HEALTHX_JSON_BEGIN=== / ===HEALTHX_JSON_END=== (read by PC_Health_Crash_Toolkit.ps1).
Exit code: 0 OK / 1 WARN / 2 ALERT.

Category:    ScriptLibrary
Run Time:    5 minutes
Arguments:   -Days 30   (lookback for events, driver installs and updates)
             -OutputDir C:\temp  -NoFiles  -NoInlineJson
Run As:      System
=========================================================
#>
# Requires PowerShell 3.0+ (no #Requires, so older hosts reach the version check).
param(
    [int]$Days = 30,
    [string]$OutputDir = 'C:\temp',
    [switch]$NoFiles,
    [switch]$NoInlineJson
)

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Output ('[WARN] PowerShell 3.0 or later is required (found ' + $PSVersionTable.PSVersion + ').')
    exit 1
}

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
if ($Days -lt 1) { $Days = 1 }

$script:Inv      = [System.Globalization.CultureInfo]::InvariantCulture
$script:Now      = Get-Date
$script:Since    = $script:Now.AddDays(-$Days)
$script:Sb       = New-Object System.Text.StringBuilder
$script:Findings = New-Object System.Collections.ArrayList
$script:Timing   = New-Object System.Collections.ArrayList
$script:Data     = @{}

# Thresholds
$SysAlertGB = 5;  $SysAlertPct = 5
$SysWarnGB  = 15; $SysWarnPct  = 10
$OtherWarnPct = 5
$CommitWarnPct = 90
$DriverOldYears = 5
$BatteryWarnPct = 60; $BatteryAlertPct = 30

# =============================================================================
# HELPERS
# =============================================================================
function Add-Line    { param([string]$Text = '') [void]$script:Sb.AppendLine($Text) }
function Add-Section { param([string]$Title) Add-Line ''; Add-Line $Title; Add-Line ('-' * $Title.Length) }
function Format-Time { param($T) if ($null -eq $T) { return '' } return ([datetime]$T).ToString('yyyy-MM-dd HH:mm', $script:Inv) }
function Format-Iso  { param($T) if ($null -eq $T) { return $null } return ([datetime]$T).ToString('yyyy-MM-ddTHH:mm:sszzz', $script:Inv) }
function Format-GB   { param([double]$Bytes) return ([math]::Round($Bytes / 1GB, 1)).ToString($script:Inv) }
function Limit-Text  {
    param([string]$Text, [int]$Max = 160)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

# Level: OK / INFO / WARN / ALERT. Area: Disk / Memory / Drivers / Windows / Power.
function Add-Finding {
    param([string]$Level, [string]$Area, [string]$Text, $When = $null)
    Add-Line ('  [' + $Level + '] ' + $Text)
    if ($Level -ne 'OK') {
        [void]$script:Findings.Add([pscustomobject]@{ sev = $Level; area = $Area; text = $Text; t = (Format-Iso $When) })
    }
}
function Add-Info { param([string]$Text) Add-Line ('        ' + $Text) }

function Start-Phase { param([string]$Name) $script:PhaseName = $Name; $script:PhaseSw = [System.Diagnostics.Stopwatch]::StartNew() }
function Stop-Phase  { [void]$script:Timing.Add(($script:PhaseName + '=' + [math]::Round($script:PhaseSw.Elapsed.TotalSeconds, 1) + 's')) }

function Get-Events {
    param([hashtable]$Filter, [int]$Max = 0)
    try {
        if ($Max -gt 0) { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
        return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
    } catch { return @() }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
        if ($null -eq $k) { return $null }
        try { return $k.GetValue($Name) } finally { $k.Close() }
    } catch { return $null }
}
function Test-RegKey {
    param([string]$Path)
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
        if ($null -eq $k) { return $false }
        $k.Close(); return $true
    } catch { return $false }
}

# Directory size with a time budget; skips folders it cannot read.
function Get-DirBytes {
    param([string]$Path, [double]$BudgetSec = 6)
    $res = [pscustomobject]@{ bytes = [long]0; partial = $false }
    if (-not [System.IO.Directory]::Exists($Path)) { return $res }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stack = New-Object System.Collections.Stack
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -gt $BudgetSec) { $res.partial = $true; break }
        $d = [string]$stack.Pop()
        try {
            $di = New-Object System.IO.DirectoryInfo($d)
            foreach ($f in $di.GetFiles()) { $res.bytes += $f.Length }
            foreach ($s in $di.GetDirectories()) {
                if (($s.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($s.FullName) }
            }
        } catch { }
    }
    return $res
}

$isAdmin = $false
try {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

$os = $null; $cs = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }

# =============================================================================
# 1. DISK SPACE
# =============================================================================
Start-Phase 'disk'
Add-Section '[1] DISK SPACE'
$sysDrive = ([string]$env:SystemDrive).ToUpper()
$disks = @()
try { $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop) } catch { }
$diskRows = New-Object System.Collections.ArrayList
$sysLow = $false
$sysFree = $null
foreach ($d in ($disks | Sort-Object DeviceID)) {
    if (-not $d.Size) { continue }
    $free = [double]$d.FreeSpace; $size = [double]$d.Size
    $pct = [math]::Round(($free / $size) * 100, 1)
    $freeGB = [math]::Round($free / 1GB, 1)
    $isSys = ([string]$d.DeviceID).ToUpper() -eq $sysDrive
    $label = ''
    if ($d.VolumeName) { $label = ' "' + $d.VolumeName + '"' }
    $line = $d.DeviceID + $label + ' ' + (Format-GB $free) + ' GB free of ' + (Format-GB $size) + ' GB (' + $pct.ToString($script:Inv) + '% free)'
    $lvl = 'OK'
    if ($isSys) {
        $sysFree = $free
        if ($freeGB -lt $SysAlertGB -or $pct -lt $SysAlertPct) { $lvl = 'ALERT' }
        elseif ($freeGB -lt $SysWarnGB -or $pct -lt $SysWarnPct) { $lvl = 'WARN' }
        if ($lvl -ne 'OK') { $sysLow = $true }
        $line = 'System disk ' + $line
        if ($lvl -eq 'ALERT') { $line += ' - critically low: updates, crash dumps and the pagefile can fail' }
        elseif ($lvl -eq 'WARN') { $line += ' - low' }
    } else {
        if ($pct -lt $OtherWarnPct -and $freeGB -lt 20) { $lvl = 'WARN'; $line += ' - nearly full' }
    }
    Add-Finding $lvl 'Disk' $line
    [void]$diskRows.Add([pscustomobject]@{ drive = $d.DeviceID; label = $d.VolumeName; fs = $d.FileSystem; sizeGB = [math]::Round($size / 1GB, 1); freeGB = $freeGB; freePct = $pct; system = $isSys; level = $lvl })
}
if ($diskRows.Count -eq 0) { Add-Finding 'INFO' 'Disk' 'No fixed volumes could be read (Win32_LogicalDisk failed).' }

# Pagefile
$pageRows = @()
try { $pageRows = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop) } catch { }
$autoPf = $null
if ($cs) { $autoPf = $cs.AutomaticManagedPagefile }
if ($pageRows.Count -eq 0) {
    Add-Finding 'WARN' 'Memory' 'No pagefile configured - Windows cannot write a kernel crash dump and large apps may fail under memory pressure.'
} else {
    foreach ($p in $pageRows) {
        Add-Info ('Pagefile ' + $p.Name + ': ' + $p.AllocatedBaseSize + ' MB allocated, ' + $p.CurrentUsage + ' MB in use, peak ' + $p.PeakUsage + ' MB' + $(if ($autoPf) { ' (system managed)' } else { '' }))
    }
}

# Crash dump headroom
$dumpType = Get-RegValue 'SYSTEM\CurrentControlSet\Control\CrashControl' 'CrashDumpEnabled'
$dumpNames = @{ 0 = 'none'; 1 = 'complete'; 2 = 'kernel'; 3 = 'small (minidump)'; 7 = 'automatic' }
$ramBytes = 0
if ($cs) { $ramBytes = [double]$cs.TotalPhysicalMemory }
if ($null -ne $dumpType) {
    $dn = $dumpNames[[int]$dumpType]; if (-not $dn) { $dn = [string]$dumpType }
    Add-Info ('Crash dump setting: ' + $dn)
    if ([int]$dumpType -eq 0) {
        Add-Finding 'WARN' 'Windows' 'Crash dumps are disabled (CrashControl CrashDumpEnabled = 0) - the next crash will leave no dump to analyse.'
    } elseif ($null -ne $sysFree -and $ramBytes -gt 0 -and ([int]$dumpType -eq 1 -or [int]$dumpType -eq 2 -or [int]$dumpType -eq 7)) {
        # A kernel dump is typically a fraction of RAM; the pagefile must hold it before it is copied out.
        $need = $ramBytes / 3
        if ([int]$dumpType -eq 1) { $need = $ramBytes }
        if ($sysFree -lt $need) {
            Add-Finding 'WARN' 'Disk' ('System disk free space (' + (Format-GB $sysFree) + ' GB) may be too small to save a ' + $dn + ' crash dump (about ' + (Format-GB $need) + ' GB needed) - a crash could leave only volmgr 161 behind.')
        }
    }
}

# Biggest space users when the system disk is low
$spaceUsers = New-Object System.Collections.ArrayList
if ($sysLow) {
    Add-Info 'System disk is low - largest known space users (time-limited scan):'
    $win = $env:SystemRoot
    $candidates = @(
        @{ n = 'Windows Update download cache'; p = (Join-Path $win 'SoftwareDistribution\Download'); dir = $true },
        @{ n = 'Windows Temp';                  p = (Join-Path $win 'Temp'); dir = $true },
        @{ n = 'Windows Installer cache';       p = (Join-Path $win 'Installer'); dir = $true },
        @{ n = 'Full crash dump MEMORY.DMP';    p = (Join-Path $win 'MEMORY.DMP'); dir = $false },
        @{ n = 'LiveKernelReports';             p = (Join-Path $win 'LiveKernelReports'); dir = $true },
        @{ n = 'Hibernation file';              p = ($sysDrive + '\hiberfil.sys'); dir = $false },
        @{ n = 'Pagefile';                      p = ($sysDrive + '\pagefile.sys'); dir = $false },
        @{ n = 'Recycle Bin (all users)';       p = ($sysDrive + '\$Recycle.Bin'); dir = $true },
        @{ n = 'Previous Windows install';      p = ($sysDrive + '\Windows.old'); dir = $true }
    )
    $profRoot = $sysDrive + '\Users'
    try {
        foreach ($u in [System.IO.Directory]::GetDirectories($profRoot)) {
            $leaf = [System.IO.Path]::GetFileName($u)
            if ($leaf -eq 'Public' -or $leaf -eq 'Default' -or $leaf -eq 'Default User' -or $leaf -eq 'All Users') { continue }
            $candidates += @{ n = ('Temp - ' + $leaf); p = (Join-Path $u 'AppData\Local\Temp'); dir = $true }
            $candidates += @{ n = ('Downloads - ' + $leaf); p = (Join-Path $u 'Downloads'); dir = $true }
        }
    } catch { }
    $budgetSw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($c in $candidates) {
        if ($budgetSw.Elapsed.TotalSeconds -gt 40) { Add-Info '(scan time budget reached - remaining folders skipped)'; break }
        $bytes = [long]0; $partial = $false
        if ($c.dir) { $r = Get-DirBytes $c.p 6; $bytes = $r.bytes; $partial = $r.partial }
        else { try { if ([System.IO.File]::Exists($c.p)) { $bytes = (New-Object System.IO.FileInfo($c.p)).Length } } catch { } }
        if ($bytes -ge 500MB) {
            [void]$spaceUsers.Add([pscustomobject]@{ name = $c.n; path = $c.p; gb = [math]::Round($bytes / 1GB, 1); partial = $partial })
        }
    }
    foreach ($s in ($spaceUsers | Sort-Object gb -Descending)) {
        Add-Info ('  ' + ('{0,6:N1}' -f $s.gb) + ' GB  ' + $s.name + '  (' + $s.path + ')' + $(if ($s.partial) { ' - at least' } else { '' }))
    }
    if ($spaceUsers.Count -eq 0) { Add-Info '  none of the usual folders hold 0.5 GB or more - check user data and installed apps' }
}
$script:Data['disks'] = @($diskRows); $script:Data['spaceUsers'] = @($spaceUsers | Sort-Object gb -Descending)
Stop-Phase

# =============================================================================
# 2. STORAGE CONTROLLER STALLS (freezes / stutter)
# =============================================================================
Start-Phase 'stalls'
Add-Section '[2] STORAGE CONTROLLER STALLS (freezes, stutter, RDP drops)'
# 129 controller reset, 9 device timeout, 11 controller error, 15 device not ready (from storage
# controller drivers), 153 I/O retried (disk). Hyper-V and Kernel-Boot reuse these IDs, so only
# storage drivers count; disk 9/11/15 are mostly USB sticks and card readers and are skipped.
$stallKinds = @{ 129 = 'controller reset'; 9 = 'device timeout'; 11 = 'controller error'; 15 = 'device not ready'; 153 = 'I/O retried' }
$ctrlRe = '(?i)iastor|stornvme|storahci|nvme|ahci|storport|vmd|vroc|raid|megasas|lsi_|sas|scsi|sata'
$rawStall = Get-Events @{ LogName = 'System'; Id = 129, 9, 11, 15, 153; StartTime = $script:Since } 3000
$stalls = New-Object System.Collections.ArrayList
foreach ($e in $rawStall) {
    $prov = [string]$e.ProviderName
    if ($prov -match 'Hyper-V|Kernel-Boot|Kernel-General|storvsp') { continue }
    $isCtrl = $prov -match $ctrlRe
    if (-not $isCtrl -and -not ($prov -eq 'disk' -and $e.Id -eq 153)) { continue }
    [void]$stalls.Add([pscustomobject]@{ T = $e.TimeCreated; Prov = $prov; Id = $e.Id; Ctrl = ($isCtrl -and $e.Id -ne 153); Text = (Limit-Text $e.Message 140) })
}
$rst = $false; $rstName = ''; $optane = $false
try {
    $rd = @(Get-CimInstance Win32_SystemDriver -Filter "Name LIKE 'iaStor%' AND State='Running'" -ErrorAction Stop)
    if ($rd.Count -gt 0) { $rst = $true; $rstName = [string]$rd[0].Name }
} catch { }
try { $optane = (@(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.Model -match 'Optane' }).Count -gt 0) } catch { }
if ($rst -or $optane) { Add-Info ('Intel RST driver: ' + $(if ($rst) { $rstName + ' (running)' } else { 'not running' }) + '    Optane drive: ' + $optane) }

$cut7 = $script:Now.AddDays(-7)
$ctrlStalls = @($stalls | Where-Object { $_.Ctrl })
$retries = @($stalls | Where-Object { -not $_.Ctrl })
$ctrl7 = @($ctrlStalls | Where-Object { $_.T -ge $cut7 })
$byDay = @($stalls | Group-Object { $_.T.ToString('yyyy-MM-dd', $script:Inv) } | Sort-Object Name | ForEach-Object {
    $grp = $_
    [pscustomobject]@{ d = $grp.Name; n = $grp.Count; ctrl = @($grp.Group | Where-Object { $_.Ctrl }).Count; retry = @($grp.Group | Where-Object { -not $_.Ctrl }).Count }
})
$byProv = @($stalls | Group-Object Prov, Id | Sort-Object Count -Descending | ForEach-Object {
    $srt = @($_.Group | Sort-Object T)
    [pscustomobject]@{ prov = $srt[0].Prov; id = $srt[0].Id; kind = $stallKinds[[int]$srt[0].Id]; n = $_.Count; first = (Format-Iso $srt[0].T); last = (Format-Iso $srt[$srt.Count - 1].T) }
})
$latest = $null
if ($stalls.Count -gt 0) { $latest = @($stalls | Sort-Object T -Descending)[0] }
if ($ctrlStalls.Count -gt 0) {
    $lvl = 'WARN'
    if ($ctrl7.Count -ge 5 -or $ctrlStalls.Count -ge 10) { $lvl = 'ALERT' }
    $kinds = @($ctrlStalls | Group-Object Id | Sort-Object Count -Descending | ForEach-Object { '' + $_.Count + ' ' + $stallKinds[[int]$_.Name] + ' (' + $_.Name + ')' }) -join ', '
    $lastCtrl = @($ctrlStalls | Sort-Object T -Descending)[0]
    Add-Finding $lvl 'Storage stalls' ('Storage controller stalls: ' + $ctrlStalls.Count + ' in ' + $Days + ' days (' + $kinds + '), ' + $ctrl7.Count + ' in the last 7 days, latest ' + (Format-Time $lastCtrl.T) + ' on ' + $lastCtrl.Prov + ' - each one freezes disk I/O for seconds (mouse/screen stutter, app hangs, RDP drops)') $lastCtrl.T
    if ($rst -or $optane) {
        Add-Finding 'INFO' 'Storage stalls' ('Storage runs through Intel RST' + $(if ($optane) { ' with an Optane drive' } else { '' }) + ' - the classic Optane/RST freeze: update the RST driver and BIOS; if it persists, disable the Optane cache or move the controller to AHCI/NVMe mode (plan it - Windows will not boot after a plain BIOS switch).')
    } else {
        Add-Info 'Next: update the storage/chipset driver and SSD firmware, check SMART health (SSD script), reseat or replace the drive if resets continue.'
    }
    if ($retries.Count -gt 0) { Add-Info ('Also ' + $retries.Count + ' disk I/O retries (disk 153).') }
} elseif ($retries.Count -gt 0) {
    $lvl = 'INFO'; if ($retries.Count -ge 5) { $lvl = 'WARN' }
    Add-Finding $lvl 'Storage stalls' ('' + $retries.Count + ' disk I/O retries (disk 153) in ' + $Days + ' days, latest ' + (Format-Time $latest.T) + ' - brief stalls; USB drives and card readers can also log these') $latest.T
} else {
    Add-Finding 'OK' 'Storage stalls' ('No storage controller resets, timeouts or I/O retries in the last ' + $Days + ' days.')
}
if ($stalls.Count -gt 0) {
    Add-Info 'Days with stalls (newest first):'
    foreach ($dd in @($byDay | Sort-Object d -Descending | Select-Object -First 15)) {
        Add-Info ('  ' + $dd.d + '  ' + $dd.n + ' stall(s): ' + $dd.ctrl + ' controller, ' + $dd.retry + ' I/O retries')
    }
    Add-Info 'By driver and event:'
    foreach ($bp in $byProv) {
        Add-Info ('  ' + ('{0,4}' -f $bp.n) + 'x  ' + $bp.prov + ' ' + $bp.id + ' ' + $bp.kind + '   first ' + (Format-Time ([datetime]::Parse($bp.first, $script:Inv))) + ', last ' + (Format-Time ([datetime]::Parse($bp.last, $script:Inv))))
    }
}
$script:Data['storageStalls'] = [pscustomobject]@{
    rst = $rst; rstDriver = $rstName; optane = $optane
    total = $stalls.Count; controller = $ctrlStalls.Count; retries = $retries.Count; last7 = $ctrl7.Count
    last = $(if ($latest) { Format-Iso $latest.T } else { $null })
    byDay = $byDay; byProvider = $byProv
    recent = @($stalls | Sort-Object T -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ t = (Format-Iso $_.T); prov = $_.Prov; id = $_.Id; x = $_.Text } })
    # Times for lining stalls up against crashes and restarts (newest 300)
    times = @($stalls | Sort-Object T -Descending | Select-Object -First 300 | ForEach-Object { [pscustomobject]@{ t = (Format-Iso $_.T); c = [bool]$_.Ctrl } })
}
Stop-Phase

# =============================================================================
# 3. MEMORY
# =============================================================================
Start-Phase 'memory'
Add-Section '[3] MEMORY'
$dimms = @()
try { $dimms = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop) } catch { }
$installed = 0
foreach ($m in $dimms) { $installed += [double]$m.Capacity }
$mem = [ordered]@{ installedGB = $null; usableGB = $null; commitPct = $null; freeGB = $null; dimms = @() }
if ($installed -gt 0) { $mem.installedGB = [math]::Round($installed / 1GB, 1) }
if ($ramBytes -gt 0)  { $mem.usableGB = [math]::Round($ramBytes / 1GB, 1) }
$memLine = 'RAM: '
if ($mem.installedGB) { $memLine += $mem.installedGB.ToString($script:Inv) + ' GB installed' }
if ($mem.usableGB)    { $memLine += ', ' + $mem.usableGB.ToString($script:Inv) + ' GB usable' }
Add-Info $memLine
if ($installed -gt 0 -and $ramBytes -gt 0) {
    $reservedPct = [math]::Round((1 - ($ramBytes / $installed)) * 100, 0)
    if ($reservedPct -ge 25) {
        Add-Finding 'WARN' 'Memory' ('' + $reservedPct + '% of installed RAM is unusable (hardware reserved) - check a DIMM is not failing, BIOS memory remap, or a large iGPU allocation.')
    }
}
foreach ($m in $dimms) {
    $speed = $m.ConfiguredClockSpeed; if (-not $speed) { $speed = $m.Speed }
    $d = [pscustomobject]@{ slot = (([string]$m.DeviceLocator + ' ' + [string]$m.BankLabel).Trim()); gb = [math]::Round(([double]$m.Capacity) / 1GB, 1); mhz = $speed; maker = ([string]$m.Manufacturer).Trim(); part = ([string]$m.PartNumber).Trim() }
    $mem.dimms += $d
    Add-Info ('  ' + $d.slot + ': ' + $d.gb + ' GB ' + $(if ($d.mhz) { '' + $d.mhz + ' MHz ' } else { '' }) + $d.maker + ' ' + $d.part)
}
if (@($mem.dimms | Select-Object -ExpandProperty part -Unique).Count -gt 1) {
    Add-Info '  Mixed DIMM part numbers - mismatched modules are a common cause of random crashes; test with one kit.'
}
if ($os) {
    $totV = [double]$os.TotalVirtualMemorySize; $freeV = [double]$os.FreeVirtualMemory
    if ($totV -gt 0) {
        $mem.commitPct = [math]::Round((($totV - $freeV) / $totV) * 100, 0)
        $mem.freeGB = [math]::Round(([double]$os.FreePhysicalMemory) * 1KB / 1GB, 1)
        $lvl = 'OK'; if ($mem.commitPct -ge $CommitWarnPct) { $lvl = 'WARN' }
        Add-Finding $lvl 'Memory' ('Commit charge ' + $mem.commitPct + '% of limit, ' + $mem.freeGB.ToString($script:Inv) + ' GB RAM free right now' + $(if ($lvl -eq 'WARN') { ' - memory pressure (apps may hang or fail to start)' } else { '' }))
    }
}

# WHEA memory-class errors
$whea = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $script:Since } 500
$wheaMem = @($whea | Where-Object { $_.Id -eq 47 -or ($_.Message -and $_.Message -match 'Component:\s*Memory|Error Type:\s*[^\r\n]*Memory') })
$wheaMemFatal = @($wheaMem | Where-Object { $_.Level -le 2 })
$wheaMemCorr  = @($wheaMem | Where-Object { $_.Level -gt 2 })
if ($wheaMemFatal.Count -gt 0) {
    Add-Finding 'ALERT' 'Memory' ('' + $wheaMemFatal.Count + ' fatal memory hardware error(s) (WHEA) in the last ' + $Days + ' days, latest ' + (Format-Time $wheaMemFatal[0].TimeCreated) + ' - test or replace RAM.') $wheaMemFatal[0].TimeCreated
}
if ($wheaMemCorr.Count -gt 0) {
    Add-Finding 'WARN' 'Memory' ('' + $wheaMemCorr.Count + ' corrected memory hardware error(s) (WHEA) in the last ' + $Days + ' days, latest ' + (Format-Time $wheaMemCorr[0].TimeCreated) + ' - early sign of a failing DIMM.') $wheaMemCorr[0].TimeCreated
}
if ($wheaMem.Count -eq 0) { Add-Finding 'OK' 'Memory' ('No memory-class WHEA hardware errors in the last ' + $Days + ' days.') }

# Windows Memory Diagnostic (verified IDs: 1101/1201 no errors, 1102/1202 errors, 1103 cancelled, 1104 incomplete)
$mdr = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } 10
$mdLast = $null
if ($mdr.Count -gt 0) {
    $e = $mdr[0]
    $res = 'result event ' + $e.Id
    $lvl = 'INFO'
    if ($e.Id -eq 1101 -or $e.Id -eq 1201) { $res = 'no errors found'; $lvl = 'OK' }
    elseif ($e.Id -eq 1102 -or $e.Id -eq 1202) { $res = 'HARDWARE ERRORS FOUND - replace or reseat RAM'; $lvl = 'ALERT' }
    elseif ($e.Id -eq 1103) { $res = 'cancelled before it finished' }
    elseif ($e.Id -eq 1104) { $res = 'could not complete' }
    $mdLast = [pscustomobject]@{ t = (Format-Iso $e.TimeCreated); id = $e.Id; result = $res }
    Add-Finding $lvl 'Memory' ('Windows Memory Diagnostic last ran ' + (Format-Time $e.TimeCreated) + ': ' + $res + '.') $e.TimeCreated
} else {
    Add-Finding 'INFO' 'Memory' 'Windows Memory Diagnostic has no recorded result on this PC (never run, or the log rolled over).'
}
$mem['wheaFatal'] = $wheaMemFatal.Count; $mem['wheaCorrected'] = $wheaMemCorr.Count; $mem['memDiag'] = $mdLast
$script:Data['memory'] = [pscustomobject]$mem
Stop-Phase

# =============================================================================
# 4. DRIVERS / DEVICES / FIRMWARE
# =============================================================================
Start-Phase 'drivers'
Add-Section '[4] DRIVERS, DEVICES AND FIRMWARE'
$problemText = @{
    1 = 'not configured correctly'; 3 = 'driver corrupted or out of memory'; 10 = 'cannot start'; 12 = 'not enough free resources'
    14 = 'needs a restart'; 18 = 'drivers need reinstalling'; 19 = 'registry configuration damaged'; 21 = 'being removed'
    22 = 'disabled'; 24 = 'not present / not working'; 28 = 'no driver installed'; 29 = 'disabled by firmware'
    31 = 'driver failed to load'; 32 = 'driver service disabled'; 33 = 'resource translation failed'; 34 = 'needs manual configuration'
    35 = 'firmware missing information'; 37 = 'driver initialisation failed'; 38 = 'previous driver instance still loaded'
    39 = 'driver corrupt or missing'; 40 = 'service registry entry invalid'; 41 = 'driver loaded but device not found'
    42 = 'duplicate device'; 43 = 'device reported a problem (stopped)'; 44 = 'shut down by an application or service'
    45 = 'not connected'; 47 = 'prepared for safe removal'; 48 = 'blocked (known compatibility problem)'
    49 = 'registry hive too large'; 52 = 'driver signature could not be verified'; 54 = 'failed (ACPI reset)'
}
$devRows = New-Object System.Collections.ArrayList
$pnp = @()
try { $pnp = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction Stop) } catch { }
foreach ($p in $pnp) {
    $code = [int]$p.ConfigManagerErrorCode
    $txt = $problemText[$code]; if (-not $txt) { $txt = 'problem code ' + $code }
    $name = $p.Name; if (-not $name) { $name = $p.DeviceID }
    $cls = [string]$p.PNPClass
    [void]$devRows.Add([pscustomobject]@{ name = $name; cls = $cls; code = $code; problem = $txt; id = $p.DeviceID })
    $lvl = 'WARN'
    if ($code -eq 22 -or $code -eq 45 -or $code -eq 47) { $lvl = 'INFO' }
    Add-Finding $lvl 'Drivers' ('Device problem: ' + $name + $(if ($cls) { ' [' + $cls + ']' } else { '' }) + ' - code ' + $code + ' (' + $txt + ')')
}
if ($pnp.Count -eq 0) { Add-Finding 'OK' 'Drivers' 'No devices with a problem code in Device Manager.' }

# Signed driver inventory (key classes, third-party only for age/signature checks)
$keyClasses = @('DISPLAY', 'SCSIADAPTER', 'HDC', 'NET', 'SYSTEM', 'MEDIA', 'BLUETOOTH')
$drvRows = New-Object System.Collections.ArrayList
$signed = @()
try { $signed = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop) } catch { }
$oldCut = $script:Now.AddYears(-$DriverOldYears)
$oldDrivers = New-Object System.Collections.ArrayList
$unsigned = New-Object System.Collections.ArrayList
$drvSeen = @{}
foreach ($s in $signed) {
    $cls = ([string]$s.DeviceClass).ToUpper()
    if ($keyClasses -notcontains $cls) { continue }
    $prov = [string]$s.DriverProviderName
    $isMs = $prov -match '^Microsoft'
    $dt = $null
    if ($s.DriverDate) { try { $dt = [datetime]$s.DriverDate } catch { } }
    $row = [pscustomobject]@{ cls = $cls; name = $s.DeviceName; provider = $prov; version = $s.DriverVersion; date = $(if ($dt) { $dt.ToString('yyyy-MM-dd', $script:Inv) } else { $null }); signed = $s.IsSigned; inf = $s.InfName }
    $dk = $cls + '|' + $s.DeviceName + '|' + $s.DriverVersion
    if (($cls -eq 'DISPLAY' -or $cls -eq 'SCSIADAPTER' -or $cls -eq 'HDC' -or ($cls -eq 'NET' -and -not $isMs)) -and
        -not $drvSeen.ContainsKey($dk) -and ([string]$s.DeviceName) -notmatch 'Storage Spaces|VHD Loopback|Microsoft Basic Display') {
        $drvSeen[$dk] = $true; [void]$drvRows.Add($row)
    }
    if (-not $isMs -and $prov) {
        if ($s.IsSigned -eq $false) { [void]$unsigned.Add($row) }
        if ($dt -and $dt -lt $oldCut -and ($cls -eq 'DISPLAY' -or $cls -eq 'SCSIADAPTER' -or $cls -eq 'HDC' -or $cls -eq 'NET' -or $cls -eq 'SYSTEM')) { [void]$oldDrivers.Add($row) }
    }
}
foreach ($r in ($drvRows | Sort-Object cls, name)) {
    Add-Info ($r.cls + ': ' + $r.name + ' - ' + $r.provider + ' ' + $r.version + $(if ($r.date) { ' (' + $r.date + ')' } else { '' }))
}
foreach ($r in $unsigned) {
    Add-Finding 'WARN' 'Drivers' ('Unsigned third-party driver: ' + $r.name + ' [' + $r.cls + '] ' + $r.provider + ' ' + $r.version)
}
$oldShown = @($oldDrivers | Sort-Object date | Select-Object -First 6)
foreach ($r in $oldShown) {
    Add-Finding 'INFO' 'Drivers' ('Driver older than ' + $DriverOldYears + ' years: ' + $r.name + ' [' + $r.cls + '] ' + $r.provider + ' ' + $r.version + ' (' + $r.date + ') - check the OEM for an update if crashes point at it')
}
if ($oldDrivers.Count -gt $oldShown.Count) { Add-Info ('(+' + ($oldDrivers.Count - $oldShown.Count) + ' more old third-party drivers)') }
if ($signed.Count -eq 0) { Add-Finding 'INFO' 'Drivers' 'Driver inventory (Win32_PnPSignedDriver) could not be read.' }

# BIOS / firmware
$biosRow = $null
try {
    $b = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $bd = $null; if ($b.ReleaseDate) { try { $bd = [datetime]$b.ReleaseDate } catch { } }
    $model = ''; if ($cs) { $model = ([string]$cs.Manufacturer).Trim() + ' ' + ([string]$cs.Model).Trim() }
    $biosRow = [pscustomobject]@{ model = $model; version = ([string]$b.SMBIOSBIOSVersion).Trim(); date = $(if ($bd) { $bd.ToString('yyyy-MM-dd', $script:Inv) } else { $null }) }
    $bl = 'BIOS ' + $biosRow.version + $(if ($bd) { ' dated ' + $biosRow.date } else { '' }) + ' on ' + $model
    if ($bd -and $bd -lt $script:Now.AddYears(-3)) { Add-Finding 'INFO' 'Drivers' ($bl + ' - over 3 years old; firmware updates often fix sleep, storage and WHEA issues') }
    else { Add-Info $bl }
} catch { }

# Driver installs in the window. UserPnp 20001: %1 driver, %4 device instance, %9 status;
# 20003 (service added for a device): %1 service, %3 device instance, %6 status.
$inst = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-UserPnp'; Id = 20001, 20003; StartTime = $script:Since } 300
$instRows = New-Object System.Collections.ArrayList
$seen = @{}
foreach ($e in $inst) {
    $drv = ''; $dev = ''; $st = ''
    try {
        if ($e.Id -eq 20001) { $drv = [string]$e.Properties[0].Value; $dev = [string]$e.Properties[3].Value; $st = [string]$e.Properties[8].Value }
        else { $drv = [string]$e.Properties[0].Value; $dev = [string]$e.Properties[2].Value; $st = [string]$e.Properties[5].Value }
    } catch { }
    if (-not $drv) { continue }
    # SWD\ and ROOT\ software devices re-install on every boot - noise for crash correlation
    if ($dev -match '^(SWD|ROOT|STORAGE\\VOLUME|USBSTOR|WPDBUSENUM)\\') { continue }
    $key = $drv + '|' + $e.TimeCreated.ToString('yyyyMMdd', $script:Inv)
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $ok = ($st -eq '0' -or $st -eq '0x0')
    [void]$instRows.Add([pscustomobject]@{ t = (Format-Iso $e.TimeCreated); driver = $drv; device = (Limit-Text $dev 90); ok = $ok; status = $st })
}
if ($instRows.Count -gt 0) {
    Add-Info ('Driver installs in the last ' + $Days + ' days (newest first, ' + $instRows.Count + '):')
    foreach ($r in ($instRows | Select-Object -First 15)) {
        Add-Info ('  ' + (Format-Time ([datetime]::Parse($r.t, $script:Inv))) + '  ' + $r.driver + '  ' + $r.device + $(if (-not $r.ok) { '  status ' + $r.status } else { '' }))
    }
    $failedInst = @($instRows | Where-Object { -not $_.ok })
    if ($failedInst.Count -gt 0) { Add-Finding 'WARN' 'Drivers' ('' + $failedInst.Count + ' driver install(s) in the window ended with a non-zero status (latest: ' + $failedInst[0].driver + ').') ([datetime]::Parse($failedInst[0].t, $script:Inv)) }
} else {
    Add-Info ('No hardware driver installs recorded in the last ' + $Days + ' days.')
}
$script:Data['devices'] = @($devRows); $script:Data['drivers'] = @($drvRows); $script:Data['unsigned'] = @($unsigned)
$script:Data['oldDrivers'] = @($oldDrivers | Sort-Object date | Select-Object -First 15); $script:Data['bios'] = $biosRow
$script:Data['driverInstalls'] = @($instRows | Select-Object -First 40)
Stop-Phase

# =============================================================================
# 5. WINDOWS INTEGRITY
# =============================================================================
Start-Phase 'windows'
Add-Section '[5] WINDOWS INTEGRITY AND UPDATES'
$cv = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = [string](Get-RegValue $cv 'CurrentBuildNumber')
$ubr = Get-RegValue $cv 'UBR'
$disp = [string](Get-RegValue $cv 'DisplayVersion'); if (-not $disp) { $disp = [string](Get-RegValue $cv 'ReleaseId') }
$edition = [string](Get-RegValue $cv 'EditionID')
$instType = [string](Get-RegValue $cv 'InstallationType')
$caption = ''; if ($os) { $caption = [string]$os.Caption }
$osInfo = [ordered]@{ caption = $caption; build = $build; ubr = $ubr; display = $disp; edition = $edition; installed = $null; lastBoot = $null; support = $null; eos = $null }
if ($os) { $osInfo.installed = Format-Iso $os.InstallDate; $osInfo.lastBoot = Format-Iso $os.LastBootUpTime }
Add-Info ($caption + ' ' + $disp + ' build ' + $build + $(if ($null -ne $ubr) { '.' + $ubr } else { '' }) + ' (' + $edition + ')')
if ($os) {
    $up = $script:Now - $os.LastBootUpTime
    Add-Info ('Installed ' + (Format-Time $os.InstallDate) + '; last boot ' + (Format-Time $os.LastBootUpTime) + ' (up ' + [math]::Floor($up.TotalDays) + 'd ' + $up.Hours + 'h)')
}

# Servicing end dates (Microsoft lifecycle, as known 2026-10). Home/Pro vs Enterprise/Education.
$eosTable = @{
    '19045' = @('2025-10-14', '2025-10-14', 'Windows 10 22H2')
    '22000' = @('2023-10-10', '2024-10-08', 'Windows 11 21H2')
    '22621' = @('2024-10-08', '2025-10-14', 'Windows 11 22H2')
    '22631' = @('2025-11-11', '2026-11-10', 'Windows 11 23H2')
    '26100' = @('2026-10-13', '2027-10-12', 'Windows 11 24H2')
    '26200' = @('2027-10-12', '2028-10-10', 'Windows 11 25H2')
}
if ($instType -eq 'Server') {
    $osInfo.support = 'server'
} elseif ($edition -match 'EnterpriseS|IoTEnterpriseS|LTSC') {
    $osInfo.support = 'ltsc'; Add-Info 'LTSC edition - long-term servicing channel (separate lifecycle).'
} elseif ($eosTable.ContainsKey($build)) {
    $row = $eosTable[$build]
    $eos = $row[0]; if ($edition -match 'Enterprise|Education') { $eos = $row[1] }
    $osInfo.eos = $eos
    $eosDt = [datetime]::ParseExact($eos, 'yyyy-MM-dd', $script:Inv)
    if ($script:Now -gt $eosDt) {
        $osInfo.support = 'ended'
        $msg = $row[2] + ' ' + $edition + ' reached end of servicing on ' + $eos + ' - no further security or reliability fixes'
        if ($build -eq '19045') { $msg += ' unless enrolled in Extended Security Updates' }
        Add-Finding 'WARN' 'Windows' ($msg + '; upgrade to a supported release.')
    } elseif (($eosDt - $script:Now).TotalDays -lt 90) {
        $osInfo.support = 'ending'
        Add-Finding 'INFO' 'Windows' ($row[2] + ' servicing ends ' + $eos + ' - plan the feature update.')
    } else { $osInfo.support = 'supported'; Add-Finding 'OK' 'Windows' ($row[2] + ' is in support until ' + $eos + '.') }
} elseif ($build -and [int]$build -gt 26200) {
    $osInfo.support = 'preview'; Add-Info ('Build ' + $build + ' is newer than the builds this script knows - likely an Insider/preview build.')
}

# Pending reboot
$pend = New-Object System.Collections.ArrayList
if (Test-RegKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { [void]$pend.Add('component servicing (CBS)') }
if (Test-RegKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { [void]$pend.Add('Windows Update') }
$cn1 = Get-RegValue 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
$cn2 = Get-RegValue 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
if ($cn1 -and $cn2 -and $cn1 -ne $cn2) { [void]$pend.Add('computer rename') }
$pfro = Get-RegValue 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
if ($pend.Count -gt 0) {
    Add-Finding 'WARN' 'Windows' ('Restart pending for: ' + ($pend -join ', ') + ' - half-installed updates can cause instability; restart before deeper troubleshooting.')
} else {
    Add-Finding 'OK' 'Windows' ('No pending restart from servicing or Windows Update' + $(if ($pfro) { ' (file renames queued - normal after app updates)' } else { '' }) + '.')
}

# Updates in the window (WindowsUpdateClient 19 = installed, 20 = failed; property 0 = title)
$wu = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19, 20; StartTime = $script:Since } 300
$updRows = New-Object System.Collections.ArrayList
foreach ($e in $wu) {
    # 19: %1 = title. 20: %1 = error code (Int32), %2 = title.
    $title = ''; $code = $null
    try {
        if ($e.Id -eq 19) { $title = [string]$e.Properties[0].Value }
        else { $title = [string]$e.Properties[1].Value; $code = '0x{0:X8}' -f [int]$e.Properties[0].Value }
    } catch { }
    if (-not $title) { $title = Limit-Text $e.Message 120 }
    # Microsoft Store app updates are titled "<12-char product id>-<package>"; in-use failures are routine
    $store = $title -match '^[0-9A-Z]{12}-'
    [void]$updRows.Add([pscustomobject]@{ t = (Format-Iso $e.TimeCreated); title = (Limit-Text $title 140); ok = ($e.Id -eq 19); code = $code; store = $store })
}
$okUpd = @($updRows | Where-Object { $_.ok -and -not $_.store })
# A failure that a later attempt installed is not a problem (rows are newest first)
$laterOk = @{}
$badUpd = New-Object System.Collections.ArrayList
foreach ($r in $updRows) {
    if ($r.store) { continue }
    if ($r.ok) { $laterOk[$r.title] = $true } elseif (-not $laterOk.ContainsKey($r.title)) { [void]$badUpd.Add($r) }
}
$badUpd = @($badUpd)
$storeOk = @($updRows | Where-Object { $_.ok -and $_.store }).Count; $storeBad = @($updRows | Where-Object { -not $_.ok -and $_.store }).Count
Add-Info ('Windows/driver updates in the last ' + $Days + ' days: ' + $okUpd.Count + ' installed, ' + $badUpd.Count + ' failed and not since installed (Store apps: ' + $storeOk + ' installed, ' + $storeBad + ' failed - not counted)')
foreach ($r in (@($updRows | Where-Object { -not $_.store }) | Select-Object -First 12)) {
    Add-Info ('  ' + (Format-Time ([datetime]::Parse($r.t, $script:Inv))) + '  ' + $(if ($r.ok) { 'installed ' } else { 'FAILED    ' }) + $r.title + $(if ($r.code) { ' (' + $r.code + ')' } else { '' }))
}
if ($badUpd.Count -gt 0) {
    $byTitle = @($badUpd | Group-Object title | Sort-Object Count -Descending)
    $rep = @($byTitle | Where-Object { $_.Count -ge 2 })
    if ($rep.Count -gt 0) {
        Add-Finding 'WARN' 'Windows' ('Update failing repeatedly: ' + $rep[0].Name + ' (' + $rep[0].Count + ' failures, ' + $rep[0].Group[0].code + ') - run DISM /RestoreHealth and SFC, then retry.') ([datetime]::Parse($rep[0].Group[0].t, $script:Inv))
    } else {
        Add-Finding 'INFO' 'Windows' ('' + $badUpd.Count + ' update install failure(s) in the window, latest ' + $badUpd[0].title) ([datetime]::Parse($badUpd[0].t, $script:Inv))
    }
}
$lastOk = $null
$script:Data['updates'] = @($updRows | Where-Object { -not $_.store } | Select-Object -First 40)
if ($okUpd.Count -gt 0) { $lastOk = [datetime]::Parse($okUpd[0].t, $script:Inv) }
else {
    $e = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19 } 1
    if ($e.Count -gt 0) { $lastOk = $e[0].TimeCreated }
}
if (-not $lastOk) {
    try { $hf = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending); if ($hf.Count -gt 0) { $lastOk = [datetime]$hf[0].InstalledOn } } catch { }
}
if ($lastOk) {
    $age = ($script:Now - $lastOk).TotalDays
    if ($age -gt 60) { Add-Finding 'WARN' 'Windows' ('Last successful update ' + (Format-Time $lastOk) + ' (' + [math]::Round($age) + ' days ago) - Windows Update may be stuck or blocked.') $lastOk }
    else { Add-Info ('Last successful update ' + (Format-Time $lastOk)) }
} else {
    Add-Finding 'INFO' 'Windows' 'No successful update install found in the System log or hotfix list.'
}

# Component store corruption markers in the tail of CBS.log
$cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
$cbsHits = New-Object System.Collections.ArrayList
$cbsInfo = [ordered]@{ read = $false; hits = 0; lastHit = $null; lastSfc = $null }
if ([System.IO.File]::Exists($cbs)) {
    try {
        $fs = [System.IO.File]::Open($cbs, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $tail = [long]4MB
            if ($fs.Length -gt $tail) { [void]$fs.Seek(-$tail, [System.IO.SeekOrigin]::End) }
            $sr = New-Object System.IO.StreamReader($fs)
            $text = $sr.ReadToEnd()
        } finally { $fs.Dispose() }
        $cbsInfo.read = $true
        foreach ($ln in ($text -split "`r?`n")) {
            if ($ln -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
                $ts = $Matches[1]
                if ($ln -match 'Cannot repair member file|CSI Payload Corrupt|Store corruption|corrupt manifest|ERROR_SXS_COMPONENT_STORE_CORRUPT|0x80073712') {
                    [void]$cbsHits.Add([pscustomobject]@{ t = $ts; x = (Limit-Text $ln 160) })
                }
                elseif ($ln -match '\[SR\] Verify complete|\[SR\] Beginning Verify and Repair') { $cbsInfo.lastSfc = $ts }
            }
        }
    } catch { Add-Info ('CBS.log could not be read: ' + $_.Exception.Message) }
}
$recentHits = @($cbsHits | Where-Object { try { [datetime]::ParseExact($_.t, 'yyyy-MM-dd HH:mm:ss', $script:Inv) -ge $script:Now.AddDays(-90) } catch { $false } })
$cbsInfo.hits = $recentHits.Count
if ($recentHits.Count -gt 0) {
    $last = $recentHits[$recentHits.Count - 1]
    $cbsInfo.lastHit = $last.t
    Add-Finding 'WARN' 'Windows' ('Component store / system file corruption logged in CBS.log (' + $recentHits.Count + ' line(s), latest ' + $last.t.Substring(0, 16) + ') - run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow.') ([datetime]::ParseExact($last.t, 'yyyy-MM-dd HH:mm:ss', $script:Inv))
    Add-Info ('  ' + $last.x)
} elseif ($cbsInfo.read) {
    Add-Finding 'OK' 'Windows' 'No component store corruption markers in the recent CBS.log.'
}
if ($cbsInfo.lastSfc) { Add-Info ('Last SFC verify seen in CBS.log: ' + $cbsInfo.lastSfc.Substring(0, 16)) }
$script:Data['os'] = [pscustomobject]$osInfo; $script:Data['pending'] = @($pend)
$script:Data['lastUpdate'] = (Format-Iso $lastOk); $script:Data['cbs'] = [pscustomobject]$cbsInfo
Stop-Phase

# =============================================================================
# 6. BATTERY AND POWER
# =============================================================================
Start-Phase 'power'
Add-Section '[6] BATTERY AND POWER'
$pwr = [ordered]@{ plan = $null; fastStartup = $null; hibernate = $null; states = $null; battery = @(); sleepDeaths = 0; wakeSources = @() }

$bat = @()
try { $bat = @(Get-CimInstance Win32_Battery -ErrorAction Stop) } catch { }
if ($bat.Count -eq 0) {
    Add-Info 'No battery (desktop or battery not reported).'
} else {
    $xmlPath = Join-Path ([System.IO.Path]::GetTempPath()) ('battery_' + [guid]::NewGuid().ToString('N') + '.xml')
    try {
        $null = & powercfg.exe /batteryreport /xml /output $xmlPath 2>&1
        if ([System.IO.File]::Exists($xmlPath)) {
            [xml]$bx = [System.IO.File]::ReadAllText($xmlPath)
            $nodes = @($bx.GetElementsByTagName('Battery'))
            foreach ($n in $nodes) {
                $dc = 0.0; $fc = 0.0
                [void][double]::TryParse([string]$n.DesignCapacity, [ref]$dc)
                [void][double]::TryParse([string]$n.FullChargeCapacity, [ref]$fc)
                $cyc = [string]$n.CycleCount
                $h = $null; if ($dc -gt 0) { $h = [math]::Round(($fc / $dc) * 100, 0) }
                $bRow = [pscustomobject]@{ name = ([string]$n.Manufacturer + ' ' + [string]$n.Id).Trim(); designMWh = $dc; fullMWh = $fc; healthPct = $h; cycles = $cyc }
                $pwr.battery += $bRow
                if ($null -ne $h) {
                    $lvl = 'OK'
                    if ($h -lt $BatteryAlertPct) { $lvl = 'ALERT' } elseif ($h -lt $BatteryWarnPct) { $lvl = 'WARN' }
                    $bt = 'Battery ' + $bRow.name + ': ' + $h + '% of design capacity (' + [math]::Round($fc) + ' / ' + [math]::Round($dc) + ' mWh' + $(if ($cyc) { ', ' + $cyc + ' cycles' } else { '' }) + ')'
                    if ($lvl -eq 'ALERT') { $bt += ' - badly worn: can drop out under load and switch the laptop off without warning' }
                    elseif ($lvl -eq 'WARN') { $bt += ' - worn; short runtime, possible sudden power-offs on battery' }
                    Add-Finding $lvl 'Power' $bt
                }
            }
        } else { Add-Info 'powercfg battery report produced no file.' }
    } catch { Add-Info ('Battery report failed: ' + $_.Exception.Message) }
    finally { try { if ([System.IO.File]::Exists($xmlPath)) { [System.IO.File]::Delete($xmlPath) } } catch { } }
    foreach ($b in $bat) { Add-Info ('Battery status: ' + $b.EstimatedChargeRemaining + '% charge, status code ' + $b.BatteryStatus + ' (1 = on battery, 2 = on AC)') }
}

# Power plan
try {
    $ap = (& powercfg.exe /getactivescheme 2>$null) -join ' '
    if ($ap -match '\(([^)]+)\)\s*$') { $pwr.plan = $Matches[1] } elseif ($ap) { $pwr.plan = Limit-Text $ap 80 }
    if ($pwr.plan) { Add-Info ('Active power plan: ' + $pwr.plan) }
} catch { }

# Fast Startup = HiberbootEnabled AND hibernation available
$hb = Get-RegValue 'SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
$he = Get-RegValue 'SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
$pwr.hibernate = ($he -eq 1)
$pwr.fastStartup = (($hb -eq 1) -and ($he -ne 0))
if ($pwr.fastStartup) {
    Add-Finding 'INFO' 'Power' 'Fast Startup is ON - "Shut down" does not reset drivers or the kernel (uptime keeps counting); use Restart when testing a fix, or turn it off while troubleshooting.'
} else { Add-Info 'Fast Startup is off.' }

# Sleep states (S3 vs Modern Standby)
try {
    $pa = @(& powercfg.exe /a 2>$null)
    $avail = New-Object System.Collections.ArrayList
    $inAvail = $false
    foreach ($l in $pa) {
        if ($l -match 'are available on this system') { $inAvail = $true; continue }
        if ($l -match 'are not available') { $inAvail = $false; continue }
        if ($inAvail -and $l -match '^\s+(Standby \([^)]+\)|Hibernate|Hybrid Sleep|Fast Startup)') { [void]$avail.Add($Matches[1]) }
    }
    if ($avail.Count -gt 0) { $pwr.states = ($avail -join ', '); Add-Info ('Sleep states available: ' + $pwr.states) }
} catch { }

# Deaths during sleep (Kernel-Power 41 with SleepInProgress) and wake sources
$kp41 = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $script:Since } 100
$sleepDeaths = New-Object System.Collections.ArrayList
foreach ($e in $kp41) {
    try {
        $x = [xml]$e.ToXml()
        $sp = $x.Event.EventData.Data | Where-Object { $_.Name -eq 'SleepInProgress' } | Select-Object -First 1
        if ($sp -and [string]$sp.'#text' -and [string]$sp.'#text' -ne '0' -and [string]$sp.'#text' -ne 'false') { [void]$sleepDeaths.Add($e.TimeCreated) }
    } catch { }
}
$pwr.sleepDeaths = $sleepDeaths.Count
if ($sleepDeaths.Count -gt 0) {
    Add-Finding 'WARN' 'Power' ('' + $sleepDeaths.Count + ' unclean restart(s) while entering or resuming from sleep (Kernel-Power 41 SleepInProgress), latest ' + (Format-Time $sleepDeaths[0]) + ' - check chipset/graphics/storage drivers and BIOS; try disabling hybrid sleep.') $sleepDeaths[0]
}
$wake = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $script:Since } 200
if ($wake.Count -gt 0) {
    $src = @{}
    foreach ($e in $wake) {
        $w = 'unknown'
        if ($e.Message -and $e.Message -match 'Wake Source:\s*([^\r\n]+)') { $w = $Matches[1].Trim() }
        if ($src.ContainsKey($w)) { $src[$w]++ } else { $src[$w] = 1 }
    }
    $top = @($src.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)
    $pwr.wakeSources = @($top | ForEach-Object { [pscustomobject]@{ source = $_.Key; count = $_.Value } })
    Add-Info ('Woke from sleep ' + $wake.Count + ' time(s) in ' + $Days + ' days; top wake sources: ' + (($top | ForEach-Object { $_.Key + ' x' + $_.Value }) -join '; '))
}
$script:Data['power'] = [pscustomobject]$pwr
Stop-Phase

# =============================================================================
# VERDICT AND OUTPUT
# =============================================================================
$alerts = @($script:Findings | Where-Object { $_.sev -eq 'ALERT' })
$warns  = @($script:Findings | Where-Object { $_.sev -eq 'WARN' })
$status = 'OK'; $exitCode = 0
if ($alerts.Count -gt 0) { $status = 'ALERT'; $exitCode = 2 } elseif ($warns.Count -gt 0) { $status = 'WARN'; $exitCode = 1 }
$headline = 'No disk-space, storage-stall, memory, driver, Windows-integrity or battery problems found.'
if ($alerts.Count -gt 0) { $headline = $alerts[0].text }
elseif ($warns.Count -gt 0) { $headline = $warns[0].text }

$body = $script:Sb.ToString()
$script:Sb = New-Object System.Text.StringBuilder
$bar = '=' * 72
Add-Line $bar
Add-Line (' SYSTEM HEALTH EXTRAS - ' + $env:COMPUTERNAME + ' - ' + (Format-Time $script:Now) + ' - last ' + $Days + ' days')
Add-Line $bar
Add-Line (' VERDICT: [' + $status + '] ' + $headline)
Add-Line ('          ' + $alerts.Count + ' alert(s), ' + $warns.Count + ' warning(s)' + $(if (-not $isAdmin) { ' - NOT ELEVATED: some checks incomplete' } else { '' }))
foreach ($f in ($alerts + $warns)) { Add-Line ('   - [' + $f.sev + '] ' + $f.area + ': ' + $f.text) }
[void]$script:Sb.Append($body)
Add-Line ''
Add-Line ('Timing: ' + ($script:Timing -join ', '))
Add-Line $bar
Add-Line (' END OF REPORT - [' + $status + '] (exit ' + $exitCode + ')')
Add-Line $bar

$payload = [pscustomobject]@{
    schema = 'healthx/1'; host = $env:COMPUTERNAME; generated = (Format-Iso $script:Now); days = $Days; admin = $isAdmin
    status = $status; exit = $exitCode; headline = $headline
    findings = @($script:Findings)
    disks = $script:Data['disks']; spaceUsers = $script:Data['spaceUsers']
    memory = $script:Data['memory']
    devices = $script:Data['devices']; drivers = $script:Data['drivers']; unsigned = $script:Data['unsigned']; oldDrivers = $script:Data['oldDrivers']
    bios = $script:Data['bios']; driverInstalls = $script:Data['driverInstalls']
    os = $script:Data['os']; pending = $script:Data['pending']; updates = $script:Data['updates']; lastUpdate = $script:Data['lastUpdate']; cbs = $script:Data['cbs']
    power = $script:Data['power']; storageStalls = $script:Data['storageStalls']
    timing = @($script:Timing)
}
$json = $payload | ConvertTo-Json -Depth 6 -Compress

$reportText = $script:Sb.ToString()
if (-not $NoFiles) {
    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        $base = Join-Path $OutputDir ('HealthExtras_' + $env:COMPUTERNAME + '_' + $script:Now.ToString('yyyyMMdd_HHmmss', $script:Inv))
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($base + '.txt', $reportText, $enc)
        [System.IO.File]::WriteAllText($base + '.json', $json, $enc)
        $reportText += ' Saved: ' + $base + '.txt / .json' + [Environment]::NewLine
    } catch { $reportText += ' (Could not save to ' + $OutputDir + ': ' + $_.Exception.Message + ')' + [Environment]::NewLine }
}
Write-Output $reportText
if (-not $NoInlineJson) {
    Write-Output '===HEALTHX_JSON_BEGIN==='
    Write-Output $json
    Write-Output '===HEALTHX_JSON_END==='
}
exit $exitCode
