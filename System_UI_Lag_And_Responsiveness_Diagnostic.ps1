# PC Health and Crash Toolkit 1.0.2 - https://ihavenoram.com - https://github.com/ihavenoram/pc-health-crash-toolkit
# MIT licence, (c) 2026 ihavenoram.com. If you publish something built on this, please credit ihavenoram.com.
<#
=========================================================
Script Name: System_UI_Lag_And_Responsiveness_Diagnostic
Description: Diagnoses a PC that is sluggish, laggy or jittery but NOT crashing -
stuttery mouse, slow/janky display, general unresponsiveness. Instead of guessing,
it takes a short LIVE sample of the signals that actually cause UI lag - DPC/interrupt
latency (the classic mouse-stutter cause), CPU and disk saturation, disk latency,
memory pressure / hard paging - then adds the usual suspects: runaway processes,
GDI/USER + kernel handle leaks, Desktop Window Manager / GPU state (incl. "Basic
Display Adapter" = no GPU driver), pending-reboot locks, power/responsiveness config,
problem devices, storage resets and recent app hangs.

Opens with an at-a-glance HEALTH VERDICT and finishes with tailored mitigation hints.
RMM-friendly: runs as SYSTEM under Windows PowerShell 5.1, writes to C:\temp and STDOUT,
and exits 0 (OK) / 1 (WARN) / 2 (ALERT) for Atera alert rules. Thermal throttling and
crash-dump analysis are handled by separate companion scripts.
Category:    ScriptLibrary
Run Time:    10 minutes
Arguments:
Run As:      System
=========================================================
#>

#Requires -RunAsAdministrator

# --- Downlevel guard ---------------------------------------------------------
# This script uses PowerShell 5.0 syntax. On an older host (Server 2008 R2 / Win 7)
# fail cleanly and point at the legacy companion instead of emitting pages of errors.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Output "[WARN] Unsupported PowerShell $($PSVersionTable.PSVersion) - this script requires 5.0 or later."
    Write-Output "[WARN] Run the downlevel companion instead: System_UI_Lag_Legacy_2008R2.ps1"
    exit 1
}

# --- Configuration -----------------------------------------------------------
$SampleSeconds     = 5     # live counter sampling window
$LookbackDays      = 3     # event-log lookback for DWM / hangs / storage resets

# Thresholds (WARN / ALERT)
$DpcWarnPct        = 8;    $DpcAlertPct       = 15    # % DPC time = driver latency -> mouse stutter
$CpuWarnPct        = 85;   $CpuAlertPct       = 97    # sustained CPU busy
$FreeRamWarnMB     = 1024; $FreeRamAlertMB    = 400
$CommitWarnPct     = 90
$HardFaultWarnPS   = 300                              # \Memory\Pages Input/sec (only flagged WITH memory pressure)
$DiskBusyWarnPct   = 85;   $DiskBusyAlertPct  = 97
$DiskLatWarnMs     = 25;   $DiskLatAlertMs    = 50    # avg disk seconds/transfer
$DiskQueueWarn     = 5
$HandleWarn        = 10000; $HandleAlert       = 25000 # normal apps (Outlook, System) sit in the low thousands
$GdiWarn           = 7000;  $GdiAlert          = 9000  # per-process GDI cap ~10000
$UserWarn          = 7000;  $UserAlert         = 9000  # per-process USER cap ~10000
$ProcCpuRunawayPct = 25                                # single process sustained CPU%
$AppHangWarn       = 3                                 # app-hang events in window before flagging
# Kernel/AV pseudo-processes normally hold huge handle counts - never "leaks" to restart
$LeakExcludeProcs  = @('System','Idle','Registry','Memory Compression','MsMpEng')
# -----------------------------------------------------------------------------

$timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$dateStamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$computerName = $env:COMPUTERNAME
$since        = (Get-Date).AddDays(-$LookbackDays)
$logicalCPUs  = [Environment]::ProcessorCount

if (!(Test-Path "C:\temp")) { New-Item -ItemType Directory -Path "C:\temp" | Out-Null }
$outputFile = "C:\temp\UI_Lag_Diagnostic_${dateStamp}.txt"

# --- Report buffer -----------------------------------------------------------
$script:sb = [System.Text.StringBuilder]::new()
function Add-Line    { param([string]$Text = '') ; [void]$script:sb.AppendLine($Text) }
function Add-Section { param([string]$Title)     ; Add-Line ''; Add-Line $Title; Add-Line ('-' * $Title.Length) }

$script:alerts = New-Object System.Collections.Generic.List[string]
$script:warns  = New-Object System.Collections.Generic.List[string]
function Flag { param([string]$Level,[string]$Msg) ; if ($Level -eq 'ALERT') { $script:alerts.Add($Msg) } elseif ($Level -eq 'WARN') { $script:warns.Add($Msg) } }

# Safe Get-WinEvent wrapper
function Get-Events {
    param([hashtable]$Filter, [int]$Max = 0)
    try {
        if ($Max -gt 0) { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
        return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
    } catch { return @() }
}

# --- GDI / USER object counts via GetGuiResources (real UI-leak signal) ------
$script:guiOk = $true
try {
    Add-Type -Namespace Win32 -Name Gui -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern uint GetGuiResources(System.IntPtr hProcess, uint uiFlags);
'@ -ErrorAction Stop
} catch { $script:guiOk = $false }
function Get-GuiCount {
    param($Process, [uint32]$Flag)   # 0 = GDI objects, 1 = USER objects
    if (-not $script:guiOk) { return $null }
    try { return [Win32.Gui]::GetGuiResources($Process.Handle, $Flag) } catch { return $null }
}

# =============================================================================
# COLLECT
# =============================================================================

# --- Live responsiveness sample (one Get-Counter call over the window) -------
$perf = @{}
$perfOk = $true
$cpuSnap0 = @{}
try { Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $cpuSnap0[$_.Id] = $_.CPU } } catch {}
$counterPaths = @(
    '\Processor Information(_Total)\% Processor Time'
    '\Processor Information(_Total)\% DPC Time'
    '\Processor Information(_Total)\% Interrupt Time'
    '\Memory\Available MBytes'
    '\Memory\% Committed Bytes In Use'
    '\Memory\Pages Input/sec'
    '\PhysicalDisk(_Total)\% Idle Time'
    '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer'
    '\PhysicalDisk(_Total)\Current Disk Queue Length'
)
try {
    $samples = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples $SampleSeconds -ErrorAction Stop
    $agg = @{}
    foreach ($s in $samples) {
        foreach ($cs in $s.CounterSamples) {
            $key = ($cs.Path -replace '.*\\','')  # last path segment
            if (-not $agg.ContainsKey($key)) { $agg[$key] = @() }
            $agg[$key] += [double]$cs.CookedValue
        }
    }
    function Avg($k) { if ($agg.ContainsKey($k) -and $agg[$k].Count) { ($agg[$k] | Measure-Object -Average).Average } else { $null } }
    $perf.CpuPct     = Avg '% processor time'
    $perf.DpcPct     = Avg '% dpc time'
    $perf.IntPct     = Avg '% interrupt time'
    $perf.FreeRamMB  = Avg 'available mbytes'
    $perf.CommitPct  = Avg '% committed bytes in use'
    $perf.HardFaults = Avg 'pages input/sec'
    $idle            = Avg '% idle time'
    $perf.DiskBusy   = if ($null -ne $idle) { [math]::Max(0, 100 - $idle) } else { $null }
    $perf.DiskLatMs  = $(if ($null -ne (Avg 'avg. disk sec/transfer')) { (Avg 'avg. disk sec/transfer') * 1000 } else { $null })
    $perf.DiskQueue  = Avg 'current disk queue length'
} catch { $perfOk = $false }

# per-process CPU% over the window
$cpuByProc = @{}
try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($cpuSnap0.ContainsKey($_.Id) -and $null -ne $_.CPU -and $null -ne $cpuSnap0[$_.Id]) {
            $delta = $_.CPU - $cpuSnap0[$_.Id]
            if ($delta -gt 0) { $cpuByProc[$_.Id] = [pscustomobject]@{ Name=$_.ProcessName; Pct=[math]::Round(($delta / $SampleSeconds / $logicalCPUs) * 100, 1) } }
        }
    }
} catch {}

# --- Process snapshot: handles, memory, GDI/USER (leak hunting) --------------
$procInfo = @()
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    $gdi  = Get-GuiCount $p 0
    $usr  = Get-GuiCount $p 1
    $cpu  = if ($cpuByProc.ContainsKey($p.Id)) { $cpuByProc[$p.Id].Pct } else { 0 }
    $procInfo += [pscustomobject]@{
        Name = $p.ProcessName; Id = $p.Id
        Handles = $p.HandleCount
        WSMB = [math]::Round($p.WorkingSet64 / 1MB, 0)
        Gdi = $gdi; User = $usr; CpuPct = $cpu
    }
}

# --- Graphics / DWM ----------------------------------------------------------
$gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
$basicDisplay = @($gpus | Where-Object { $_.Name -match '(?i)Basic Display|Standard VGA|Basic Render|Microsoft Basic' })
# Query DWM providers individually - an unknown provider name on some builds would
# otherwise make a single combined query fail and drop all DWM events.
$dwmEvents = @()
foreach ($prov in @('Microsoft-Windows-Dwm-Core','Microsoft-Windows-Dwm-Api','Desktop Window Manager','Microsoft-Windows-Desktop Window Manager')) {
    $dwmEvents += Get-Events @{ LogName='System'; ProviderName=$prov; StartTime=$since }
}
$tdrEvents = @(Get-Events @{ LogName='System'; ProviderName='Display'; Id=@(4101,4104); StartTime=$since })

# --- Pending reboot / servicing locks ----------------------------------------
$pendingReasons = @()
$pfr = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
$pfrCount = @($pfr | Where-Object { $_ }).Count
if ($pfrCount -gt 0) { $pendingReasons += "PendingFileRenameOperations ($pfrCount file(s) queued for next boot)" }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReasons += 'Component-Based Servicing reboot pending' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReasons += 'Windows Update reboot required' }
if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations2 -ErrorAction SilentlyContinue) { $pendingReasons += 'PendingFileRenameOperations2 present' }

# --- Power & responsiveness config -------------------------------------------
$powerPlan = 'Unknown'
try { $raw = powercfg /getactivescheme 2>&1; if ($raw -match '\(([^)]+)\)') { $powerPlan = $Matches[1] } } catch {}
$procMaxState = $null
try {
    $out = powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 2>$null
    $line = $out | Select-String -Pattern 'Current AC Power Setting Index' | Select-Object -First 1
    if ($line) { $procMaxState = [Convert]::ToInt32((($line.ToString() -split ':')[-1].Trim()), 16) }
} catch {}
$sysResp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name SystemResponsiveness -ErrorAction SilentlyContinue).SystemResponsiveness

# --- Problem devices + lag-related events ------------------------------------
$problemDevices = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction SilentlyContinue)
$storageResets  = @(Get-Events @{ LogName='System'; Id=@(129,153); StartTime=$since } |
    Where-Object { $_.ProviderName -match '(?i)stor|nvme|ahci|disk|iastor|vmd|sata|scsi|raid|megasas|spaceport|classpnp' })
$appHangs = @(Get-Events @{ LogName='Application'; ProviderName=@('Application Hang'); StartTime=$since })

# =============================================================================
# ANALYSE  (evaluate each signal, build the verdict)
# =============================================================================
if ($perfOk) {
    if ($null -ne $perf.DpcPct)   { if ($perf.DpcPct   -ge $DpcAlertPct)  { Flag ALERT "high DPC latency ($([math]::Round($perf.DpcPct,1))% DPC time) - a driver is stalling the CPU (mouse stutter)" } elseif ($perf.DpcPct -ge $DpcWarnPct) { Flag WARN "elevated DPC time ($([math]::Round($perf.DpcPct,1))%)" } }
    if ($null -ne $perf.CpuPct)   { if ($perf.CpuPct   -ge $CpuAlertPct)  { Flag ALERT "CPU saturated ($([math]::Round($perf.CpuPct))%)" } elseif ($perf.CpuPct -ge $CpuWarnPct) { Flag WARN "high CPU load ($([math]::Round($perf.CpuPct))%)" } }
    if ($null -ne $perf.FreeRamMB){ if ($perf.FreeRamMB -le $FreeRamAlertMB){ Flag ALERT "critically low memory ($([math]::Round($perf.FreeRamMB)) MB free)" } elseif ($perf.FreeRamMB -le $FreeRamWarnMB) { Flag WARN "low free memory ($([math]::Round($perf.FreeRamMB)) MB)" } }
    if ($null -ne $perf.CommitPct -and $perf.CommitPct -ge $CommitWarnPct) { Flag WARN "commit charge high ($([math]::Round($perf.CommitPct))%) - paging likely" }
    if ($null -ne $perf.HardFaults -and $perf.HardFaults -ge $HardFaultWarnPS -and (($null -ne $perf.FreeRamMB -and $perf.FreeRamMB -le $FreeRamWarnMB) -or ($null -ne $perf.CommitPct -and $perf.CommitPct -ge $CommitWarnPct))) { Flag WARN "heavy hard paging ($([math]::Round($perf.HardFaults))/s) under memory pressure" }
    if ($null -ne $perf.DiskBusy) { if ($perf.DiskBusy -ge $DiskBusyAlertPct) { Flag ALERT "disk saturated ($([math]::Round($perf.DiskBusy))% busy)" } elseif ($perf.DiskBusy -ge $DiskBusyWarnPct) { Flag WARN "disk busy ($([math]::Round($perf.DiskBusy))%)" } }
    if ($null -ne $perf.DiskLatMs){ if ($perf.DiskLatMs -ge $DiskLatAlertMs) { Flag ALERT "slow disk response ($([math]::Round($perf.DiskLatMs)) ms/transfer)" } elseif ($perf.DiskLatMs -ge $DiskLatWarnMs) { Flag WARN "elevated disk latency ($([math]::Round($perf.DiskLatMs)) ms)" } }
    if ($null -ne $perf.DiskQueue -and $perf.DiskQueue -ge $DiskQueueWarn) { Flag WARN "disk queue backing up (avg $([math]::Round($perf.DiskQueue,1)))" }
}

# Runaway process
$runaway = @($procInfo | Where-Object { $_.CpuPct -ge $ProcCpuRunawayPct } | Sort-Object CpuPct -Descending)
if ($runaway.Count) { Flag WARN ("runaway CPU: {0} ({1}%)" -f $runaway[0].Name, $runaway[0].CpuPct) }

# Handle / GDI / USER leaks
$leakCandidates = @($procInfo | Where-Object { $_.Name -notin $LeakExcludeProcs })
$handleLeak = @($leakCandidates | Where-Object { $_.Handles -ge $HandleWarn })
$gdiLeak    = @($leakCandidates | Where-Object { $null -ne $_.Gdi  -and $_.Gdi  -ge $GdiWarn })
$userLeak   = @($leakCandidates | Where-Object { $null -ne $_.User -and $_.User -ge $UserWarn })
foreach ($p in $handleLeak) { if ($p.Handles -ge $HandleAlert) { Flag ALERT "$($p.Name) handle leak ($($p.Handles) handles)" } else { Flag WARN "$($p.Name) high handles ($($p.Handles))" } }
foreach ($p in $gdiLeak)    { if ($p.Gdi -ge $GdiAlert)       { Flag ALERT "$($p.Name) GDI object leak ($($p.Gdi)/10000 - UI will break near cap)" } else { Flag WARN "$($p.Name) high GDI objects ($($p.Gdi))" } }
foreach ($p in $userLeak)   { if ($p.User -ge $UserAlert)     { Flag ALERT "$($p.Name) USER object leak ($($p.User)/10000)" } else { Flag WARN "$($p.Name) high USER objects ($($p.User))" } }

# Graphics / DWM
if ($basicDisplay.Count) { Flag ALERT "Microsoft Basic Display Adapter active - no GPU driver, software rendering (slow, no acceleration)" }
if ($tdrEvents.Count)    { Flag WARN "$($tdrEvents.Count) GPU driver reset (TDR) event(s) in ${LookbackDays}d" }
if ($dwmEvents.Count)    { Flag WARN "$($dwmEvents.Count) Desktop Window Manager event(s) in ${LookbackDays}d" }

# Pending reboot / config / devices / storage
if ($pendingReasons.Count)   { Flag WARN "pending reboot ($($pendingReasons.Count) item(s)) - can cause file-lock sluggishness" }
if ($powerPlan -match '(?i)power ?saver') { Flag WARN 'Power Saver plan active - caps performance' }
if ($null -ne $procMaxState -and $procMaxState -lt 100) { Flag WARN "max processor state capped at $procMaxState%" }
if ($problemDevices.Count)   { Flag WARN "$($problemDevices.Count) problem device(s) in Device Manager" }
if ($storageResets.Count)    { Flag WARN "$($storageResets.Count) storage reset/timeout event(s) - drive dropout causes system-wide stalls" }
if ($appHangs.Count -ge $AppHangWarn) { Flag WARN "$($appHangs.Count) application-hang event(s) in ${LookbackDays}d" }

# Verdict
if ($script:alerts.Count)     { $status='UNHEALTHY'; $tag='[ALERT]'; $exitCode=2 }
elseif ($script:warns.Count)  { $status='DEGRADED';  $tag='[WARN]';  $exitCode=1 }
else                          { $status='HEALTHY';   $tag='[OK]';    $exitCode=0 }

# =============================================================================
# RENDER
# =============================================================================
function FmtNum { param($v,$suffix='') ; if ($null -ne $v) { "{0}{1}" -f ([math]::Round([double]$v,1)), $suffix } else { 'n/a' } }
function Lvl { param($v,$warn,$alert,[switch]$LowerBad)
    if ($null -eq $v) { return 'INFO' }
    if ($LowerBad) { if ($v -le $alert) { 'ALERT' } elseif ($v -le $warn) { 'WARN' } else { 'OK' } }
    else           { if ($v -ge $alert) { 'ALERT' } elseif ($v -ge $warn) { 'WARN' } else { 'OK' } }
}

Add-Line "=================================================================="
Add-Line " UI LAG & RESPONSIVENESS DIAGNOSTIC"
Add-Line "=================================================================="
Add-Line " Computer   : $computerName"
Add-Line " Generated  : $timestamp"
Add-Line " Sample     : ${SampleSeconds}s live  |  Event lookback: $LookbackDays days"

# --- Verdict box ---
Add-Line ''
Add-Line "=================================================================="
Add-Line " HEALTH VERDICT:  $tag $status"
Add-Line "=================================================================="
if ($perfOk) {
    Add-Line ("  DPC latency (mouse stutter)  : {0}   [{1}]" -f (FmtNum $perf.DpcPct '%'), (Lvl $perf.DpcPct $DpcWarnPct $DpcAlertPct))
    Add-Line ("  CPU busy                     : {0}   [{1}]" -f (FmtNum $perf.CpuPct '%'), (Lvl $perf.CpuPct $CpuWarnPct $CpuAlertPct))
    Add-Line ("  Free memory                  : {0}   [{1}]" -f (FmtNum $perf.FreeRamMB ' MB'), (Lvl $perf.FreeRamMB $FreeRamWarnMB $FreeRamAlertMB -LowerBad))
    Add-Line ("  Disk busy / latency          : {0} / {1}   [{2}]" -f (FmtNum $perf.DiskBusy '%'), (FmtNum $perf.DiskLatMs ' ms'), (Lvl $perf.DiskLatMs $DiskLatWarnMs $DiskLatAlertMs))
} else {
    Add-Line "  Live counters unavailable (perf counters may be disabled/localised)."
}
$topCpu = @($procInfo | Sort-Object CpuPct -Descending | Select-Object -First 1)
if ($topCpu.Count -and $topCpu[0].CpuPct -gt 0) { Add-Line ("  Top CPU process              : {0} ({1}%)" -f $topCpu[0].Name, $topCpu[0].CpuPct) }
$gdiTop = @($procInfo | Where-Object { $null -ne $_.Gdi } | Sort-Object Gdi -Descending | Select-Object -First 1)
if ($gdiTop.Count) { Add-Line ("  Peak GDI objects (1 proc)    : {0} ({1})" -f $gdiTop[0].Gdi, $gdiTop[0].Name) }
Add-Line ("  Graphics                     : {0}" -f $(if ($basicDisplay.Count) { 'Basic Display Adapter (NO GPU DRIVER)' } elseif ($gpus.Count) { $gpus[0].Name } else { 'unknown' }))
Add-Line ("  Pending reboot               : {0}" -f $(if ($pendingReasons.Count) { "YES ($($pendingReasons.Count))" } else { 'no' }))
Add-Line "  ----------------------------------------------------------------"
$assess = if ($script:alerts.Count) { ($script:alerts -join '; ') } elseif ($script:warns.Count) { ($script:warns -join '; ') } else { 'no responsiveness problems detected' }
Add-Line ("  Assessment                   : {0}" -f $assess)

# --- [1] Live responsiveness sample ---
Add-Section "[1] LIVE RESPONSIVENESS SAMPLE (${SampleSeconds}s average)"
if ($perfOk) {
    Add-Line ("  {0,-26} {1,10}   [{2}]" -f 'DPC time',        (FmtNum $perf.DpcPct '%'),     (Lvl $perf.DpcPct $DpcWarnPct $DpcAlertPct))
    Add-Line ("  {0,-26} {1,10}" -f 'Interrupt time',          (FmtNum $perf.IntPct '%'))
    Add-Line ("  {0,-26} {1,10}   [{2}]" -f 'CPU busy',         (FmtNum $perf.CpuPct '%'),     (Lvl $perf.CpuPct $CpuWarnPct $CpuAlertPct))
    Add-Line ("  {0,-26} {1,10}   [{2}]" -f 'Free RAM',         (FmtNum $perf.FreeRamMB ' MB'),(Lvl $perf.FreeRamMB $FreeRamWarnMB $FreeRamAlertMB -LowerBad))
    Add-Line ("  {0,-26} {1,10}" -f 'Commit charge',            (FmtNum $perf.CommitPct '%'))
    Add-Line ("  {0,-26} {1,10}" -f 'Hard page faults',         (FmtNum $perf.HardFaults '/s'))
    Add-Line ("  {0,-26} {1,10}   [{2}]" -f 'Disk busy',        (FmtNum $perf.DiskBusy '%'),   (Lvl $perf.DiskBusy $DiskBusyWarnPct $DiskBusyAlertPct))
    Add-Line ("  {0,-26} {1,10}   [{2}]" -f 'Disk latency',     (FmtNum $perf.DiskLatMs ' ms'),(Lvl $perf.DiskLatMs $DiskLatWarnMs $DiskLatAlertMs))
    Add-Line ("  {0,-26} {1,10}" -f 'Disk queue length',        (FmtNum $perf.DiskQueue))
    Add-Line ''
    Add-Line "  DPC/interrupt time is the #1 cause of a stuttery mouse; high disk latency"
    Add-Line "  or low free RAM cause general lag/jank."
} else {
    Add-Line "  Performance counters unavailable on this system."
}

# --- [2] Top resource consumers / leak hunt ---
Add-Section "[2] TOP PROCESSES & HANDLE/GDI LEAK HUNT"
Add-Line ("  {0,-22} {1,6} {2,7} {3,8} {4,7} {5,7}" -f 'Process','PID','CPU%','Handles','GDI','USER')
Add-Line ("  {0,-22} {1,6} {2,7} {3,8} {4,7} {5,7}" -f '-------','---','----','-------','---','----')
$topN = @($procInfo | Sort-Object @{e={$_.CpuPct};Descending=$true}, @{e={$_.Handles};Descending=$true} | Select-Object -First 12)
foreach ($p in $topN) {
    Add-Line ("  {0,-22} {1,6} {2,7} {3,8} {4,7} {5,7}" -f $p.Name, $p.Id, $p.CpuPct, $p.Handles, $(if($null -ne $p.Gdi){$p.Gdi}else{'-'}), $(if($null -ne $p.User){$p.User}else{'-'}))
}
if ($handleLeak.Count -or $gdiLeak.Count -or $userLeak.Count) {
    Add-Line ''
    foreach ($p in ($handleLeak | Sort-Object Handles -Descending)) { Add-Line ("  [!] $($p.Name) - $($p.Handles) kernel handles") }
    foreach ($p in ($gdiLeak    | Sort-Object Gdi -Descending))     { Add-Line ("  [!] $($p.Name) - $($p.Gdi) GDI objects (cap ~10000)") }
    foreach ($p in ($userLeak   | Sort-Object User -Descending))    { Add-Line ("  [!] $($p.Name) - $($p.User) USER objects (cap ~10000)") }
} else {
    Add-Line ''
    Add-Line "  No handle/GDI/USER leaks above thresholds."
}

# --- [3] Graphics / DWM ---
Add-Section "[3] GRAPHICS / DESKTOP WINDOW MANAGER (last $LookbackDays days)"
if ($gpus.Count) { foreach ($g in $gpus) { Add-Line ("  GPU: {0}  (driver {1})" -f $g.Name, $g.DriverVersion) } }
if ($basicDisplay.Count) { Add-Line "  [!ALERT] Basic Display Adapter is active - GPU driver missing/failed => software rendering, sluggish/jittery display." }
Add-Line ("  GPU driver resets (TDR)      : {0}" -f $tdrEvents.Count)
Add-Line ("  DWM events logged            : {0}" -f $dwmEvents.Count)
if ($dwmEvents.Count) {
    foreach ($e in ($dwmEvents | Sort-Object TimeCreated -Descending | Select-Object -First 5)) {
        $m = ($e.Message -replace '\s+',' ').Trim(); if ($m.Length -gt 90) { $m = $m.Substring(0,90)+'...' }
        Add-Line ('    {0}  ID {1}  {2}' -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $e.Id, $m)
    }
}

# --- [4] Pending reboot / servicing ---
Add-Section "[4] PENDING REBOOT / FILE-LOCK AUDIT"
if ($pendingReasons.Count) {
    Add-Line "A pending reboot can hold file locks and slow the system:"
    foreach ($r in $pendingReasons) { Add-Line "  - $r" }
    if ($pfrCount -gt 0) {
        foreach ($f in (@($pfr | Where-Object { $_ }) | Select-Object -First 6)) { Add-Line "      queued: $f" }
    }
} else {
    Add-Line "None. No pending reboot / file-rename locks."
}

# --- [5] Power & responsiveness config ---
Add-Section "[5] POWER & RESPONSIVENESS CONFIG"
Add-Line ("  Active power plan            : {0}" -f $powerPlan)
Add-Line ("  Max processor state (AC)     : {0}" -f $(if ($null -ne $procMaxState) { "$procMaxState%" } else { 'n/a' }))
Add-Line ("  MMCSS SystemResponsiveness   : {0}" -f $(if ($null -ne $sysResp) { "$sysResp%" } else { 'default (20%)' }))
Add-Line "  (CPU thermal throttling is checked by the separate thermal script.)"

# --- [6] Problem devices & lag-related events ---
Add-Section "[6] PROBLEM DEVICES & LAG-RELATED EVENTS (last $LookbackDays days)"
Add-Line ("  Problem devices              : {0}" -f $problemDevices.Count)
foreach ($d in ($problemDevices | Select-Object -First 5)) { Add-Line ("    - {0} (Code {1})" -f $d.Name, $d.ConfigManagerErrorCode) }
Add-Line ("  Storage resets / timeouts    : {0}" -f $storageResets.Count)
foreach ($e in ($storageResets | Sort-Object TimeCreated -Descending | Select-Object -First 3)) {
    Add-Line ('    {0}  {1}  ID {2}' -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $e.ProviderName, $e.Id)
}
Add-Line ("  Application hangs             : {0}" -f $appHangs.Count)

# --- Mitigation hints (tailored) ---
Add-Section "MITIGATION HINTS"
$hintN = 0
function Hint { param([string]$Text) ; $script:hintN++ ; Add-Line ("  {0}. {1}" -f $script:hintN, $Text) }
if ($perfOk -and $null -ne $perf.DpcPct -and $perf.DpcPct -ge $DpcWarnPct) {
    Hint "High DPC latency: update/roll back network, storage, audio and GPU drivers (common culprits); check with LatencyMon if it persists."
}
if ($perfOk -and $null -ne $perf.DiskLatMs -and ($perf.DiskLatMs -ge $DiskLatWarnMs -or $perf.DiskBusy -ge $DiskBusyWarnPct)) {
    Hint "Disk is slow/saturated: check drive SMART/health, disable Windows Search/SysMain temporarily, look for a process hammering the disk; consider SSD upgrade/firmware."
}
if ($perfOk -and $null -ne $perf.FreeRamMB -and $perf.FreeRamMB -le $FreeRamWarnMB) {
    Hint "Low memory / paging: close heavy apps, check for a memory-leaking process, add RAM, ensure pagefile is on an SSD."
}
if ($runaway.Count) { Hint "Runaway process '$($runaway[0].Name)': investigate/restart it; check for updates or malware." }
if ($gdiLeak.Count -or $userLeak.Count -or $handleLeak.Count) { Hint "Resource leak: restarting the flagged process(es) frees GDI/USER/handles immediately; update the app - a near-cap GDI count freezes the whole desktop." }
if ($basicDisplay.Count) { Hint "Install the correct GPU driver (vendor package) - the Basic Display Adapter has no acceleration and always feels laggy." }
if ($tdrEvents.Count -or $dwmEvents.Count) { Hint "Graphics instability: update GPU driver; if it persists try disabling hardware acceleration in the offending app, or test another monitor/cable/port." }
if ($pendingReasons.Count) { Hint "Reboot to clear pending file-rename/servicing locks, then re-test responsiveness." }
if (($powerPlan -match '(?i)power ?saver') -or ($null -ne $procMaxState -and $procMaxState -lt 100)) { Hint "Set power plan to Balanced/High performance and max processor state to 100% (unless intentionally capped)." }
if ($problemDevices.Count) { Hint "Resolve Device Manager problem devices (Code errors) - a stalling device driver drags the whole UI." }
if ($script:hintN -eq 0) { Add-Line "  System responsiveness looks healthy - no action required." }

Add-Line ''
Add-Line "=================================================================="
Add-Line " END OF REPORT  -  $tag $status (exit $exitCode)  -  $computerName  -  $timestamp"
Add-Line "=================================================================="

# --- Output: file + STDOUT (Atera captures STDOUT) ---------------------------
$reportText = $script:sb.ToString()
try { [System.IO.File]::WriteAllText($outputFile, $reportText, [System.Text.Encoding]::UTF8) } catch {}
Write-Output $reportText
Write-Host ""
Write-Host "Report saved: $outputFile" -ForegroundColor Green

# Exit code for RMM alerting: 0 = OK, 1 = Warning, 2 = Alert
exit $exitCode
