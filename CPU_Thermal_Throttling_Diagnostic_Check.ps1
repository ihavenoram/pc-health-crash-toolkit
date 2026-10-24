<#
=========================================================
Script Name: CPU_Thermal_Throttling_Diagnostic_Check
Description: Detects real-world CPU thermal throttling on Windows. Pulls CPU die
temperatures from the best available source (LibreHardwareMonitor / OpenHardwareMonitor
if installed, else ACPI thermal-zone perf counter, else MSAcpi), measures actually-
delivered frequency via the "% Processor Performance" counter, runs a short optional
all-core load test to surface throttling that idle scans miss, and scans the System log
for the definitive Kernel-Processor-Power throttle events (ID 37/38) plus WHEA thermal
errors. Opens with an at-a-glance verdict and finishes with tailored mitigation hints.

RMM-friendly: runs as SYSTEM under Windows PowerShell 5.1, all output to STDOUT, exits
0 (OK) / 1 (WARN) / 2 (ALERT) for alert rules. CPU temperature alerting is driven by real
throttle proof, not absolute temperature, to avoid false alarms on hot-but-normal laptops.
Category:    ScriptLibrary
Run Time:    10 minutes
Arguments:
Run As:      System
=========================================================
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Thermal Throttling Detection Script (RMM-Compatible)
.NOTES
    Author:  ihavenoram.com
    Version: 3.0
    Run as:  SYSTEM or elevated Administrator
#>

# --- Configuration -----------------------------------------------------------
$LookbackHours    = 24    # event-log lookback window
$HotTempC         = 85    # peak temp at/above this raises a WARN (never an ALERT on its own)
$ElevatedTempC    = 75    # informational "running warm" note
$RunLoadTest      = $true # briefly load all cores to surface hidden throttling
$LoadTestSeconds  = 12    # duration of the all-core load test
$ThrottlePerfPct  = 80    # delivered freq % of base, under load, below this = throttle ALERT
$WarnPerfPct      = 90    # delivered freq % of base, under load, below this = WARN
$HighLoadPct      = 70    # utilisation considered "high" for passive-sample throttle checks
# -----------------------------------------------------------------------------

# --- Helper: structured output line (level prefix eases RMM alert parsing) ----
function Out-Line {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ALERT','OK','DEBUG')]
        [string]$Level = 'INFO'
    )
    Write-Output "[$Level] $Message"
}

# --- CPU information ----------------------------------------------------------
function Get-CPUInfo {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        return [pscustomobject]@{
            Name       = $cpu.Name.Trim()
            BaseMHz    = [int]$cpu.MaxClockSpeed   # rated base frequency
            CurrentMHz = [int]$cpu.CurrentClockSpeed
            Cores      = [int]$cpu.NumberOfCores
            Threads    = [int]$cpu.NumberOfLogicalProcessors
            LoadPct    = [int]$cpu.LoadPercentage
        }
    } catch {
        Out-Line "Failed to retrieve CPU info: $_" -Level WARN
        return $null
    }
}

# --- MSAcpi thermal zone (last-resort temperature source) --------------------
function Get-ThermalZoneTemps {
    try {
        $zones = Get-CimInstance -Namespace "root\WMI" -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
        if (-not $zones) { return $null }
        $temps = foreach ($zone in $zones) {
            $celsius = [math]::Round(($zone.CurrentTemperature / 10) - 273.15, 1)
            if ($celsius -gt 0 -and $celsius -lt 150) {
                [pscustomobject]@{ InstanceName = $zone.InstanceName; TempCelsius = $celsius }
            }
        }
        return $temps
    } catch { return $null }
}

# --- Best-available CPU temperatures + live throttle signals ------------------
# Priority: real die temps (LHM/OHM) > ACPI thermal-zone perf counter > MSAcpi.
# Also harvests PercentPassiveLimit / ThrottleReasons (active thermal throttling).
function Get-CpuTemperatures {
    $readings        = @()
    $passiveLimit    = 100   # % the thermal zone permits the CPU; 100 = no throttle, lower = throttling
    $throttleReasons = 0

    # 1) LibreHardwareMonitor / OpenHardwareMonitor (true die temps when agent present)
    foreach ($ns in @('root\LibreHardwareMonitor','root\OpenHardwareMonitor')) {
        try {
            $sensors = @(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop |
                Where-Object { $_.SensorType -eq 'Temperature' -and ($_.Name -match 'CPU|Core|Package|Tctl|Tdie|Tccd') })
            foreach ($s in $sensors) {
                $val = [math]::Round([double]$s.Value, 1)
                if ($val -gt 0 -and $val -lt 150) {
                    $readings += [pscustomobject]@{ Source = ($ns -replace 'root\\',''); Label = $s.Name; TempC = $val; IsDie = $true }
                }
            }
            if ($readings.Count) { break }
        } catch {}
    }

    # 2) ACPI thermal-zone perf counter (ACPI-derived temp + passive/throttle signals)
    try {
        $tz = @(Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop)
        $haveDie = [bool](@($readings | Where-Object { $_.IsDie }).Count)
        foreach ($z in $tz) {
            if (-not $haveDie -and $z.HighPrecisionTemperature) {
                $c = [math]::Round(($z.HighPrecisionTemperature / 10.0) - 273.15, 1)
                if ($c -gt 0 -and $c -lt 150) {
                    $readings += [pscustomobject]@{ Source = 'ACPI ThermalZone (perf)'; Label = $z.Name; TempC = $c; IsDie = $false }
                }
            }
            if ($z.PSObject.Properties['PercentPassiveLimit']) {
                $pl = [int]$z.PercentPassiveLimit
                if ($pl -gt 0 -and $pl -lt $passiveLimit) { $passiveLimit = $pl }   # track the most-throttled zone
            }
            if ($z.PSObject.Properties['ThrottleReasons'] -and [int]$z.ThrottleReasons -gt $throttleReasons) { $throttleReasons = [int]$z.ThrottleReasons }
        }
    } catch {}

    # 3) MSAcpi fallback (only if nothing better answered)
    if (-not $readings.Count) {
        $acpi = Get-ThermalZoneTemps
        if ($acpi) {
            foreach ($t in $acpi) {
                $readings += [pscustomobject]@{ Source = 'ACPI ThermalZone (MSAcpi)'; Label = $t.InstanceName; TempC = $t.TempCelsius; IsDie = $false }
            }
        }
    }

    $peak = $null; $peakLabel = $null; $anyDie = $false
    if ($readings.Count) {
        $top = $readings | Sort-Object TempC -Descending | Select-Object -First 1
        $peak = $top.TempC
        $peakLabel = "$($top.Source) / $($top.Label)"
        $anyDie = [bool](@($readings | Where-Object { $_.IsDie }).Count)
    }
    return [pscustomobject]@{
        Readings = $readings; PeakC = $peak; PeakLabel = $peakLabel; AnyDie = $anyDie
        PassivePct = $passiveLimit; ThrottleReasons = $throttleReasons
    }
}

# --- Delivered-frequency sampling via perf counters --------------------------
# % Processor Performance = delivered frequency relative to base (100 = base, >100 = turbo).
$script:PerfCounterOk = $true
function Get-PerfSamples {
    param([int]$Samples = 2, [int]$IntervalSec = 1)
    try {
        $c = Get-Counter -Counter '\Processor Information(_Total)\% Processor Performance','\Processor Information(_Total)\% Processor Time' -SampleInterval $IntervalSec -MaxSamples $Samples -ErrorAction Stop
        $perf = @(); $util = @()
        foreach ($s in $c) {
            foreach ($cs in $s.CounterSamples) {
                if     ($cs.Path -like '*% processor performance*') { $perf += [double]$cs.CookedValue }
                elseif ($cs.Path -like '*% processor time*')        { $util += [double]$cs.CookedValue }
            }
        }
        return [pscustomobject]@{ Ok = $true; Perf = $perf; Util = $util }
    } catch {
        $script:PerfCounterOk = $false
        return [pscustomobject]@{ Ok = $false; Perf = @(); Util = @() }
    }
}
function Get-PerfSingle {
    try {
        $c = Get-Counter -Counter '\Processor Information(_Total)\% Processor Performance' -MaxSamples 1 -ErrorAction Stop
        return [double]$c.CounterSamples[0].CookedValue
    } catch { return $null }
}

# --- Active all-core load test (time-boxed; guaranteed teardown) --------------
function Invoke-CpuLoadTest {
    param([int]$Seconds = 12)
    $logical = [Environment]::ProcessorCount
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $logical))
    $pool.Open()
    $workers = @()
    $perf = @(); $temps = @()
    try {
        for ($i = 0; $i -lt $logical; $i++) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            $null = $ps.AddScript({
                param($secs)
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $v = 0.0
                while ($sw.Elapsed.TotalSeconds -lt $secs) {
                    for ($k = 0; $k -lt 200000; $k++) { $v += [math]::Sqrt(($k + 1) * 1.0001) }
                }
                return $v
            }).AddArgument($Seconds)
            $workers += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
        }
        # Sample temperature + delivered frequency while the cores spin
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
            Start-Sleep -Milliseconds 1000
            $p = Get-PerfSingle
            if ($null -ne $p) { $perf += $p }
            $t = (Get-CpuTemperatures).PeakC
            if ($null -ne $t) { $temps += $t }
        }
    } finally {
        foreach ($w in $workers) {
            try { [void]$w.PS.EndInvoke($w.Handle) } catch {}
            try { $w.PS.Dispose() } catch {}
        }
        try { $pool.Close(); $pool.Dispose() } catch {}
    }
    return [pscustomobject]@{ Perf = $perf; Temps = $temps }
}

# --- Throttle / thermal events ------------------------------------------------
function Get-ThrottleEvents {
    param([int]$Hours = 24)
    $start = (Get-Date).AddHours(-$Hours)
    $id37 = @(); $id38 = @(); $whea = @(); $keyword = @()

    # Definitive: processor performance limited by system firmware
    try {
        $e = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; Id=@(37,38); StartTime=$start } -ErrorAction Stop)
        $id37 = @($e | Where-Object { $_.Id -eq 37 })
        $id38 = @($e | Where-Object { $_.Id -eq 38 })
    } catch {}

    # WHEA thermal hardware errors
    try {
        $w = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$start } -ErrorAction Stop)
        $whea = @($w | Where-Object { $_.Message -match '(?i)thermal|temperature' })
    } catch {}

    # Keyword catch-all across power providers (anything ID 37/38 missed)
    foreach ($prov in @('Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-Processor-Power')) {
        try {
            $k = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName=$prov; StartTime=$start } -MaxEvents 100 -ErrorAction Stop)
            foreach ($evt in $k) {
                if ($evt.Id -in @(37,38)) { continue }
                $m = ($evt.Message -replace '\s+',' ')
                if ($m -match '(?i)thermal|throttl|temperature.*(exceed|limit|threshold)') { $keyword += $evt }
            }
        } catch {}
    }
    return [pscustomobject]@{ Id37 = $id37; Id38 = $id38; Whea = $whea; Keyword = $keyword }
}

# --- Power configuration ------------------------------------------------------
function Get-ActivePowerPlan {
    try {
        $raw = powercfg /getactivescheme 2>&1
        if ($raw -match '\(([^)]+)\)') { return $Matches[1] }
        return 'Unknown'
    } catch { return 'Unknown' }
}
function Get-PowerThrottlingStatus {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling'
        if (Test-Path $path) {
            $val = Get-ItemProperty -Path $path -Name 'PowerThrottlingOff' -ErrorAction SilentlyContinue
            if ($null -ne $val -and $val.PowerThrottlingOff -eq 1) { return 'Disabled (PowerThrottlingOff=1)' }
            return 'Enabled (default)'
        }
        return 'Enabled (default - key absent)'
    } catch { return 'Unknown' }
}
function Get-ProcMaxState {
    # Max processor state % on AC for the active scheme; <100 caps the CPU.
    try {
        $out = powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 2>$null
        $line = $out | Select-String -Pattern 'Current AC Power Setting Index' | Select-Object -First 1
        if ($line) {
            $hex = ($line.ToString() -split ':')[-1].Trim()
            return [Convert]::ToInt32($hex, 16)
        }
    } catch {}
    return $null
}

# ============================================================================
# COLLECT
# ============================================================================
$now      = Get-Date
$cpuInfo  = Get-CPUInfo

# Idle baseline (temperature + delivered frequency)
$idleTemps  = Get-CpuTemperatures
$idleSample = Get-PerfSamples -Samples 2 -IntervalSec 1

# Active load test
$load = $null
if ($RunLoadTest -and $cpuInfo) {
    $load = Invoke-CpuLoadTest -Seconds $LoadTestSeconds
}

# Throttle / thermal events + power config
$events       = Get-ThrottleEvents -Hours $LookbackHours
$powerPlan    = Get-ActivePowerPlan
$procMaxState = Get-ProcMaxState
$powerThrott  = Get-PowerThrottlingStatus

# ============================================================================
# ANALYSE
# ============================================================================
# Temperatures
$loadPeakTemp = if ($load -and $load.Temps.Count) { ($load.Temps | Measure-Object -Maximum).Maximum } else { $null }
$peakTempVals = @()
if ($null -ne $idleTemps.PeakC) { $peakTempVals += $idleTemps.PeakC }
if ($null -ne $loadPeakTemp)    { $peakTempVals += $loadPeakTemp }
$peakTemp  = if ($peakTempVals.Count) { ($peakTempVals | Measure-Object -Maximum).Maximum } else { $null }
$tempSource = $idleTemps.PeakLabel
$haveDie    = $idleTemps.AnyDie
$passiveThrottle = ($idleTemps.PassivePct -lt 100) -or ($idleTemps.ThrottleReasons -gt 0)

# Delivered frequency
$idlePerf = if ($idleSample.Perf.Count) { [math]::Round(($idleSample.Perf | Measure-Object -Average).Average, 0) } else { $null }
$idleUtil = if ($idleSample.Util.Count) { [math]::Round(($idleSample.Util | Measure-Object -Average).Average, 0) } else { $null }
$loadMinPerf = if ($load -and $load.Perf.Count) { [math]::Round(($load.Perf | Measure-Object -Minimum).Minimum, 0) } else { $null }
$loadAvgPerf = if ($load -and $load.Perf.Count) { [math]::Round(($load.Perf | Measure-Object -Average).Average, 0) } else { $null }

$ev37 = $events.Id37.Count
$ev38 = $events.Id38.Count
$wheaThermal = $events.Whea.Count

# Verdict (event/frequency-driven; high temp alone is only WARN)
$alertReasons = @()
$warnReasons  = @()

if ($ev37 -gt 0)        { $alertReasons += "$ev37 firmware/thermal throttle event(s) (Kernel-Processor-Power ID 37) in ${LookbackHours}h" }
if ($passiveThrottle)   { $alertReasons += "live throttle active (passive limit $($idleTemps.PassivePct)%, reasons=$($idleTemps.ThrottleReasons))" }
if ($null -ne $loadMinPerf -and $loadMinPerf -lt $ThrottlePerfPct) { $alertReasons += "delivered frequency fell to $loadMinPerf% of base under load" }
elseif ($null -ne $idlePerf -and $null -ne $idleUtil -and $idleUtil -gt $HighLoadPct -and $idlePerf -lt $ThrottlePerfPct) { $alertReasons += "delivered frequency $idlePerf% of base while utilisation $idleUtil%" }

if ($null -ne $peakTemp -and $peakTemp -ge $HotTempC) { $warnReasons += "peak temperature ${peakTemp}C (>= ${HotTempC}C)" }
if ($powerPlan -match 'Power ?Saver') { $warnReasons += "Power Saver plan caps CPU performance" }
if ($null -ne $procMaxState -and $procMaxState -lt 100) { $warnReasons += "max processor state capped at $procMaxState% (AC)" }
if ($null -ne $loadAvgPerf -and $loadAvgPerf -lt $WarnPerfPct -and ($null -eq $loadMinPerf -or $loadMinPerf -ge $ThrottlePerfPct)) { $warnReasons += "frequency moderately reduced under load (avg $loadAvgPerf% of base)" }

if ($alertReasons.Count)     { $status = 'THROTTLING DETECTED'; $tag = '[ALERT]'; $exitCode = 2 }
elseif ($warnReasons.Count)  { $status = 'WARNING';             $tag = '[WARN]';  $exitCode = 1 }
else                         { $status = 'OK';                  $tag = '[OK]';    $exitCode = 0 }

# ============================================================================
# RENDER
# ============================================================================
function PctOrNA { param($v) ; if ($null -ne $v) { "$v%" } else { 'n/a' } }
function TempOrNA { param($v) ; if ($null -ne $v) { "$v C" } else { 'unavailable (no CPU sensor)' } }

$cpuLine = if ($cpuInfo) { "$($cpuInfo.Name)  ($($cpuInfo.Cores)C/$($cpuInfo.Threads)T, base $($cpuInfo.BaseMHz) MHz)" } else { 'CPU info unavailable' }

Write-Output "================================================================"
Write-Output " CPU THERMAL & THROTTLING CHECK   $($now.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Output " Host: $($env:COMPUTERNAME)"
Write-Output " CPU : $cpuLine"
Write-Output "================================================================"

# --- Verdict box ---
$freqUnderLoad = if ($null -ne $loadMinPerf) { "$loadMinPerf% of base (min during ${LoadTestSeconds}s test)" } elseif ($null -ne $idlePerf) { "$idlePerf% of base (idle sample)" } else { 'n/a' }
$dieNote = if ($null -eq $peakTemp) { '' } elseif ($haveDie) { ' [CPU die]' } else { ' [ACPI zone - may not be CPU die]' }

Write-Output ""
Write-Output "================================================================"
Write-Output " THERMAL VERDICT:  $tag $status"
Write-Output "================================================================"
Write-Output ("  Peak temperature          : {0}{1}" -f (TempOrNA $peakTemp), $dieNote)
if ($tempSource) { Write-Output ("  Temperature source        : {0}" -f $tempSource) }
Write-Output ("  Delivered freq under load : {0}" -f $freqUnderLoad)
Write-Output ("  Throttle events (ID 37)   : {0} in last {1}h" -f $ev37, $LookbackHours)
Write-Output ("  Live throttle reasons     : {0}" -f $(if ($passiveThrottle) { "ACTIVE (passive limit $($idleTemps.PassivePct)%)" } else { 'none' }))
Write-Output ("  Power plan / max state    : {0} / {1}" -f $powerPlan, (PctOrNA $procMaxState))
Write-Output "  --------------------------------------------------------------"
$reasonText = if ($alertReasons.Count) { ($alertReasons -join '; ') } elseif ($warnReasons.Count) { ($warnReasons -join '; ') } else { 'no throttling indicators detected' }
Write-Output ("  Assessment                : {0}" -f $reasonText)

# --- Temperature detail ---
Write-Output ""
Write-Output "--- Temperature ---"
if ($idleTemps.Readings.Count) {
    foreach ($r in ($idleTemps.Readings | Sort-Object TempC -Descending)) {
        $kind = if ($r.IsDie) { 'die' } else { 'ACPI/zone' }
        $lvl  = if ($r.TempC -ge $HotTempC) { 'WARN' } elseif ($r.TempC -ge $ElevatedTempC) { 'INFO' } else { 'OK' }
        Out-Line ("{0} [{1}]: {2} C ({3})" -f $r.Source, $r.Label, $r.TempC, $kind) -Level $lvl
    }
    if ($null -ne $loadPeakTemp) { Out-Line "Peak under load test: $loadPeakTemp C" -Level INFO }
    Out-Line ("Overall peak: {0} C" -f $peakTemp) -Level INFO
} else {
    Out-Line "No CPU temperature sensor available (no LHM/OHM agent, no ACPI zone)." -Level WARN
    Out-Line "Install HWiNFO or LibreHardwareMonitor (as a service) for accurate CPU die temps." -Level INFO
}
if ($passiveThrottle -and $idleTemps.PassivePct -lt 100) { Out-Line "ACPI passive cooling limit engaged: CPU capped to $($idleTemps.PassivePct)% (actively throttling to cool)." -Level ALERT }

# --- Frequency & load ---
Write-Output ""
Write-Output "--- Frequency & Load ---"
if ($script:PerfCounterOk) {
    Out-Line ("Idle: {0} delivered freq @ {1} utilisation" -f (PctOrNA $idlePerf), (PctOrNA $idleUtil)) -Level INFO
    if ($load) {
        $loadSamplesStr = (($load.Perf | ForEach-Object { [math]::Round($_,0) }) -join ',')
        Out-Line ("Load test (${LoadTestSeconds}s, all cores): min {0} / avg {1} of base; samples: {2}" -f (PctOrNA $loadMinPerf), (PctOrNA $loadAvgPerf), $loadSamplesStr) -Level INFO
        if ($null -ne $loadMinPerf -and $loadMinPerf -lt $ThrottlePerfPct) {
            Out-Line "Delivered frequency collapsed under load -> throttling." -Level ALERT
        } elseif ($null -ne $loadAvgPerf -and $loadAvgPerf -lt $WarnPerfPct) {
            Out-Line "Delivered frequency moderately reduced under load." -Level WARN
        } else {
            Out-Line "Delivered frequency held under load (no throttling seen during test)." -Level OK
        }
    } else {
        Out-Line "Active load test skipped (RunLoadTest = false); throttling may be missed at idle." -Level INFO
    }
} else {
    # Fallback when perf counters unavailable (e.g. localised/corrupt counters)
    Out-Line "Processor performance counter unavailable; falling back to clock-speed sampling." -Level WARN
    if ($cpuInfo) {
        $samples = @()
        for ($i = 0; $i -lt 3; $i++) {
            try { $samples += [int](Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).CurrentClockSpeed } catch {}
            if ($i -lt 2) { Start-Sleep -Milliseconds 800 }
        }
        if ($samples.Count) {
            $best = ($samples | Measure-Object -Maximum).Maximum
            $pct  = [math]::Round(($best / $cpuInfo.BaseMHz) * 100, 0)
            Out-Line ("Clock samples (MHz): {0}; best {1}% of base, load {2}%" -f ($samples -join ','), $pct, $cpuInfo.LoadPct) -Level INFO
        }
    }
}

# --- Power configuration ---
Write-Output ""
Write-Output "--- Power Configuration ---"
Out-Line "Active power plan: $powerPlan" -Level $(if ($powerPlan -match 'Power ?Saver') { 'WARN' } else { 'INFO' })
Out-Line ("Max processor state (AC): {0}" -f (PctOrNA $procMaxState)) -Level $(if ($null -ne $procMaxState -and $procMaxState -lt 100) { 'WARN' } else { 'INFO' })
Out-Line "Windows power throttling: $powerThrott" -Level INFO

# --- Throttle / thermal events ---
Write-Output ""
Write-Output "--- Throttle / Thermal Events (last $LookbackHours h) ---"
if ($ev37 -gt 0) {
    Out-Line "Kernel-Processor-Power ID 37 (CPU limited by firmware): $ev37" -Level ALERT
    foreach ($e in ($events.Id37 | Select-Object -First 3)) {
        $m = ($e.Message -replace '\s+',' ').Trim()
        if ($m.Length -gt 160) { $m = $m.Substring(0,160) + '...' }
        Out-Line ("  {0}  {1}" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $m) -Level ALERT
    }
    if ($ev38 -gt 0) { Out-Line "Returned-to-normal ID 38: $ev38 (throttling was intermittent)" -Level INFO }
} else {
    Out-Line "No firmware-throttle (ID 37) events." -Level OK
}
if ($wheaThermal -gt 0) {
    Out-Line "WHEA thermal hardware events: $wheaThermal" -Level ALERT
} else {
    Out-Line "No WHEA thermal events." -Level OK
}
if ($events.Keyword.Count -gt 0) { Out-Line "Other thermal-related power events: $($events.Keyword.Count)" -Level INFO }

# --- Mitigation hints (always printed, tailored to findings) ---
Write-Output ""
Write-Output "--- Mitigation Hints ---"
$hintN = 0
function Hint { param([string]$Text, [string]$Level='INFO') ; $script:hintN++ ; Out-Line ("{0}. {1}" -f $script:hintN, $Text) -Level $Level }

$thermalProblem = ($alertReasons.Count -gt 0) -or ($null -ne $peakTemp -and $peakTemp -ge $HotTempC) -or $passiveThrottle
if ($thermalProblem) {
    Hint "Clean dust from fans, heatsink fins and vents; verify all fans spin and ramp under load." 'ALERT'
    Hint "Reapply CPU thermal paste / pads if aged (commonly needed on laptops 2-3+ years old)." 'ALERT'
    Hint "Improve airflow: clear vents, avoid soft surfaces/enclosed cabinets, check ambient room temperature." 'ALERT'
    Hint "If docked, test undocked - dock placement and blocked vents are a common laptop cause." 'INFO'
    Hint "Update BIOS/EC firmware and review fan-curve / thermal settings in firmware." 'INFO'
    Hint "Advanced: consider a CPU undervolt (e.g. vendor tool / ThrottleStop / XTU) to cut heat." 'INFO'
} else {
    Hint "No thermal action required. Preventively keep vents clear and fans dust-free." 'OK'
}
if (($powerPlan -match 'Power ?Saver') -or ($null -ne $procMaxState -and $procMaxState -lt 100)) {
    Hint "Performance is capped by power settings (plan/max processor state) - confirm this is intended; raise max processor state to 100% if not." 'WARN'
}
# High sustained load without throttle proof => likely software, not a hardware fault
$highLoad = ($null -ne $idleUtil -and $idleUtil -gt $HighLoadPct)
if ($highLoad -and $alertReasons.Count -eq 0) {
    Hint "CPU utilisation is high but no throttling was confirmed - check for a runaway process (Task Manager / Get-Process | Sort CPU). High load alone is not a hardware fault." 'INFO'
}
if (-not $haveDie) {
    Hint "For ongoing accurate CPU die temperatures, deploy HWiNFO or LibreHardwareMonitor as a service (exposes a WMI namespace this script reads automatically)." 'INFO'
}

Write-Output ""
Write-Output "================================================================"
Write-Output " RESULT: $tag $status   (exit $exitCode)"
Write-Output "================================================================"

# Exit code for RMM alerting: 0 = OK, 1 = Warning, 2 = Alert
exit $exitCode
