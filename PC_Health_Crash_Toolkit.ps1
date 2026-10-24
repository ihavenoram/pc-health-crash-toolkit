# PC Health and Crash Toolkit 1.0.2 - https://ihavenoram.com - https://github.com/ihavenoram/pc-health-crash-toolkit
# MIT licence, (c) 2026 ihavenoram.com. If you publish something built on this, please credit ihavenoram.com.
<#
=========================================================
Script Name: PC_Health_Crash_Toolkit
Description: Windows Forms front end for the crash and health scripts in this folder. One
window that:
  - runs the crash/shutdown incident diagnostic over the last 30 days and highlights
    crashes, unexpected restarts, forced power-offs and unexplained shutdowns on a
    30-day calendar and in a transition list (newest first, with full detail);
  - runs the SSD/SMART health check (asks before installing smartmontools), the
    system-health extras (system-disk space, memory, drivers, Windows integrity,
    battery/power), the UI-lag check and the thermal throttling check;
  - lists every finding by severity on one Overview tab;
  - lets the tech tick crash artefacts (minidumps, LiveKernelReports, user-mode dumps,
    WER reports, event logs, these reports) and zip them to C:\temp, with the full
    MEMORY.DMP copied raw beside the zip;
  - copies a plain-text report to the clipboard, saves it to C:\temp, and opens the crash
    data in Crash_Incident_Viewer.html.

Runs on the client desktop (self-elevates after staging to C:\ProgramData\PCHealthToolkit,
because scripts on a cloud-synced or network path are refused when elevated) and in
ScreenConnect Backstage (already SYSTEM). Windows PowerShell 5.1, Windows Forms (WPF
renders black in session 0). Child scripts run hidden with a timeout each; the window never
blocks.

Launch:  PC_Health_Crash_Toolkit.cmd   (or: powershell.exe -ExecutionPolicy Bypass -STA -File PC_Health_Crash_Toolkit.ps1)
Options: -NoElevate  -NoAutoRun
Needs beside it: System_Crash_And_Shutdown_Incident_Diagnostic.ps1, System_Health_Extras_Check.ps1,
CPU_Thermal_Throttling_Diagnostic_Check.ps1, System_UI_Lag_And_Responsiveness_Diagnostic.ps1,
Crash_Incident_Viewer.html, and SSD_Hard_Drive_Info_Health_Status_Enhanced.ps1 (here or in ..\SSD).
Missing scripts are shown as "not available".
=========================================================
#>
param(
    [switch]$NoElevate,
    [switch]$NoAutoRun,
    [switch]$Staged,
    [switch]$BuildOnly
)

if ($PSVersionTable.PSVersion.Major -lt 3) { Write-Output 'PowerShell 3.0 or later is required.'; exit 1 }

$ErrorActionPreference = 'Continue'
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture
$script:ToolRoot = $PSScriptRoot
if (-not $script:ToolRoot) { $script:ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:SelfName = 'PC_Health_Crash_Toolkit.ps1'
$script:SelfPath = $MyInvocation.MyCommand.Path
if (-not $script:SelfPath) { $script:SelfPath = Join-Path $script:ToolRoot $script:SelfName }

$script:FileNames = @{
    crash   = 'System_Crash_And_Shutdown_Incident_Diagnostic.ps1'
    extras  = 'System_Health_Extras_Check.ps1'
    thermal = 'CPU_Thermal_Throttling_Diagnostic_Check.ps1'
    uilag   = 'System_UI_Lag_And_Responsiveness_Diagnostic.ps1'
    ssd     = 'SSD_Hard_Drive_Info_Health_Status_Enhanced.ps1'
    viewer  = 'Crash_Incident_Viewer.html'
    cmd     = 'PC_Health_Crash_Toolkit.cmd'
}

function Find-Sibling {
    param([string]$Name)
    $p = Join-Path $script:ToolRoot $Name
    if (Test-Path -LiteralPath $p) { return $p }
    $p = Join-Path (Join-Path (Split-Path -Parent $script:ToolRoot) 'SSD') $Name
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

$script:PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $script:PsExe = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
}
$script:IsAdmin  = Test-IsAdmin
$script:IsSystem = $false
try { $script:IsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') } catch { }
$script:ElevateNote = ''

# -----------------------------------------------------------------------------
# Elevation: stage to local disk, relaunch elevated, exit. UAC declined = carry on.
# -----------------------------------------------------------------------------
if (-not $script:IsAdmin -and -not $NoElevate -and -not $BuildOnly -and -not $Staged) {
    try {
        $stage = Join-Path $env:ProgramData 'PCHealthToolkit'
        if ([System.IO.Path]::GetFullPath($script:ToolRoot).TrimEnd('\') -ne [System.IO.Path]::GetFullPath($stage).TrimEnd('\')) {
            if (-not (Test-Path -LiteralPath $stage)) { New-Item -ItemType Directory -Path $stage -Force -ErrorAction Stop | Out-Null }
            Copy-Item -LiteralPath $script:SelfPath -Destination (Join-Path $stage $script:SelfName) -Force -ErrorAction Stop
            foreach ($n in $script:FileNames.Values) {
                $src = Find-Sibling $n
                if ($src) { Copy-Item -LiteralPath $src -Destination (Join-Path $stage $n) -Force -ErrorAction Stop }
            }
        }
        $argLine = '-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "' + (Join-Path $stage $script:SelfName) + '" -Staged'
        if ($NoAutoRun) { $argLine += ' -NoAutoRun' }
        Start-Process -FilePath $script:PsExe -ArgumentList $argLine -Verb RunAs -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        $script:ElevateNote = 'Not elevated (' + $_.Exception.Message + ') - several checks need administrator rights.'
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# -----------------------------------------------------------------------------
# Session state
# -----------------------------------------------------------------------------
$script:HostName = $env:COMPUTERNAME
$script:Stamp    = (Get-Date).ToString('yyyyMMdd_HHmmss', $script:Inv)
$script:OutRoot  = 'C:\temp'
$script:WorkDir  = Join-Path $script:OutRoot ('PCHealthToolkit\' + $script:HostName + '_' + $script:Stamp)
try { New-Item -ItemType Directory -Path $script:WorkDir -Force -ErrorAction Stop | Out-Null }
catch {
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('PCHealthToolkit_' + $script:Stamp)
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
}

$script:ModOrder  = @('crash', 'ssd', 'extras', 'uilag', 'thermal')
$script:ModTitles = @{ crash = 'Crashes & restarts'; ssd = 'Storage (SSD/SMART)'; extras = 'System health'; uilag = 'Responsiveness (UI lag)'; thermal = 'Thermal throttling'; dism = 'DISM health check' }
$script:ModState  = @{}      # name -> @{ Status; Summary; Secs }
$script:Findings  = @{}      # name -> finding[]
$script:RawOut    = @{}      # name -> text
$script:CrashData = $null
$script:CrashRaw  = $null
$script:CrashRef  = Get-Date
$script:CrashEpisodes = @()
$script:ExtrasData = $null
$script:Sync      = $null
$script:PsInst    = $null
$script:Handle    = $null
$script:Applied   = @{}
$script:JobKind   = ''
$script:SmartMissing = $false
$script:LogItems  = @()
$script:SevRank   = @{ ALERT = 3; WARN = 2; ERROR = 2; INFO = 1; OK = 0; 'N/A' = 0 }

# System info for the header
$script:SysInfo = [ordered]@{ model = ''; os = ''; uptime = ''; boot = $null }
try {
    $csi = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $script:SysInfo.model = (([string]$csi.Manufacturer).Trim() + ' ' + ([string]$csi.Model).Trim()).Trim()
} catch { }
try {
    $osi = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $disp = ''
    try { $disp = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion } catch { }
    $script:SysInfo.os = ([string]$osi.Caption + ' ' + $disp + ' (build ' + $osi.BuildNumber + ')') -replace '\s+', ' '
    $script:SysInfo.boot = $osi.LastBootUpTime
    $up = (Get-Date) - $osi.LastBootUpTime
    $script:SysInfo.uptime = ('' + [math]::Floor($up.TotalDays) + 'd ' + $up.Hours + 'h ' + $up.Minutes + 'm')
} catch { }
$script:RunAs = 'standard user (not elevated)'
if ($script:IsSystem) { $script:RunAs = 'SYSTEM' } elseif ($script:IsAdmin) { $script:RunAs = 'administrator' }

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Format-When { param($T) if ($null -eq $T) { return '' } return ([datetime]$T).ToString('yyyy-MM-dd HH:mm', $script:Inv) }
function ConvertFrom-Iso {
    param([string]$Text)
    if (-not $Text) { return $null }
    # Keep the clock time as recorded on the machine (ignore the offset)
    try { return ([System.DateTimeOffset]::Parse($Text, $script:Inv)).DateTime } catch { return $null }
}
function Format-Ago {
    param($T, $Ref)
    if ($null -eq $T) { return '' }
    $d = ([datetime]$Ref).Date.Subtract(([datetime]$T).Date).Days
    if ($d -le 0) { return 'today' } elseif ($d -eq 1) { return 'yesterday' }
    return ('' + $d + ' days ago')
}
function Format-Span {
    param($Seconds)
    if ($null -eq $Seconds -or "$Seconds" -eq '') { return '' }
    $s = [math]::Abs([double]$Seconds)
    if ($s -lt 90) { return ('' + [math]::Round($s) + ' s') }
    if ($s -lt 5400) { return ('' + [math]::Round($s / 60) + ' min') }
    if ($s -lt 172800) { return ('' + [math]::Round($s / 3600, 1) + ' h') }
    return ('' + [math]::Round($s / 86400, 1) + ' d')
}
function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}
function Format-Any {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    try { return ($Value | ConvertTo-Json -Compress -Depth 4) } catch { return [string]$Value }
}
function New-Finding {
    param([string]$Sev, [string]$Area, [string]$Text, $When, [string]$Source)
    return [pscustomobject]@{ Sev = $Sev; Area = $Area; Text = $Text; When = $When; Source = $Source }
}
function Get-WorstSev {
    param([string[]]$List)
    $best = 'OK'
    foreach ($s in $List) { if ($s -and $script:SevRank[$s] -gt $script:SevRank[$best]) { $best = $s } }
    return $best
}
function Set-PaneText {
    param($Box, [string]$Text)
    $Box.Text = $Text
    $Box.SelectionStart = 0
    $Box.SelectionLength = 0
}
function Write-AsciiFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

# Episode classification for the calendar, grid and findings
$script:EpClass = @{
    crash       = @{ Rank = 6; Label = 'CRASH (bugcheck / BSOD)';            Char = 'X'; Back = [System.Drawing.Color]::FromArgb(220, 53, 69);  Fore = [System.Drawing.Color]::White }
    unclean     = @{ Rank = 5; Label = 'UNEXPECTED - no clean shutdown';     Char = 'U'; Back = [System.Drawing.Color]::FromArgb(253, 126, 20); Fore = [System.Drawing.Color]::White }
    powerbutton = @{ Rank = 4; Label = 'Forced off (power button)';          Char = 'F'; Back = [System.Drawing.Color]::FromArgb(255, 193, 7);  Fore = [System.Drawing.Color]::Black }
    unexplained = @{ Rank = 3; Label = 'Shutdown, requester not recorded';   Char = '?'; Back = [System.Drawing.Color]::FromArgb(255, 236, 153); Fore = [System.Drawing.Color]::Black }
    unknown     = @{ Rank = 2; Label = 'Not enough evidence';                Char = '-'; Back = [System.Drawing.Color]::FromArgb(222, 222, 222); Fore = [System.Drawing.Color]::Black }
    controlled  = @{ Rank = 1; Label = 'Requested restart / shutdown';       Char = 'r'; Back = [System.Drawing.Color]::FromArgb(197, 216, 240); Fore = [System.Drawing.Color]::Black }
    none        = @{ Rank = 0; Label = 'No restart';                         Char = '.'; Back = [System.Drawing.Color]::FromArgb(246, 247, 249); Fore = [System.Drawing.Color]::DimGray }
}
$script:StallColor = [System.Drawing.Color]::FromArgb(111, 66, 193)
$script:RetryColor = [System.Drawing.Color]::FromArgb(196, 178, 232)
function Get-EpisodeClass {
    param($Ep)
    switch ([string]$Ep.type) {
        'unclean-bugcheck'      { return 'crash' }
        'unclean-no-bugcheck'   { return 'unclean' }
        'unclean-powerbutton'   { return 'powerbutton' }
        'insufficient-evidence' { return 'unknown' }
        'orderly-no-initiator'  { return 'unexplained' }
    }
    if ($Ep.unexplained) { return 'unexplained' }
    return 'controlled'
}
function Get-EpisodeTime {
    param($Ep)
    $t = ConvertFrom-Iso ([string]$Ep.t0)
    if (-not $t) { $t = ConvertFrom-Iso ([string]$Ep.down) }
    if (-not $t) { $t = ConvertFrom-Iso ([string]$Ep.boot) }
    return $t
}
function Get-EpisodeCause {
    param($Ep)
    $parts = @()
    if ($Ep.bug) { $parts += ('BSOD ' + $Ep.bug.code + ' ' + $Ep.bug.name) }
    if ($Ep.initiator) {
        $i = $Ep.initiator
        $who = $i.name; if (-not $who) { $who = $i.process }
        if ($who) { $parts += ($who + $(if ($i.user) { ' for ' + $i.user } else { '' }) + $(if ($i.category) { ' (' + $i.category + ')' } else { '' })) }
    }
    if ($Ep.kp41 -and $Ep.kp41.powerButton) { $parts += $(if ($Ep.kp41.longPress) { 'power button held' } else { 'power button pressed' }) }
    if ($Ep.kp41 -and $Ep.kp41.sleep) { $parts += 'during sleep' }
    if ($parts.Count -eq 0) {
        $cls = Get-EpisodeClass $Ep
        if ($cls -eq 'unclean') { $parts += 'power loss, hard hang, reset or crash without a dump' }
        elseif ($cls -eq 'unexplained') { $parts += 'no restart request recorded' }
    }
    return ($parts -join '; ')
}

# -----------------------------------------------------------------------------
# Background worker (runs in its own runspace; touches only $sync)
# -----------------------------------------------------------------------------
$script:WorkerCode = {
    param($sync, $job)
    $ErrorActionPreference = 'Continue'
    function New-Result { param($Code, $Out, $Err, $Secs, $TimedOut) return @{ Exit = $Code; Out = $Out; Err = $Err; Secs = $Secs; TimedOut = $TimedOut } }
    function Start-Child {
        param($Spec)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Spec.Exe
        $psi.Arguments = $Spec.Args
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        if ($Spec.Dir) { $psi.WorkingDirectory = $Spec.Dir }
        $p = [System.Diagnostics.Process]::Start($psi)
        return @{ Spec = $Spec; P = $p; O = $p.StandardOutput.ReadToEndAsync(); E = $p.StandardError.ReadToEndAsync(); Sw = [System.Diagnostics.Stopwatch]::StartNew() }
    }
    function Stop-Tree { param($Proc) try { $null = & taskkill.exe /PID $Proc.Id /T /F 2>&1 } catch { } }
    function Copy-Shared {
        param([string]$Source, [System.IO.Stream]$Target)
        $in = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        try { $in.CopyTo($Target) } finally { $in.Dispose() }
    }
    try {
        if ($job.Kind -eq 'run') {
            foreach ($phase in $job.Phases) {
                if ($sync.Cancel) { break }
                $running = New-Object System.Collections.ArrayList
                foreach ($spec in $phase) {
                    try { [void]$running.Add((Start-Child $spec)); $sync.Running[$spec.Name] = [DateTime]::Now }
                    catch { $sync.Results[$spec.Name] = New-Result -1 '' ('Could not start: ' + $_.Exception.Message) 0 $false }
                }
                while ($running.Count -gt 0) {
                    foreach ($r in @($running.ToArray())) {
                        $done = $false; $to = $false
                        if ($r.P.HasExited) { $done = $true }
                        elseif ($sync.Cancel -or $r.Sw.Elapsed.TotalSeconds -gt $r.Spec.Timeout) { Stop-Tree $r.P; [void]$r.P.WaitForExit(5000); $done = $true; $to = $true }
                        if ($done) {
                            $out = ''; $err = ''
                            try { if ($r.O.Wait(8000)) { $out = $r.O.Result } } catch { }
                            try { if ($r.E.Wait(3000)) { $err = $r.E.Result } } catch { }
                            $code = -1; try { $code = $r.P.ExitCode } catch { }
                            $sync.Results[$r.Spec.Name] = New-Result $code $out $err ([math]::Round($r.Sw.Elapsed.TotalSeconds, 1)) $to
                            $sync.Running.Remove($r.Spec.Name)
                            $running.Remove($r)
                        }
                    }
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        elseif ($job.Kind -eq 'zip') {
            Add-Type -AssemblyName System.IO.Compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $res = @{ Zip = $job.ZipPath; Files = 0; Bytes = [long]0; Raw = (New-Object System.Collections.ArrayList); Errors = (New-Object System.Collections.ArrayList) }
            $files = New-Object System.Collections.ArrayList
            foreach ($f in $job.Files) { [void]$files.Add($f) }
            # Event logs: export the last N days
            foreach ($log in $job.EventLogs) {
                if ($sync.Cancel) { break }
                $sync.Progress = 'Exporting event log ' + $log + '...'
                $dest = Join-Path $job.TempDir (($log -replace '[\\/]', '_') + '.evtx')
                $q = '*[System[TimeCreated[timediff(@SystemTime) <= ' + ([int64]$job.Days * 86400000) + ']]]'
                $o = & wevtutil.exe epl $log $dest ('/q:' + $q) '/ow:true' 2>&1
                if (Test-Path -LiteralPath $dest) { [void]$files.Add(@{ Src = $dest; Entry = ('EventLogs/' + [System.IO.Path]::GetFileName($dest)) }) }
                else { [void]$res.Errors.Add('Event log ' + $log + ': ' + (($o | Out-String).Trim())) }
            }
            # Full memory dump: copied raw beside the zip (large, compresses poorly, often needed only on request)
            foreach ($rf in $job.RawFiles) {
                if ($sync.Cancel) { break }
                try {
                    $fi = New-Object System.IO.FileInfo($rf)
                    $dest = Join-Path $job.OutDir ([System.IO.Path]::GetFileNameWithoutExtension($rf) + '_' + $job.HostName + '_' + $job.Stamp + $fi.Extension)
                    $drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($dest))
                    if ($drive.AvailableFreeSpace -lt ($fi.Length + 512MB)) { [void]$res.Errors.Add('Not enough free space to copy ' + $rf + ' (' + [math]::Round($fi.Length / 1GB, 2) + ' GB) - drag it from its original location instead'); continue }
                    $sync.Progress = 'Copying ' + $fi.Name + ' raw (' + [math]::Round($fi.Length / 1GB, 2) + ' GB)...'
                    $out = [System.IO.File]::Open($dest, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try { Copy-Shared $rf $out } finally { $out.Dispose() }
                    [void]$res.Raw.Add($dest)
                } catch { [void]$res.Errors.Add('Raw copy ' + $rf + ': ' + $_.Exception.Message) }
            }
            # Zip, streamed straight from the source files
            $fs = [System.IO.File]::Open($job.ZipPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
                try {
                    $used = @{}
                    $n = 0
                    foreach ($f in $files) {
                        if ($sync.Cancel) { [void]$res.Errors.Add('Cancelled'); break }
                        $n++
                        $sync.Progress = 'Zipping ' + $n + ' of ' + $files.Count + ': ' + [System.IO.Path]::GetFileName($f.Src)
                        $entryName = $f.Entry
                        $k = 1
                        while ($used.ContainsKey($entryName.ToLowerInvariant())) { $k++; $entryName = [System.IO.Path]::ChangeExtension($f.Entry, $null).TrimEnd('.') + '_' + $k + [System.IO.Path]::GetExtension($f.Entry) }
                        $used[$entryName.ToLowerInvariant()] = $true
                        try {
                            $entry = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                            try { $entry.LastWriteTime = [System.DateTimeOffset](New-Object System.IO.FileInfo($f.Src)).LastWriteTime } catch { }
                            $es = $entry.Open()
                            try { Copy-Shared $f.Src $es } finally { $es.Dispose() }
                            $res.Files++
                            $res.Bytes += (New-Object System.IO.FileInfo($f.Src)).Length
                        } catch { [void]$res.Errors.Add($f.Src + ': ' + $_.Exception.Message) }
                    }
                    $man = $zip.CreateEntry('MANIFEST.txt')
                    $sw = New-Object System.IO.StreamWriter($man.Open())
                    try {
                        $sw.WriteLine('Crash log collection - ' + $job.HostName + ' - ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
                        $sw.WriteLine('Files: ' + $res.Files + '   Event logs: last ' + $job.Days + ' days')
                        foreach ($rp in $res.Raw) { $sw.WriteLine('Raw copy beside the zip: ' + $rp) }
                        foreach ($f in $files) { $sw.WriteLine('  ' + $f.Entry + '   <- ' + $f.Src) }
                        foreach ($e in $res.Errors) { $sw.WriteLine('ERROR: ' + $e) }
                    } finally { $sw.Dispose() }
                } finally { $zip.Dispose() }
            } finally { $fs.Dispose() }
            $sync.ZipResult = $res
        }
    } catch {
        $sync.WorkerError = $_.Exception.Message
    } finally {
        $sync.Done = $true
    }
}

function Start-Worker {
    param([hashtable]$Job, [string]$Kind)
    $script:Sync = [hashtable]::Synchronized(@{
        Running = [hashtable]::Synchronized(@{}); Results = [hashtable]::Synchronized(@{})
        Done = $false; Cancel = $false; Progress = ''; WorkerError = $null; ZipResult = $null; Started = [DateTime]::Now
    })
    $script:Applied = @{}
    $script:JobKind = $Kind
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $script:PsInst = [powershell]::Create()
    $script:PsInst.Runspace = $rs
    [void]$script:PsInst.AddScript($script:WorkerCode.ToString()).AddArgument($script:Sync).AddArgument($Job)
    $script:Handle = $script:PsInst.BeginInvoke()
    Set-Busy $true
    $script:Timer.Start()
}

function Get-ThermalScript {
    param([bool]$LoadTest)
    $src = Find-Sibling $script:FileNames.thermal
    if (-not $src -or $LoadTest) { return $src }
    # Same script with its load test switched off (the original file is not changed)
    try {
        $text = [System.IO.File]::ReadAllText($src)
        $patched = [regex]::Replace($text, '(?m)^\$RunLoadTest\s*=\s*\$true', '$$RunLoadTest = $$false')
        if ($patched -eq $text) { return $src }
        $dst = Join-Path $script:WorkDir 'CPU_Thermal_Throttling_Diagnostic_Check_NoLoadTest.ps1'
        Write-AsciiFile $dst $patched
        return $dst
    } catch { return $src }
}

function Get-ModuleSpec {
    param([string]$Name, [switch]$InstallSmart)
    $dir = Join-Path $script:WorkDir $Name
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file = $null; $argText = ''; $timeout = 300
    switch ($Name) {
        'crash'   { $file = Find-Sibling $script:FileNames.crash; $argText = '-LookbackDays 30 -HistoryDays 30 -MaxEpisodes 40 -MaxJsonKB 500 -NoInlineJson -OutputDir "' + $dir + '"'; $timeout = 420 }
        'ssd'     { $file = Find-Sibling $script:FileNames.ssd; if (-not $InstallSmart) { $argText = '-NoSmartInstall' }; $timeout = $(if ($InstallSmart) { 900 } else { 480 }) }
        'extras'  { $file = Find-Sibling $script:FileNames.extras; $argText = '-Days 30 -OutputDir "' + $dir + '"'; $timeout = 240 }
        'uilag'   { $file = Find-Sibling $script:FileNames.uilag; $timeout = 180 }
        'thermal' { $file = Get-ThermalScript ([bool]$script:ChkLoad.Checked); $timeout = 180 }
        'dism'    { return @{ Name = 'dism'; Exe = (Join-Path $env:SystemRoot 'System32\Dism.exe'); Args = '/Online /Cleanup-Image /CheckHealth'; Timeout = 300; Dir = $dir } }
    }
    if (-not $file) { return $null }
    return @{ Name = $Name; Exe = $script:PsExe; Args = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $file + '" ' + $argText).Trim(); Timeout = $timeout; Dir = $dir }
}

function Start-Modules {
    param([object[]]$Phases, [switch]$InstallSmart)
    $list = New-Object System.Collections.ArrayList
    foreach ($ph in $Phases) {
        $specs = @()
        foreach ($name in @($ph)) {
            $sp = Get-ModuleSpec $name -InstallSmart:$InstallSmart
            if ($sp) {
                $specs += $sp
                $script:ModState[$name] = @{ Status = 'RUNNING'; Summary = 'running...'; Secs = $null }
            } else {
                $script:ModState[$name] = @{ Status = 'N/A'; Summary = ($script:FileNames[$name] + ' not found beside the toolkit'); Secs = $null }
                $script:Findings[$name] = @(New-Finding 'INFO' $script:ModTitles[$name] ('Check not available: ' + $script:FileNames[$name] + ' is missing.') $null $name)
            }
        }
        if ($specs.Count -gt 0) { [void]$list.Add($specs) }
    }
    Update-ModuleLabels
    Update-Overview
    if ($list.Count -eq 0) { return }
    Start-Worker @{ Kind = 'run'; Phases = $list } 'run'
}

function Start-RunAll {
    if ($script:Sync -and -not $script:Sync.Done) { return }
    # Event-log and inventory checks in parallel first; the timing-sensitive samplers run alone afterwards
    Start-Modules -Phases (@(, @('crash', 'ssd', 'extras')) + @(, @('uilag')) + @(, @('thermal')))
}

# -----------------------------------------------------------------------------
# Result parsers
# -----------------------------------------------------------------------------
function Use-Result {
    param([string]$Name, [hashtable]$Res)
    $text = [string]$Res.Out
    if ($Res.Err) { $text += [Environment]::NewLine + '--- stderr ---' + [Environment]::NewLine + [string]$Res.Err }
    if ($Res.TimedOut) { $text += [Environment]::NewLine + '*** Stopped after ' + $Res.Secs + ' s (timeout or cancelled) ***' }
    if ($Name -ne 'dism') { $script:RawOut[$Name] = $text }
    $err = $null
    try {
        switch ($Name) {
            'crash'   { Use-CrashResult $Res }
            'ssd'     { Use-SsdResult $Res }
            'extras'  { Use-ExtrasResult $Res }
            'uilag'   { Use-VerdictResult 'uilag' $Res 'HEALTH VERDICT' 'Responsiveness' }
            'thermal' { Use-VerdictResult 'thermal' $Res 'THERMAL VERDICT' 'Thermal' }
            'dism'    { Use-DismResult $Res }
        }
    } catch { $err = $_.Exception.Message }
    if ($err -and $Name -ne 'dism') {
        $script:ModState[$Name] = @{ Status = 'ERROR'; Summary = ('Could not read the result: ' + $err); Secs = $Res.Secs }
    }
    if ($script:ModState.ContainsKey($Name)) { $script:ModState[$Name].Secs = $Res.Secs }
    Update-ModuleLabels
    Update-Overview
    Update-RawText
}

function Get-FailureSummary {
    param([hashtable]$Res)
    if ($Res.TimedOut) { return ('Stopped after ' + $Res.Secs + ' s (timeout)') }
    $e = ([string]$Res.Err).Trim()
    # The PowerShell error text wraps across lines at the console width, hence (?s)
    if ($e -match '(?s)#requires.*Administrator|RunAsAdministrator|elevated') { return 'Needs administrator rights - restart the toolkit elevated' }
    if ($e) { return ('Failed: ' + (($e -split "`r?`n")[0])) }
    return ('No verdict in the output (exit ' + $Res.Exit + ')')
}

function Use-CrashResult {
    param([hashtable]$Res)
    $dir = Join-Path $script:WorkDir 'crash'
    $json = @(Get-ChildItem -LiteralPath $dir -Filter 'CrashIncident_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($json.Count -eq 0) {
        $script:ModState['crash'] = @{ Status = 'ERROR'; Summary = (Get-FailureSummary $Res); Secs = $Res.Secs }
        $script:Findings['crash'] = @(New-Finding 'WARN' 'Crashes' ('Crash diagnostic produced no result: ' + (Get-FailureSummary $Res)) $null 'crash')
        return
    }
    Import-CrashJson $json[0].FullName
}

function Import-CrashJson {
    param([string]$Path)
    $raw = [System.IO.File]::ReadAllText($Path)
    $obj = $raw | ConvertFrom-Json
    Set-CrashData $obj $raw
}

function Set-CrashData {
    param($Data, [string]$Raw)
    $script:CrashData = $Data
    $script:CrashRaw = $Raw
    $ref = ConvertFrom-Iso ([string]$Data.generated)
    if (-not $ref) { $ref = Get-Date }
    $script:CrashRef = $ref
    $eps = @($Data.episodes | Sort-Object { Get-EpisodeTime $_ } -Descending)
    $script:CrashEpisodes = $eps

    # Findings: every non-routine transition in the last 30 days, plus background health
    $list = @()
    $c7 = @{}; $c30 = @{}
    foreach ($k in $script:EpClass.Keys) { $c7[$k] = 0; $c30[$k] = 0 }
    foreach ($ep in $eps) {
        $t = Get-EpisodeTime $ep
        if (-not $t) { continue }
        $age = ($ref - $t).TotalDays
        if ($age -gt 30) { continue }
        $cls = Get-EpisodeClass $ep
        $c30[$cls]++
        if ($age -le 7) { $c7[$cls]++ }
        $when = Format-When $t
        switch ($cls) {
            'crash' {
                $hint = ''; if ($ep.bug.hint) { $hint = ' - ' + $ep.bug.hint }
                $list += New-Finding 'ALERT' 'Crashes' ('Crash (BSOD) ' + $ep.bug.code + ' ' + $ep.bug.name + ' at ' + $when + $hint) $t 'crash'
            }
            'unclean' {
                $sev = 'WARN'; if ($age -le 7) { $sev = 'ALERT' }
                $list += New-Finding $sev 'Crashes' ('Unexpected restart at ' + $when + ' - Windows did not shut down cleanly (power loss, hard hang, reset or a crash that left no dump)') $t 'crash'
            }
            'powerbutton' { $list += New-Finding 'WARN' 'Crashes' ('Forced power-off with the power button at ' + $when + ' - usually means the PC had frozen') $t 'crash' }
            'unexplained' {
                $sev = 'INFO'; if ($age -le 7) { $sev = 'WARN' }
                $list += New-Finding $sev 'Crashes' ('Shutdown at ' + $when + ' with no restart request recorded - requester unknown') $t 'crash'
            }
        }
    }
    $bad30 = $c30['crash'] + $c30['unclean'] + $c30['powerbutton']
    if ($bad30 -ge 3) { $list += New-Finding 'ALERT' 'Crashes' ('' + $bad30 + ' crashes / unexpected restarts / forced power-offs in the last 30 days - recurring instability') $null 'crash' }
    $hs = 'INFO'
    if ([int]$Data.verdict.healthSev -ge 2) { $hs = 'ALERT' } elseif ([int]$Data.verdict.healthSev -eq 1) { $hs = 'WARN' }
    foreach ($h in @($Data.verdict.health)) { if ($h) { $list += New-Finding $hs 'Crash history' ([string]$h) $null 'crash' } }
    foreach ($p in @($Data.patterns)) { if ($p) { $list += New-Finding 'INFO' 'Crash pattern' ([string]$p) $null 'crash' } }
    if ($Data.dumpCap -and $Data.dumpCap.status -and $Data.dumpCap.status -ne 'OK' -and $Data.dumpCap.status -ne 'UNKNOWN') {
        $list += New-Finding 'WARN' 'Crash dumps' ('Crash dump capture ' + $Data.dumpCap.status + ': ' + (@($Data.dumpCap.reasons) -join '; ') + ' - the next crash may leave no dump') $null 'crash'
    }
    if ($Data.health -and [int]$Data.health.appCrashes -gt 0) {
        $top = @($Data.health.topApps | Select-Object -First 3) -join ', '
        $list += New-Finding 'INFO' 'App crashes' ('' + $Data.health.appCrashes + ' application crashes in ' + $Data.health.days + ' days' + $(if ($top) { ' (top: ' + $top + ')' } else { '' }) + ' - informational, not system crashes') $null 'crash'
    }
    $script:Findings['crash'] = $list
    $st = Get-WorstSev (@([string]$Data.verdict.status) + @($list | Where-Object { $_.Sev -ne 'INFO' } | ForEach-Object { $_.Sev }))
    $script:ModState['crash'] = @{ Status = $st; Summary = [string]$Data.verdict.headline; Secs = $null }
    $script:CrashCounts = @{ c7 = $c7; c30 = $c30 }
    Update-StallCorrelation

    # Grid
    $grid = $script:GridEp
    $grid.Rows.Clear()
    foreach ($ep in $eps) {
        $t = Get-EpisodeTime $ep
        $cls = Get-EpisodeClass $ep
        $info = $script:EpClass[$cls]
        $bug = ''; if ($ep.bug) { $bug = [string]$ep.bug.code }
        $idx = $grid.Rows.Add(@([string]$ep.id, (Format-When $t), (Format-Ago $t $ref), $info.Label, (Get-EpisodeCause $ep), (Format-Span $ep.downtimeSec), $bug))
        $row = $grid.Rows[$idx]
        $row.Tag = $ep
        if ($cls -ne 'controlled' -and $cls -ne 'unknown' -and $t -and ($ref - $t).TotalDays -le 30) {
            $row.DefaultCellStyle.BackColor = $info.Back
            $row.DefaultCellStyle.ForeColor = $info.Fore
        }
    }
    $fmt = {
        param($h)
        ('' + $h['crash'] + ' crash' + $(if ($h['crash'] -ne 1) { 'es' } else { '' }) + ', ' + $h['unclean'] + ' unexpected, ' + $h['powerbutton'] + ' forced off, ' +
         ($h['unexplained']) + ' unexplained, ' + $h['controlled'] + ' requested')
    }
    $script:LblCrashCounts.Text = 'Last 7 days: ' + (& $fmt $c7) + '     |     Last 30 days: ' + (& $fmt $c30)
    $script:LblCrashHead.Text = 'Verdict: ' + [string]$Data.verdict.status + ' - ' + [string]$Data.verdict.headline
    Update-Calendar
    if ($grid.Rows.Count -gt 0) { $grid.CurrentCell = $grid.Rows[0].Cells[1]; Show-EpisodeDetail $grid.Rows[0].Tag }
    $script:BtnHtml.Enabled = $true
}

function Show-EpisodeDetail {
    param($Ep)
    if (-not $Ep) { Set-PaneText $script:TxtEp ''; return }
    $nl = [Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    $add = { param($s) [void]$sb.Append($s + $nl) }
    $t = Get-EpisodeTime $Ep
    & $add ('#' + $Ep.id + '  ' + [string]$Ep.typeLabel + '   [confidence: ' + [string]$Ep.typeConf + ']' + $(if ($Ep.unexplained) { '   UNEXPLAINED' } else { '' }))
    & $add ('Went down: ' + (Format-When $t) + ' (' + (Format-Ago $t $script:CrashRef) + ')' + $(if ($Ep.downSrc) { ' from ' + $Ep.downSrc } else { '' }) +
            '    Booted: ' + (Format-When (ConvertFrom-Iso ([string]$Ep.boot))) + $(if ($Ep.bootType -ne $null) { ' (boot type ' + $Ep.bootType + ')' } else { '' }) +
            '    Downtime: ' + (Format-Span $Ep.downtimeSec))
    if ($Ep.initiator) {
        $i = $Ep.initiator
        & $add ('Requested by: ' + [string]$i.process + ' on behalf of ' + [string]$i.user + ' (' + [string]$i.action + ')' + $(if ($i.code) { ', reason ' + $i.code + ' = ' + $i.decoded } else { '' }))
        if ($i.comment) { & $add ('  Comment: ' + $i.comment) }
        & $add ('Initiator: ' + [string]$i.label + ' [' + [string]$i.category + ', ' + [string]$i.conf + ']')
        if ($i.caveat) { & $add ('  Caveat: ' + $i.caveat) }
    }
    if ($Ep.bug) { & $add ('Bugcheck: ' + $Ep.bug.code + ' ' + $Ep.bug.name + ' (' + $Ep.bug.cat + ') - ' + $Ep.bug.hint + $(if ($Ep.bug.dump) { '  dump: ' + $Ep.bug.dump } else { '' })) }
    if ($Ep.kp41) { & $add ('Kernel-Power 41: bugcheck ' + $Ep.kp41.bugcheck + ', power button ' + $Ep.kp41.powerButton + ', long press ' + $Ep.kp41.longPress + ', during sleep ' + $Ep.kp41.sleep) }
    if ($Ep.kp109) { & $add ('Kernel-Power 109: ' + $Ep.kp109.action + ' ' + $Ep.kp109.reason) }
    if ($script:ExtrasData -and $script:ExtrasData.storageStalls) {
        $ns = Get-StallsBefore $t 60
        & $add ('Storage controller stalls in the hour before: ' + $ns + $(if ($ns -gt 0) { '   <-- storage hang is a strong lead' } else { '' }))
    }
    if ($Ep.lastAlive) { & $add ('Last sign of life: ' + (Format-When (ConvertFrom-Iso ([string]$Ep.lastAlive.t))) + ' ' + $Ep.lastAlive.prov + ' ' + $Ep.lastAlive.id) }
    foreach ($d in @($Ep.dumpFail)) { if ($d) { & $add ('Dump write failed: ' + (Format-Any $d)) } }
    foreach ($d in @($Ep.dumps)) { if ($d) { & $add ('Matched dump: ' + (Format-Any $d)) } }
    foreach ($s in @($Ep.sessions)) { if ($s) { & $add ('Session: ' + (Format-Any $s)) } }
    $sections = @(@('ESTABLISHED', $Ep.established), @('NOT ESTABLISHED', $Ep.notEstablished), @('ASK THE CLIENT', $Ep.ask), @('NEXT STEPS', $Ep.next))
    foreach ($sec in $sections) {
        $items = @($sec[1] | Where-Object { $_ })
        if ($items.Count -gt 0) { & $add ''; & $add $sec[0]; foreach ($x in $items) { & $add ('  - ' + (Format-Any $x)) } }
    }
    $hyp = @($Ep.hyp | Where-Object { $_ })
    if ($hyp.Count -gt 0) {
        & $add ''; & $add 'EXPLANATIONS CHECKED'
        foreach ($h in $hyp) {
            & $add ('  ' + ([string]$h.status).ToUpper() + ' (' + [string]$h.conf + ')  ' + [string]$h.label)
            foreach ($x in @($h.for)) { if ($x) { & $add ('      + ' + $x) } }
            foreach ($x in @($h.against)) { if ($x) { & $add ('      - ' + $x) } }
            foreach ($x in @($h.gaps)) { if ($x) { & $add ('      ? ' + (Format-Any $x)) } }
        }
    }
    $seq = @($Ep.seq | Where-Object { $_ })
    if ($seq.Count -gt 0) {
        & $add ''; & $add 'EVENT SEQUENCE'
        foreach ($x in $seq) { & $add ('  ' + (Format-When (ConvertFrom-Iso ([string]$x.t))) + '  ' + [string]$x.ch + ' ' + [string]$x.id + '  ' + [string]$x.x) }
    }
    $corr = @($Ep.corr | Where-Object { $_ })
    if ($corr.Count -gt 0) {
        & $add ''; & $add 'NEARBY EVENTS (by time only - leads, not causes)'
        foreach ($x in $corr) { & $add ('  ' + (Format-When (ConvertFrom-Iso ([string]$x.t))) + '  ' + [string]$x.pos + '  ' + [string]$x.ch + ' ' + [string]$x.id + '  ' + [string]$x.x) }
    }
    Set-PaneText $script:TxtEp ($sb.ToString())
}

function Use-SsdResult {
    param([hashtable]$Res)
    $lines = @(([string]$Res.Out) -split "`r?`n")
    $verdict = $null; $flags = @(); $inFlags = $false
    foreach ($l in $lines) {
        if ($l -match '^\s*VERDICT:\s*(PASS|CONCERN|FAIL)') { $verdict = $Matches[1]; $inFlags = $true; continue }
        if ($inFlags) {
            if ($l -match '^\s+-\s+(.+)$') { $flags += $Matches[1].Trim() } else { $inFlags = $false }
        }
    }
    $script:SmartMissing = ([string]$Res.Out) -match 'smartmontools not installed'
    $list = @()
    if (-not $verdict) {
        $script:ModState['ssd'] = @{ Status = 'ERROR'; Summary = (Get-FailureSummary $Res); Secs = $Res.Secs }
        $list += New-Finding 'WARN' 'Storage' ('Storage check produced no verdict: ' + (Get-FailureSummary $Res)) $null 'ssd'
    } else {
        $sev = 'OK'
        if ($verdict -eq 'FAIL') { $sev = 'ALERT' } elseif ($verdict -eq 'CONCERN') { $sev = 'WARN' }
        if ($sev -ne 'OK') { foreach ($f in $flags) { $list += New-Finding $sev 'Storage' $f $null 'ssd' } }
        $sum = 'Drive health ' + $verdict
        if ($sev -ne 'OK' -and $flags.Count -gt 0) { $sum += ': ' + $flags[0] }
        $script:ModState['ssd'] = @{ Status = $sev; Summary = $sum; Secs = $Res.Secs }
    }
    if ($script:SmartMissing) {
        $list += New-Finding 'INFO' 'Storage' 'SMART attributes not read - smartmontools is not installed (Storage tab: Install smartmontools and re-run).' $null 'ssd'
    }
    $script:Findings['ssd'] = $list
    $script:LblSsd.Text = $script:ModState['ssd'].Summary + $(if ($script:SmartMissing) { '   (SMART not read: smartmontools not installed)' } else { '' })
    $script:BtnSmart.Enabled = $true
    Set-PaneText $script:TxtSsd ($script:RawOut['ssd'])
}

function Use-ExtrasResult {
    param([hashtable]$Res)
    $out = [string]$Res.Out
    $b = $out.IndexOf('===HEALTHX_JSON_BEGIN===')
    $e = $out.IndexOf('===HEALTHX_JSON_END===')
    Set-PaneText $script:TxtExtras ($(if ($b -gt 0) { $out.Substring(0, $b) } else { $out }) + $(if ($Res.Err) { [Environment]::NewLine + [string]$Res.Err } else { '' }))
    if ($b -lt 0 -or $e -lt $b) {
        $script:ModState['extras'] = @{ Status = 'ERROR'; Summary = (Get-FailureSummary $Res); Secs = $Res.Secs }
        $script:Findings['extras'] = @(New-Finding 'WARN' 'System health' ('System health check produced no result: ' + (Get-FailureSummary $Res)) $null 'extras')
        return
    }
    $jsonText = $out.Substring($b + 24, $e - $b - 24).Trim()
    $obj = $jsonText | ConvertFrom-Json
    Set-ExtrasData $obj
}

function Set-ExtrasData {
    param($Data)
    $script:ExtrasData = $Data
    $list = @()
    foreach ($f in @($Data.findings)) {
        if (-not $f) { continue }
        $list += New-Finding ([string]$f.sev) ([string]$f.area) ([string]$f.text) (ConvertFrom-Iso ([string]$f.t)) 'extras'
    }
    $script:Findings['extras'] = $list
    $script:ModState['extras'] = @{ Status = [string]$Data.status; Summary = [string]$Data.headline; Secs = $null }
    # System health grid
    $g = $script:GridHealth
    $g.Rows.Clear()
    foreach ($f in @($list | Sort-Object @{ e = { $script:SevRank[$_.Sev] }; Descending = $true }, Area)) {
        $idx = $g.Rows.Add(@($f.Sev, $f.Area, (Format-When $f.When), $f.Text))
        Set-SevRowColor $g.Rows[$idx] $f.Sev
    }
    $script:LblExtras.Text = 'System health: ' + [string]$Data.status + ' - ' + [string]$Data.headline
    Update-StallCorrelation
    Update-Calendar
    # Volumes grid
    $v = $script:GridVol
    $v.Rows.Clear()
    foreach ($d in @($Data.disks)) {
        if (-not $d) { continue }
        $lvl = [string]$d.level
        $idx = $v.Rows.Add(@(([string]$d.drive + $(if ($d.system) { ' (system)' } else { '' })), [string]$d.label, [string]$d.fs, ('' + $d.sizeGB + ' GB'), ('' + $d.freeGB + ' GB'), ('' + $d.freePct + ' %'), $lvl))
        Set-SevRowColor $v.Rows[$idx] $lvl
    }
}

function Use-VerdictResult {
    param([string]$Name, [hashtable]$Res, [string]$Marker, [string]$Area)
    $out = [string]$Res.Out
    $txt = $script:RawOut[$Name]
    if ($Name -eq 'thermal') { Set-PaneText $script:TxtThermal $txt } else { Set-PaneText $script:TxtLag $txt }
    $tag = $null; $status = ''; $assess = ''
    if ($out -match ($Marker + ':\s*\[(\w+)\]\s*([^\r\n]+)')) { $tag = $Matches[1].ToUpper(); $status = $Matches[2].Trim() }
    if ($out -match 'Assessment\s*:\s*([^\r\n]+)') { $assess = $Matches[1].Trim() }
    $list = @()
    if (-not $tag) {
        $script:ModState[$Name] = @{ Status = 'ERROR'; Summary = (Get-FailureSummary $Res); Secs = $Res.Secs }
        $list += New-Finding 'WARN' $Area ($script:ModTitles[$Name] + ' check produced no verdict: ' + (Get-FailureSummary $Res)) $null $Name
    } else {
        $sev = 'OK'
        if ($tag -eq 'ALERT') { $sev = 'ALERT' } elseif ($tag -eq 'WARN') { $sev = 'WARN' }
        if ($sev -ne 'OK' -and $assess) { foreach ($a in ($assess -split ';\s*')) { if ($a.Trim()) { $list += New-Finding $sev $Area $a.Trim() $null $Name } } }
        $script:ModState[$Name] = @{ Status = $sev; Summary = ($status + $(if ($assess) { ' - ' + $assess } else { '' })); Secs = $Res.Secs }
    }
    $script:Findings[$Name] = $list
    $lbl = $script:LblLag; if ($Name -eq 'thermal') { $lbl = $script:LblThermal }
    $lbl.Text = $script:ModTitles[$Name] + ': ' + $script:ModState[$Name].Status + ' - ' + $script:ModState[$Name].Summary
}

function Use-DismResult {
    param([hashtable]$Res)
    $nl = [Environment]::NewLine
    $script:TxtExtras.AppendText($nl + $nl + '===== DISM /Online /Cleanup-Image /CheckHealth (exit ' + $Res.Exit + ', ' + $Res.Secs + ' s) =====' + $nl + ([string]$Res.Out).Trim() + $nl + ([string]$Res.Err).Trim() + $nl)
    $script:RawOut['dism'] = [string]$Res.Out
    $msg = 'DISM finished (exit ' + $Res.Exit + ').'
    if ([string]$Res.Out -match 'repairable') { $msg = 'DISM: component store corruption found and is repairable - run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow.' }
    elseif ([string]$Res.Out -match 'No component store corruption detected') { $msg = 'DISM: no component store corruption detected.' }
    $script:LblExtras.Text = $msg
}

# -----------------------------------------------------------------------------
# UI updates
# -----------------------------------------------------------------------------
function Set-SevRowColor {
    param($Row, [string]$Sev)
    $bg = $null
    switch ($Sev) {
        'ALERT' { $bg = [System.Drawing.Color]::FromArgb(248, 215, 218) }
        'WARN'  { $bg = [System.Drawing.Color]::FromArgb(255, 243, 205) }
        'ERROR' { $bg = [System.Drawing.Color]::FromArgb(230, 230, 230) }
        'INFO'  { $bg = [System.Drawing.Color]::FromArgb(236, 243, 254) }
    }
    if ($bg) { $Row.DefaultCellStyle.BackColor = $bg }
}

function Get-AllFindings {
    $all = @()
    foreach ($k in $script:Findings.Keys) { $all += @($script:Findings[$k]) }
    return @($all | Where-Object { $_ } | Sort-Object @{ e = { $script:SevRank[$_.Sev] }; Descending = $true }, @{ e = { if ($_.When) { $_.When } else { [datetime]::MinValue } }; Descending = $true })
}

function Get-OverallStatus {
    $sts = @()
    foreach ($k in $script:ModState.Keys) { $sts += [string]$script:ModState[$k].Status }
    if ($sts.Count -eq 0) { return 'NOT RUN' }
    $w = Get-WorstSev @($sts | Where-Object { $_ -ne 'RUNNING' -and $_ -ne 'N/A' -and $_ -ne 'ERROR' })
    if ($w -eq 'INFO') { $w = 'OK' }
    if ($w -eq 'OK' -and ($sts -contains 'ERROR')) { return 'INCOMPLETE' }
    return $w
}

function Update-Overview {
    $g = $script:GridFind
    $g.Rows.Clear()
    foreach ($f in (Get-AllFindings)) {
        $when = ''; if ($f.When) { $when = (Format-When $f.When) + '  (' + (Format-Ago $f.When (Get-Date)) + ')' }
        $idx = $g.Rows.Add(@($f.Sev, $f.Area, $when, $f.Text))
        $g.Rows[$idx].Tag = $f.Source
        Set-SevRowColor $g.Rows[$idx] $f.Sev
    }
    $st = Get-OverallStatus
    $busy = $script:Sync -and -not $script:Sync.Done
    $script:LblBadge.Text = $(if ($busy) { 'RUNNING...' } else { $st })
    $col = [System.Drawing.Color]::FromArgb(108, 117, 125)
    if (-not $busy) {
        switch ($st) {
            'ALERT'      { $col = [System.Drawing.Color]::FromArgb(198, 40, 40) }
            'WARN'       { $col = [System.Drawing.Color]::FromArgb(230, 126, 0) }
            'OK'         { $col = [System.Drawing.Color]::FromArgb(46, 125, 50) }
            'INCOMPLETE' { $col = [System.Drawing.Color]::FromArgb(120, 120, 120) }
        }
    }
    $script:LblBadge.BackColor = $col
}

function Update-ModuleLabels {
    $parts = @()
    foreach ($m in $script:ModOrder) {
        if (-not $script:ModState.ContainsKey($m)) { continue }
        $s = $script:ModState[$m]
        $parts += ($script:ModTitles[$m] + ': ' + $s.Status + $(if ($s.Secs) { ' (' + $s.Secs + ' s)' } else { '' }))
    }
    $script:LblModules.Text = $(if ($parts.Count) { $parts -join '    ' } else { 'Press Run all checks to start.' })
}

function Get-StallDays {
    # yyyy-MM-dd -> stall summary row from the extras script (empty until it has run)
    $map = @{}
    if ($script:ExtrasData -and $script:ExtrasData.storageStalls) {
        foreach ($d in @($script:ExtrasData.storageStalls.byDay)) { if ($d) { $map[[string]$d.d] = $d } }
    }
    return $map
}

function Get-StallsBefore {
    # Controller stalls in the $Minutes before (and the minute after) a transition time
    param($T, [int]$Minutes = 60)
    if (-not $T -or -not $script:ExtrasData -or -not $script:ExtrasData.storageStalls) { return 0 }
    $from = $T.AddMinutes(-$Minutes); $to = $T.AddMinutes(1)
    $n = 0
    foreach ($s in @($script:ExtrasData.storageStalls.times)) {
        if (-not $s -or -not $s.c) { continue }
        $st = ConvertFrom-Iso ([string]$s.t)
        if ($st -and $st -ge $from -and $st -le $to) { $n++ }
    }
    return $n
}

function Update-StallCorrelation {
    # A run of storage stalls just before a crash / unexpected restart / forced power-off is a strong lead
    $list = @()
    if ($script:CrashData -and $script:ExtrasData) {
        foreach ($ep in @($script:CrashEpisodes)) {
            $cls = Get-EpisodeClass $ep
            if ($cls -ne 'crash' -and $cls -ne 'unclean' -and $cls -ne 'powerbutton') { continue }
            $t = Get-EpisodeTime $ep
            if (-not $t -or ($script:CrashRef - $t).TotalDays -gt 30) { continue }
            $n = Get-StallsBefore $t 60
            if ($n -gt 0) {
                $what = @{ crash = 'crash'; unclean = 'unexpected restart'; powerbutton = 'forced power-off' }[$cls]
                $list += New-Finding 'WARN' 'Crash + storage' ('' + $n + ' storage controller stall(s) in the hour before the ' + $what + ' at ' + (Format-When $t) + ' - a storage hang is a strong lead (timing only, not proof)') $t 'crash'
            }
        }
    }
    $script:Findings['corr'] = $list
}

function Update-Calendar {
    $ref = $script:CrashRef
    $stallDays = Get-StallDays
    $byDay = @{}
    foreach ($ep in @($script:CrashEpisodes)) {
        $t = Get-EpisodeTime $ep
        if (-not $t) { continue }
        $key = $t.ToString('yyyy-MM-dd', $script:Inv)
        if (-not $byDay.ContainsKey($key)) { $byDay[$key] = New-Object System.Collections.ArrayList }
        [void]$byDay[$key].Add($ep)
    }
    for ($i = 0; $i -lt 30; $i++) {
        $day = $ref.Date.AddDays($i - 29)
        $key = $day.ToString('yyyy-MM-dd', $script:Inv)
        $cell = $script:CalCells[$i]
        $worst = 'none'
        $tip = $day.ToString('ddd d MMM yyyy', $script:Inv)
        if ($byDay.ContainsKey($key)) {
            foreach ($ep in $byDay[$key]) {
                $cls = Get-EpisodeClass $ep
                if ($script:EpClass[$cls].Rank -gt $script:EpClass[$worst].Rank) { $worst = $cls }
                $tip += [Environment]::NewLine + (Get-EpisodeTime $ep).ToString('HH:mm', $script:Inv) + '  ' + $script:EpClass[$cls].Label
            }
        } else { $tip += [Environment]::NewLine + 'no restarts or shutdowns recorded' }
        $bar = $script:CalStall[$i]
        $bar.BackColor = [System.Drawing.Color]::White
        if ($stallDays.ContainsKey($key)) {
            $sd = $stallDays[$key]
            $tip += [Environment]::NewLine + 'Storage stalls: ' + $sd.n + ' (' + $sd.ctrl + ' controller, ' + $sd.retry + ' I/O retries)'
            $bar.BackColor = $(if ([int]$sd.ctrl -gt 0) { $script:StallColor } else { $script:RetryColor })
        }
        $info = $script:EpClass[$worst]
        $cell.BackColor = $info.Back
        $cell.ForeColor = $info.Fore
        $cell.Text = '' + $day.Day
        $cell.Tag = $key
        $script:Tip.SetToolTip($cell, $tip)
        $script:Tip.SetToolTip($bar, $tip)
    }
    $script:LblCalRange.Text = $ref.Date.AddDays(-29).ToString('d MMM', $script:Inv) + '  ->  ' + $ref.ToString('d MMM yyyy', $script:Inv) + '   (click a day to see its restarts)'
}

function Select-CrashDay {
    param([string]$Key)
    foreach ($row in $script:GridEp.Rows) {
        $t = Get-EpisodeTime $row.Tag
        if ($t -and $t.ToString('yyyy-MM-dd', $script:Inv) -eq $Key) {
            $script:Tabs.SelectedTab = $script:TabCrash
            $script:GridEp.CurrentCell = $row.Cells[1]
            Show-EpisodeDetail $row.Tag
            return $true
        }
    }
    # No restart that day: a stall-only day opens the storage-stall finding instead
    if ((Get-StallDays).ContainsKey($Key)) {
        $script:Tabs.SelectedTab = $script:TabHealth
        foreach ($row in $script:GridHealth.Rows) {
            if ([string]$row.Cells[1].Value -eq 'Storage stalls') { $script:GridHealth.CurrentCell = $row.Cells[3]; break }
        }
        return $true
    }
    $script:Tabs.SelectedTab = $script:TabCrash
    return $false
}

function Update-RawText {
    $nl = [Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    foreach ($m in $script:ModOrder) {
        if (-not $script:RawOut.ContainsKey($m)) { continue }
        [void]$sb.Append(('#' * 100) + $nl + '# ' + $script:ModTitles[$m] + $nl + ('#' * 100) + $nl + $script:RawOut[$m] + $nl + $nl)
    }
    Set-PaneText $script:TxtRaw ($sb.ToString())
}

function Set-Busy {
    param([bool]$Busy)
    foreach ($b in $script:BusyButtons) { $b.Enabled = -not $Busy }
    $script:BtnStop.Enabled = $Busy
    $script:Progress.Visible = $Busy
    if (-not $Busy) { $script:BtnHtml.Enabled = [bool]$script:CrashRaw; $script:BtnSmart.Enabled = $true }
}

function Invoke-TimerTick {
    $sync = $script:Sync
    if (-not $sync) { $script:Timer.Stop(); return }
    $keys = @()
    try { $keys = @($sync.Results.Keys) } catch { }
    foreach ($k in $keys) {
        if ($script:Applied.ContainsKey($k)) { continue }
        $script:Applied[$k] = $true
        Use-Result $k $sync.Results[$k]
    }
    $run = @()
    try { foreach ($k in @($sync.Running.Keys)) { $run += ($script:ModTitles[$k] + ' ' + [math]::Round(([DateTime]::Now - $sync.Running[$k]).TotalSeconds) + ' s') } } catch { }
    $elapsed = [math]::Round(([DateTime]::Now - $sync.Started).TotalSeconds)
    if ($sync.Done) {
        $script:Timer.Stop()
        try { $script:PsInst.EndInvoke($script:Handle) | Out-Null } catch { }
        try { $script:PsInst.Runspace.Dispose(); $script:PsInst.Dispose() } catch { }
        $script:Sync = $null
        Set-Busy $false
        if ($script:JobKind -eq 'zip') { Show-ZipResult $sync.ZipResult $sync.WorkerError }
        elseif ($sync.WorkerError) { $script:LblStatus.Text = 'Worker error: ' + $sync.WorkerError }
        else { $script:LblStatus.Text = 'Finished in ' + $elapsed + ' s. Reports and raw output: ' + $script:WorkDir }
        Update-Overview
        return
    }
    if ($script:JobKind -eq 'zip') { $script:LblStatus.Text = [string]$sync.Progress }
    elseif ($run.Count) { $script:LblStatus.Text = 'Running (' + $elapsed + ' s): ' + ($run -join ', ') }
}

# -----------------------------------------------------------------------------
# Report text, save, HTML viewer
# -----------------------------------------------------------------------------
function Get-ReportText {
    $nl = [Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    $add = { param($s) [void]$sb.Append($s + $nl) }
    & $add ('PC HEALTH & CRASH REPORT - ' + $script:HostName + ' - ' + (Format-When (Get-Date)))
    & $add ($script:SysInfo.model + ' | ' + $script:SysInfo.os + ' | up ' + $script:SysInfo.uptime + ' | run as ' + $script:RunAs)
    $mods = @()
    foreach ($m in $script:ModOrder) { if ($script:ModState.ContainsKey($m)) { $mods += ($script:ModTitles[$m] + ' ' + $script:ModState[$m].Status) } }
    & $add ('OVERALL: ' + (Get-OverallStatus) + '   (' + ($mods -join ', ') + ')')
    & $add ''
    & $add 'CRASHES AND UNEXPECTED RESTARTS - LAST 30 DAYS'
    if ($script:CrashData) {
        $ref = $script:CrashRef
        $map = ''
        for ($i = 0; $i -lt 30; $i++) {
            $day = $ref.Date.AddDays($i - 29); $worst = 'none'
            foreach ($ep in @($script:CrashEpisodes)) {
                $t = Get-EpisodeTime $ep
                if ($t -and $t.Date -eq $day) { $cls = Get-EpisodeClass $ep; if ($script:EpClass[$cls].Rank -gt $script:EpClass[$worst].Rank) { $worst = $cls } }
            }
            $map += $script:EpClass[$worst].Char
        }
        & $add ('  Day map ' + $ref.Date.AddDays(-29).ToString('dd MMM', $script:Inv) + ' [' + $map + '] ' + $ref.ToString('dd MMM', $script:Inv) + '   X crash  U unexpected  F forced off  ? unexplained  r requested  - no evidence')
        $stallDays = Get-StallDays
        if ($stallDays.Count -gt 0) {
            $smap = ''
            for ($i = 0; $i -lt 30; $i++) {
                $k = $ref.Date.AddDays($i - 29).ToString('yyyy-MM-dd', $script:Inv)
                if ($stallDays.ContainsKey($k)) { $n = [int]$stallDays[$k].n; $smap += $(if ($n -gt 9) { '+' } else { '' + $n }) } else { $smap += '.' }
            }
            $pre = '  Day map ' + $ref.Date.AddDays(-29).ToString('dd MMM', $script:Inv) + ' '
            & $add (('  Storage stalls').PadRight($pre.Length) + '[' + $smap + ']   stalls per day (+ = 10 or more)')
        }
        & $add ('  ' + $script:LblCrashCounts.Text)
        $routine = 0
        foreach ($ep in @($script:CrashEpisodes)) {
            $t = Get-EpisodeTime $ep
            if (-not $t -or ($ref - $t).TotalDays -gt 30) { continue }
            $cls = Get-EpisodeClass $ep
            if ($cls -eq 'controlled') { $routine++; continue }
            & $add ('  ' + (Format-When $t) + ' (' + (Format-Ago $t $ref) + ')  ' + $script:EpClass[$cls].Label + $(if ((Get-EpisodeCause $ep)) { ' - ' + (Get-EpisodeCause $ep) } else { '' }))
        }
        & $add ('  (' + $routine + ' requested restarts/shutdowns not listed)')
        & $add ('  Crash tool verdict: ' + [string]$script:CrashData.verdict.status + ' - ' + [string]$script:CrashData.verdict.headline)
    } else { & $add '  (crash diagnostic not run or no result)' }
    & $add ''
    & $add 'FINDINGS'
    $all = @(Get-AllFindings | Where-Object { $_.Sev -ne 'OK' })
    if ($all.Count -eq 0) { & $add '  none' }
    foreach ($f in $all) { & $add ('  [' + $f.Sev + '] ' + $f.Area + ': ' + $f.Text) }
    & $add ''
    & $add 'CHECKS'
    foreach ($m in $script:ModOrder) {
        if (-not $script:ModState.ContainsKey($m)) { continue }
        $s = $script:ModState[$m]
        & $add ('  ' + $script:ModTitles[$m] + ': ' + $s.Status + ' - ' + $s.Summary + $(if ($s.Secs) { ' (' + $s.Secs + ' s)' } else { '' }))
    }
    if ($script:ElevateNote) { & $add ('  NOTE: ' + $script:ElevateNote) }
    & $add ('  Output folder: ' + $script:WorkDir)
    return $sb.ToString()
}

function Copy-Report {
    $text = Get-ReportText
    try {
        [System.Windows.Forms.Clipboard]::SetText($text)
        $script:LblStatus.Text = 'Report copied to the clipboard (' + $text.Length + ' characters). In Backstage the clipboard may not reach your PC - use Save report.'
        return $true
    } catch {
        $script:LblStatus.Text = 'Clipboard unavailable (' + $_.Exception.Message + ') - use Save report.'
        return $false
    }
}

function Save-Report {
    param([switch]$Quiet)
    $nl = [Environment]::NewLine
    $text = Get-ReportText
    $text += $nl + $nl + ('=' * 100) + $nl + 'FULL OUTPUT OF EACH CHECK' + $nl + ('=' * 100) + $nl + $script:TxtRaw.Text
    if (-not (Test-Path -LiteralPath $script:OutRoot)) { New-Item -ItemType Directory -Path $script:OutRoot -Force | Out-Null }
    $path = Join-Path $script:OutRoot ('PCHealth_' + $script:HostName + '_' + (Get-Date).ToString('yyyyMMdd_HHmm', $script:Inv) + '.txt')
    Write-AsciiFile $path $text
    $script:LblStatus.Text = 'Report saved: ' + $path
    if (-not $Quiet) {
        $r = [System.Windows.Forms.MessageBox]::Show('Saved to' + $nl + $path + $nl + $nl + 'Open it in Notepad?', 'Save report', 'YesNo', 'Information')
        if ($r -eq 'Yes') { Start-Process notepad.exe -ArgumentList ('"' + $path + '"') }
    }
    return $path
}

function New-ViewerHtml {
    param([string]$Path)
    $viewer = Find-Sibling $script:FileNames.viewer
    if (-not $viewer) { throw ($script:FileNames.viewer + ' not found beside the toolkit') }
    if (-not $script:CrashRaw) { throw 'No crash diagnostic result yet' }
    $html = [System.IO.File]::ReadAllText($viewer)
    $open = '<script type="application/json" id="saved-data">'
    $a = $html.IndexOf($open)
    if ($a -lt 0) { throw 'Viewer has no saved-data block' }
    $z = $html.IndexOf('</script>', $a)
    $payload = '{"savedAt":"' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Inv) + '","payloads":[' + $script:CrashRaw.Trim() + ']}'
    # Escaping "<" keeps the JSON from closing its script tag
    $payload = $payload.Replace('<', '\u003c')
    $html = $html.Substring(0, $a + $open.Length) + $payload + $html.Substring($z)
    $dOpen = '<script type="application/json" id="demo-data">'
    $d = $html.IndexOf($dOpen)
    if ($d -ge 0) { $dz = $html.IndexOf('</script>', $d); $html = $html.Substring(0, $d + $dOpen.Length) + '[]' + $html.Substring($dz) }
    # First <title> only: the viewer's own script contains '<title>...</title>' strings too
    $html = ([regex]'<title>[^<]*</title>').Replace($html, ('<title>Crash incident - ' + $script:HostName + '</title>'), 1)
    Write-AsciiFile $Path $html
    return $Path
}

function Open-HtmlReport {
    try {
        if (-not (Test-Path -LiteralPath $script:OutRoot)) { New-Item -ItemType Directory -Path $script:OutRoot -Force | Out-Null }
        $path = Join-Path $script:OutRoot ('CrashIncident_' + $script:HostName + '_' + (Get-Date).ToString('yyyyMMdd_HHmm', $script:Inv) + '.html')
        New-ViewerHtml $path | Out-Null
        $script:LblStatus.Text = 'HTML report written: ' + $path
        Start-Process -FilePath $path
    } catch { [System.Windows.Forms.MessageBox]::Show('Could not create the HTML report: ' + $_.Exception.Message, 'HTML report', 'OK', 'Warning') | Out-Null }
}

# -----------------------------------------------------------------------------
# Collect logs
# -----------------------------------------------------------------------------
function Get-FilesSafe {
    param([string]$Path, [string]$Filter = '*', [switch]$Recurse)
    if (-not $Path -or -not [System.IO.Directory]::Exists($Path)) { return @() }
    try {
        if ($Recurse) { return @(Get-ChildItem -LiteralPath $Path -Filter $Filter -File -Recurse -Force -ErrorAction Ignore) }
        return @(Get-ChildItem -LiteralPath $Path -Filter $Filter -File -Force -ErrorAction Ignore)
    } catch { return @() }
}

function Get-LogInventory {
    $items = @()
    $win = $env:SystemRoot
    $miniDir = Join-Path $win 'Minidump'
    $fullDump = Join-Path $win 'MEMORY.DMP'
    try {
        $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
        if ($cc.MinidumpDir) { $miniDir = [Environment]::ExpandEnvironmentVariables([string]$cc.MinidumpDir) }
        if ($cc.DumpFile) { $fullDump = [Environment]::ExpandEnvironmentVariables([string]$cc.DumpFile) }
    } catch { }
    $items += [pscustomobject]@{ Key = 'Minidump'; Name = 'Kernel minidumps (BSOD)'; Kind = 'files'; Location = $miniDir; Files = @(Get-FilesSafe $miniDir '*.dmp'); Default = $true; Note = '' }
    $items += [pscustomobject]@{ Key = 'LiveKernelReports'; Name = 'Live kernel reports (GPU/USB/watchdog resets)'; Kind = 'files'; Location = (Join-Path $win 'LiveKernelReports'); Files = @(Get-FilesSafe (Join-Path $win 'LiveKernelReports') '*.dmp' -Recurse); Default = $true; Note = '' }
    $user = @()
    $profRoot = Join-Path $env:SystemDrive 'Users'
    foreach ($p in @(Get-ChildItem -LiteralPath $profRoot -Directory -Force -ErrorAction Ignore)) {
        $user += @(Get-FilesSafe (Join-Path $p.FullName 'AppData\Local\CrashDumps') '*.dmp')
    }
    $user += @(Get-FilesSafe (Join-Path $win 'System32\config\systemprofile\AppData\Local\CrashDumps') '*.dmp')
    $items += [pscustomobject]@{ Key = 'UserCrashDumps'; Name = 'Application crash dumps (all profiles)'; Kind = 'files'; Location = ($profRoot + '\*\AppData\Local\CrashDumps'); Files = $user; Default = $true; Note = '' }
    $werRoot = Join-Path $env:ProgramData 'Microsoft\Windows\WER'
    $wer = @(Get-FilesSafe (Join-Path $werRoot 'ReportArchive') '*' -Recurse) + @(Get-FilesSafe (Join-Path $werRoot 'ReportQueue') '*' -Recurse)
    $items += [pscustomobject]@{ Key = 'WER'; Name = 'Windows Error Reporting reports'; Kind = 'files'; Location = $werRoot; Files = $wer; Default = $true; Note = '' }
    $items += [pscustomobject]@{ Key = 'EventLogs'; Name = 'Event logs: System, Application, Setup'; Kind = 'events'; Location = 'exported with wevtutil'; Files = @(); Default = $true; Note = 'last N days' }
    $mem = @(); if (Test-Path -LiteralPath $fullDump) { $mem = @(Get-Item -LiteralPath $fullDump -Force -ErrorAction SilentlyContinue) }
    $items += [pscustomobject]@{ Key = 'MemoryDmp'; Name = 'Full kernel dump MEMORY.DMP'; Kind = 'raw'; Location = $fullDump; Files = $mem; Default = $false; Note = 'copied raw beside the zip' }
    $items += [pscustomobject]@{ Key = 'Reports'; Name = 'This toolkit''s reports and raw output'; Kind = 'reports'; Location = $script:WorkDir; Files = @(); Default = $true; Note = 'written when zipping' }
    if (-not $script:IsAdmin) {
        foreach ($it in $items) { if ($it.Key -eq 'Minidump' -or $it.Key -eq 'LiveKernelReports' -or $it.Key -eq 'MemoryDmp' -or $it.Key -eq 'WER') { $it.Note = 'needs elevation to read' } }
    }
    return $items
}

function Update-LogGrid {
    $script:LogItems = @(Get-LogInventory)
    $g = $script:GridLogs
    $g.Rows.Clear()
    $cut = (Get-Date).AddDays(-30)
    foreach ($it in $script:LogItems) {
        $files = @($it.Files)
        $recent = @($files | Where-Object { $_.LastWriteTime -ge $cut })
        $bytes = [double]0; foreach ($f in $files) { $bytes += $f.Length }
        $newest = ''
        if ($files.Count) { $newest = Format-When (($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime) }
        $count = ''
        if ($it.Kind -eq 'files' -or $it.Kind -eq 'raw') { $count = '' + $files.Count + ' (' + $recent.Count + ' in 30 d)' }
        $size = ''; if ($files.Count) { $size = Format-Size $bytes }
        $check = [bool]$it.Default
        if (($it.Kind -eq 'files' -or $it.Kind -eq 'raw') -and $files.Count -eq 0) { $check = $false }
        $idx = $g.Rows.Add(@($check, $it.Name, $count, $size, $newest, $it.Location, $it.Note))
        $g.Rows[$idx].Tag = $it
        if (($it.Kind -eq 'files' -or $it.Kind -eq 'raw') -and $files.Count -eq 0) { $g.Rows[$idx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Gray }
    }
}

function Set-LogChecks {
    param([bool]$Value)
    foreach ($row in $script:GridLogs.Rows) { $row.Cells[0].Value = $Value }
    $script:GridLogs.RefreshEdit() | Out-Null
}

function Start-ZipLogs {
    param([string]$OutDir = $script:OutRoot)
    if ($script:Sync -and -not $script:Sync.Done) { return }
    [void]$script:GridLogs.EndEdit()
    $recentOnly = $script:ChkRecent.Checked
    $days = [int]$script:NumDays.Value
    $cut = (Get-Date).AddDays(-30)
    $files = New-Object System.Collections.ArrayList
    $raw = @(); $logs = @()
    foreach ($row in $script:GridLogs.Rows) {
        if (-not [bool]$row.Cells[0].Value) { continue }
        $it = $row.Tag
        switch ($it.Kind) {
            'files' {
                foreach ($f in @($it.Files)) {
                    if ($recentOnly -and $f.LastWriteTime -lt $cut) { continue }
                    $entry = $it.Key + '/' + $f.Name
                    if ($it.Key -eq 'UserCrashDumps' -and $f.FullName -match '\\Users\\([^\\]+)\\') { $entry = $it.Key + '/' + $Matches[1] + '/' + $f.Name }
                    elseif ($it.Key -eq 'WER' -or $it.Key -eq 'LiveKernelReports') {
                        $rel = $f.FullName.Substring($it.Location.Length).TrimStart('\')
                        $entry = $it.Key + '/' + ($rel -replace '\\', '/')
                    }
                    [void]$files.Add(@{ Src = $f.FullName; Entry = $entry })
                }
            }
            'raw' { foreach ($f in @($it.Files)) { $raw += $f.FullName } }
            'events' { $logs = @('System', 'Application', 'Setup') }
            'reports' {
                $rp = Join-Path $script:WorkDir 'PCHealth_Report.txt'
                try {
                    $nl = [Environment]::NewLine
                    Write-AsciiFile $rp ((Get-ReportText) + $nl + $nl + $script:TxtRaw.Text)
                    if ($script:CrashRaw) { New-ViewerHtml (Join-Path $script:WorkDir ('CrashIncident_' + $script:HostName + '.html')) | Out-Null }
                } catch { }
                foreach ($f in @(Get-FilesSafe $script:WorkDir '*' -Recurse)) {
                    if ($f.Name -like 'CPU_Thermal_*_NoLoadTest.ps1' -or $f.Extension -eq '.evtx') { continue }
                    $rel = $f.FullName.Substring($script:WorkDir.Length).TrimStart('\')
                    [void]$files.Add(@{ Src = $f.FullName; Entry = ('Reports/' + ($rel -replace '\\', '/')) })
                }
            }
        }
    }
    if ($files.Count -eq 0 -and $raw.Count -eq 0 -and $logs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Nothing selected (or the selected items have no files).', 'Zip crash logs', 'OK', 'Information') | Out-Null
        return
    }
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $tmp = Join-Path $script:WorkDir 'evtx'
    if (-not (Test-Path -LiteralPath $tmp)) { New-Item -ItemType Directory -Path $tmp -Force | Out-Null }
    $zipPath = Join-Path $OutDir ('CrashLogs_' + $script:HostName + '_' + (Get-Date).ToString('yyyyMMdd_HHmmss', $script:Inv) + '.zip')
    $script:LblZip.Text = 'Zipping...'
    Start-Worker @{ Kind = 'zip'; Files = @($files); RawFiles = $raw; EventLogs = $logs; Days = $days; ZipPath = $zipPath; OutDir = $OutDir; TempDir = $tmp; HostName = $script:HostName; Stamp = (Get-Date).ToString('yyyyMMdd_HHmm', $script:Inv) } 'zip'
}

function Show-ZipResult {
    param($Res, $WorkerError)
    if (-not $Res) { $script:LblZip.Text = 'Zip failed: ' + $WorkerError; $script:LblStatus.Text = $script:LblZip.Text; return }
    $size = 0; try { $size = (New-Object System.IO.FileInfo($Res.Zip)).Length } catch { }
    $msg = 'Zip: ' + $Res.Zip + '  (' + $Res.Files + ' files, ' + (Format-Size $size) + ')'
    foreach ($r in $Res.Raw) { $msg += '   Raw: ' + $r }
    if ($Res.Errors.Count) { $msg += '   ' + $Res.Errors.Count + ' problem(s): ' + ($Res.Errors[0]) }
    $script:LblZip.Text = $msg
    $script:LblStatus.Text = $msg
    $script:LastZip = $Res.Zip
}

# -----------------------------------------------------------------------------
# Form
# -----------------------------------------------------------------------------
$Theme = @{
    Header = [System.Drawing.Color]::FromArgb(32, 45, 64)
    HeaderText = [System.Drawing.Color]::White
    Back = [System.Drawing.Color]::FromArgb(250, 251, 252)
    Bar = [System.Drawing.Color]::FromArgb(236, 239, 243)
}
$FontMain = New-Object System.Drawing.Font('Segoe UI', 9)
$FontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$FontBig  = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$FontMono = New-Object System.Drawing.Font('Consolas', 9)

function New-Button {
    param([string]$Text, [int]$Width = 120)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Width = $Width
    $b.Height = 28
    $b.FlatStyle = 'System'
    $b.Margin = New-Object System.Windows.Forms.Padding(0, 4, 8, 4)
    return $b
}
function New-Bar {
    param([int]$Height = 40)
    $p = New-Object System.Windows.Forms.FlowLayoutPanel
    $p.Dock = 'Top'
    $p.Height = $Height
    $p.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 0)
    $p.BackColor = $Theme.Bar
    $p.WrapContents = $false
    return $p
}
function New-BarLabel {
    param([string]$Text, [int]$Width = 600)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $false
    $l.Width = $Width
    $l.Height = 30
    $l.TextAlign = 'MiddleLeft'
    $l.AutoEllipsis = $true
    return $l
}
function New-TextPane {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true
    $t.ReadOnly = $true
    $t.ScrollBars = 'Both'
    $t.WordWrap = $false
    $t.Font = $FontMono
    $t.BackColor = [System.Drawing.Color]::White
    $t.Dock = 'Fill'
    $t.MaxLength = 0
    return $t
}
function New-Grid {
    param([object[]]$Columns)
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.BorderStyle = 'None'
    $g.AutoSizeColumnsMode = 'Fill'
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    $g.DefaultCellStyle.WrapMode = 'False'
    $g.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(51, 102, 170)
    foreach ($c in $Columns) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.HeaderText = $c[0]
        $col.FillWeight = $c[1]
        $col.MinimumWidth = $c[2]
        $col.SortMode = 'NotSortable'
        [void]$g.Columns.Add($col)
    }
    return $g
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PC Health & Crash Toolkit - ' + $script:HostName
$form.Size = New-Object System.Drawing.Size(1240, 820)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 640)
$form.StartPosition = 'CenterScreen'
$form.Font = $FontMain
$form.BackColor = $Theme.Back
$script:Form = $form

# Header
$hdr = New-Object System.Windows.Forms.Panel
$hdr.Dock = 'Top'
$hdr.Height = 104
$hdr.BackColor = $Theme.Header
$hdr.ForeColor = $Theme.HeaderText

$script:LblBadge = New-Object System.Windows.Forms.Label
$script:LblBadge.Dock = 'Right'
$script:LblBadge.Width = 190
$script:LblBadge.TextAlign = 'MiddleCenter'
$script:LblBadge.Font = $FontBig
$script:LblBadge.ForeColor = [System.Drawing.Color]::White
$script:LblBadge.BackColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
$script:LblBadge.Text = 'NOT RUN'

$lblHost = New-Object System.Windows.Forms.Label
$lblHost.Location = New-Object System.Drawing.Point(12, 6)
$lblHost.AutoSize = $true
$lblHost.Font = $FontBig
$lblHost.Text = $script:HostName + '   ' + $script:SysInfo.model

$lblSys = New-Object System.Windows.Forms.Label
$lblSys.Location = New-Object System.Drawing.Point(14, 34)
$lblSys.Size = New-Object System.Drawing.Size(880, 18)
$lblSys.AutoEllipsis = $true
$lblSys.Text = $script:SysInfo.os + '   |   up ' + $script:SysInfo.uptime + '   |   running as ' + $script:RunAs + $(if ($script:ElevateNote) { '   |   ' + $script:ElevateNote } else { '' })

$btnRow = New-Object System.Windows.Forms.FlowLayoutPanel
$btnRow.Location = New-Object System.Drawing.Point(10, 58)
$btnRow.Size = New-Object System.Drawing.Size(880, 40)
$btnRow.WrapContents = $false
$btnRow.BackColor = $Theme.Header

$script:BtnRunAll = New-Button 'Run all checks' 120
$script:BtnStop   = New-Button 'Stop' 60
$script:BtnCopy   = New-Button 'Copy report' 100
$script:BtnSave   = New-Button 'Save report' 100
$script:BtnHtml   = New-Button 'Open HTML crash report' 160
$script:ChkLoad   = New-Object System.Windows.Forms.CheckBox
$script:ChkLoad.Text = 'Include 12 s CPU load test (thermal)'
$script:ChkLoad.Checked = $true
$script:ChkLoad.AutoSize = $true
$script:ChkLoad.ForeColor = $Theme.HeaderText
$script:ChkLoad.Margin = New-Object System.Windows.Forms.Padding(6, 9, 0, 0)
$script:BtnStop.Enabled = $false
$script:BtnHtml.Enabled = $false
$btnRow.Controls.AddRange(@($script:BtnRunAll, $script:BtnStop, $script:BtnCopy, $script:BtnSave, $script:BtnHtml, $script:ChkLoad))
$hdr.Controls.AddRange(@($lblHost, $lblSys, $btnRow, $script:LblBadge))

# Status strip
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$script:LblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:LblStatus.Spring = $true
$script:LblStatus.TextAlign = 'MiddleLeft'
$script:LblStatus.Text = 'Ready. Output folder: ' + $script:WorkDir
$script:Progress = New-Object System.Windows.Forms.ToolStripProgressBar
$script:Progress.Style = 'Marquee'
$script:Progress.Visible = $false
[void]$statusStrip.Items.Add($script:LblStatus)
[void]$statusStrip.Items.Add($script:Progress)

$script:Tip = New-Object System.Windows.Forms.ToolTip
$script:Tip.AutoPopDelay = 20000
$script:Tip.InitialDelay = 200

$script:Tabs = New-Object System.Windows.Forms.TabControl
$script:Tabs.Dock = 'Fill'
$script:Tabs.Padding = New-Object System.Drawing.Point(12, 5)

function New-Tab { param([string]$Text) $t = New-Object System.Windows.Forms.TabPage; $t.Text = $Text; $t.BackColor = $Theme.Back; return $t }

# --- Overview -----------------------------------------------------------------
$script:TabOverview = New-Tab 'Overview'
$calPanel = New-Object System.Windows.Forms.Panel
$calPanel.Dock = 'Top'
$calPanel.Height = 128
$calPanel.BackColor = [System.Drawing.Color]::White
$lblCalTitle = New-Object System.Windows.Forms.Label
$lblCalTitle.Text = 'Crashes and unexpected restarts - last 30 days'
$lblCalTitle.Font = $FontBold
$lblCalTitle.Location = New-Object System.Drawing.Point(10, 6)
$lblCalTitle.AutoSize = $true
$script:LblCalRange = New-Object System.Windows.Forms.Label
$script:LblCalRange.Location = New-Object System.Drawing.Point(330, 7)
$script:LblCalRange.Size = New-Object System.Drawing.Size(560, 18)
$script:LblCalRange.ForeColor = [System.Drawing.Color]::DimGray
$script:LblCalRange.Text = 'Run the checks to fill the calendar.'
$calPanel.Controls.AddRange(@($lblCalTitle, $script:LblCalRange))
$script:CalCells = @()
$script:CalStall = @()
for ($i = 0; $i -lt 30; $i++) {
    $cell = New-Object System.Windows.Forms.Label
    $cell.Size = New-Object System.Drawing.Size(32, 34)
    $cell.Location = New-Object System.Drawing.Point((10 + $i * 35), 30)
    $cell.TextAlign = 'MiddleCenter'
    $cell.BorderStyle = 'FixedSingle'
    $cell.BackColor = $script:EpClass['none'].Back
    $cell.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cell.Add_Click({ if ($this.Tag) { [void](Select-CrashDay ([string]$this.Tag)) } })
    $calPanel.Controls.Add($cell)
    $script:CalCells += $cell
    # Storage-stall bar under the day (filled from the extras script)
    $bar = New-Object System.Windows.Forms.Label
    $bar.Size = New-Object System.Drawing.Size(32, 5)
    $bar.Location = New-Object System.Drawing.Point((10 + $i * 35), 66)
    $bar.BackColor = $calPanel.BackColor
    $calPanel.Controls.Add($bar)
    $script:CalStall += $bar
}
$legendX = 10
$legendItems = @()
$legendText = @{ crash = 'Crash (BSOD)'; unclean = 'Unexpected restart'; powerbutton = 'Forced off (power button)'; unexplained = 'Requester not recorded'; controlled = 'Requested restart / shutdown'; none = 'No restart' }
foreach ($k in @('crash', 'unclean', 'powerbutton', 'unexplained', 'controlled', 'none')) { $legendItems += , @($script:EpClass[$k].Back, $legendText[$k], 14) }
$legendItems += , @($script:StallColor, 'Storage stalls (bar under the day)', 5)
foreach ($li in $legendItems) {
    $sw = New-Object System.Windows.Forms.Label
    $sw.Size = New-Object System.Drawing.Size(14, $li[2])
    $sw.Location = New-Object System.Drawing.Point($legendX, (78 + [int]((14 - $li[2]) / 2)))
    $sw.BackColor = $li[0]
    if ($li[2] -eq 14) { $sw.BorderStyle = 'FixedSingle' }
    $lt = New-Object System.Windows.Forms.Label
    $lt.Text = $li[1]
    $lt.AutoSize = $true
    $lt.Location = New-Object System.Drawing.Point(($legendX + 18), 77)
    $calPanel.Controls.AddRange(@($sw, $lt))
    $legendX += 18 + [System.Windows.Forms.TextRenderer]::MeasureText($lt.Text, $FontMain).Width + 14
}
$script:LblModules = New-Object System.Windows.Forms.Label
$script:LblModules.Location = New-Object System.Drawing.Point(10, 102)
$script:LblModules.Size = New-Object System.Drawing.Size(1180, 18)
$script:LblModules.ForeColor = [System.Drawing.Color]::DimGray
$script:LblModules.Text = 'Press Run all checks to start.'
$calPanel.Controls.Add($script:LblModules)

$script:GridFind = New-Grid @(@('Severity', 8, 60), @('Area', 12, 90), @('When', 16, 120), @('Finding', 64, 300))
$script:TabOverview.Controls.Add($script:GridFind)
$script:TabOverview.Controls.Add($calPanel)

# --- Crashes & restarts ---------------------------------------------------------
$script:TabCrash = New-Tab 'Crashes & restarts'
$crashBar = New-Object System.Windows.Forms.Panel
$crashBar.Dock = 'Top'
$crashBar.Height = 50
$crashBar.BackColor = $Theme.Bar
$script:LblCrashHead = New-Object System.Windows.Forms.Label
$script:LblCrashHead.Location = New-Object System.Drawing.Point(8, 5)
$script:LblCrashHead.Size = New-Object System.Drawing.Size(1180, 18)
$script:LblCrashHead.Font = $FontBold
$script:LblCrashHead.AutoEllipsis = $true
$script:LblCrashHead.Text = 'Crash / shutdown diagnostic (last 30 days) - not run yet'
$script:LblCrashCounts = New-Object System.Windows.Forms.Label
$script:LblCrashCounts.Location = New-Object System.Drawing.Point(8, 26)
$script:LblCrashCounts.Size = New-Object System.Drawing.Size(1180, 18)
$script:LblCrashCounts.AutoEllipsis = $true
$crashBar.Controls.AddRange(@($script:LblCrashHead, $script:LblCrashCounts))
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.SplitterWidth = 6
$script:GridEp = New-Grid @(@('#', 4, 30), @('When', 13, 110), @('Ago', 9, 70), @('Transition', 22, 160), @('Requested by / cause', 38, 200), @('Downtime', 7, 60), @('Bugcheck', 9, 70))
$script:TxtEp = New-TextPane
$split.Panel1.Controls.Add($script:GridEp)
$split.Panel2.Controls.Add($script:TxtEp)
$script:SplitCrash = $split
$script:TabCrash.Controls.Add($split)
$script:TabCrash.Controls.Add($crashBar)

# --- Storage --------------------------------------------------------------------
$script:TabStorage = New-Tab 'Storage'
$script:GridVol = New-Grid @(@('Volume', 14, 90), @('Label', 18, 90), @('File system', 10, 70), @('Size', 12, 70), @('Free', 12, 70), @('Free %', 10, 60), @('Status', 10, 60))
$script:GridVol.Dock = 'Top'
$script:GridVol.Height = 118
$ssdBar = New-Bar 40
$script:BtnSsd = New-Button 'Re-run storage check' 150
$script:BtnSmart = New-Button 'Install smartmontools && re-run' 210
$script:LblSsd = New-BarLabel 'Drive health: not run yet' 780
$ssdBar.Controls.AddRange(@($script:BtnSsd, $script:BtnSmart, $script:LblSsd))
$script:TxtSsd = New-TextPane
$script:TabStorage.Controls.Add($script:TxtSsd)
$script:TabStorage.Controls.Add($ssdBar)
$script:TabStorage.Controls.Add($script:GridVol)

# --- Thermal & responsiveness ---------------------------------------------------
$script:TabThermal = New-Tab 'Thermal & responsiveness'
$thBar = New-Object System.Windows.Forms.Panel
$thBar.Dock = 'Top'
$thBar.Height = 80
$thBar.BackColor = $Theme.Bar
$script:BtnThermal = New-Button 'Run thermal check' 140
$script:BtnThermal.Location = New-Object System.Drawing.Point(8, 6)
$script:BtnLag = New-Button 'Run responsiveness check' 170
$script:BtnLag.Location = New-Object System.Drawing.Point(156, 6)
$script:LblThermal = New-Object System.Windows.Forms.Label
$script:LblThermal.Location = New-Object System.Drawing.Point(10, 40)
$script:LblThermal.Size = New-Object System.Drawing.Size(1180, 17)
$script:LblThermal.AutoEllipsis = $true
$script:LblThermal.Text = 'Thermal throttling: not run yet'
$script:LblLag = New-Object System.Windows.Forms.Label
$script:LblLag.Location = New-Object System.Drawing.Point(10, 58)
$script:LblLag.Size = New-Object System.Drawing.Size(1180, 17)
$script:LblLag.AutoEllipsis = $true
$script:LblLag.Text = 'Responsiveness (UI lag): not run yet'
$thBar.Controls.AddRange(@($script:BtnThermal, $script:BtnLag, $script:LblThermal, $script:LblLag))
$split2 = New-Object System.Windows.Forms.SplitContainer
$split2.Dock = 'Fill'
$split2.Orientation = 'Vertical'
$split2.SplitterWidth = 6
$script:TxtThermal = New-TextPane
$script:TxtLag = New-TextPane
$split2.Panel1.Controls.Add($script:TxtThermal)
$split2.Panel2.Controls.Add($script:TxtLag)
$script:SplitThermal = $split2
$script:TabThermal.Controls.Add($split2)
$script:TabThermal.Controls.Add($thBar)

# --- System health --------------------------------------------------------------
$script:TabHealth = New-Tab 'System health'
$hBar = New-Bar 40
$script:BtnExtras = New-Button 'Re-run health checks' 150
$script:BtnMemTest = New-Button 'Schedule memory test...' 160
$script:BtnDism = New-Button 'DISM health check' 130
$script:LblExtras = New-BarLabel 'System health: not run yet' 700
$hBar.Controls.AddRange(@($script:BtnExtras, $script:BtnMemTest, $script:BtnDism, $script:LblExtras))
$split3 = New-Object System.Windows.Forms.SplitContainer
$split3.Dock = 'Fill'
$split3.Orientation = 'Horizontal'
$split3.SplitterWidth = 6
$script:GridHealth = New-Grid @(@('Level', 8, 60), @('Area', 10, 80), @('When', 14, 110), @('Finding', 68, 300))
$script:TxtExtras = New-TextPane
$split3.Panel1.Controls.Add($script:GridHealth)
$split3.Panel2.Controls.Add($script:TxtExtras)
$script:SplitHealth = $split3
$script:TabHealth.Controls.Add($split3)
$script:TabHealth.Controls.Add($hBar)

# --- Collect logs ---------------------------------------------------------------
$script:TabLogs = New-Tab 'Collect logs'
$lBar = New-Bar 40
$script:BtnLogRefresh = New-Button 'Refresh list' 100
$script:BtnLogAll = New-Button 'Select all' 80
$script:BtnLogNone = New-Button 'Select none' 90
$script:ChkRecent = New-Object System.Windows.Forms.CheckBox
$script:ChkRecent.Text = 'Only files from the last 30 days'
$script:ChkRecent.AutoSize = $true
$script:ChkRecent.Checked = $true
$script:ChkRecent.Margin = New-Object System.Windows.Forms.Padding(4, 9, 12, 0)
$lblDays = New-Object System.Windows.Forms.Label
$lblDays.Text = 'Event log days:'
$lblDays.AutoSize = $true
$lblDays.Margin = New-Object System.Windows.Forms.Padding(0, 10, 2, 0)
$script:NumDays = New-Object System.Windows.Forms.NumericUpDown
$script:NumDays.Minimum = 1
$script:NumDays.Maximum = 365
$script:NumDays.Value = 30
$script:NumDays.Width = 55
$script:NumDays.Margin = New-Object System.Windows.Forms.Padding(0, 7, 12, 0)
$script:BtnZip = New-Button 'Zip selected' 110
$script:BtnOpenOut = New-Button 'Open C:\temp' 100
$lBar.Controls.AddRange(@($script:BtnLogRefresh, $script:BtnLogAll, $script:BtnLogNone, $script:ChkRecent, $lblDays, $script:NumDays, $script:BtnZip, $script:BtnOpenOut))
$script:GridLogs = New-Grid @(@('Item', 26, 160), @('Files', 12, 90), @('Size', 9, 70), @('Newest', 12, 100), @('Location', 28, 150), @('Note', 13, 90))
$script:GridLogs.ReadOnly = $false
$chkCol = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$chkCol.HeaderText = 'Include'
$chkCol.FillWeight = 6
$chkCol.MinimumWidth = 55
$script:GridLogs.Columns.Insert(0, $chkCol)
for ($i = 1; $i -lt $script:GridLogs.Columns.Count; $i++) { $script:GridLogs.Columns[$i].ReadOnly = $true }
$script:LblZip = New-Object System.Windows.Forms.Label
$script:LblZip.Dock = 'Bottom'
$script:LblZip.Height = 40
$script:LblZip.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$script:LblZip.Text = 'The zip goes to C:\temp\CrashLogs_<host>_<time>.zip. A full MEMORY.DMP is copied raw beside it (it is large and compresses poorly) - drag it out only when it is needed.'
$script:TabLogs.Controls.Add($script:GridLogs)
$script:TabLogs.Controls.Add($script:LblZip)
$script:TabLogs.Controls.Add($lBar)

# --- Raw output -----------------------------------------------------------------
$script:TabRaw = New-Tab 'Raw output'
$script:TxtRaw = New-TextPane
$script:TabRaw.Controls.Add($script:TxtRaw)

$script:Tabs.TabPages.AddRange(@($script:TabOverview, $script:TabCrash, $script:TabStorage, $script:TabThermal, $script:TabHealth, $script:TabLogs, $script:TabRaw))
$form.Controls.Add($script:Tabs)
$form.Controls.Add($statusStrip)
$form.Controls.Add($hdr)

function Disable-Mnemonics {
    param($Parent)
    foreach ($ctl in $Parent.Controls) {
        if ($ctl -is [System.Windows.Forms.Label]) { $ctl.UseMnemonic = $false }
        if ($ctl.Controls.Count) { Disable-Mnemonics $ctl }
    }
}
Disable-Mnemonics $form

$script:BusyButtons = @($script:BtnRunAll, $script:BtnSsd, $script:BtnSmart, $script:BtnThermal, $script:BtnLag, $script:BtnExtras, $script:BtnDism, $script:BtnZip)

# -----------------------------------------------------------------------------
# Events (all built at script scope, so handlers see these variables when they fire)
# -----------------------------------------------------------------------------
$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 300
$script:Timer.Add_Tick({ Invoke-TimerTick })

$script:BtnRunAll.Add_Click({ Start-RunAll })
$script:BtnStop.Add_Click({ if ($script:Sync) { $script:Sync.Cancel = $true; $script:LblStatus.Text = 'Stopping...' } })
$script:BtnCopy.Add_Click({ [void](Copy-Report) })
$script:BtnSave.Add_Click({ [void](Save-Report) })
$script:BtnHtml.Add_Click({ Open-HtmlReport })
$script:BtnSsd.Add_Click({ Start-Modules -Phases @(, @('ssd')) })
$script:BtnSmart.Add_Click({
    $msg = 'This downloads smartmontools 7.5 from github.com/smartmontools and installs it silently to C:\Program Files\smartmontools, then re-runs the storage check with full SMART data.' + [Environment]::NewLine + [Environment]::NewLine + 'Install it on this PC?'
    if ([System.Windows.Forms.MessageBox]::Show($msg, 'Install smartmontools', 'YesNo', 'Question') -eq 'Yes') { Start-Modules -Phases @(, @('ssd')) -InstallSmart }
})
$script:BtnThermal.Add_Click({ Start-Modules -Phases @(, @('thermal')) })
$script:BtnLag.Add_Click({ Start-Modules -Phases @(, @('uilag')) })
$script:BtnExtras.Add_Click({ Start-Modules -Phases @(, @('extras')) })
$script:BtnDism.Add_Click({
    if (-not $script:IsAdmin) { [System.Windows.Forms.MessageBox]::Show('DISM needs administrator rights.', 'DISM', 'OK', 'Warning') | Out-Null; return }
    $script:LblExtras.Text = 'DISM /CheckHealth running (read-only, usually under a minute)...'
    $sp = Get-ModuleSpec 'dism'
    $list = New-Object System.Collections.ArrayList
    [void]$list.Add(@($sp))
    Start-Worker @{ Kind = 'run'; Phases = $list } 'run'
})
$script:BtnMemTest.Add_Click({
    $msg = 'Windows Memory Diagnostic needs a restart to test RAM (takes 10-30 minutes; the result appears in this toolkit afterwards).' + [Environment]::NewLine + [Environment]::NewLine +
           'Open it now? You choose "Restart now" or "Check the next time I start" in its window.'
    if ([System.Windows.Forms.MessageBox]::Show($msg, 'Memory test', 'YesNo', 'Question') -eq 'Yes') {
        try { Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\MdSched.exe') } catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Memory test', 'OK', 'Warning') | Out-Null }
    }
})
$script:GridEp.Add_CurrentCellChanged({ if ($script:GridEp.CurrentRow) { Show-EpisodeDetail $script:GridEp.CurrentRow.Tag } })
$script:GridFind.Add_CellDoubleClick({
    if ($_.RowIndex -lt 0) { return }
    $src = [string]$script:GridFind.Rows[$_.RowIndex].Tag
    switch ($src) {
        'crash'   { $script:Tabs.SelectedTab = $script:TabCrash }
        'ssd'     { $script:Tabs.SelectedTab = $script:TabStorage }
        'extras'  { $script:Tabs.SelectedTab = $script:TabHealth }
        'thermal' { $script:Tabs.SelectedTab = $script:TabThermal }
        'uilag'   { $script:Tabs.SelectedTab = $script:TabThermal }
    }
})
$script:GridLogs.Add_CurrentCellDirtyStateChanged({ if ($script:GridLogs.IsCurrentCellDirty) { [void]$script:GridLogs.CommitEdit('CurrentCellChange') } })
$script:BtnLogRefresh.Add_Click({ Update-LogGrid })
$script:BtnLogAll.Add_Click({ Set-LogChecks $true })
$script:BtnLogNone.Add_Click({ Set-LogChecks $false })
$script:BtnZip.Add_Click({ Start-ZipLogs })
$script:BtnOpenOut.Add_Click({ try { Start-Process explorer.exe -ArgumentList ('"' + $script:OutRoot + '"') } catch { } })

function Set-InitialLayout {
    # Unselected tab pages have not laid out yet: visit each so the splitters get real sizes
    foreach ($pg in $script:Tabs.TabPages) { $script:Tabs.SelectedTab = $pg; $pg.PerformLayout() }
    $script:Tabs.SelectedTab = $script:TabOverview
    try { $script:SplitCrash.SplitterDistance = [math]::Max(100, [int]($script:SplitCrash.Height * 0.42)) } catch { }
    try { $script:SplitThermal.SplitterDistance = [math]::Max(100, [int]($script:SplitThermal.Width / 2)) } catch { }
    try { $script:SplitHealth.SplitterDistance = [math]::Max(100, [int]($script:SplitHealth.Height * 0.40)) } catch { }
}
$form.Add_Shown({
    Set-InitialLayout
    Update-LogGrid
    if (-not $NoAutoRun -and -not $BuildOnly) { Start-RunAll }
})
$form.Add_FormClosing({
    if ($script:Sync -and -not $script:Sync.Done) {
        $r = [System.Windows.Forms.MessageBox]::Show('Checks are still running. Stop them and close?', 'PC Health & Crash Toolkit', 'YesNo', 'Question')
        if ($r -ne 'Yes') { $_.Cancel = $true; return }
        $script:Sync.Cancel = $true
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $script:Sync.Done -and $sw.Elapsed.TotalSeconds -lt 8) { Start-Sleep -Milliseconds 200 }
    }
    $script:Timer.Stop()
})

if ($BuildOnly) { return }

try { Start-Transcript -Path (Join-Path $script:WorkDir 'toolkit_transcript.txt') -ErrorAction Stop | Out-Null } catch { }
[void]$form.ShowDialog()
try { Stop-Transcript | Out-Null } catch { }
$form.Dispose()
