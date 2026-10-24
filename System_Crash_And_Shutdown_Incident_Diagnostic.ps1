<#
=========================================================
Script Name: System_Crash_And_Shutdown_Incident_Diagnostic
Description: Answers "why did this PC restart / shut down?" for a reported incident.
Rebuilds every shutdown -> startup EPISODE in the lookback window from the event logs,
labels how Windows went down (controlled restart/power-off, orderly without a recorded
request, unclean with or without a bugcheck, held power button, not enough evidence),
decodes WHAT REQUESTED IT (User32 1074 process, account, decoded reason code, matched
against known Windows Update / shell / RMM / installer / WMI / script signatures), and
lists what corroborates or contradicts each explanation in a window around the event
(Windows Update, scheduled tasks, installers, console/RDP sessions, logoffs, process
creation, app/service errors). Missing or disabled logs are reported as gaps, never as
"nothing happened". Older history (dumps, past crashes, app crashes) is shown separately
and never drives the incident verdict.

Output: a text report written for engineers and the MSP Commander Gem, then ONE compact
JSON line between ===CRASHDIAG_JSON_BEGIN=== / ===CRASHDIAG_JSON_END=== for
Crash_Incident_Viewer.html. Both are also saved to C:\temp.
Exit code: 0 OK / 1 WARN / 2 ALERT (see VERDICT in the report).

Category:    ScriptLibrary
Run Time:    10 minutes
Arguments:   -IncidentTime "yyyy-MM-dd HH:mm"   (optional: time the client reported)
             -LookbackDays 7  -HistoryDays 30  -WindowBefore 15  -WindowAfter 5
             -EnableAttributionLogging          (opt-in: turns on Task Scheduler history
                                                 and process-creation auditing so the
                                                 NEXT restart names its caller)
             -ExportEventsPath C:\temp\x.json   (save the evidence as a test fixture)
Run As:      System
=========================================================
#>
# Requires PowerShell 3.0+. Deliberately no "#Requires -RunAsAdministrator" (PS 4.0+ only),
# so older hosts reach the version check below and exit cleanly.
[CmdletBinding()]
param(
    [string]$IncidentTime,
    [int]$LookbackDays = 7,
    [int]$HistoryDays = 30,
    [int]$WindowBefore = 15,
    [int]$WindowAfter = 5,
    [int]$MaxEpisodes = 8,
    [int]$MaxJsonKB = 40,
    [string]$OutputDir = 'C:\temp',
    [string]$ReplayPath,
    [string]$ExportEventsPath,
    [switch]$EnableAttributionLogging,
    [switch]$NoInlineJson,
    [switch]$NoFiles
)

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Output ('[WARN] PowerShell 3.0 or later is required (found ' + $PSVersionTable.PSVersion + ').')
    Write-Output '[WARN] On this host run System_Crash_Analysis_Legacy_2008R2.ps1 instead.'
    exit 1
}

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:ToolName = 'System_Crash_And_Shutdown_Incident_Diagnostic'
$script:ToolVer  = '1.0'
$script:Schema   = 'crashdiag/1'
$script:EvtNs    = 'http://schemas.microsoft.com/win/2004/08/events/event'
$script:Inv      = [System.Globalization.CultureInfo]::InvariantCulture
$script:Replay   = [bool]$ReplayPath
$script:Notes    = New-Object System.Collections.ArrayList

if ($LookbackDays -lt 1) { $LookbackDays = 1 }
if ($HistoryDays -lt $LookbackDays) { $HistoryDays = $LookbackDays }
if ($MaxEpisodes -lt 1) { $MaxEpisodes = 1 }

# =============================================================================
# REFERENCE DATA
# =============================================================================

# Bugcheck code (lower-case hex, no leading zeros) -> name, cause category, hint
$script:BugTable = @{
    'a'        = @('IRQL_NOT_LESS_OR_EQUAL', 'Driver', 'driver or kernel touched invalid memory (faulty driver or RAM)')
    '18'       = @('REFERENCE_BY_POINTER', 'Driver', 'driver object reference-count bug')
    '1a'       = @('MEMORY_MANAGEMENT', 'RAM', 'memory management fault - test RAM, check drivers')
    '1e'       = @('KMODE_EXCEPTION_NOT_HANDLED', 'Driver', 'unhandled kernel exception (driver)')
    '24'       = @('NTFS_FILE_SYSTEM', 'Disk', 'NTFS fault - run chkdsk, check disk health')
    '3b'       = @('SYSTEM_SERVICE_EXCEPTION', 'Driver', 'exception in a system service (driver/software)')
    '4e'       = @('PFN_LIST_CORRUPT', 'RAM', 'page frame list corrupt - test RAM, check drivers')
    '50'       = @('PAGE_FAULT_IN_NONPAGED_AREA', 'RAM', 'invalid memory referenced (RAM or driver)')
    '7a'       = @('KERNEL_DATA_INPAGE_ERROR', 'Disk', 'paging read failed - failing disk or storage driver')
    '7e'       = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', 'Driver', 'driver threw an unhandled exception')
    '7f'       = @('UNEXPECTED_KERNEL_MODE_TRAP', 'CPU/Hardware', 'CPU trap - RAM, CPU or overclock instability')
    '9e'       = @('USER_MODE_HEALTH_MONITOR', 'Software', 'user-mode health check timed out (cluster/server)')
    '9f'       = @('DRIVER_POWER_STATE_FAILURE', 'Driver', 'driver mishandled a sleep/resume/shutdown power transition')
    'a0'       = @('INTERNAL_POWER_ERROR', 'Driver', 'power policy or driver failure during a power change')
    'ab'       = @('SESSION_HAS_VALID_POOL_ON_EXIT', 'Software', 'session pool leak at logoff (common on terminal servers)')
    'be'       = @('ATTEMPTED_WRITE_TO_READONLY_MEMORY', 'Driver', 'driver wrote to read-only memory')
    'c2'       = @('BAD_POOL_CALLER', 'Driver', 'driver made a bad pool allocation')
    'c4'       = @('DRIVER_VERIFIER_DETECTED_VIOLATION', 'Driver', 'Driver Verifier caught a misbehaving driver')
    'c5'       = @('DRIVER_CORRUPTED_EXPOOL', 'Driver', 'pool corruption (driver, sometimes RAM)')
    'd1'       = @('DRIVER_IRQL_NOT_LESS_OR_EQUAL', 'Driver', 'driver touched invalid memory at high IRQL')
    'ef'       = @('CRITICAL_PROCESS_DIED', 'Software', 'critical system process died - SFC/DISM, malware or corruption')
    'f4'       = @('CRITICAL_OBJECT_TERMINATION', 'Disk', 'critical process ended - often a failing disk')
    '101'      = @('CLOCK_WATCHDOG_TIMEOUT', 'CPU/Hardware', 'a CPU core stopped responding - CPU, firmware or overclock')
    '109'      = @('CRITICAL_STRUCTURE_CORRUPTION', 'CPU/Hardware', 'kernel structure corrupted - RAM, driver or rootkit')
    '116'      = @('VIDEO_TDR_FAILURE', 'Driver', 'GPU driver failed to recover from a timeout - update or roll back the GPU driver')
    '117'      = @('VIDEO_TDR_TIMEOUT_DETECTED', 'Driver', 'GPU stopped responding and was reset (live dump)')
    '119'      = @('VIDEO_SCHEDULER_INTERNAL_ERROR', 'Driver', 'GPU scheduler fault - GPU driver or hardware')
    '124'      = @('WHEA_UNCORRECTABLE_ERROR', 'CPU/Hardware', 'fatal hardware error - CPU, RAM, PSU, overheating or voltage')
    '12b'      = @('FAULTY_HARDWARE_CORRUPTED_PAGE', 'RAM', 'memory error - test or replace RAM')
    '133'      = @('DPC_WATCHDOG_VIOLATION', 'Driver', 'driver or storage firmware stuck - update SSD firmware and drivers')
    '139'      = @('KERNEL_SECURITY_CHECK_FAILURE', 'Driver', 'kernel integrity check failed - driver or RAM')
    '13a'      = @('KERNEL_MODE_HEAP_CORRUPTION', 'Driver', 'kernel heap corruption (driver)')
    '141'      = @('VIDEO_ENGINE_TIMEOUT_DETECTED', 'Driver', 'a GPU engine timed out and was reset (live dump)')
    '144'      = @('BUGCODE_USB3_DRIVER', 'Driver', 'USB 3 controller/driver fault (live dump)')
    '14f'      = @('PDC_WATCHDOG_TIMEOUT', 'Driver', 'a component did not respond during a standby/power transition')
    '154'      = @('UNEXPECTED_STORE_EXCEPTION', 'RAM', 'store manager exception - RAM, driver or disk')
    '15f'      = @('CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP', 'Driver', 'Modern Standby transition timed out (live dump)')
    '193'      = @('VIDEO_DXGKRNL_LIVEDUMP', 'Driver', 'graphics kernel captured a live dump')
    '19c'      = @('WIN32K_CRITICAL_FAILURE', 'Software', 'Win32k subsystem failure (graphics/software)')
    '1ca'      = @('SYNTHETIC_WATCHDOG_TIMEOUT', 'Driver', 'hypervisor/driver watchdog timeout')
    'c000021a' = @('STATUS_SYSTEM_PROCESS_TERMINATED', 'Software', 'csrss or winlogon ended unexpectedly')
}
function Get-BugMeta {
    param($Code)
    $k = ''
    try { $k = ('{0:x}' -f [int64]$Code) } catch { }
    if ($k -and $script:BugTable.ContainsKey($k)) {
        $v = $script:BugTable[$k]
        return @{ Name = $v[0]; Cat = $v[1]; Hint = $v[2] }
    }
    return @{ Name = 'UNKNOWN'; Cat = 'Unknown'; Hint = 'unrecognised bugcheck code' }
}
function Format-BugHex {
    param($Code)
    try { return ('0x{0:X8}' -f [int64]$Code) } catch { return [string]$Code }
}

# Shutdown reason codes (Reason.h, verified against Microsoft "System Shutdown Reason Codes")
$script:ReasonMajor = @{ 0 = 'Other'; 1 = 'Hardware'; 2 = 'Operating System'; 3 = 'Software'
                         4 = 'Application'; 5 = 'System'; 6 = 'Power'; 7 = 'Legacy API' }
$script:ReasonMinor = @{ 0 = 'Other'; 1 = 'Maintenance'; 2 = 'Installation'; 3 = 'Upgrade'; 4 = 'Reconfiguration'
                         5 = 'Unresponsive'; 6 = 'Unstable'; 7 = 'Disk'; 8 = 'Processor'; 9 = 'Network card'
                         10 = 'Power supply'; 11 = 'Cord unplugged'; 12 = 'Environment (power outage)'
                         13 = 'Hardware driver'; 14 = 'Other driver'; 15 = 'Blue screen'; 16 = 'Service pack'
                         17 = 'Hot fix'; 18 = 'Security fix'; 19 = 'Security'; 20 = 'Network connectivity'
                         21 = 'WMI'; 22 = 'Service pack uninstall'; 23 = 'Hot fix uninstall'
                         24 = 'Security fix uninstall'; 25 = 'MMC'; 32 = 'Terminal Services'; 255 = 'none supplied' }

# Who requested it: process leaf name (regex, case-insensitive) -> category. Order matters.
$script:InitiatorSigs = @(
    @{ Re = '^(runtimebroker|explorer|shellexperiencehost|startmenuexperiencehost|shellhost|searchhost|sihost)\.exe$'
       Cat = 'interactive-shell'; Conf = 'medium'
       Label = 'Interactive session action through the Windows shell (Start/power menu, notification or modern-app broker)'
       Caveat = 'Names the shell process acting for the signed-in account. It does not prove a person chose Restart: an app or prompt in that session can route through the same broker.' }
    @{ Re = '^(winlogon|logonui)\.exe$'
       Cat = 'signin-screen'; Conf = 'medium'
       Label = 'Sign-in, lock or Ctrl+Alt+Del screen power option, or a restart at sign-out'
       Caveat = 'Winlogon also acts for other components during sign-out.' }
    @{ Re = '^(musnotification|musnotificationux|musnotifyicon|monotificationux|monotification|mousocoreworker|usoclient|trustedinstaller|tiworker|wuauclt|waasmedicagent|sihclient|setuphost|windowsupdatebox|updatenotificationmgr)\.exe$'
       Cat = 'windows-update'; Conf = 'high'
       Label = 'Windows Update / servicing component'
       Caveat = 'The servicing stack issued the restart; active hours, restart deadlines or a patch policy decide when.' }
    @{ Re = '^(ateraagent|agentpackage.*|screenconnect.*|connectwisecontrol.*|srservice|srmanager|srserver|srfeature|splashtop.*|teamviewer.*|anydesk|ninjarmmagent.*|ninjarmm.*|ltsvc|ltsvcmon|lttray|agentmon|cagservice|basupsrvc.*|syncro.*|kaseya.*|winagent|rmmagent.*)\.exe$'
       Cat = 'rmm-remote'; Conf = 'high'
       Label = 'Remote-management / remote-support agent'
       Caveat = 'A technician action or an automation in that tool; its own activity log names which.' }
    @{ Re = '^(omadmclient|deviceenroller|intunemanagementextension|microsoft\.management\.services\.intunewindowsagent|mdmappinstaller)\.exe$'
       Cat = 'mdm'; Conf = 'high'
       Label = 'Intune / MDM device management'
       Caveat = 'Check device actions and update rings in the MDM console for the time.' }
    @{ Re = '^(dcu-cli|dellcommandupdate|dellclientmanagementservice|supportassist.*|hpimageassistant|hpsa.*|hpsf.*|hp.*update.*|tvsu.*|lenovo.*|imcontroller.*|dsaservice|dsatray)\.exe$'
       Cat = 'oem-updater'; Conf = 'medium'
       Label = 'Hardware vendor driver/BIOS update tool'
       Caveat = 'These tools restart after firmware or driver updates; check the tool history.' }
    @{ Re = '^(msmpeng|mpcmdrun|sentinelagent|sentinelservicehost|sentinelctl|csfalconservice|sophos.*|savservice|bdagent|epsecurityservice|ekrn|mbamservice)\.exe$'
       Cat = 'security-agent'; Conf = 'medium'
       Label = 'Security / anti-malware agent'
       Caveat = 'Usually an agent upgrade or remediation that needed a restart; check the security console.' }
    @{ Re = '^wmiprvse\.exe$'
       Cat = 'wmi'; Conf = 'medium'
       Label = 'WMI shutdown call (Win32Shutdown) - remote management, RMM or a script'
       Caveat = 'WMI hides the real caller; process-creation auditing or WMI-Activity tracing names it next time.' }
    @{ Re = '^(powershell|pwsh|powershell_ise)\.exe$'
       Cat = 'command-line'; Conf = 'medium'
       Label = 'PowerShell Restart-Computer / Stop-Computer (script, task, agent or admin)'
       Caveat = 'The script that ran it is not recorded here; process-creation auditing records the parent next time.' }
    @{ Re = '^shutdown\.exe$'
       Cat = 'command-line'; Conf = 'medium'
       Label = 'shutdown.exe command (script, scheduled task, agent or admin)'
       Caveat = 'The caller of shutdown.exe is not recorded here; process-creation auditing records the parent next time.' }
    @{ Re = '^(msiexec|setup|install|unins\d+|.*setup.*|.*install.*|.*updater.*)\.exe$'
       Cat = 'installer'; Conf = 'medium'
       Label = 'Software installer or updater'
       Caveat = 'Installers request a restart to replace files in use; the correlated MSI/Restart Manager entries name the product.' }
    @{ Re = '^(csrss|wininit|lsass|services|svchost|smss)\.exe$'
       Cat = 'system-process'; Conf = 'low'
       Label = 'Core Windows process acting for another component'
       Caveat = 'The reason code and correlated events are better clues than the process name.' }
)
# Categories that count as "unexplained" for the exit code
$script:UnexplainedCats = @('unknown')

# LiveKernelEvent codes (WER P1, hex) worth naming
$script:LiveKernelNames = @{ '117' = 'VIDEO_TDR_TIMEOUT_DETECTED (GPU reset)'; '141' = 'VIDEO_ENGINE_TIMEOUT_DETECTED (GPU engine reset)'
                             '144' = 'BUGCODE_USB3_DRIVER'; '15f' = 'CONNECTED_STANDBY_WATCHDOG_TIMEOUT'
                             '193' = 'VIDEO_DXGKRNL_LIVEDUMP' }

$script:Channels = @(
    'System'
    'Application'
    'Security'
    'Microsoft-Windows-WindowsUpdateClient/Operational'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
)
$script:ChanShort = @{
    'system' = 'Sys'; 'application' = 'App'; 'security' = 'Sec'
    'microsoft-windows-windowsupdateclient/operational' = 'WU'
    'microsoft-windows-taskscheduler/operational' = 'Task'
    'microsoft-windows-terminalservices-localsessionmanager/operational' = 'LSM'
    'microsoft-windows-terminalservices-remoteconnectionmanager/operational' = 'RCM'
}
$script:StorageProvRe = '(?i)stor|nvme|ahci|disk|iastor|vmd|sata|scsi|raid|megasas|spaceport|classpnp|lsi'

# =============================================================================
# GENERAL HELPERS
# =============================================================================
function Pick { param($Cond, $A, $B) if ($Cond) { return $A } return $B }

function Limit-Text {
    param([string]$Text, [int]$Max = 160)
    if ($null -eq $Text) { return '' }
    $t = ($Text -replace '[\u200e\u200f\u202a-\u202e]', '' -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function ConvertTo-Dto {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [datetime]) { return (New-Object DateTimeOffset($Value)) }
    $s = [string]$Value
    if (-not $s) { return $null }
    $o = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($s, $script:Inv, [System.Globalization.DateTimeStyles]::None, [ref]$o)) { return $o }
    return $null
}
function Format-Time  { param($T) if ($null -eq $T) { return '' } return $T.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv) }
function Format-Short { param($T) if ($null -eq $T) { return '' } return $T.ToString('ddd dd MMM HH:mm', $script:Inv) }
function Format-Clock { param($T) if ($null -eq $T) { return '' } return $T.ToString('HH:mm:ss', $script:Inv) }
function Format-Iso   { param($T) if ($null -eq $T) { return $null } return $T.ToString('yyyy-MM-ddTHH:mm:sszzz', $script:Inv) }
function Format-Span {
    param([double]$Seconds)
    $neg = $Seconds -lt 0
    $s = [math]::Abs([math]::Round($Seconds))
    if ($s -lt 60)        { $r = '{0}s' -f $s }
    elseif ($s -lt 3600)  { $r = '{0}m {1}s' -f [math]::Floor($s / 60), ($s % 60) }
    elseif ($s -lt 86400) { $r = '{0}h {1}m' -f [math]::Floor($s / 3600), [math]::Floor(($s % 3600) / 60) }
    else                  { $r = '{0}d {1}h' -f [math]::Floor($s / 86400), [math]::Floor(($s % 86400) / 3600) }
    if ($neg) { return '-' + $r }
    return $r
}
function Format-Offset { param([double]$Seconds) if ($Seconds -ge 0) { return '+' + (Format-Span $Seconds) } return (Format-Span $Seconds) }
function Get-Sec { param($A, $B) return [double](($A - $B).TotalSeconds) }

function Get-First { param($Items) $a = @($Items); if ($a.Count -gt 0) { return $a[0] } return $null }
function Get-Last  { param($Items) $a = @($Items); if ($a.Count -gt 0) { return $a[$a.Count - 1] } return $null }

function Add-Note { param([string]$Text) [void]$script:Notes.Add($Text) }

function Test-IsSystemAccount {
    param([string]$User)
    if (-not $User) { return $false }
    return ($User -match '(?i)^(NT AUTHORITY\\|NT-AUTORIT|AUTORITE NT\\)?(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' -or $User -match '(?i)\\SYSTEM$' -or $User -match '\$$')
}

function Get-CimSafe {
    param([string]$Class, [string]$Filter)
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return @(Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop) }
            return @(Get-CimInstance -ClassName $Class -ErrorAction Stop)
        }
    } catch { }
    try {
        if ($Filter) { return @(Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop) }
        return @(Get-WmiObject -Class $Class -ErrorAction Stop)
    } catch { }
    return @()
}

# =============================================================================
# NORMALISED EVENT POOL  (live and replay feed the same structure)
# =============================================================================
$script:Pool     = New-Object System.Collections.ArrayList
$script:PoolKeys = @{}
$script:Idx      = @{}
$script:LogIdx   = @{}
$script:QueryErrors = @{}
$script:Truncated   = @{}
$script:PhaseTwo    = $false

function New-NormEvent {
    param($T, [string]$Log, [string]$Prov, [int]$Id, [int]$Ver, [int64]$Rec, [int]$Lvl, [hashtable]$Data, [string]$Bin, [string]$Msg)
    if ($null -eq $Data) { $Data = @{} }
    if ($Rec -gt 0) { $key = $Log + '|' + $Rec }
    else { $key = $Log + '|' + $Prov + '|' + $Id + '|' + $T.UtcTicks }
    return [pscustomobject]@{
        T = $T; Log = $Log; Prov = $Prov; Id = $Id; Ver = $Ver; Rec = $Rec; Lvl = $Lvl
        Data = $Data; Bin = $Bin; Msg = $Msg; Key = $key
    }
}

function ConvertTo-NormEvent {
    param($E)
    $data = @{}
    $bin = ''
    try {
        $x = [xml]$E.ToXml()
        $m = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
        $m.AddNamespace('e', $script:EvtNs)
        $i = 0
        foreach ($n in @($x.SelectNodes('//e:EventData/e:Data', $m))) {
            $nm = $n.GetAttribute('Name')
            if (-not $nm) { $nm = 'p' + $i }
            $data[$nm] = $n.InnerText
            $i++
        }
        $b = $x.SelectSingleNode('//e:EventData/e:Binary', $m)
        if ($b) { $bin = $b.InnerText }
        $ud = $x.SelectSingleNode('//e:UserData', $m)
        if ($ud -and $ud.FirstChild) {
            foreach ($c in @($ud.FirstChild.ChildNodes)) {
                if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) { $data[$c.LocalName] = $c.InnerText }
            }
        }
    } catch { }
    $msg = ''
    try { if ($E.Message) { $msg = Limit-Text $E.Message 300 } } catch { }
    $lvl = 0
    try { $lvl = [int]$E.Level } catch { }
    $ver = 0
    try { $ver = [int]$E.Version } catch { }
    $rec = 0
    try { $rec = [int64]$E.RecordId } catch { }
    return (New-NormEvent -T (New-Object DateTimeOffset($E.TimeCreated)) -Log ([string]$E.LogName) -Prov ([string]$E.ProviderName) `
            -Id ([int]$E.Id) -Ver $ver -Rec $rec -Lvl $lvl -Data $data -Bin $bin -Msg $msg)
}

function Add-PoolEvent {
    param($Ev)
    if ($null -eq $Ev) { return }
    if ($script:PoolKeys.ContainsKey($Ev.Key)) { return }
    $script:PoolKeys[$Ev.Key] = $true
    [void]$script:Pool.Add($Ev)
}

function Update-PoolIndex {
    $script:Idx = @{}
    $script:LogIdx = @{}
    foreach ($e in $script:Pool) {
        $k = ([string]$e.Prov).ToLower() + '|' + $e.Id
        if (-not $script:Idx.ContainsKey($k)) { $script:Idx[$k] = New-Object System.Collections.ArrayList }
        [void]$script:Idx[$k].Add($e)
        $lk = ([string]$e.Log).ToLower()
        if (-not $script:LogIdx.ContainsKey($lk)) { $script:LogIdx[$lk] = New-Object System.Collections.ArrayList }
        [void]$script:LogIdx[$lk].Add($e)
    }
}

function Find-Ev {
    param([string[]]$Prov, [int[]]$Id, $From = $null, $To = $null)
    $out = New-Object System.Collections.ArrayList
    foreach ($p in $Prov) {
        foreach ($i in $Id) {
            $k = ([string]$p).ToLower() + '|' + $i
            if (-not $script:Idx.ContainsKey($k)) { continue }
            foreach ($e in $script:Idx[$k]) {
                if ($null -ne $From -and $e.T -lt $From) { continue }
                if ($null -ne $To -and $e.T -gt $To) { continue }
                [void]$out.Add($e)
            }
        }
    }
    if ($out.Count -eq 0) { return @() }
    return @($out.ToArray() | Sort-Object -Property T)
}

function Find-ByLog {
    param([string]$Log, $From = $null, $To = $null)
    $out = New-Object System.Collections.ArrayList
    $lk = $Log.ToLower()
    if ($script:LogIdx.ContainsKey($lk)) {
        foreach ($e in $script:LogIdx[$lk]) {
            if ($null -ne $From -and $e.T -lt $From) { continue }
            if ($null -ne $To -and $e.T -gt $To) { continue }
            [void]$out.Add($e)
        }
    }
    if ($out.Count -eq 0) { return @() }
    return @($out.ToArray() | Sort-Object -Property T)
}

function Get-EvData {
    param($Ev, [string]$Name)
    if ($null -eq $Ev -or $null -eq $Ev.Data) { return $null }
    if ($Ev.Data.ContainsKey($Name)) { return [string]$Ev.Data[$Name] }
    return $null
}

function Get-ChanShort {
    param([string]$Log)
    $k = ([string]$Log).ToLower()
    if ($script:ChanShort.ContainsKey($k)) { return $script:ChanShort[$k] }
    return $Log
}

# Live read into the pool. Returns the number read, or -1 on a real error.
function Read-Log {
    param([hashtable]$Filter, [int]$Max = 500, [switch]$NoCapFlag)
    $log = [string]$Filter['LogName']
    try {
        $evs = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop)
        foreach ($e in $evs) { Add-PoolEvent (ConvertTo-NormEvent $e) }
        # Only history/lookback reads count as "capped"; targeted window reads are small on purpose.
        if ($evs.Count -ge $Max -and -not $NoCapFlag -and -not $script:PhaseTwo) { $script:Truncated[$log] = $true }
        return $evs.Count
    } catch {
        $fq = [string]$_.FullyQualifiedErrorId
        if ($fq -like 'NoMatchingEventsFound*') { return 0 }
        $msg = [string]$_.Exception.Message
        if ($fq -like 'NoMatchingLogsFound*') { $script:QueryErrors[$log] = 'channel not present' }
        elseif ($msg -match '(?i)access|unauthori') { $script:QueryErrors[$log] = 'access denied' }
        elseif (-not $script:QueryErrors.ContainsKey($log)) { $script:QueryErrors[$log] = (Limit-Text $msg 120) }
        return -1
    }
}

# =============================================================================
# DECODERS
# =============================================================================
function Get-ReasonInfo {
    param([string]$CodeText)
    $r = @{ Hex = [string]$CodeText; Known = $false; Planned = $false; UserDefined = $false
            Major = ''; Minor = ''; MajorN = -1; MinorN = -1; Servicing = $false; Text = 'not recorded' }
    $v = $null
    $s = ([string]$CodeText).Trim()
    if ($s -match '^0x([0-9a-fA-F]+)$') {
        $h = $Matches[1]
        try { $v = [Convert]::ToInt64($h, 16) } catch { }
    } elseif ($s -match '^\d+$') {
        try { $v = [int64]$s } catch { }
    }
    if ($null -eq $v) { return $r }
    $r.Known = $true
    $r.Planned = (($v -band 0x80000000L) -ne 0)
    $r.UserDefined = (($v -band 0x40000000L) -ne 0)
    $maj = [int](($v -band 0x00FF0000L) / 0x10000L)
    $min = [int]($v -band 0xFFFFL)
    $r.MajorN = $maj
    $r.MinorN = $min
    if ($script:ReasonMajor.ContainsKey($maj)) { $r.Major = $script:ReasonMajor[$maj] } else { $r.Major = 'Major ' + $maj }
    if ($script:ReasonMinor.ContainsKey($min)) { $r.Minor = $script:ReasonMinor[$min] } else { $r.Minor = 'Minor ' + $min }
    $r.Servicing = ($maj -eq 2 -and (@(2, 3, 16, 17, 18) -contains $min))
    $plan = Pick $r.Planned 'planned' 'unplanned'
    if ($v -eq 0) {
        $r.Text = 'Other (unplanned) - no reason supplied; Windows records this when a restart or shutdown is requested without a reason, including ordinary Start-menu restarts on client Windows'
    } elseif ($min -eq 255) {
        $r.Text = $r.Major + ': none supplied (' + $plan + ') - typical of shutdown.exe or an API call made without a reason'
    } else {
        $r.Text = $r.Major + ': ' + $r.Minor + ' (' + $plan + ')'
    }
    if ($r.UserDefined) { $r.Text += ', custom (user-defined) reason' }
    return $r
}

function Get-InitiatorFrom1074 {
    param($Ev)
    $p1 = Get-EvData $Ev 'param1'
    $proc = ''
    if ($p1) { $proc = ($p1 -replace '\s*\([^()]*\)\s*$', '').Trim() }
    $user = Get-EvData $Ev 'param7'
    $reasonText = Get-EvData $Ev 'param3'
    $code = Get-EvData $Ev 'param4'
    $action = Get-EvData $Ev 'param5'
    $comment = Get-EvData $Ev 'param6'
    # Message fallback for providers that did not render named data
    if (-not $proc -and $Ev.Msg -match 'The process (.+?) has initiated') { $g = $Matches[1]; $proc = ($g -replace '\s*\([^()]*\)\s*$', '').Trim() }
    if (-not $user -and $Ev.Msg -match 'on behalf of user (\S+)') { $g = $Matches[1]; $user = $g }
    if (-not $code -and $Ev.Msg -match 'Reason Code:\s*(0x[0-9A-Fa-f]+)') { $g = $Matches[1]; $code = $g }
    if (-not $action -and $Ev.Msg -match 'Shutdown Type:\s*(.+?)\s*(Comment:|$)') { $g = $Matches[1]; $action = $g }
    $leaf = ''
    if ($proc) { $leaf = ($proc -split '\\')[-1] }
    $ri = Get-ReasonInfo $code
    $cat = 'unknown'; $conf = 'low'
    $label = 'Unrecognised process'
    $caveat = 'Not a known Windows, update, remote-management or installer signature - identify what software this belongs to.'
    foreach ($sig in $script:InitiatorSigs) {
        if ($leaf -match ('(?i)' + $sig.Re)) {
            $cat = $sig.Cat; $conf = $sig.Conf; $label = $sig.Label; $caveat = $sig.Caveat
            break
        }
    }
    # Reason-code overrides: a servicing reason from a generic process is Windows Update.
    if ((@('unknown', 'system-process') -contains $cat) -and $ri.Servicing -and $ri.Planned) {
        $cat = 'windows-update'; $conf = 'medium'
        $label = 'Windows service with an OS servicing reason - typically Windows Update / servicing'
        $caveat = 'Process name is generic; the planned servicing reason code is what points to updates.'
    }
    if ($cat -eq 'command-line' -and (Test-IsSystemAccount $user)) {
        $label += ' - run as SYSTEM, so a scheduled task, management agent or startup script'
    }
    return [pscustomobject]@{
        Source = '1074'; RequestedAt = $Ev.T; Process = $proc; ProcessName = $leaf; User = $user
        ReasonText = $reasonText; Code = $code; Reason = $ri; Action = $action; Comment = $comment
        Category = $cat; Label = $label; Conf = $conf; Caveat = $caveat; DelaySec = $null
    }
}

function Get-Kp109Info {
    param($Ev)
    if ($null -eq $Ev) { return $null }
    $act = Get-EvData $Ev 'ShutdownActionType'
    $acts = @{ '4' = 'Shutdown'; '5' = 'Restart'; '6' = 'Power off' }
    $actText = ''
    if ($act -and $acts.ContainsKey($act)) { $actText = $acts[$act] }
    $reason = ''
    $msg = [string]$Ev.Msg
    $i = $msg.LastIndexOf('Reason:')
    if ($i -ge 0) { $reason = $msg.Substring($i + 7).Trim().TrimEnd('.') }
    $kind = ''
    if ($reason -match '(?i)button') { $kind = 'power-button' }
    elseif ($reason -match '(?i)thermal|temperature') { $kind = 'thermal' }
    elseif ($reason -match '(?i)battery') { $kind = 'battery' }
    elseif ($reason -match '(?i)\blid\b') { $kind = 'lid' }
    elseif ($reason -match '(?i)kernel api') { $kind = 'software-request' }
    elseif ($reason) { $kind = 'other' }
    return [pscustomobject]@{ Action = $actText; Reason = $reason; Kind = $kind }
}

function Get-Kp41Info {
    param($Ev)
    if ($null -eq $Ev) { return $null }
    $bc = 0L
    try { $v = Get-EvData $Ev 'BugcheckCode'; if ($v) { $bc = [int64]$v } } catch { }
    $pb = $false
    try { $v = Get-EvData $Ev 'PowerButtonTimestamp'; if ($v -and $v -ne '0') { $pb = ([uint64]$v -ne 0) } } catch { }
    $long = ((Get-EvData $Ev 'LongPowerButtonPressDetected') -eq 'true')
    $sl = Get-EvData $Ev 'SleepInProgress'
    $sleep = ($sl -and $sl -ne '0' -and $sl -ne 'false')
    $params = @()
    foreach ($n in 'BugcheckParameter1', 'BugcheckParameter2', 'BugcheckParameter3', 'BugcheckParameter4') {
        $v = Get-EvData $Ev $n
        if ($v) { try { $params += ('0x{0:X}' -f [uint64]$v) } catch { $params += $v } }
    }
    return [pscustomobject]@{ BugcheckCode = $bc; PowerButton = $pb; LongPress = $long; SleepInProgress = $sleep; Params = $params }
}

function Get-Bug1001Info {
    param($Ev)
    if ($null -eq $Ev) { return $null }
    $text = Get-EvData $Ev 'param1'
    if (-not $text) { $text = [string]$Ev.Msg }
    $code = $null; $params = ''; $dump = ''
    if ($text -match '(0x[0-9a-fA-F]+)\s*\(([^)]*)\)') {
        $g1 = $Matches[1]; $g2 = $Matches[2]
        try { $code = [Convert]::ToInt64($g1.Substring(2), 16) } catch { }
        $params = $g2
    } elseif ([string]$Ev.Msg -match 'bugcheck was:\s*(0x[0-9A-Fa-f]+)') {
        $g1 = $Matches[1]
        try { $code = [Convert]::ToInt64($g1.Substring(2), 16) } catch { }
    }
    $dump = Get-EvData $Ev 'param2'
    if (-not $dump -and [string]$Ev.Msg -match 'saved in:\s*(\S+?\.dmp)') { $g = $Matches[1]; $dump = $g }
    if ($null -eq $code) { return $null }
    return [pscustomobject]@{ Code = $code; Params = $params; Dump = $dump }
}

function Get-WerInfo {
    param($Ev)
    $name = Get-EvData $Ev 'EventName'
    if (-not $name -and $Ev.Msg -match 'Event Name:\s*(\S+)') { $g = $Matches[1]; $name = $g }
    $p1 = Get-EvData $Ev 'P1'
    return [pscustomobject]@{ EventName = $name; P1 = $p1; P2 = (Get-EvData $Ev 'P2'); P3 = (Get-EvData $Ev 'P3'); P4 = (Get-EvData $Ev 'P4'); P5 = (Get-EvData $Ev 'P5') }
}

function Get-FaultingApp {
    param($Ev)
    $m = [string]$Ev.Msg
    $p0 = Get-EvData $Ev 'p0'
    if ($Ev.Id -eq 1000 -and $p0) { return $p0 }
    if ($m -match 'Faulting application name:\s*([^\s,]+)') { $g = $Matches[1]; return $g }
    if ($m -match 'The program\s+(\S+)\s+version') { $g = $Matches[1]; return $g }
    if ($m -match 'Application:\s*(\S+?\.exe)') { $g = $Matches[1]; return $g }
    if ($m -match '([\w.+-]+\.exe)') { $g = $Matches[1]; return $g }
    return '(unknown)'
}

# 6008 payload: SYSTEMTIME structure(s) in the binary data (the 6005 payload on Win 11 is UTC).
function Get-6008Time {
    param($Ev)
    $hex = [string]$Ev.Bin
    if ($hex.Length -lt 32) { return $null }
    $times = @()
    for ($o = 0; ($o + 32) -le $hex.Length; $o += 32) {
        try {
            $b = New-Object byte[] 16
            for ($j = 0; $j -lt 16; $j++) { $b[$j] = [Convert]::ToByte($hex.Substring($o + $j * 2, 2), 16) }
            $y = [BitConverter]::ToUInt16($b, 0); $mo = [BitConverter]::ToUInt16($b, 2)
            $d = [BitConverter]::ToUInt16($b, 6); $h = [BitConverter]::ToUInt16($b, 8)
            $mi = [BitConverter]::ToUInt16($b, 10); $s = [BitConverter]::ToUInt16($b, 12)
            if ($y -ge 2000 -and $y -le 2100 -and $mo -ge 1 -and $mo -le 12 -and $d -ge 1 -and $d -le 31) {
                $times += (New-Object DateTime($y, $mo, $d, $h, $mi, $s))
            }
        } catch { }
    }
    if ($times.Count -eq 0) { return $null }
    # Two structures = local then UTC; one = UTC. Express in the event's own offset.
    $utc = $times[$times.Count - 1]
    $dto = New-Object DateTimeOffset($utc, [TimeSpan]::Zero)
    return $dto.ToOffset($Ev.T.Offset)
}

# Kernel dump header: "PAGE"+"DU64" (x64: code @0x38, params @0x40..0x58) / "PAGE"+"DUMP" (x86: code @0x28)
function Get-DumpInfo {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $hdr = New-Object byte[] 96
            if ($fs.Read($hdr, 0, 96) -lt 96) { return $null }
        } finally { $fs.Dispose() }
        $sig = [System.Text.Encoding]::ASCII.GetString($hdr, 0, 4)
        $sig2 = [System.Text.Encoding]::ASCII.GetString($hdr, 4, 4)
        if ($sig -ne 'PAGE') { return $null }
        $p = @()
        if ($sig2 -eq 'DU64') {
            $code = [int64][BitConverter]::ToUInt32($hdr, 0x38)
            foreach ($o in 0x40, 0x48, 0x50, 0x58) { $p += ('0x{0:X}' -f [BitConverter]::ToUInt64($hdr, $o)) }
        } elseif ($sig2 -eq 'DUMP') {
            $code = [int64][BitConverter]::ToUInt32($hdr, 0x28)
            foreach ($o in 0x2C, 0x30, 0x34, 0x38) { $p += ('0x{0:X}' -f [BitConverter]::ToUInt32($hdr, $o)) }
        } else { return $null }
        return [pscustomobject]@{ Code = $code; Params = $p }
    } catch { return $null }
}

# =============================================================================
# LIVE COLLECTION
# =============================================================================
$script:Meta = @{}
$script:Coverage = @{}
$script:Dumps = New-Object System.Collections.ArrayList
$script:DumpCap = [pscustomobject]@{ status = 'UNKNOWN'; reasons = @() }
$script:Devices = @()
$script:Attr = [pscustomobject]@{ taskHistory = 'unknown'; processAudit = 'unknown'; cmdLine = 'unknown'; changed = @(); notes = @() }

function Get-ChannelCoverage {
    param([string]$Log)
    $c = [pscustomobject]@{ log = $Log; state = 'unknown'; records = $null; oldest = $null; maxMB = $null; error = $null }
    try {
        $l = Get-WinEvent -ListLog $Log -ErrorAction Stop
        $c.records = $l.RecordCount
        $c.maxMB = [math]::Round($l.MaximumSizeInBytes / 1MB, 1)
        $c.state = Pick $l.IsEnabled 'enabled' 'disabled'
        try {
            $o = Get-WinEvent -LogName $Log -MaxEvents 1 -Oldest -ErrorAction Stop
            if ($o) { $c.oldest = New-Object DateTimeOffset($o.TimeCreated) }
        } catch {
            $fq = [string]$_.FullyQualifiedErrorId
            if ($fq -like 'NoMatchingEventsFound*') { $c.records = 0 }
            elseif ([string]$_.Exception.Message -match '(?i)access|unauthori') { $c.state = 'denied'; $c.error = 'access denied' }
        }
    } catch {
        $fq = [string]$_.FullyQualifiedErrorId
        $m = [string]$_.Exception.Message
        if ($fq -like 'NoMatchingLogsFound*') { $c.state = 'missing' }
        elseif ($fq -like 'LogInfoUnavailable*' -or $m -match '(?i)access|unauthori') { $c.state = 'denied'; $m = 'access denied (not elevated?)' }
        else { $c.state = 'error' }
        $c.error = Limit-Text $m 120
    }
    return $c
}

function Get-AttributionState {
    $a = [pscustomobject]@{ taskHistory = 'unknown'; processAudit = 'unknown'; cmdLine = 'unknown'; changed = @(); notes = @() }
    $tc = $script:Coverage['microsoft-windows-taskscheduler/operational']
    if ($tc) { $a.taskHistory = Pick ($tc.state -eq 'enabled') 'on' (Pick ($tc.state -eq 'disabled') 'off' 'unknown') }
    try {
        $out = & auditpol.exe /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /r 2>$null
        $rows = @($out | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv)
        if ($rows.Count -gt 0) {
            $inc = [string]$rows[0].'Inclusion Setting'
            if ($inc -match '(?i)success') { $a.processAudit = 'on' }
            elseif ($inc -match '(?i)no auditing') { $a.processAudit = 'off' }
            elseif ($inc) { $a.processAudit = 'off (' + $inc + ')' }
        }
    } catch { }
    if ($a.processAudit -eq 'unknown' -and -not $script:IsAdmin) { $a.processAudit = 'unknown (reading audit policy needs elevation)' }
    try {
        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction Stop).ProcessCreationIncludeCmdLine_Enabled
        $a.cmdLine = Pick ($v -eq 1) 'on' 'off'
    } catch { $a.cmdLine = 'off' }
    return $a
}

function Invoke-LiveCollection {
    $now = New-Object DateTimeOffset((Get-Date))
    $script:Now = $now
    $L = $now.AddDays(-$LookbackDays).LocalDateTime
    $H = $now.AddDays(-$HistoryDays).LocalDateTime

    # --- Host facts ---
    $os = Get-First (Get-CimSafe 'Win32_OperatingSystem')
    $caption = ''; $ver = ''; $lastBoot = $null
    if ($os) {
        $caption = ([string]$os.Caption -replace 'Microsoft ', '').Trim()
        $ver = [string]$os.Version
        $lb = $os.LastBootUpTime
        if ($lb -is [datetime]) { $lastBoot = New-Object DateTimeOffset($lb) }
        elseif ($lb) { try { $lastBoot = New-Object DateTimeOffset([Management.ManagementDateTimeConverter]::ToDateTime([string]$lb)) } catch { } }
    }
    $disp = ''
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.PSObject.Properties['DisplayVersion'] -and $cv.DisplayVersion) { $disp = $cv.DisplayVersion }
        elseif ($cv.PSObject.Properties['ReleaseId'] -and $cv.ReleaseId) { $disp = $cv.ReleaseId }
    } catch { }
    $fast = 'unknown'
    try {
        $hb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
        $fast = Pick ($hb -eq 1) 'on' 'off'
    } catch { }
    $tz = ''
    try { $tz = [TimeZoneInfo]::Local.Id } catch { }
    $script:Meta = @{
        host = $env:COMPUTERNAME; os = (($caption + ' ' + $disp).Trim() + ' (build ' + $ver + ')')
        ps = $PSVersionTable.PSVersion.ToString(); generated = $now; lastBoot = $lastBoot
        tz = $tz; fastStartup = $fast; elevated = $script:IsAdmin; mode = 'live'
    }

    # --- Coverage of every channel the analysis relies on ---
    foreach ($ch in $script:Channels) { $script:Coverage[$ch.ToLower()] = Get-ChannelCoverage $ch }

    # --- Core transition events (lookback) ---
    $q = @(
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12, 13; StartTime = $L }; M = 400 }
        @{ F = @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6005, 6006, 6008; StartTime = $L }; M = 400 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $H }; M = 20 }
        @{ F = @{ LogName = 'System'; ProviderName = 'User32'; Id = 1074, 1076; StartTime = $L }; M = 300 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41, 109, 42, 107; StartTime = $L }; M = 400 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $H }; M = 200 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 506, 507; StartTime = $L }; M = 60 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27; StartTime = $L }; M = 200 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $L }; M = 100 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $H }; M = 100 }
        @{ F = @{ LogName = 'System'; ProviderName = 'volmgr'; Id = 45, 46, 49, 161; StartTime = $H }; M = 100 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19, 20, 43, 44; StartTime = $L }; M = 300 }
        # Background health (history)
        @{ F = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $H }; M = 1000 }
        @{ F = @{ LogName = 'System'; Id = 129, 153; StartTime = $H }; M = 400 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101, 4104; StartTime = $H }; M = 200 }
        @{ F = @{ LogName = 'System'; ProviderName = 'Ntfs', 'Microsoft-Windows-Ntfs'; Id = 55, 130, 140; StartTime = $H }; M = 200 }
        @{ F = @{ LogName = 'System'; ProviderName = 'disk', 'Microsoft-Windows-Disk', 'volsnap', 'Microsoft-Windows-StorDiag'; Level = 1, 2, 3; StartTime = $H }; M = 400 }
        @{ F = @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $H }; M = 400 }
        @{ F = @{ LogName = 'Application'; ProviderName = 'Application Error', 'Application Hang'; Id = 1000, 1002; StartTime = $H }; M = 400 }
    )
    foreach ($item in $q) {
        # Modern Standby enter/exit is high-volume context; its small cap is deliberate.
        $nc = ($item.F['Id'] -and (@($item.F['Id']) -contains 506))
        [void](Read-Log -Filter $item.F -Max $item.M -NoCapFlag:$nc)
    }

    # --- Dumps on disk ---
    $files = New-Object System.Collections.ArrayList
    $mem = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (Test-Path -LiteralPath $mem) { $f = Get-Item -LiteralPath $mem -ErrorAction SilentlyContinue; if ($f) { [void]$files.Add(@($f, 'MEMORY.DMP')) } }
    foreach ($dir in @((Join-Path $env:SystemRoot 'Minidump'), (Join-Path $env:SystemRoot 'LiveKernelReports'))) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $label = Split-Path $dir -Leaf
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.dmp' -ErrorAction SilentlyContinue)) { if (-not $f.PSIsContainer) { [void]$files.Add(@($f, $label)) } }
        foreach ($sub in @(Get-ChildItem -LiteralPath $dir -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
            foreach ($f in @(Get-ChildItem -LiteralPath $sub.FullName -Filter '*.dmp' -ErrorAction SilentlyContinue)) {
                if (-not $f.PSIsContainer) { [void]$files.Add(@($f, ($label + '\' + $sub.Name))) }
            }
        }
    }
    $sorted = @($files.ToArray() | Sort-Object { $_[0].LastWriteTime } -Descending | Select-Object -First 20)
    $n = 0
    foreach ($pair in $sorted) {
        $f = $pair[0]
        $info = $null
        if ($n -lt 12) { $info = Get-DumpInfo $f.FullName }
        $n++
        [void]$script:Dumps.Add([pscustomobject]@{
            name = $f.Name; loc = $pair[1]; written = (New-Object DateTimeOffset($f.LastWriteTime))
            sizeMB = [math]::Round($f.Length / 1MB, 1)
            code = (Pick ($null -ne $info) $info.Code $null); params = (Pick ($null -ne $info) $info.Params @())
        })
    }

    # --- Dump capability ---
    $st = 'OK'; $rs = @()
    try {
        $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
        $types = @{ 0 = 'None'; 1 = 'Complete'; 2 = 'Kernel'; 3 = 'Small (minidump)'; 7 = 'Automatic' }
        $ty = [int]$cc.CrashDumpEnabled
        if ($ty -eq 0) { $st = 'BROKEN'; $rs += 'crash dumps disabled (type None)' }
        $pf = @(Get-CimSafe 'Win32_PageFileUsage')
        $ded = ''
        if ($cc.PSObject.Properties['DedicatedDumpFile']) { $ded = [string]$cc.DedicatedDumpFile }
        if ($pf.Count -eq 0 -and -not $ded) { $st = 'BROKEN'; $rs += 'no pagefile and no dedicated dump file' }
        $dp = ''
        if ($cc.PSObject.Properties['DumpFile']) { $dp = [Environment]::ExpandEnvironmentVariables([string]$cc.DumpFile) }
        if ($dp) {
            try {
                $free = [math]::Floor((New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($dp))).AvailableFreeSpace / 1MB)
                if ($free -lt 800) { if ($st -eq 'OK') { $st = 'LIMITED' }; $rs += ('low free space on dump volume (' + $free + ' MB)') }
            } catch { }
        }
        $tn = Pick ($types.ContainsKey($ty)) $types[$ty] ('type ' + $ty)
        $script:DumpCap = [pscustomobject]@{ status = $st; reasons = $rs; type = $tn; autoReboot = [bool]($cc.AutoReboot -eq 1) }
    } catch {
        $script:DumpCap = [pscustomobject]@{ status = 'UNKNOWN'; reasons = @('could not read CrashControl'); type = ''; autoReboot = $null }
    }

    # --- Problem devices ---
    $devs = @(Get-CimSafe 'Win32_PnPEntity' 'ConfigManagerErrorCode <> 0')
    $script:Devices = @($devs | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; code = [int]$_.ConfigManagerErrorCode } })
    $script:Meta['deviceCount'] = $devs.Count

    # --- Attribution logging state ---
    $script:Attr = Get-AttributionState
}

# Phase 2 (live): per-episode evidence windows, read after episodes are known.
function Invoke-LiveWindowReads {
    param($Episodes)
    foreach ($ep in $Episodes) {
        $boot = $ep.Boot.LocalDateTime
        $prev = $null
        if ($ep.PrevBoundary) { $prev = $ep.PrevBoundary.LocalDateTime }
        else { $prev = $ep.Boot.AddDays(-$HistoryDays).LocalDateTime }
        # Shutdown path, even when it fell outside the lookback
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'User32'; Id = 1074; StartTime = $prev; EndTime = $boot } -Max 5)
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6006; StartTime = $prev; EndTime = $boot } -Max 3)
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 13; StartTime = $prev; EndTime = $boot } -Max 3)
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 109; StartTime = $prev; EndTime = $boot } -Max 3)
        # Last sign of life before the boot
        $endAlive = $ep.Boot.AddSeconds(-2).LocalDateTime
        [void](Read-Log -Filter @{ LogName = 'System'; StartTime = $prev; EndTime = $endAlive } -Max 8)
        [void](Read-Log -Filter @{ LogName = 'Application'; StartTime = $prev; EndTime = $endAlive } -Max 4)
    }
}

function Invoke-LiveCorrelationReads {
    param($Episodes)
    foreach ($ep in $Episodes) {
        $t0 = $ep.T0
        $a = $t0.AddMinutes(-$WindowBefore).LocalDateTime
        $b = $t0.AddMinutes($WindowAfter).LocalDateTime
        $bootEnd = $ep.Boot.AddMinutes($WindowAfter).LocalDateTime
        if ($bootEnd -gt $b) { $wEnd = $bootEnd } else { $wEnd = $b }
        [void](Read-Log -Filter @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $a; EndTime = $b } -Max 80)
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Winlogon'; Id = 7001, 7002; StartTime = $a; EndTime = $b } -Max 20)
        [void](Read-Log -Filter @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034; StartTime = $a; EndTime = $b } -Max 20)
        [void](Read-Log -Filter @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $a; EndTime = $b } -Max 60)
        [void](Read-Log -Filter @{ LogName = 'Application'; ProviderName = 'MsiInstaller', 'Microsoft-Windows-RestartManager'; StartTime = $a; EndTime = $b } -Max 60)
        [void](Read-Log -Filter @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime = $a; EndTime = $wEnd } -Max 60)
        [void](Read-Log -Filter @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 100, 102, 106, 107, 110, 129, 200, 201; StartTime = $a; EndTime = $b } -Max 150)
        [void](Read-Log -Filter @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21, 23, 24, 25; StartTime = (Get-SessionWindowStart $ep).LocalDateTime; EndTime = $wEnd } -Max 300 -NoCapFlag)
        [void](Read-Log -Filter @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = $t0.AddHours(-24).LocalDateTime; EndTime = $b } -Max 30)
        $sa = $t0.AddMinutes(-$WindowBefore).LocalDateTime
        $sb2 = $t0.AddMinutes(2).LocalDateTime
        [void](Read-Log -Filter @{ LogName = 'Security'; Id = 4647, 4688, 1102; StartTime = $sa; EndTime = $sb2 } -Max 400)
        [void](Read-Log -Filter @{ LogName = 'Security'; Id = 4624; StartTime = $sa; EndTime = $sb2 } -Max 200)
    }
}

# =============================================================================
# REPLAY COLLECTION (fixture / exported evidence)
# =============================================================================
function ConvertTo-Hashtable {
    param($Obj)
    $h = @{}
    if ($null -eq $Obj) { return $h }
    if ($Obj -is [hashtable]) { return $Obj }
    foreach ($p in $Obj.PSObject.Properties) { $h[$p.Name] = [string]$p.Value }
    return $h
}

function Invoke-ReplayCollection {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Replay file not found: $Path" }
    $raw = [System.IO.File]::ReadAllText($Path)
    $fx = $raw | ConvertFrom-Json
    $m = $fx.meta
    $gen = ConvertTo-Dto $m.generated
    if ($null -eq $gen) { $gen = New-Object DateTimeOffset((Get-Date)) }
    $script:Now = $gen
    $script:Meta = @{
        host = [string]$m.host; os = [string]$m.os; ps = [string]$m.ps; generated = $gen
        lastBoot = (ConvertTo-Dto $m.lastBoot); tz = [string]$m.tz; fastStartup = (Pick ($m.fastStartup) ([string]$m.fastStartup) 'unknown')
        elevated = $true; mode = 'replay'; deviceCount = 0
    }
    foreach ($e in @($fx.events)) {
        if ($null -eq $e) { continue }
        $t = ConvertTo-Dto $e.t
        if ($null -eq $t) { continue }
        $rec = 0L
        if ($e.rec) { $rec = [int64]$e.rec }
        $ev = New-NormEvent -T $t -Log ([string]$e.log) -Prov ([string]$e.prov) -Id ([int]$e.id) -Ver ([int]$e.ver) -Rec $rec `
              -Lvl ([int]$e.lvl) -Data (ConvertTo-Hashtable $e.data) -Bin ([string]$e.bin) -Msg ([string]$e.msg)
        Add-PoolEvent $ev
    }
    foreach ($c in @($fx.coverage)) {
        if ($null -eq $c) { continue }
        $script:Coverage[([string]$c.log).ToLower()] = [pscustomobject]@{
            log = [string]$c.log; state = [string]$c.state; records = $c.records; oldest = (ConvertTo-Dto $c.oldest)
            maxMB = $c.maxMB; error = [string]$c.error }
    }
    foreach ($ch in $script:Channels) {
        if (-not $script:Coverage.ContainsKey($ch.ToLower())) {
            $script:Coverage[$ch.ToLower()] = [pscustomobject]@{ log = $ch; state = 'unknown'; records = $null; oldest = $null; maxMB = $null; error = 'not in fixture' }
        }
    }
    foreach ($d in @($fx.dumps)) {
        if ($null -eq $d) { continue }
        $code = $null
        if ($d.code) { try { $code = [Convert]::ToInt64(([string]$d.code -replace '^0x', ''), 16) } catch { } }
        [void]$script:Dumps.Add([pscustomobject]@{ name = [string]$d.name; loc = [string]$d.loc; written = (ConvertTo-Dto $d.written)
            sizeMB = $d.sizeMB; code = $code; params = @($d.params) })
    }
    if ($fx.dumpCap) { $script:DumpCap = [pscustomobject]@{ status = [string]$fx.dumpCap.status; reasons = @($fx.dumpCap.reasons); type = [string]$fx.dumpCap.type; autoReboot = $fx.dumpCap.autoReboot } }
    else { $script:DumpCap = [pscustomobject]@{ status = 'OK'; reasons = @(); type = 'Automatic'; autoReboot = $true } }
    $script:Devices = @(@($fx.devices) | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; code = [int]$_.code } })
    $script:Meta['deviceCount'] = $script:Devices.Count
    if ($fx.attribution) {
        $script:Attr = [pscustomobject]@{ taskHistory = [string]$fx.attribution.taskHistory; processAudit = [string]$fx.attribution.processAudit
            cmdLine = [string]$fx.attribution.cmdLine; changed = @(); notes = @() }
    } else {
        $tc = $script:Coverage['microsoft-windows-taskscheduler/operational']
        $th = 'unknown'
        if ($tc) { $th = Pick ($tc.state -eq 'enabled') 'on' (Pick ($tc.state -eq 'disabled') 'off' 'unknown') }
        $script:Attr = [pscustomobject]@{ taskHistory = $th; processAudit = 'unknown'; cmdLine = 'unknown'; changed = @(); notes = @() }
    }
}

function Get-ChanState {
    param([string]$Log)
    $k = $Log.ToLower()
    $c = $null
    if ($script:Coverage.ContainsKey($k)) { $c = $script:Coverage[$k] }
    if ($null -eq $c) { return [pscustomobject]@{ log = $Log; state = 'unknown'; oldest = $null; error = $null } }
    if ($script:QueryErrors.ContainsKey($Log) -and $c.state -eq 'enabled') {
        $qe = $script:QueryErrors[$Log]
        if ($qe -eq 'access denied') { $c.state = 'denied' }
        $c.error = $qe
    }
    return $c
}
# Usable = enabled, readable and its oldest record is not after the window start.
function Test-ChanUsable {
    param([string]$Log, $WindowStart)
    $c = Get-ChanState $Log
    if ($c.state -ne 'enabled') { return $false }
    if ($null -ne $c.oldest -and $null -ne $WindowStart -and $c.oldest -gt $WindowStart) { return $false }
    return $true
}
function Get-ChanGapText {
    param([string]$Log, $WindowStart)
    $c = Get-ChanState $Log
    $short = Get-ChanShort $Log
    switch ($c.state) {
        'disabled' { return ($Log + ' is disabled (history off)') }
        'missing'  { return ($Log + ' does not exist on this system') }
        'denied'   { return ($Log + ' could not be read (access denied)') }
        'unknown'  { return ($Log + ' state unknown') }
        'error'    { return ($Log + ' query error: ' + $c.error) }
    }
    if ($null -ne $c.oldest -and $null -ne $WindowStart -and $c.oldest -gt $WindowStart) {
        return ($Log + ' only goes back to ' + (Format-Time $c.oldest) + ' (rolled over)')
    }
    return ''
}

# =============================================================================
# EPISODE BUILDER + CLASSIFIER
# =============================================================================
function Get-BootAnchors {
    $anchors = New-Object System.Collections.ArrayList
    foreach ($e in @(Find-Ev -Prov 'Microsoft-Windows-Kernel-General' -Id 12)) {
        [void]$anchors.Add([pscustomobject]@{ T = $e.T; Source = 'Kernel-General 12'; Ev = $e })
    }
    foreach ($e in @(Find-Ev -Prov 'EventLog' -Id 6005)) {
        $near = $false
        foreach ($a in $anchors) { if ([math]::Abs((Get-Sec $a.T $e.T)) -le 120) { $near = $true; break } }
        if (-not $near) { [void]$anchors.Add([pscustomobject]@{ T = $e.T; Source = 'EventLog 6005'; Ev = $e }) }
    }
    $lb = $script:Meta['lastBoot']
    if ($null -ne $lb) {
        $near = $false
        foreach ($a in $anchors) { if ([math]::Abs((Get-Sec $a.T $lb)) -le 180) { $near = $true; break } }
        if (-not $near) { [void]$anchors.Add([pscustomobject]@{ T = $lb; Source = 'OS last boot time'; Ev = $null }) }
    }
    if ($anchors.Count -eq 0) { return @() }
    $sorted = @($anchors.ToArray() | Sort-Object -Property T)
    $out = New-Object System.Collections.ArrayList
    foreach ($a in $sorted) {
        $last = Get-Last $out.ToArray()
        if ($null -ne $last -and (Get-Sec $a.T $last.T) -le 120) { continue }
        [void]$out.Add($a)
    }
    return @($out.ToArray())
}

function Get-SeqText {
    param($Ev, $Ep)
    $p = [string]$Ev.Prov
    $id = $Ev.Id
    if ($p -eq 'User32' -and $id -eq 1074) {
        $i = Get-InitiatorFrom1074 $Ev
        return ('{0} requested by {1} for {2} (reason {3})' -f (Pick $i.Action $i.Action 'shutdown'), (Pick $i.ProcessName $i.ProcessName '?'), (Pick $i.User $i.User '?'), (Pick $i.Code $i.Code '?'))
    }
    if ($p -eq 'User32' -and $id -eq 1076) { return ('Reason given after an unexpected shutdown: ' + (Limit-Text $Ev.Msg 100)) }
    if ($p -eq 'EventLog' -and $id -eq 6006) { return 'Event Log service stopped (orderly shutdown)' }
    if ($p -eq 'EventLog' -and $id -eq 6005) { return 'Event Log service started' }
    if ($p -eq 'EventLog' -and $id -eq 6008) {
        $pt = Get-6008Time $Ev
        if ($pt) { return ('Previous shutdown was unexpected (payload time ' + (Format-Time $pt) + ')') }
        return 'Previous shutdown was unexpected'
    }
    if ($p -eq 'Microsoft-Windows-Kernel-General' -and $id -eq 13) { return 'Operating system shutting down' }
    if ($p -eq 'Microsoft-Windows-Kernel-General' -and $id -eq 12) { return 'Operating system started' }
    if ($p -eq 'Microsoft-Windows-Kernel-Power' -and $id -eq 109) {
        $k = Get-Kp109Info $Ev
        $t = 'Kernel power manager began the shutdown'
        if ($k.Action) { $t += ' (' + $k.Action + ')' }
        if ($k.Reason) { $t += '; reason: ' + $k.Reason }
        return $t
    }
    if ($p -eq 'Microsoft-Windows-Kernel-Power' -and $id -eq 41) {
        $k = Get-Kp41Info $Ev
        $t = 'Rebooted without a clean shutdown (Kernel-Power 41): BugcheckCode ' + (Pick ($k.BugcheckCode -ne 0) (Format-BugHex $k.BugcheckCode) '0')
        if ($k.PowerButton) { $t += ', power-button press recorded' }
        if ($k.LongPress) { $t += ', long press detected' }
        if ($k.SleepInProgress) { $t += ', during a sleep transition' }
        return $t
    }
    if ($p -eq 'Microsoft-Windows-Kernel-Boot' -and $id -eq 27) {
        $bt = Get-EvData $Ev 'BootType'
        $names = @{ '0' = 'cold boot'; '1' = 'fast startup (hybrid boot)'; '2' = 'resume from hibernation' }
        $n = Pick ($bt -and $names.ContainsKey($bt)) $names[$bt] ('type ' + $bt)
        return ('Boot type 0x' + $bt + ' = ' + $n)
    }
    if ($p -eq 'Microsoft-Windows-WER-SystemErrorReporting' -and $id -eq 1001) {
        $b = Get-Bug1001Info $Ev
        if ($b) { return ('Bugcheck recorded: ' + (Format-BugHex $b.Code) + ' ' + (Get-BugMeta $b.Code).Name) }
        return 'Bugcheck recorded'
    }
    if ($p -eq 'volmgr') {
        $names = @{ 45 = 'crash dump driver failed to load'; 46 = 'crash dump initialisation failed'; 49 = 'pagefile for crash dumps could not be configured'; 161 = 'crash dump could not be written' }
        return ('volmgr ' + $id + ': ' + (Pick ($names.ContainsKey($id)) $names[$id] 'dump-related error'))
    }
    if ($p -eq 'Windows Error Reporting' -and $id -eq 1001) {
        $w = Get-WerInfo $Ev
        return ('WER ' + $w.EventName + ' report (P1 ' + $w.P1 + ')')
    }
    return ($p + ' ' + $id + ': ' + (Limit-Text $Ev.Msg 90))
}

function New-Episode {
    param($Anchor, $Prev, $Next, [int]$Number)
    $boot = $Anchor.T
    $from = $null
    if ($Prev) { $from = $Prev.T } else { $from = $boot.AddDays(-$HistoryDays) }
    $nextT = $null
    if ($Next) { $nextT = $Next.T }
    $fwd15 = $boot.AddMinutes(15)
    $fwd60 = $boot.AddMinutes(60)
    if ($nextT -and $nextT -lt $fwd15) { $fwd15 = $nextT.AddSeconds(-1) }
    if ($nextT -and $nextT -lt $fwd60) { $fwd60 = $nextT.AddSeconds(-1) }
    $justBefore = $boot.AddSeconds(-1)

    $ep = [pscustomobject]@{
        Id = $Number; Boot = $boot; BootSource = $Anchor.Source; BootType = ''; PrevBoundary = (Pick $Prev $from $null)
        Down = $null; DownSource = ''; DowntimeSec = $null; Type = ''; TypeConf = ''; Summary = ''
        Initiator = $null; Kp109 = $null; Kp41 = $null; Bug = $null; DumpFail = @(); MatchedDumps = @()
        LastAlive = $null; T0 = $null; Seq = @(); Corr = @(); Sessions = @(); Hyp = @()
        Established = @(); NotEstablished = @(); Ask = @(); Next = @(); Notes = @(); IsCurrent = $false; Unexplained = $false
    }

    $e1074 = Get-Last (Find-Ev -Prov 'User32' -Id 1074 -From $from -To $justBefore)
    $e6006 = Get-Last (Find-Ev -Prov 'EventLog' -Id 6006 -From $from -To $justBefore)
    $e13   = Get-Last (Find-Ev -Prov 'Microsoft-Windows-Kernel-General' -Id 13 -From $from -To $justBefore)
    $e109  = Get-Last (Find-Ev -Prov 'Microsoft-Windows-Kernel-Power' -Id 109 -From $from -To $justBefore)
    $e41   = Get-First (Find-Ev -Prov 'Microsoft-Windows-Kernel-Power' -Id 41 -From $boot.AddSeconds(-60) -To $fwd15)
    $e6008 = Get-First (Find-Ev -Prov 'EventLog' -Id 6008 -From $boot.AddSeconds(-60) -To $fwd15)
    $e1001 = Get-First (Find-Ev -Prov 'Microsoft-Windows-WER-SystemErrorReporting' -Id 1001 -From $boot.AddSeconds(-60) -To $fwd60)
    $e1076 = Get-First (Find-Ev -Prov 'User32' -Id 1076 -From $boot -To $fwd60)
    # Nearest boot-type record within 60 s (a hibernate resume minutes earlier is a different event)
    $e27 = $null
    foreach ($c in @(Find-Ev -Prov 'Microsoft-Windows-Kernel-Boot' -Id 27 -From $boot.AddSeconds(-60) -To $boot.AddSeconds(60))) {
        if ($null -eq $e27 -or [math]::Abs((Get-Sec $c.T $boot)) -lt [math]::Abs((Get-Sec $e27.T $boot))) { $e27 = $c }
    }
    $eDumpFail = @(Find-Ev -Prov 'volmgr' -Id 45, 46, 49, 161 -From $boot.AddSeconds(-60) -To $fwd15)
    $eWerBlue = $null
    foreach ($w in @(Find-Ev -Prov 'Windows Error Reporting' -Id 1001 -From $boot.AddSeconds(-60) -To $fwd60)) {
        if ((Get-WerInfo $w).EventName -eq 'BlueScreen') { $eWerBlue = $w; break }
    }

    # Last logged activity before the boot (excluding boot-time providers)
    $alive = $null
    foreach ($log in 'System', 'Application') {
        foreach ($e in @(Find-ByLog -Log $log -From $from -To $boot.AddSeconds(-2))) {
            if ($e.Prov -eq 'Microsoft-Windows-Kernel-Boot') { continue }
            if ($e.Prov -eq 'EventLog' -and $e.Id -eq 6005) { continue }
            if ($null -eq $alive -or $e.T -gt $alive.T) { $alive = $e }
        }
    }
    $ep.LastAlive = $alive

    if ($e27) {
        $bt = Get-EvData $e27 'BootType'
        $names = @{ '0' = 'cold'; '1' = 'fast-startup'; '2' = 'hibernate-resume' }
        if ($bt -and $names.ContainsKey($bt)) { $ep.BootType = $names[$bt] }
    }
    if ($e109) { $ep.Kp109 = Get-Kp109Info $e109 }

    # Shutdown marker = start of the orderly shutdown path
    $marker = $null
    foreach ($c in @($e6006, $e109, $e13)) { if ($c -and ($null -eq $marker -or $c.T -lt $marker.T)) { $marker = $c } }

    # Link the 1074 only if it belongs to this shutdown (not an earlier, abandoned request)
    $linked = $null
    if ($e1074) {
        $ref = $marker
        if ($null -eq $ref) { $ref = $alive }
        $gap = 0
        if ($ref) { $gap = Get-Sec $ref.T $e1074.T }
        if ($null -ne $marker) {
            if ($gap -ge -5 -and $gap -le 43200) { $linked = $e1074 }
        } elseif ($null -ne $alive) {
            if ($gap -le 1800) { $linked = $e1074 }
        } else { $linked = $e1074 }
        if ($null -eq $linked) {
            $ep.Notes += ('An earlier restart request at ' + (Format-Time $e1074.T) + ' was not followed by a shutdown and is treated as abandoned.')
        }
    }
    if ($linked) {
        $ep.Initiator = Get-InitiatorFrom1074 $linked
        if ($marker) {
            $d = Get-Sec $marker.T $linked.T
            $ep.Initiator.DelaySec = $d
            if ($d -gt 120) { $ep.Notes += ('The shutdown began ' + (Format-Span $d) + ' after the request (timed/delayed restart, or the request waited for apps or a user to respond).') }
        }
    }

    $unclean = ($null -ne $e41 -or $null -ne $e6008)
    $k41 = $null
    if ($e41) { $k41 = Get-Kp41Info $e41; $ep.Kp41 = $k41 }

    # Bugcheck evidence: KP41 code, System 1001, WER BlueScreen
    $bug = $null
    if ($k41 -and $k41.BugcheckCode -ne 0) {
        $bug = [pscustomobject]@{ Code = $k41.BugcheckCode; Params = ($k41.Params -join ', '); Source = 'Kernel-Power 41'; Dump = '' }
    }
    if ($e1001) {
        $bi = Get-Bug1001Info $e1001
        if ($bi) {
            if ($null -eq $bug) { $bug = [pscustomobject]@{ Code = $bi.Code; Params = $bi.Params; Source = 'BugCheck 1001'; Dump = $bi.Dump } }
            else { $bug.Source += ' + BugCheck 1001'; $bug.Dump = $bi.Dump; if (-not $bug.Params) { $bug.Params = $bi.Params } }
        }
    }
    if ($eWerBlue -and $null -eq $bug) {
        $wi = Get-WerInfo $eWerBlue
        try {
            $c = [Convert]::ToInt64(([string]$wi.P1 -replace '^0x', ''), 16)
            $bug = [pscustomobject]@{ Code = $c; Params = (@($wi.P2, $wi.P3, $wi.P4, $wi.P5) -join ', '); Source = 'WER BlueScreen'; Dump = '' }
        } catch { }
    }
    if ($bug) {
        $meta = Get-BugMeta $bug.Code
        $bug | Add-Member -NotePropertyName Hex -NotePropertyValue (Format-BugHex $bug.Code)
        $bug | Add-Member -NotePropertyName Name -NotePropertyValue $meta.Name
        $bug | Add-Member -NotePropertyName Cat -NotePropertyValue $meta.Cat
        $bug | Add-Member -NotePropertyName Hint -NotePropertyValue $meta.Hint
        $ep.Bug = $bug
    }
    foreach ($f in $eDumpFail) { $ep.DumpFail += (Get-SeqText $f $ep) }

    # --- Classification (evidence-led; volmgr 161 alone is never a crash) ---
    if ($unclean -or $bug) {
        if ($bug) {
            $ep.Type = 'unclean-bugcheck'
            $ep.TypeConf = Pick ($bug.Source -match 'Kernel-Power|1001') 'high' 'medium'
        } elseif ($k41 -and ($k41.PowerButton -or $k41.LongPress)) {
            $ep.Type = 'unclean-powerbutton'
            $ep.TypeConf = Pick $k41.LongPress 'high' 'medium'
        } else {
            $ep.Type = 'unclean-no-bugcheck'
            $ep.TypeConf = Pick ($null -ne $e41) 'high' 'medium'
        }
    } elseif ($linked) {
        $act = ([string]$ep.Initiator.Action).ToLower()
        if ($act -match 'restart|reboot') { $ep.Type = 'controlled-restart' } else { $ep.Type = 'controlled-poweroff' }
        $ep.TypeConf = Pick ($null -ne $e6006 -or $null -ne $e13) 'high' 'medium'
    } elseif ($marker) {
        $ep.Type = 'orderly-no-initiator'
        $ep.TypeConf = 'medium'
    } else {
        $ep.Type = 'insufficient-evidence'
        $ep.TypeConf = 'low'
    }

    # Initiator when no 1074: KP109 reason can still name a physical/policy cause
    if ($null -eq $ep.Initiator -and $ep.Kp109 -and $ep.Kp109.Kind -and $ep.Kp109.Kind -ne 'other') {
        $kind = $ep.Kp109.Kind
        $map = @{
            'power-button'     = @('power-button', 'medium', 'Physical power button (short press set to shut down)', 'Kernel-Power 109 reports the power button; it does not say who pressed it.')
            'thermal'          = @('thermal-protection', 'medium', 'Thermal protection shutdown', 'The firmware/OS shut down to protect against overheating - run the thermal companion script.')
            'battery'          = @('battery-critical', 'medium', 'Critical battery level', 'The power policy shut down on a critical battery level.')
            'lid'              = @('power-policy', 'medium', 'Lid / power policy action', 'Power policy acted on a lid or power event.')
            'software-request' = @('unknown', 'low', 'Software request through the kernel API, with no restart request (1074) recorded', 'A component asked the kernel to shut down without the usual User32 record.')
        }
        if ($map.ContainsKey($kind)) {
            $v = $map[$kind]
            $ep.Initiator = [pscustomobject]@{
                Source = 'kp109'; RequestedAt = $e109.T; Process = ''; ProcessName = ''; User = ''; ReasonText = $ep.Kp109.Reason
                Code = ''; Reason = (Get-ReasonInfo ''); Action = $ep.Kp109.Action; Comment = ''
                Category = $v[0]; Conf = $v[1]; Label = $v[2]; Caveat = $v[3]; DelaySec = $null }
        }
    }

    # Down time and T0
    if ($ep.Type -like 'unclean-*' -or $ep.Type -eq 'insufficient-evidence') {
        if ($alive) { $ep.Down = $alive.T; $ep.DownSource = 'last logged activity' }
    } else {
        if ($e13) { $ep.Down = $e13.T; $ep.DownSource = 'Kernel-General 13' }
        elseif ($e6006) { $ep.Down = $e6006.T; $ep.DownSource = 'EventLog 6006' }
        elseif ($alive) { $ep.Down = $alive.T; $ep.DownSource = 'last logged activity' }
    }
    if ($ep.Down) { $ep.DowntimeSec = Get-Sec $boot $ep.Down }
    if ($ep.Initiator -and $ep.Initiator.Source -eq '1074') { $ep.T0 = $ep.Initiator.RequestedAt }
    elseif ($marker) { $ep.T0 = $marker.T }
    elseif ($ep.Down) { $ep.T0 = $ep.Down }
    else { $ep.T0 = $boot }

    # Sequence (raw evidence, ordered)
    $seq = New-Object System.Collections.ArrayList
    foreach ($c in @($linked, $e6006, $e109, $e13, $e41, $e6008, $e1001, $e1076, $e27, $eWerBlue)) { if ($c) { [void]$seq.Add($c) } }
    foreach ($c in $eDumpFail) { [void]$seq.Add($c) }
    if ($Anchor.Ev) { [void]$seq.Add($Anchor.Ev) }
    $e6005 = Get-First (Find-Ev -Prov 'EventLog' -Id 6005 -From $boot.AddSeconds(-5) -To $boot.AddSeconds(120))
    if ($e6005) { [void]$seq.Add($e6005) }
    if ($alive) {
        $dup = $false
        foreach ($c in $seq) { if ($c.Key -eq $alive.Key) { $dup = $true } }
        if (-not $dup) { [void]$seq.Add($alive) }
    }
    $items = @()
    foreach ($c in @($seq.ToArray() | Sort-Object -Property T)) {
        $txt = Get-SeqText $c $ep
        if ($alive -and $c.Key -eq $alive.Key -and -not ($c.Prov -eq 'EventLog' -or $c.Prov -like 'Microsoft-Windows-Kernel-*' -or $c.Prov -eq 'User32')) {
            $txt = 'Last logged activity: ' + $txt
        }
        $items += [pscustomobject]@{ T = $c.T; Off = (Get-Sec $c.T $ep.T0); Ch = (Get-ChanShort $c.Log); Prov = $c.Prov; Id = $c.Id; Text = $txt }
    }
    $ep.Seq = @($items | Select-Object -First 20)

    if ($ep.Type -eq 'controlled-poweroff' -and $ep.BootType -eq 'fast-startup') {
        $ep.Notes += 'The next boot was a fast-startup (hybrid) boot, so this power-off hibernated the kernel session rather than fully shutting down.'
    }
    if ($ep.Type -like 'unclean-*' -and $linked) {
        $ep.Notes += ('A ' + $ep.Initiator.Action + ' was requested at ' + (Format-Time $linked.T) + ' but Windows did not complete a clean shutdown (it stopped responding or crashed while shutting down).')
    }
    return $ep
}

# =============================================================================
# CORRELATION + SESSIONS + HYPOTHESES
# =============================================================================
function Get-CorrItem {
    param($Ev, $Ep)
    $p = [string]$Ev.Prov
    $id = $Ev.Id
    $log = ([string]$Ev.Log).ToLower()
    $tag = ''; $text = ''; $w = 1
    if ($p -eq 'Microsoft-Windows-WindowsUpdateClient') {
        $title = Get-EvData $Ev 'updateTitle'
        switch ($id) {
            19 { $tag = 'wu-installed'; $text = 'Update installed: ' + $title; $w = 3 }
            20 { $tag = 'wu-install-failed'; $text = 'Update install failed: ' + $title; $w = 3 }
            43 { $tag = 'wu-install-started'; $text = 'Update install started: ' + $title; $w = 3 }
            44 { $tag = 'wu-download-started'; $text = 'Update download started: ' + $title; $w = 2 }
            26 { $tag = 'wu-found'; $text = 'Update scan found ' + (Get-EvData $Ev 'updateCount') + ' update(s)'; $w = 2 }
            default {
                $m = [string]$Ev.Msg
                if ($m -match '(?i)restart|reboot') { $tag = 'wu-restart-required'; $w = 3 }
                elseif ($m -match '(?i)install') { $tag = 'wu-installed'; $w = 3 }
                elseif ($m -match '(?i)download') { $tag = 'wu-download-started'; $w = 2 }
                elseif ($m -match '(?i)found') { $tag = 'wu-found'; $w = 2 }
                else { $tag = 'wu-activity'; $w = 1 }
                $text = Limit-Text $m 110
            }
        }
    } elseif ($log -eq 'microsoft-windows-taskscheduler/operational') {
        $tn = Get-EvData $Ev 'TaskName'
        $an = Get-EvData $Ev 'ActionName'
        if (-not $tn) { return $null }
        if (($tn + ' ' + $an) -match '(?i)reboot|restart|shut ?down|\\UpdateOrchestrator\\|USO_|MusUx|ExitWindows' -and $tn -notmatch '(?i)reboot required') { $tag = 'task-reboot'; $w = 4 }
        else { $tag = 'task-ran'; $w = 1 }
        $verb = @{ 100 = 'started'; 102 = 'completed'; 106 = 'registered'; 107 = 'started by time trigger'; 110 = 'started by a user'; 129 = 'created a process'; 200 = 'action started'; 201 = 'action completed' }
        $text = 'Task ' + $tn + ' ' + (Pick ($verb.ContainsKey($id)) $verb[$id] ('event ' + $id))
        if ($an -and $tag -eq 'task-reboot') { $text += ' (' + (Limit-Text $an 60) + ')' }
    } elseif ($p -eq 'MsiInstaller') {
        $m = [string]$Ev.Msg
        if ($m -match '(?i)restart|reboot') { $tag = 'installer-restart'; $w = 4 }
        else { $tag = 'installer-activity'; $w = 2 }
        $text = Limit-Text $m 110
    } elseif ($p -eq 'Microsoft-Windows-RestartManager') {
        $tag = 'restartmgr-session'; $w = 2
        $text = 'Restart Manager session (an installer/updater closing apps): ' + (Limit-Text $Ev.Msg 70)
    } elseif ($p -eq 'Application Error') {
        $tag = 'app-crash'; $w = 2; $text = 'Application crash: ' + (Get-FaultingApp $Ev)
    } elseif ($p -eq 'Application Hang') {
        $tag = 'app-hang'; $w = 2; $text = 'Application stopped responding: ' + (Get-FaultingApp $Ev)
    } elseif ($p -eq 'Windows Error Reporting') {
        $wi = Get-WerInfo $Ev
        if ($wi.EventName -eq 'BlueScreen') { return $null }
        if ($wi.EventName -eq 'LiveKernelEvent') {
            $code = ([string]$wi.P1).ToLower().TrimStart('0')
            $nm = Pick ($script:LiveKernelNames.ContainsKey($code)) $script:LiveKernelNames[$code] ('code ' + $wi.P1)
            $tag = 'livekernel'; $w = 3; $text = 'Live kernel event (device/driver hang captured without a crash): ' + $nm
        } else { return $null }
    } elseif ($p -eq 'Microsoft-Windows-Winlogon') {
        if ($id -eq 7002) { $tag = 'user-logoff-notify'; $w = 2; $text = 'User sign-out notification (session ' + (Get-EvData $Ev 'TSId') + ')' }
        elseif ($id -eq 7001) { $tag = 'user-logon-notify'; $w = 1; $text = 'User sign-in notification (session ' + (Get-EvData $Ev 'TSId') + ')' }
        else { return $null }
    } elseif ($p -eq 'Service Control Manager' -and (@(7031, 7034) -contains $id)) {
        $tag = 'service-crash'; $w = 2; $text = 'Service terminated unexpectedly: ' + (Pick (Get-EvData $Ev 'param1') (Get-EvData $Ev 'param1') (Limit-Text $Ev.Msg 80))
    } elseif ($log -eq 'microsoft-windows-terminalservices-localsessionmanager/operational') {
        $u = Get-EvData $Ev 'User'; $addr = Get-EvData $Ev 'Address'
        $via = ''
        if ($addr) { $via = Pick ($addr -eq 'LOCAL') ' at the console' (' from ' + $addr) }
        switch ($id) {
            21 { $tag = 'session-logon'; $w = 2; $text = 'Session sign-in: ' + $u + $via }
            22 { return $null }
            23 { $tag = 'session-logoff'; $w = 2; $text = 'Session sign-out: ' + $u }
            24 { $tag = 'session-disconnect'; $w = 1; $text = 'Session disconnected: ' + $u + $via }
            25 { $tag = 'session-reconnect'; $w = 2; $text = 'Session reconnected: ' + $u + $via }
            default { return $null }
        }
    } elseif ($log -eq 'microsoft-windows-terminalservices-remoteconnectionmanager/operational') {
        $tag = 'rdp-auth'; $w = 2
        $u = Get-EvData $Ev 'Param1'; $dom = Get-EvData $Ev 'Param2'
        $text = 'RDP authentication from ' + (Get-EvData $Ev 'Param3') + (Pick $u (' as ' + (Pick $dom ($dom + '\') '') + $u) '')
    } elseif ($log -eq 'security') {
        if ($id -eq 4647) { $tag = 'user-logoff-4647'; $w = 3; $text = 'Sign-out started from within the session of ' + (Get-EvData $Ev 'TargetDomainName') + '\' + (Get-EvData $Ev 'TargetUserName') + ' (Security 4647)' }
        elseif ($id -eq 4624) {
            $lt = Get-EvData $Ev 'LogonType'
            if (-not (@('2', '7', '10', '11') -contains $lt)) { return $null }
            $types = @{ '2' = 'console'; '7' = 'unlock'; '10' = 'RDP'; '11' = 'cached' }
            $tag = 'logon'; $w = 1
            $text = 'Sign-in (' + $types[$lt] + '): ' + (Get-EvData $Ev 'TargetDomainName') + '\' + (Get-EvData $Ev 'TargetUserName')
            $ip = Get-EvData $Ev 'IpAddress'
            if ($ip -and $ip -ne '-' -and $ip -ne '127.0.0.1' -and $ip -ne '::1') { $text += ' from ' + $ip }
        } elseif ($id -eq 4688) {
            $np = Get-EvData $Ev 'NewProcessName'
            if (-not ($np -match '(?i)\\(shutdown|msiexec|powershell|pwsh|cmd|wscript|cscript|wmic|rundll32)\.exe$')) { return $null }
            $tag = 'process-created'; $w = Pick ($np -match '(?i)shutdown') 4 2
            $text = 'Process ' + (Split-Path $np -Leaf) + ' started by ' + (Get-EvData $Ev 'ParentProcessName')
            $cl = Get-EvData $Ev 'CommandLine'
            if ($cl) { $text += ' : ' + (Limit-Text $cl 80) }
        } elseif ($id -eq 1102) { $tag = 'log-cleared'; $w = 3; $text = 'The Security log was cleared' }
        else { return $null }
    } elseif ($p -eq 'Microsoft-Windows-Kernel-Power' -and (@(42, 107) -contains $id)) {
        if ($id -eq 42) { $tag = 'sleep-enter'; $text = 'System entering sleep: ' + (Limit-Text $Ev.Msg 70) } else { $tag = 'sleep-resume'; $text = 'System resumed from sleep' }
        $w = 1
    } elseif ($p -eq 'Microsoft-Windows-WHEA-Logger') {
        $tag = 'whea'; $w = 3; $text = 'Hardware error (WHEA ' + $id + '): ' + (Limit-Text $Ev.Msg 80)
    } elseif ($log -eq 'system' -and $Ev.Lvl -ge 1 -and $Ev.Lvl -le 2) {
        if (@('User32', 'EventLog', 'Microsoft-Windows-Kernel-General', 'Microsoft-Windows-Kernel-Boot', 'Microsoft-Windows-Kernel-Power', 'volmgr', 'Microsoft-Windows-WER-SystemErrorReporting') -contains $p) { return $null }
        $m = [string]$Ev.Msg
        if ($m -match '(?i)thermal|temperature') { $tag = 'thermal'; $w = 3 }
        elseif ($p -match $script:StorageProvRe -and (@(129, 153) -contains $id)) { $tag = 'storage-reset'; $w = 3 }
        else { $tag = 'system-error'; $w = 1 }
        $text = $p + ' ' + $id + ': ' + (Limit-Text $m 90)
    } else {
        return $null
    }
    $pos = 'before'
    if ($Ev.T -ge $Ep.Boot) { $pos = 'after-boot' }
    elseif ($Ev.T -gt $Ep.T0) { $pos = 'during' }
    return [pscustomobject]@{ T = $Ev.T; Off = (Get-Sec $Ev.T $Ep.T0); Pos = $pos; Ch = (Get-ChanShort $Ev.Log); Prov = $p; Id = $id
                              Tag = $tag; Text = (Limit-Text $text 150); W = $w }
}

function Get-Correlations {
    param($Ep)
    $a = $Ep.T0.AddMinutes(-$WindowBefore)
    $b = $Ep.T0.AddMinutes($WindowAfter)
    $bootEnd = $Ep.Boot.AddMinutes($WindowAfter)
    $seqKeys = @{}
    foreach ($s in $Ep.Seq) { $seqKeys[([string]$s.Prov + '|' + $s.Id + '|' + $s.T.UtcTicks)] = $true }
    $out = New-Object System.Collections.ArrayList
    $logs = @('System', 'Application', 'Security', 'Microsoft-Windows-WindowsUpdateClient/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
              'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational')
    foreach ($log in $logs) {
        $evs = @(Find-ByLog -Log $log -From $a -To $b)
        if ($Ep.Boot -gt $b) { $evs += @(Find-ByLog -Log $log -From $Ep.Boot -To $bootEnd) }
        foreach ($e in $evs) {
            if ($seqKeys.ContainsKey(([string]$e.Prov + '|' + $e.Id + '|' + $e.T.UtcTicks))) { continue }
            $ci = Get-CorrItem $e $Ep
            if ($null -eq $ci) { continue }
            # After the boot only startup-relevant signals are kept (the rest is boot chatter)
            if ($ci.Pos -eq 'after-boot' -and -not ($ci.Tag -like 'wu-*' -or $ci.Tag -like 'session-*')) { continue }
            # Generic errors while an orderly shutdown is already running are shutdown chatter
            if ($ci.Pos -eq 'during' -and $ci.Tag -eq 'system-error') { continue }
            # Routine tasks only matter just before the request
            if ($ci.Tag -eq 'task-ran' -and ($ci.Off -lt -300 -or $ci.Off -gt 30)) { continue }
            if (($ci.Tag -like 'session-*') -and $ci.Pos -eq 'before' -and $ci.Off -lt -($WindowBefore * 60)) { continue }
            [void]$out.Add($ci)
        }
    }
    # De-duplicate the same signal logged twice (e.g. Windows Update in System and Operational)
    $seen = @{}
    $uniq = New-Object System.Collections.ArrayList
    foreach ($c in @($out.ToArray() | Sort-Object -Property T)) {
        $k = $c.Tag + '|' + $c.Text
        if ($seen.ContainsKey($k) -and [math]::Abs((Get-Sec $c.T $seen[$k])) -le 5) { continue }
        $seen[$k] = $c.T
        [void]$uniq.Add($c)
    }
    # Only the first few post-boot signals matter (they show what happened after, not before)
    $kept = New-Object System.Collections.ArrayList
    $afterWu = 0; $afterSess = 0
    foreach ($c in $uniq) {
        if ($c.Pos -eq 'after-boot') {
            if ($c.Tag -like 'wu-*') { $afterWu++; if ($afterWu -gt 2) { continue } }
            else { $afterSess++; if ($afterSess -gt 2) { continue } }
        }
        [void]$kept.Add($c)
    }
    # Keep the strongest and nearest items
    $ranked = @($kept.ToArray() | Sort-Object @{ Expression = { $_.W }; Descending = $true }, @{ Expression = { [math]::Abs($_.Off) }; Descending = $false } | Select-Object -First 20)
    return @($ranked | Sort-Object -Property T)
}

# Sessions open at T0, rebuilt from LocalSessionManager history since the previous boot
# (sessions never survive a reboot, so that is the complete window).
function Get-SessionWindowStart {
    param($Ep)
    if ($Ep.PrevBoundary) { return $Ep.PrevBoundary }
    return $Ep.T0.AddDays(-7)
}
function Get-SessionsAt {
    param($T0, $From)
    $state = @{}
    foreach ($e in @(Find-ByLog -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -From $From -To $T0)) {
        $sid = Get-EvData $e 'SessionID'
        if (-not $sid) { $sid = Get-EvData $e 'Session' }
        if (-not $sid) { continue }
        $u = Get-EvData $e 'User'; $addr = Get-EvData $e 'Address'
        if (-not $state.ContainsKey($sid)) { $state[$sid] = @{ user = ''; addr = ''; st = '' } }
        $s = $state[$sid]
        if ($u) { $s.user = $u }
        switch ($e.Id) {
            21 { $s.st = 'active'; if ($addr) { $s.addr = $addr } }
            25 { $s.st = 'active'; if ($addr) { $s.addr = $addr } }
            24 { $s.st = 'disconnected' }
            23 { $s.st = 'signed-out' }
        }
    }
    $out = @()
    foreach ($k in $state.Keys) {
        $s = $state[$k]
        if ($s.st -eq 'active' -or $s.st -eq 'disconnected') {
            $via = Pick ($s.addr -eq 'LOCAL' -or -not $s.addr) 'console' 'rdp'
            $out += [pscustomobject]@{ user = $s.user; session = $k; state = $s.st; via = $via; address = $s.addr }
        }
    }
    return @($out)
}

function New-Hyp {
    param([string]$Key, [string]$Label)
    return [pscustomobject]@{ Key = $Key; Label = $Label; Score = 0; For = @(); Against = @(); Gaps = @(); Status = ''; Conf = '' }
}
function Add-HypFor { param($H, [int]$W, [string]$Text) $H.Score += $W; $H.For += $Text }
function Add-HypAgainst { param($H, [int]$W, [string]$Text) $H.Score -= $W; $H.Against += $Text }

function Get-Hypotheses {
    param($Ep)
    $init = $Ep.Initiator
    $cat = ''
    if ($init) { $cat = $init.Category }
    $corr = @($Ep.Corr)
    $wStart = $Ep.T0.AddMinutes(-$WindowBefore)
    $list = New-Object System.Collections.ArrayList

    # --- Windows Update / servicing ---
    $h = New-Hyp 'windows-update' 'Windows Update / servicing restart'
    if ($cat -eq 'windows-update') { Add-HypFor $h 3 ('Requested by a Windows Update component (' + $init.ProcessName + ')') }
    if ($init -and $init.Reason.Known -and $init.Reason.Servicing) { Add-HypFor $h 3 ('Reason code ' + $init.Code + ' = ' + $init.Reason.Major + ': ' + $init.Reason.Minor + ' (servicing)') }
    $wuTask = @($corr | Where-Object { $_.Tag -eq 'task-reboot' -and $_.Text -match '(?i)UpdateOrchestrator|USO_|MusUx' })
    if ($wuTask.Count -gt 0) { Add-HypFor $h 3 ($wuTask[0].Text + ' at ' + (Format-Offset $wuTask[0].Off)) }
    $wuBefore = @($corr | Where-Object { $_.Pos -eq 'before' -and (@('wu-installed', 'wu-install-started', 'wu-restart-required') -contains $_.Tag) })
    if ($wuBefore.Count -gt 0) { Add-HypFor $h 2 ([string]$wuBefore.Count + ' update install/restart event(s) before the request (first ' + (Format-Offset $wuBefore[0].Off) + ')') }
    $wuAny = @($corr | Where-Object { $_.Tag -like 'wu-*' })
    $wuAfter = @($wuAny | Where-Object { $_.Pos -eq 'after-boot' })
    if ($wuAfter.Count -gt 0 -and $wuBefore.Count -eq 0 -and $cat -ne 'windows-update') {
        Add-HypAgainst $h 2 ('Windows Update activity in the window is only after the boot (first ' + (Format-Offset $wuAfter[0].Off) + ': ' + $wuAfter[0].Text + ')')
    }
    if ($cat -and $cat -ne 'windows-update' -and $cat -ne 'unknown' -and $cat -ne 'system-process' -and -not ($init.Reason.Servicing)) {
        Add-HypAgainst $h 1 ('The recorded requester is ' + $init.ProcessName + ' (' + $cat + ') with a non-servicing reason')
    }
    $wuLog = 'Microsoft-Windows-WindowsUpdateClient/Operational'
    if (-not (Test-ChanUsable $wuLog $wStart)) { $h.Gaps += (Get-ChanGapText $wuLog $wStart) }
    elseif ($wuAny.Count -eq 0 -and $cat -ne 'windows-update') { Add-HypAgainst $h 1 ('No Windows Update events within ' + $WindowBefore + ' min before the request (log readable)') }
    [void]$list.Add($h)

    # --- Action in the signed-in session ---
    $h = New-Hyp 'interactive' 'Action in the signed-in session (a person, or an app/prompt running in that session)'
    $user = ''
    if ($init) { $user = [string]$init.User }
    # The requester alone reaches "medium" at most; "high" needs session evidence.
    if ($cat -eq 'interactive-shell' -or $cat -eq 'signin-screen') { Add-HypFor $h 2 ('Requested through ' + $init.ProcessName + ' (' + $cat + ')') }
    if ($user -and -not (Test-IsSystemAccount $user)) { Add-HypFor $h 1 ('On behalf of a user account (' + $user + ')') }
    elseif ($user -and (Test-IsSystemAccount $user)) { Add-HypAgainst $h 3 ('Requested as ' + $user + ', not a signed-in user') }
    $sess = @($Ep.Sessions)
    $sws = Get-SessionWindowStart $Ep
    $mine = @($sess | Where-Object { $user -and $_.user -and $_.user -ieq $user -and $_.state -eq 'active' })
    if ($mine.Count -gt 0) {
        $s = $mine[0]
        Add-HypFor $h 2 ('That account had an active ' + (Pick ($s.via -eq 'rdp') ('RDP session from ' + $s.address) 'console session') + ' at the time')
    } elseif ($user -and -not (Test-IsSystemAccount $user)) {
        $lsm = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        if (Test-ChanUsable $lsm $sws) {
            if (@(Find-ByLog -Log $lsm -From $sws -To $Ep.T0).Count -gt 0) { Add-HypAgainst $h 1 ('No active session for ' + $user + ' found in the session log at the time') }
        } else { $h.Gaps += (Get-ChanGapText $lsm $sws) }
    }
    $lo = @($corr | Where-Object { $_.Tag -eq 'user-logoff-4647' -and $_.Pos -eq 'before' })
    if ($lo.Count -gt 0) { Add-HypFor $h 2 ($lo[0].Text + ' at ' + (Format-Offset $lo[0].Off)) }
    $lo2 = @($corr | Where-Object { $_.Tag -eq 'user-logoff-notify' -and $_.Pos -eq 'before' })
    if ($lo2.Count -gt 0 -and $lo.Count -eq 0) { Add-HypFor $h 1 ('Sign-out notification at ' + (Format-Offset $lo2[0].Off)) }
    [void]$list.Add($h)

    # --- Scheduled task ---
    $h = New-Hyp 'scheduled-task' 'Scheduled task'
    $tr = @($corr | Where-Object { $_.Tag -eq 'task-reboot' -and $_.Off -ge -600 -and $_.Off -le 60 })
    if ($tr.Count -gt 0) { Add-HypFor $h 4 ($tr[0].Text + ' at ' + (Format-Offset $tr[0].Off)) }
    $trun = @($corr | Where-Object { $_.Tag -eq 'task-ran' -and $_.Off -ge -120 -and $_.Off -le 5 })
    if ($trun.Count -gt 0 -and $tr.Count -eq 0) { Add-HypFor $h 1 ($trun[0].Text + ' at ' + (Format-Offset $trun[0].Off)) }
    if ((@('command-line', 'wmi') -contains $cat) -and (Test-IsSystemAccount $user)) { Add-HypFor $h 1 ('Command-line/WMI request running as ' + $user + ' (typical of tasks and agents)') }
    $tl = 'Microsoft-Windows-TaskScheduler/Operational'
    if (-not (Test-ChanUsable $tl $wStart)) { $h.Gaps += (Get-ChanGapText $tl $wStart) }
    else {
        $any = @(Find-ByLog -Log $tl -From $Ep.T0.AddMinutes(-10) -To $Ep.T0.AddSeconds(30))
        if ($any.Count -eq 0) { Add-HypAgainst $h 2 'Task Scheduler history is on and no task ran in the 10 minutes before the request' }
    }
    [void]$list.Add($h)

    # --- Remote management / remote session ---
    $h = New-Hyp 'remote' 'Remote management, remote support or a remote session'
    if ($cat -eq 'rmm-remote') { Add-HypFor $h 4 ('Requested by ' + $init.ProcessName + ' (remote-management agent)') }
    if ($cat -eq 'mdm') { Add-HypFor $h 4 ('Requested by ' + $init.ProcessName + ' (MDM)') }
    if ($cat -eq 'wmi') { Add-HypFor $h 2 'Requested through WMI (commonly remote management or scripts)' }
    if ($init -and $init.Comment) { Add-HypFor $h 1 ('A shutdown comment was supplied: "' + (Limit-Text $init.Comment 60) + '" (typical of scripted/remote shutdown /c)') }
    $rdp = @($sess | Where-Object { $_.via -eq 'rdp' -and $_.state -eq 'active' })
    if ($rdp.Count -gt 0) { Add-HypFor $h 2 ('Active RDP session: ' + $rdp[0].user + ' from ' + $rdp[0].address) }
    $pc = @($corr | Where-Object { $_.Tag -eq 'process-created' -and $_.Text -match '(?i)atera|screenconnect|splashtop|teamviewer|anydesk|ninja|ltsvc|kaseya|cagservice|syncro' })
    if ($pc.Count -gt 0) { Add-HypFor $h 4 $pc[0].Text }
    [void]$list.Add($h)

    # --- Installer / updater ---
    $h = New-Hyp 'installer' 'Software installer or vendor updater'
    if ($cat -eq 'installer' -or $cat -eq 'oem-updater') { Add-HypFor $h 3 ('Requested by ' + $init.ProcessName + ' (' + $cat + ')') }
    if ($init -and $init.Reason.Known -and $init.Reason.MajorN -eq 4 -and $init.Reason.MinorN -eq 2) { Add-HypFor $h 2 ('Reason code ' + $init.Code + ' = Application: Installation') }
    $ir = @($corr | Where-Object { $_.Tag -eq 'installer-restart' -and $_.Pos -eq 'before' })
    if ($ir.Count -gt 0) { Add-HypFor $h 3 ($ir[0].Text + ' at ' + (Format-Offset $ir[0].Off)) }
    $ia = @($corr | Where-Object { ($_.Tag -eq 'installer-activity' -or $_.Tag -eq 'restartmgr-session') -and $_.Pos -eq 'before' })
    if ($ia.Count -gt 0) { Add-HypFor $h 1 ([string]$ia.Count + ' installer/Restart Manager event(s) before the request (first ' + (Format-Offset $ia[0].Off) + ')') }
    [void]$list.Add($h)

    # --- Fault before the shutdown (apps, services, devices) ---
    $h = New-Hyp 'fault-before' 'Application, service or device fault shortly before'
    $fb = @($corr | Where-Object { $_.Pos -ne 'after-boot' -and (@('app-crash', 'app-hang', 'service-crash', 'livekernel', 'storage-reset', 'whea', 'thermal') -contains $_.Tag) })
    # Closer in time weighs more (still correlation): within 5 min before, or a hardware-class signal.
    foreach ($f in @($fb | Select-Object -First 3)) { Add-HypFor $h (Pick ($f.W -ge 3 -or ($f.Off -le 0 -and $f.Off -ge -300)) 2 1) ($f.Text + ' at ' + (Format-Offset $f.Off)) }
    [void]$list.Add($h)

    # --- Unclean-specific ---
    if ($Ep.Type -eq 'unclean-bugcheck' -and $Ep.Bug) {
        $h = New-Hyp 'kernel-crash' 'Kernel crash (bugcheck)'
        Add-HypFor $h 4 ($Ep.Bug.Hex + ' ' + $Ep.Bug.Name + ' recorded by ' + $Ep.Bug.Source + ' - ' + $Ep.Bug.Hint)
        if (@($Ep.MatchedDumps).Count -gt 0) { Add-HypFor $h 1 ('Matching dump on disk: ' + $Ep.MatchedDumps[0]) }
        [void]$list.Add($h)
    }
    if ($Ep.Type -eq 'unclean-no-bugcheck' -or $Ep.Type -eq 'unclean-powerbutton') {
        $h = New-Hyp 'power-hang' 'Power loss, hard hang or hardware reset'
        if ($Ep.Type -eq 'unclean-powerbutton') { Add-HypFor $h 3 'Power-button press recorded by Kernel-Power 41 (switched off by hand, usually after a freeze)' }
        else { Add-HypFor $h 2 'Unclean shutdown with no bugcheck code (Kernel-Power 41 / 6008)' }
        if ($Ep.LastAlive) {
            $hw = @(Find-Ev -Prov 'Microsoft-Windows-WHEA-Logger' -Id 1, 17, 18, 19, 20, 46, 47 -From $Ep.LastAlive.T.AddMinutes(-30) -To $Ep.LastAlive.T.AddSeconds(5))
            if ($hw.Count -gt 0) { Add-HypFor $h 2 ([string]$hw.Count + ' WHEA hardware error(s) in the 30 min before the last logged activity') }
        }
        if ($null -ne $Ep.DowntimeSec -and $Ep.DowntimeSec -gt 1800) { Add-HypFor $h 1 ('Long gap (' + (Format-Span $Ep.DowntimeSec) + ') between the last logged activity and the next boot') }
        if ($Ep.Kp41 -and $Ep.Kp41.SleepInProgress) { Add-HypFor $h 1 'A sleep/resume transition was in progress (driver power-transition faults fit this pattern)' }
        [void]$list.Add($h)
    }

    # Score -> status
    foreach ($x in $list) {
        if ($x.Score -ge 4) { $x.Status = 'supported'; $x.Conf = 'high' }
        elseif ($x.Score -ge 2) { $x.Status = 'supported'; $x.Conf = 'medium' }
        elseif ($x.Score -eq 1) { $x.Status = 'weak'; $x.Conf = 'low' }
        elseif ($x.Against.Count -gt 0 -and $x.Score -lt 0) { $x.Status = 'not-supported'; $x.Conf = '' }
        elseif ($x.Gaps.Count -gt 0) { $x.Status = 'cannot-assess'; $x.Conf = '' }
        else { $x.Status = '' }
    }
    $rank = @{ 'supported' = 0; 'weak' = 1; 'cannot-assess' = 2; 'not-supported' = 3 }
    $keep = @($list.ToArray() | Where-Object { $_.Status })
    return @($keep | Sort-Object @{ Expression = { $rank[$_.Status] } }, @{ Expression = { $_.Score }; Descending = $true } | Select-Object -First 6)
}

# =============================================================================
# PLAIN-LANGUAGE FINDINGS PER EPISODE
# =============================================================================
function Set-Statements {
    param($Ep, $IncidentT)
    $est = @(); $not = @(); $ask = @(); $next = @()
    $init = $Ep.Initiator
    $bootTxt = Format-Time $Ep.Boot
    $dt = ''
    if ($null -ne $Ep.DowntimeSec) { $dt = Format-Span $Ep.DowntimeSec }

    switch -Regex ($Ep.Type) {
        '^controlled-' {
            $est += ('Windows recorded a ' + $init.Action + ' request at ' + (Format-Time $init.RequestedAt) + ' from ' + $init.Process +
                     ' on behalf of ' + $init.User + ' (reason ' + $init.Code + ': ' + $init.Reason.Text + ').')
            $marks = @()
            foreach ($s in $Ep.Seq) {
                if ($s.Prov -eq 'EventLog' -and $s.Id -eq 6006) { $marks += 'Event Log stopped' }
                if ($s.Prov -eq 'Microsoft-Windows-Kernel-Power' -and $s.Id -eq 109) { $marks += 'Kernel-Power 109' }
                if ($s.Prov -eq 'Microsoft-Windows-Kernel-General' -and $s.Id -eq 13) { $marks += 'Kernel-General 13' }
            }
            if ($marks.Count -gt 0) { $est += ('The shutdown completed in order (' + ($marks -join ', ') + ') and Windows started again at ' + $bootTxt + (Pick $dt (' (' + $dt + ' after the OS stopped)') '') + '.') }
            else { $est += ('Windows started again at ' + $bootTxt + '; the orderly-shutdown markers (6006 / Kernel-General 13) are not in the log.') }
            $est += 'No unclean-shutdown or bugcheck record (Kernel-Power 41, EventLog 6008, BugCheck 1001) exists for this transition.'
            $not += ('What upstream action or component made ' + $init.ProcessName + ' request it. Event 1074 records the requesting process and account, not a person or the original trigger.')
            $ask += ('Did the screen show "Restarting" / "Shutting down", or did it go black instantly?')
            $ask += ('Was anyone using the PC around ' + (Format-Clock $init.RequestedAt) + '? Did an app, update or prompt ask to restart?')
            switch ($init.Category) {
                'interactive-shell' {
                    $next += ('Ask staff whether a restart was chosen, or a restart prompt accepted, at ' + (Format-Clock $init.RequestedAt) + ' by ' + $init.User + '.')
                    $next += ('If nobody did: review software running in that session (POS/kiosk apps, update prompts, auto-logon shell) and enable attribution logging to catch a recurrence.')
                }
                'signin-screen' { $next += 'Ask whether someone used the power option on the sign-in / lock screen.' }
                'windows-update' { $next += 'Review Windows Update active hours / restart deadlines or the RMM patch policy so restarts land outside business hours.' }
                'rmm-remote' { $next += ('Check the ' + $init.ProcessName + ' activity/audit log for ' + (Format-Time $init.RequestedAt) + ' (technician action or automation).') }
                'mdm' { $next += 'Check Intune device actions and update rings for that time.' }
                'oem-updater' { $next += 'Check the vendor update tool history (BIOS/driver updates restart the PC); schedule them outside hours.' }
                'security-agent' { $next += 'Check the security console for an agent upgrade or remediation that required a restart.' }
                'installer' { $next += 'Name the installer from the correlated MSI / Restart Manager entries; schedule such installs outside hours.' }
                'command-line' { $next += 'Find the script, task or agent that ran it: Task Scheduler, RMM scripts, GPO startup/shutdown scripts. Enable attribution logging so the parent process is recorded next time.' }
                'wmi' { $next += 'Look for remote management or scripts calling Win32Shutdown (RMM, monitoring, admin scripts); enable attribution logging so the caller is recorded next time.' }
                'system-process' { $next += 'Use the reason code and the correlated events; enable attribution logging so the caller is recorded next time.' }
                default { $next += ('Identify ' + $init.Process + ': which product it belongs to and whether it is expected to restart the PC.') }
            }
        }
        '^orderly-no-initiator$' {
            $est += ('Windows shut down in order before the boot at ' + $bootTxt + ', but no restart request (User32 1074) was recorded.')
            if ($Ep.Kp109 -and $Ep.Kp109.Reason) { $est += ('Kernel-Power 109 gives the shutdown reason "' + $Ep.Kp109.Reason + '"' + (Pick $Ep.Kp109.Action (' (' + $Ep.Kp109.Action + ')') '') + '.') }
            if ($init -and $init.Category -eq 'power-button') { $est += 'That reason points to a short press of the physical power button.' }
            $not += 'Which process or person requested the shutdown.'
            $ask += 'Did anyone press the power button, or did the PC shut down by itself?'
            $next += 'Enable attribution logging so a recurrence records the caller; check power-button and UPS/power settings.'
        }
        '^unclean-bugcheck$' {
            $b = $Ep.Bug
            $est += ('Windows crashed: bugcheck ' + $b.Hex + ' ' + $b.Name + ' recorded by ' + $b.Source + (Pick $b.Params (' (parameters ' + $b.Params + ')') '') + '.')
            $est += ('Likely area: ' + $b.Cat + ' - ' + $b.Hint + '.')
            if (@($Ep.MatchedDumps).Count -gt 0) { $est += ('A matching crash dump is on disk: ' + ($Ep.MatchedDumps -join ', ') + '.') }
            elseif (@($Ep.DumpFail).Count -gt 0) { $est += ('No dump was saved: ' + ($Ep.DumpFail -join '; ') + '.') }
            else { $est += 'No matching crash dump was found on disk (overwritten, cleaned up, or not written).' }
            $not += 'Which driver or module faulted - that needs the dump analysed (WinDbg !analyze -v).'
            $ask += 'Did anyone see a blue screen or a "Your PC ran into a problem" message?'
            $next += 'Collect the dumps with Collect_Crash_Dump_Files_For_Analysis.ps1 and run !analyze -v.'
            switch ($b.Cat) {
                'Driver' { $next += 'Update or roll back recently changed drivers (GPU, storage, network, audio, chipset).' }
                'RAM' { $next += 'Run a memory test (Windows Memory Diagnostic or MemTest86) and check for recent RAM changes.' }
                'Disk' { $next += 'Check disk health (SMART), run chkdsk, and update storage firmware/drivers.' }
                'CPU/Hardware' { $next += 'Check thermals (thermal companion script), PSU, BIOS version and any overclock.' }
                default { $next += 'Run SFC /scannow and DISM /RestoreHealth; check for recent software changes.' }
            }
        }
        '^unclean-powerbutton$' {
            $est += ('Kernel-Power 41 at ' + $bootTxt + ' records a power-button press: the PC was switched off with the power button instead of shutting down' + (Pick ($Ep.Kp41 -and $Ep.Kp41.LongPress) ' (long press detected)' '') + '.')
            if ($Ep.LastAlive) { $est += ('Last logged activity before that: ' + (Format-Time $Ep.LastAlive.T) + ' (' + $Ep.LastAlive.Prov + ' ' + $Ep.LastAlive.Id + ').') }
            $not += 'Why it was switched off - most often because it had stopped responding.'
            $ask += 'Was the PC frozen or unresponsive before someone held the power button?'
            $next += 'Review events before the last logged activity (hangs, app errors, storage resets) and run the UI lag / responsiveness companion script.'
        }
        '^unclean-no-bugcheck$' {
            $src = @()
            if ($Ep.Kp41) { $src += 'Kernel-Power 41 (BugcheckCode 0, no power-button press)' }
            if (@($Ep.Seq | Where-Object { $_.Prov -eq 'EventLog' -and $_.Id -eq 6008 }).Count -gt 0) { $src += 'EventLog 6008' }
            $est += ('Windows did not shut down cleanly before the boot at ' + $bootTxt + ': ' + ($src -join ' and ') + ', with no bugcheck code.')
            if ($Ep.LastAlive) { $est += ('Last logged activity: ' + (Format-Time $Ep.LastAlive.T) + ' (' + $Ep.LastAlive.Prov + ' ' + $Ep.LastAlive.Id + '); Windows started again ' + $dt + ' later.') }
            if ($null -ne $Ep.DowntimeSec) {
                if ($Ep.DowntimeSec -lt 120) { $est += 'The short gap is consistent with an automatic restart (reset, watchdog, or crash with auto-restart).' }
                elseif ($Ep.DowntimeSec -gt 1800) { $est += 'The long gap is consistent with the PC staying off until someone powered it on again.' }
            }
            $not += 'Whether it was a power loss, a hard hang, a hardware reset or a crash Windows could not record - Event 41 with BugcheckCode 0 does not tell these apart.'
            $ask += 'Did the PC lose power or go black instantly, or freeze first?'
            $ask += 'Any power cut, UPS alarm, cable bumped, or someone switching it off at the wall?'
            $ask += 'Did it come back on by itself, or did someone turn it on?'
            $next += 'If it froze first: run the UI lag and thermal companion scripts; check WHEA and storage-reset events before the last logged activity.'
            $next += 'If power loss is suspected: check the power supply, power board/UPS and BIOS "restore on AC power loss" setting.'
            if ($script:DumpCap.status -ne 'OK') { $next += ('Fix crash-dump capture (' + $script:DumpCap.status + ': ' + (@($script:DumpCap.reasons) -join '; ') + ') so a real crash leaves evidence.') }
        }
        '^insufficient-evidence$' {
            $est += ('The boot at ' + $bootTxt + ' has no recorded shutdown path and no unclean-shutdown record before it.')
            $ws = $Ep.PrevBoundary
            if ($null -eq $ws) { $ws = $Ep.Boot.AddHours(-1) }
            $sysGap = Get-ChanGapText 'System' $ws
            if ($sysGap) { $est += ($sysGap + '.') }
            foreach ($c in @(Find-Ev -Prov 'Microsoft-Windows-Eventlog' -Id 104, 1102 -From $Ep.Boot.AddDays(-1) -To $Ep.Boot)) {
                $chn = Get-EvData $c 'Channel'
                if (-not $chn) { $chn = 'Security' }
                $est += ('The ' + $chn + ' log was cleared at ' + (Format-Time $c.T) + ' - anything before that is gone.')
            }
            $not += 'How Windows went down before this boot.'
            $ask += 'What did the client see at the time (restart screen, black screen, freeze)?'
            $next += 'Increase the System log size (e.g. wevtutil sl System /ms:67108864) and enable attribution logging so the next event is captured.'
        }
    }

    foreach ($n in $Ep.Notes) { $est += $n }

    if ($null -ne $IncidentT) {
        $dist = [math]::Abs((Get-Sec $Ep.T0 $IncidentT))
        if ($Ep.T0 -le $IncidentT -and $Ep.Boot -ge $IncidentT) { $dist = 0 }
        if ($dist -gt 7200) {
            $est += ('No shutdown/startup transition is recorded within 2 hours of the reported time ' + (Format-Time $IncidentT) + '; this is the nearest (' + (Format-Span $dist) + ' away).')
            $ask += 'Confirm the time of the incident and exactly what was seen - it may not have been a restart (e.g. an app closing, a display or network drop).'
        }
    } else {
        $not += 'Whether this is the interruption the client reported - no incident time was given; confirm the time with the client.'
    }

    $Ep.Established = $est
    $Ep.NotEstablished = $not
    $Ep.Ask = $ask
    $Ep.Next = $next
}

# =============================================================================
# ATTRIBUTION LOGGING (opt-in)
# =============================================================================
function Enable-AttributionLogging {
    $changed = @(); $notes = @()
    $before = $script:Attr
    if ($script:Replay) {
        $notes += 'Replay mode: no changes made. A live run would enable Task Scheduler history, Process Creation auditing and command-line capture.'
        $script:Attr.notes = $notes
        return
    }
    if (-not $script:IsAdmin) {
        $notes += 'Not elevated - attribution logging was NOT changed. Run as SYSTEM/Administrator.'
        $script:Attr.notes = $notes
        return
    }
    if ($before.taskHistory -ne 'on') {
        & wevtutil.exe sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true 2>$null
        if ($LASTEXITCODE -eq 0) { $changed += 'Task Scheduler history enabled' } else { $notes += ('wevtutil failed (exit ' + $LASTEXITCODE + ')') }
    }
    if ($before.processAudit -ne 'on') {
        & auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $changed += 'Process Creation auditing (success) enabled' } else { $notes += ('auditpol failed (exit ' + $LASTEXITCODE + ')') }
    }
    if ($before.cmdLine -ne 'on') {
        try {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
            New-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
            $changed += 'Command lines included in process-creation events'
        } catch { $notes += ('command-line capture not set: ' + $_.Exception.Message) }
    }
    $notes += 'Domain audit policy (GPO) can override auditpol at the next policy refresh - re-run this report later to confirm it stuck.'
    $script:Coverage['microsoft-windows-taskscheduler/operational'] = Get-ChannelCoverage 'Microsoft-Windows-TaskScheduler/Operational'
    $after = Get-AttributionState
    $after.changed = $changed
    $after.notes = $notes
    $script:Attr = $after
}

# =============================================================================
# MAIN
# =============================================================================
$script:IsAdmin = $false
try {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wpr = New-Object Security.Principal.WindowsPrincipal($wid)
    $script:IsAdmin = $wpr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

if ($script:Replay) {
    Invoke-ReplayCollection -Path $ReplayPath
} else {
    if (-not $script:IsAdmin) { Add-Note 'Not elevated: the Security log and some channels cannot be read. Run as SYSTEM or Administrator for full evidence.' }
    Invoke-LiveCollection
}
Update-PoolIndex

$now = $script:Now
$lookStart = $now.AddDays(-$LookbackDays)
$histStart = $now.AddDays(-$HistoryDays)

$incidentT = $null
if ($IncidentTime) {
    $fmts = [string[]]@('yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm', 'yyyy-MM-ddTHH:mm:ss', 'yyyy-MM-dd')
    $dtp = [datetime]::MinValue
    if ([datetime]::TryParseExact($IncidentTime.Trim(), $fmts, $script:Inv, [System.Globalization.DateTimeStyles]::None, [ref]$dtp)) {
        $off = $now.Offset
        if (-not $script:Replay) { try { $off = [TimeZoneInfo]::Local.GetUtcOffset($dtp) } catch { } }
        $incidentT = New-Object DateTimeOffset($dtp, $off)
    } else {
        Add-Note ('-IncidentTime "' + $IncidentTime + '" was not understood (use yyyy-MM-dd HH:mm). Focusing on the most recent transition.')
    }
}

# --- Build episodes (two passes live: anchors, then targeted window reads) ---
function Get-EpisodeSet {
    $anchors = @(Get-BootAnchors)
    $inRange = @()
    for ($i = 0; $i -lt $anchors.Count; $i++) { if ($anchors[$i].T -ge $lookStart) { $inRange += $i } }
    if ($inRange.Count -gt $MaxEpisodes) { $inRange = @($inRange | Select-Object -Last $MaxEpisodes) }
    $eps = @()
    $n = 0
    foreach ($i in $inRange) {
        $prev = $null; $next = $null
        if ($i -gt 0) { $prev = $anchors[$i - 1] }
        if ($i -lt $anchors.Count - 1) { $next = $anchors[$i + 1] }
        $n++
        $eps += New-Episode -Anchor $anchors[$i] -Prev $prev -Next $next -Number $n
    }
    return @($eps)
}

$episodes = @(Get-EpisodeSet)
if (-not $script:Replay -and $episodes.Count -gt 0) {
    $script:PhaseTwo = $true
    Invoke-LiveWindowReads -Episodes $episodes
    Update-PoolIndex
    $episodes = @(Get-EpisodeSet)
    Invoke-LiveCorrelationReads -Episodes $episodes
    Update-PoolIndex
    $episodes = @(Get-EpisodeSet)
}

# Dumps: freshness and matching
$dumpRows = @()
foreach ($d in $script:Dumps) {
    $tag = 'historical'; $match = $null
    foreach ($ep in $episodes) {
        $lo = $ep.Boot.AddHours(-1)
        if ($ep.LastAlive) { $lo = $ep.LastAlive.T.AddMinutes(-10) }
        if ($null -ne $d.written -and $d.written -ge $lo -and $d.written -le $ep.Boot.AddMinutes(60)) { $match = $ep; break }
    }
    if ($match) { $tag = 'matched'; $match.MatchedDumps += $d.name }
    elseif ($null -ne $d.written -and $d.written -ge $lookStart) { $tag = 'recent-unmatched' }
    $age = $null
    if ($null -ne $d.written) { $age = [math]::Round((Get-Sec $now $d.written) / 86400, 1) }
    $bn = ''; $bh = ''
    if ($null -ne $d.code) { $bh = Format-BugHex $d.code; $bn = (Get-BugMeta $d.code).Name }
    $dumpRows += [pscustomobject]@{ name = $d.name; loc = $d.loc; written = $d.written; ageDays = $age; sizeMB = $d.sizeMB
                                    bugHex = $bh; bugName = $bn; tag = $tag; episode = (Pick $match $match.Id $null) }
}

# Correlation, sessions, hypotheses, statements
foreach ($ep in $episodes) {
    $ep.Sessions = @(Get-SessionsAt $ep.T0 (Get-SessionWindowStart $ep))
    $ep.Corr = @(Get-Correlations $ep)
    $ep.Hyp = @(Get-Hypotheses $ep)
    if ($script:Meta['lastBoot'] -and [math]::Abs((Get-Sec $ep.Boot $script:Meta['lastBoot'])) -le 180) { $ep.IsCurrent = $true }
    $cat = ''
    if ($ep.Initiator) { $cat = $ep.Initiator.Category }
    $ep.Unexplained = (($ep.Type -like 'controlled-*' -and ($script:UnexplainedCats -contains $cat)) -or
                       ($ep.Type -eq 'orderly-no-initiator' -and (-not $ep.Initiator -or $script:UnexplainedCats -contains $cat)) -or
                       $ep.Type -eq 'insufficient-evidence')
}
if ($episodes.Count -gt 0 -and -not ($episodes | Where-Object { $_.IsCurrent })) { $episodes[$episodes.Count - 1].IsCurrent = $true }

# Focus episode
$focus = $null
if ($episodes.Count -gt 0) {
    if ($null -ne $incidentT) {
        $best = $null; $bestD = [double]::MaxValue
        foreach ($ep in $episodes) {
            $d = 0
            if ($incidentT -lt $ep.T0) { $d = Get-Sec $ep.T0 $incidentT }
            elseif ($incidentT -gt $ep.Boot) { $d = Get-Sec $incidentT $ep.Boot }
            if ($d -lt $bestD) { $bestD = $d; $best = $ep }
        }
        $focus = $best
    } else {
        $focus = $episodes[$episodes.Count - 1]
    }
}
foreach ($ep in $episodes) {
    $it = $null
    if ($ep -eq $focus) { $it = $incidentT }
    Set-Statements $ep $it
}

# Patterns across episodes
$patterns = @()
$groups = @{}
foreach ($ep in $episodes) {
    if (-not $ep.Initiator -or $ep.Initiator.Source -ne '1074') { continue }
    $k = $ep.Initiator.ProcessName + ' / ' + $ep.Initiator.User
    if (-not $groups.ContainsKey($k)) { $groups[$k] = @() }
    $groups[$k] += $ep
}
foreach ($k in $groups.Keys) {
    $g = @($groups[$k])
    if ($g.Count -ge 2) {
        $when = @($g | ForEach-Object { (Format-Short $_.Initiator.RequestedAt) + ' ' + $_.Initiator.Action })
        $patterns += ([string]$g.Count + ' of ' + $episodes.Count + ' transitions were requested by ' + $k + ': ' + ($when -join '; '))
    }
}
$ctrl = @($episodes | Where-Object { $_.Initiator -and $_.Initiator.Source -eq '1074' })
for ($i = 0; $i -lt $ctrl.Count; $i++) {
    $same = @($ctrl[$i])
    for ($j = 0; $j -lt $ctrl.Count; $j++) {
        if ($i -eq $j) { continue }
        $a = $ctrl[$i].Initiator.RequestedAt; $b = $ctrl[$j].Initiator.RequestedAt
        if ($a.Date -ne $b.Date) {
            $da = [math]::Abs(($a.TimeOfDay - $b.TimeOfDay).TotalMinutes)
            if ($da -le 20) { $same += $ctrl[$j] }
        }
    }
    if ($same.Count -ge 2) {
        $patterns += ('Requests cluster around ' + $ctrl[$i].Initiator.RequestedAt.ToString('HH:mm', $script:Inv) + ' on different days (' + $same.Count + ' times) - consistent with a routine or a schedule.')
        break
    }
}
$uncleanEps = @($episodes | Where-Object { $_.Type -like 'unclean-*' })
if ($uncleanEps.Count -ge 2) { $patterns += ([string]$uncleanEps.Count + ' unclean shutdowns in the last ' + $LookbackDays + ' days.') }
$bugEps = @($episodes | Where-Object { $_.Bug })
$bugGroups = @($bugEps | Group-Object { $_.Bug.Hex } | Where-Object { $_.Count -ge 2 })
foreach ($bg in $bugGroups) { $patterns += ('Bugcheck ' + $bg.Name + ' ' + $bg.Group[0].Bug.Name + ' recurred ' + $bg.Count + ' times.') }
for ($i = 0; $i -le $episodes.Count - 3; $i++) {
    if ((Get-Sec $episodes[$i + 2].Boot $episodes[$i].Boot) -le 1800) {
        $patterns += ('Boot loop: 3 boots within 30 minutes starting ' + (Format-Time $episodes[$i].Boot) + '.')
        break
    }
}

# =============================================================================
# BACKGROUND HEALTH (history window - kept out of the incident verdict)
# =============================================================================
function Get-CountIn { param($Items, $From) return @($Items | Where-Object { $_.T -ge $From }).Count }
$hWhea = @(Find-Ev -Prov 'Microsoft-Windows-WHEA-Logger' -Id (1..60) -From $histStart)
$hWheaFatalL = @($hWhea | Where-Object { $_.T -ge $lookStart -and ($_.Lvl -eq 1 -or $_.Lvl -eq 2 -or ([string]$_.Msg -match '(?i)fatal|uncorrect')) })
$hDisk = @()
foreach ($e in @(Find-ByLog -Log 'System' -From $histStart)) {
    if ((@('disk', 'microsoft-windows-disk', 'volsnap', 'microsoft-windows-stordiag') -contains ([string]$e.Prov).ToLower()) -and $e.Lvl -ge 1 -and $e.Lvl -le 3) { $hDisk += $e }
}
$hDiskPredL = @($hDisk | Where-Object { $_.T -ge $lookStart -and ($_.Id -eq 7 -or $_.Id -eq 52 -or ([string]$_.Msg -match '(?i)bad block|predictive failure|failure is imminent|S\.M\.A\.R\.T')) })
$hReset = @(Find-ByLog -Log 'System' -From $histStart | Where-Object { (@(129, 153) -contains $_.Id) -and ([string]$_.Prov -match $script:StorageProvRe) })
$hTdr = @(Find-Ev -Prov 'Display' -Id 4101, 4104 -From $histStart)
$hNtfs = @(Find-Ev -Prov 'Ntfs', 'Microsoft-Windows-Ntfs' -Id 55, 130, 140 -From $histStart)
$hKp41 = @(Find-Ev -Prov 'Microsoft-Windows-Kernel-Power' -Id 41 -From $histStart)
$hBsod = @(Find-Ev -Prov 'Microsoft-Windows-WER-SystemErrorReporting' -Id 1001 -From $histStart)
$hApp = @(Find-Ev -Prov 'Application Error', 'Application Hang' -Id 1000, 1002 -From $histStart)
$hLiveRaw = @(Find-Ev -Prov 'Windows Error Reporting' -Id 1001 -From $histStart | Where-Object { (Get-WerInfo $_).EventName -eq 'LiveKernelEvent' })
# WER re-queues the same report many times; count distinct reports, not log entries.
$hLive = @($hLiveRaw | Group-Object { $r = Get-EvData $_ 'ReportId'; if ($r) { $r } else { $_.Key } } | ForEach-Object { $_.Group[0] })
$hCleared = @(Find-Ev -Prov 'Microsoft-Windows-Eventlog' -Id 104, 1102 -From $histStart)
$appTop = @()
if ($hApp.Count -gt 0) {
    $appTop = @($hApp | ForEach-Object { Get-FaultingApp $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { $_.Name + ' x' + $_.Count })
}

$healthFlags = @()
$healthSev = 0
if ($hWheaFatalL.Count -gt 0) { $healthFlags += ([string]$hWheaFatalL.Count + ' fatal/uncorrectable WHEA hardware error(s) in the last ' + $LookbackDays + ' days'); $healthSev = 2 }
if ($hDiskPredL.Count -gt 0) { $healthFlags += 'Disk predictive-failure / bad-block events in the lookback window'; $healthSev = 2 }
$wl = Get-CountIn $hWhea $lookStart
if ($wl -gt 0 -and $hWheaFatalL.Count -eq 0) { $healthFlags += ([string]$wl + ' corrected WHEA hardware error(s) in the lookback window'); if ($healthSev -lt 1) { $healthSev = 1 } }
$rl = Get-CountIn $hReset $lookStart
if ($rl -gt 0) { $healthFlags += ([string]$rl + ' storage reset/timeout event(s) in the lookback window (drive or controller dropping out)'); if ($healthSev -lt 1) { $healthSev = 1 } }
$nl = Get-CountIn $hNtfs $lookStart
if ($nl -gt 0) { $healthFlags += ([string]$nl + ' NTFS corruption event(s) in the lookback window'); if ($healthSev -lt 1) { $healthSev = 1 } }
$tl = Get-CountIn $hTdr $lookStart
if ($tl -gt 0) { $healthFlags += ([string]$tl + ' GPU driver reset (TDR) event(s) in the lookback window'); if ($healthSev -lt 1) { $healthSev = 1 } }
$devCount = [int]$script:Meta['deviceCount']
if ($devCount -gt 0) { $healthFlags += ([string]$devCount + ' device(s) with a driver problem in Device Manager'); if ($healthSev -lt 1) { $healthSev = 1 } }

# =============================================================================
# VERDICT
# =============================================================================
$incSev = 0
$incWhy = @()
if ($focus) {
    switch ($focus.Type) {
        'unclean-bugcheck' { $incSev = 2; $incWhy += 'crash (bugcheck) in the incident transition' }
        'unclean-no-bugcheck' { $incSev = 1; $incWhy += 'unclean shutdown with no bugcheck' }
        'unclean-powerbutton' { $incSev = 1; $incWhy += 'PC switched off with the power button' }
        'insufficient-evidence' { $incSev = 1; $incWhy += 'not enough evidence to tell how Windows went down' }
    }
    if ($focus.Unexplained -and $incSev -lt 1) { $incSev = 1; $incWhy += 'restart requester not identified' }
    if ($focus.Initiator -and (@('thermal-protection', 'battery-critical') -contains $focus.Initiator.Category) -and $incSev -lt 1) { $incSev = 1; $incWhy += $focus.Initiator.Label }
}
$others = @($episodes | Where-Object { $_ -ne $focus })
if (@($others | Where-Object { $_.Type -eq 'unclean-bugcheck' }).Count -gt 0 -and $incSev -lt 1) { $incSev = 1; $incWhy += 'another crash (bugcheck) in the lookback window' }
if ($uncleanEps.Count -ge 2 -and $incSev -lt 1) { $incSev = 1; $incWhy += 'repeated unclean shutdowns' }

$exitCode = [math]::Max($incSev, $healthSev)
$status = @('OK', 'WARN', 'ALERT')[$exitCode]
$tag = '[' + $status + ']'

$typeLabels = @{
    'controlled-restart'    = 'CONTROLLED RESTART (request recorded, orderly shutdown)'
    'controlled-poweroff'   = 'CONTROLLED POWER-OFF (request recorded, orderly shutdown)'
    'orderly-no-initiator'  = 'ORDERLY SHUTDOWN, NO RESTART REQUEST RECORDED'
    'unclean-bugcheck'      = 'UNCLEAN - CRASH (BUGCHECK RECORDED)'
    'unclean-powerbutton'   = 'UNCLEAN - SWITCHED OFF WITH THE POWER BUTTON'
    'unclean-no-bugcheck'   = 'UNCLEAN - NO BUGCHECK (power loss, hard hang, reset or uncaptured crash)'
    'insufficient-evidence' = 'NOT ENOUGH EVIDENCE (no shutdown path recorded)'
}
$headline = 'No shutdown/startup transition found in the last ' + $LookbackDays + ' days.'
if ($focus) {
    $tl2 = $typeLabels[$focus.Type]
    if ($focus.Initiator -and $focus.Initiator.Source -eq '1074') {
        $headline = (Pick ($focus.Type -like 'controlled-*') 'Controlled ' 'Unclean ') + ([string]$focus.Initiator.Action).ToLower() + ' requested by ' + $focus.Initiator.ProcessName +
                    ' for ' + $focus.Initiator.User + ' at ' + (Format-Time $focus.Initiator.RequestedAt) + ' (' + $focus.Initiator.Category + ')'
        if ($focus.Type -like 'controlled-*') { $headline += '; no crash or unclean-shutdown evidence.' } else { $headline += '; ' + $tl2.ToLower() + '.' }
    } else {
        $bt = Format-Time $focus.Boot
        $sentences = @{
            'unclean-bugcheck'      = 'Windows crashed before the boot at ' + $bt + '.'
            'unclean-powerbutton'   = 'The PC was switched off with the power button (unclean shutdown) before the boot at ' + $bt + '.'
            'unclean-no-bugcheck'   = 'Unclean shutdown with no bugcheck before the boot at ' + $bt + ' (power loss, hard hang, reset or a crash Windows could not record).'
            'orderly-no-initiator'  = 'Orderly shutdown with no restart request recorded before the boot at ' + $bt + '.'
            'insufficient-evidence' = 'Not enough evidence to tell how Windows went down before the boot at ' + $bt + '.'
        }
        $headline = Pick ($sentences.ContainsKey($focus.Type)) $sentences[$focus.Type] ($tl2 + ' before the boot at ' + $bt + '.')
        if ($focus.Type -eq 'orderly-no-initiator' -and $focus.Initiator) { $headline = $headline.TrimEnd('.') + ' - ' + $focus.Initiator.Label.ToLower() + '.' }
        if ($focus.Bug) { $headline = 'Windows crashed before the boot at ' + $bt + ': ' + $focus.Bug.Hex + ' ' + $focus.Bug.Name + ' (' + $focus.Bug.Cat + ').' }
    }
}

if ($EnableAttributionLogging) { Enable-AttributionLogging }

# =============================================================================
# TEXT REPORT
# =============================================================================
$script:sb = New-Object System.Text.StringBuilder
function Add-Line { param([string]$Text = '') [void]$script:sb.AppendLine($Text) }
function Add-Section { param([string]$Title) Add-Line ''; Add-Line $Title; Add-Line ('-' * $Title.Length) }
function Add-Wrapped {
    param([string]$Prefix, [string]$Text, [int]$Width = 100)
    $indent = ' ' * $Prefix.Length
    $line = $Prefix
    $empty = $true
    foreach ($w in @(([string]$Text) -split '\s+' | Where-Object { $_ -ne '' })) {
        if ($empty) { $line += $w; $empty = $false; continue }
        if (($line.Length + 1 + $w.Length) -gt $Width) { Add-Line $line; $line = $indent + $w }
        else { $line += ' ' + $w }
    }
    Add-Line $line
}

$bar = '=' * 78
Add-Line $bar
Add-Line (' CRASH & SHUTDOWN INCIDENT DIAGNOSTIC                    ' + $tag + ' ' + $status)
Add-Line $bar
Add-Line (' Computer   : ' + $script:Meta['host'])
Add-Line (' Windows    : ' + $script:Meta['os'])
Add-Line (' Generated  : ' + (Format-Time $now) + ' (UTC' + $now.ToString('zzz', $script:Inv) + (Pick $script:Meta['tz'] (', ' + $script:Meta['tz']) '') + ')')
if ($script:Meta['lastBoot']) { Add-Line (' Last boot  : ' + (Format-Time $script:Meta['lastBoot']) + '  (up ' + (Format-Span (Get-Sec $now $script:Meta['lastBoot'])) + ')') }
Add-Line (' Window     : ' + $LookbackDays + ' days for transitions, ' + $HistoryDays + ' days for history; correlation -' + $WindowBefore + '/+' + $WindowAfter + ' min')
if ($incidentT) { Add-Line (' Reported   : ' + (Format-Time $incidentT) + ' (incident time given)') }
if ($script:Replay) { Add-Line (' Mode       : REPLAY of ' + (Split-Path $ReplayPath -Leaf)) }
foreach ($n in $script:Notes) { Add-Wrapped ' NOTE       : ' $n 100 }

Add-Line ''
Add-Line $bar
Add-Line (' VERDICT: ' + $tag + ' ' + $status + '   (exit ' + $exitCode + ')')
Add-Line $bar
Add-Wrapped '  ' $headline 100
if ($incWhy.Count -gt 0) { Add-Wrapped '  Incident : ' ($incWhy -join '; ') 100 }
if ($healthFlags.Count -gt 0) { Add-Wrapped '  Health   : ' ($healthFlags -join '; ') 100 } else { Add-Line '  Health   : no hardware/storage warning signs in the lookback window' }

if ($focus) {
    Add-Line ''
    Add-Line $bar
    Add-Line (' INCIDENT FOCUS: transition #' + $focus.Id + '   ' + (Format-Time $focus.T0) + '  ->  boot ' + (Format-Time $focus.Boot))
    Add-Line $bar
    Add-Wrapped '  Transition    : ' ($typeLabels[$focus.Type] + '  [confidence: ' + $focus.TypeConf + ']') 100
    if ($focus.Initiator) {
        $fi = $focus.Initiator
        if ($fi.Source -eq '1074') {
            Add-Wrapped '  Requested by  : ' ($fi.Process + ' on behalf of ' + $fi.User + ' (' + $fi.Action + ')') 100
            Add-Wrapped '  Reason        : ' ($fi.Code + ' "' + $fi.ReasonText + '" = ' + $fi.Reason.Text) 100
            if ($fi.Comment) { Add-Wrapped '  Comment       : ' $fi.Comment 100 }
        } else {
            Add-Wrapped '  Requested by  : ' ('(no 1074) Kernel-Power 109 reason "' + $fi.ReasonText + '"') 100
        }
        Add-Wrapped '  Initiator     : ' ($fi.Label + '  [' + $fi.Category + ', confidence: ' + $fi.Conf + ']') 100
        Add-Wrapped '                  ' ('Caveat: ' + $fi.Caveat) 100
    } else {
        Add-Line '  Requested by  : nothing recorded'
    }
    if ($null -ne $focus.DowntimeSec) { Add-Line ('  Down time     : ' + (Format-Span $focus.DowntimeSec) + ' (' + $focus.DownSource + ' -> boot' + (Pick $focus.BootType (', ' + $focus.BootType) '') + ')') }
    if (@($focus.Sessions).Count -gt 0) {
        $ss = @($focus.Sessions | ForEach-Object { $_.user + ' (' + $_.state + ', ' + (Pick ($_.via -eq 'rdp') ('RDP from ' + $_.address) 'console') + ')' })
        Add-Wrapped '  Sessions      : ' ($ss -join '; ') 100
    } else {
        Add-Line ('  Sessions      : none recorded open at the time' + (Pick (Test-ChanUsable 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' (Get-SessionWindowStart $focus)) '' ' (session log not usable)'))
    }
    Add-Line '  ESTABLISHED:'
    foreach ($s in $focus.Established) { Add-Wrapped '   - ' $s 100 }
    Add-Line '  NOT ESTABLISHED:'
    foreach ($s in $focus.NotEstablished) { Add-Wrapped '   - ' $s 100 }
    if (@($focus.Hyp).Count -gt 0) {
        Add-Line '  EXPLANATIONS CHECKED (correlation in time, not proof of cause):'
        foreach ($h in $focus.Hyp) {
            $st = $h.Status.ToUpper()
            if ($h.Conf) { $st += ' (' + $h.Conf + ')' }
            Add-Wrapped '   * ' ($h.Label + ': ' + $st) 100
            foreach ($x in $h.For) { Add-Wrapped '       + ' $x 100 }
            foreach ($x in $h.Against) { Add-Wrapped '       - ' $x 100 }
            foreach ($x in $h.Gaps) { Add-Wrapped '       ? ' ('cannot assess: ' + $x) 100 }
        }
    }
    Add-Line '  ASK THE CLIENT:'
    foreach ($s in $focus.Ask) { Add-Wrapped '   - ' $s 100 }
    Add-Line '  NEXT STEPS:'
    foreach ($s in $focus.Next) { Add-Wrapped '   - ' $s 100 }
}

Add-Section ('[1] TRANSITIONS IN THE LAST ' + $LookbackDays + ' DAYS (oldest first)')
if ($episodes.Count -eq 0) {
    Add-Line 'None found. The System log may not cover the window - see [4].'
} else {
    Add-Line (' {0,-3} {1,-17} {2,-17} {3,-9} {4,-22} {5}' -f '#', 'Went down', 'Booted', 'Down', 'Type', 'Requested by')
    foreach ($ep in $episodes) {
        $who = '-'
        if ($ep.Initiator) {
            if ($ep.Initiator.Source -eq '1074') { $who = $ep.Initiator.ProcessName + ' (' + $ep.Initiator.User + ')' }
            else { $who = $ep.Initiator.Label }
        }
        $mark = Pick ($ep -eq $focus) '*' ' '
        Add-Line ('{0}{1,-3} {2,-17} {3,-17} {4,-9} {5,-22} {6}' -f $mark, $ep.Id, (Format-Short $ep.T0), (Format-Short $ep.Boot),
            (Pick ($null -ne $ep.DowntimeSec) (Format-Span $ep.DowntimeSec) '?'), $ep.Type, (Limit-Text $who 40))
    }
    Add-Line ' (* = incident focus)'
}

Add-Section '[2] TRANSITION DETAIL (times relative to the request / shutdown start)'
foreach ($ep in @($episodes | Sort-Object -Property Boot -Descending)) {
    Add-Line ('#' + $ep.Id + '  ' + $ep.Type + ' [' + $ep.TypeConf + ']  boot ' + (Format-Time $ep.Boot) + (Pick $ep.IsCurrent '  (current boot)' ''))
    foreach ($s in $ep.Seq) { Add-Line ('   {0,-9} {1}  {2,-4} {3}' -f (Format-Offset $s.Off), (Format-Clock $s.T), $s.Ch, (Limit-Text $s.Text 80)) }
    if ($ep -ne $focus -and $ep.Initiator) { Add-Wrapped '   Initiator: ' ($ep.Initiator.Label + ' [' + $ep.Initiator.Category + ']') 100 }
    if (@($ep.Corr).Count -gt 0) {
        Add-Line '   Correlated (time only):'
        foreach ($c in $ep.Corr) { Add-Line ('     {0,-9} {1,-10} {2,-4} {3}' -f (Format-Offset $c.Off), $c.Pos, $c.Ch, (Limit-Text $c.Text 75)) }
    }
    if ($ep -ne $focus) {
        foreach ($s in $ep.Established) { Add-Wrapped '   . ' $s 100 }
    }
    if (@($ep.Sessions).Count -gt 0) {
        $ss = @($ep.Sessions | ForEach-Object { $_.user + ' (' + $_.state + ', ' + (Pick ($_.via -eq 'rdp') ('RDP ' + $_.address) 'console') + ')' })
        Add-Wrapped '   Sessions at the time: ' ($ss -join '; ') 100
    }
    Add-Line ''
}

Add-Section '[3] PATTERNS'
if ($patterns.Count -eq 0) { Add-Line 'No repeating pattern across the transitions in the window.' }
else { foreach ($p in $patterns) { Add-Wrapped ' - ' $p 100 } }

Add-Section '[4] LOG COVERAGE & GAPS (an empty result only counts when the log was on and readable)'
foreach ($ch in $script:Channels) {
    $c = Get-ChanState $ch
    $old = Pick ($c.oldest -and $c.state -eq 'enabled') (Format-Time $c.oldest) '-'
    $cov = ''
    if ($c.state -eq 'enabled' -and $c.oldest) { $cov = Pick ($c.oldest -le $lookStart) 'covers window' 'PARTIAL - rolled over' }
    $extra = ''
    if ($c.error) { $extra = ' (' + $c.error + ')' }
    if ($script:Truncated.ContainsKey($ch)) { $extra += ' (query capped)' }
    Add-Line (' {0,-12} {1,-9} oldest {2,-19} {3}{4}' -f (Get-ChanShort $ch), $c.state, $old, $cov, $extra)
}
foreach ($e in $hCleared) {
    $chn = Get-EvData $e 'Channel'
    if (-not $chn) { $chn = Pick ($e.Id -eq 1102) 'Security' 'a log' }
    $who = Get-EvData $e 'SubjectUserName'
    $dom = Get-EvData $e 'SubjectDomainName'
    if ($who -and $dom) { $who = $dom + '\' + $who }
    Add-Line (' ! ' + $chn + ' log cleared at ' + (Format-Time $e.T) + (Pick $who (' by ' + $who) '') + ' - evidence in it before this time is gone')
}
Add-Line ' Sys=System App=Application Sec=Security WU=WindowsUpdateClient Task=TaskScheduler LSM/RCM=Remote Desktop session logs'

Add-Section '[5] CRASH DUMPS (freshness - presence alone never raises the verdict)'
Add-Line (' Dump capture: ' + $script:DumpCap.status + (Pick $script:DumpCap.type (' (' + $script:DumpCap.type + ')') '') + (Pick (@($script:DumpCap.reasons).Count -gt 0) (' - ' + (@($script:DumpCap.reasons) -join '; ')) ''))
if ($dumpRows.Count -eq 0) { Add-Line ' No crash dump files on disk.' }
foreach ($d in $dumpRows) {
    $t = $d.tag
    if ($d.tag -eq 'matched') { $t = 'matched to #' + $d.episode }
    $when = ''
    if ($null -ne $d.written) { $when = $d.written.ToString('yyyy-MM-dd HH:mm', $script:Inv) + ' (' + $d.ageDays + 'd)' }
    Add-Line (' {0,-26} {1,-26} {2,8} MB {3,-17} {4} {5}' -f (Limit-Text $d.name 26), $when, $d.sizeMB, ('[' + $t + ']'), $d.bugHex, $d.bugName)
}

Add-Section ('[6] BACKGROUND HEALTH (last ' + $HistoryDays + ' days - does not change the incident verdict)')
Add-Line (' Unclean shutdowns (Kernel-Power 41) : {0,4}    Bugchecks (1001)    : {1,4}' -f $hKp41.Count, $hBsod.Count)
Add-Line (' WHEA hardware errors                : {0,4}    fatal in lookback   : {1,4}' -f $hWhea.Count, $hWheaFatalL.Count)
Add-Line (' Storage resets / timeouts           : {0,4}    disk errors         : {1,4}' -f $hReset.Count, $hDisk.Count)
Add-Line (' GPU driver resets (TDR)             : {0,4}    live kernel events  : {1,4}' -f $hTdr.Count, $hLive.Count)
Add-Line (' NTFS corruption                     : {0,4}    problem devices     : {1,4}' -f $hNtfs.Count, $devCount)
Add-Line (' Application crashes / hangs (info)  : {0,4}' -f $hApp.Count)
if ($appTop.Count -gt 0) { Add-Wrapped '   top: ' ($appTop -join ', ') 100 }
foreach ($d in $script:Devices) { Add-Line ('   device: ' + $d.name + ' (code ' + $d.code + ')') }
foreach ($f in $healthFlags) { Add-Wrapped ' ! ' $f 100 }

Add-Section '[7] ATTRIBUTION LOGGING (what Windows needs to name the caller of the NEXT restart)'
Add-Line (' Task Scheduler history        : ' + $script:Attr.taskHistory)
Add-Line (' Process Creation auditing     : ' + $script:Attr.processAudit)
Add-Line (' Command line in 4688 events   : ' + $script:Attr.cmdLine)
foreach ($c in @($script:Attr.changed)) { Add-Line (' CHANGED: ' + $c) }
foreach ($n in @($script:Attr.notes)) { Add-Wrapped ' note: ' $n 100 }
if (-not $EnableAttributionLogging -and ($script:Attr.taskHistory -ne 'on' -or $script:Attr.processAudit -ne 'on' -or $script:Attr.cmdLine -ne 'on')) {
    Add-Line ' To capture the caller next time, re-run with -EnableAttributionLogging, or run:'
    Add-Line '   wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'
    Add-Line '   auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable'
    Add-Line '   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'
}

Add-Line ''
Add-Line ' READING RULES: Event 1074 names the process and account that requested a restart, not a'
Add-Line ' person. Correlated events are listed by time only and are not proof of cause. "Cannot'
Add-Line ' assess" means the log needed was off, missing or unreadable. History in [6] never changes'
Add-Line ' the incident verdict.'
Add-Line ''
Add-Line $bar
Add-Line (' END OF REPORT - ' + $tag + ' ' + $status + ' (exit ' + $exitCode + ') - ' + $script:Meta['host'] + ' - ' + (Format-Time $now))
Add-Line $bar

# =============================================================================
# JSON (one compact line for Atera + the viewer)
# =============================================================================
function ConvertTo-JsonEpisode {
    param($Ep, [int]$SeqCap, [int]$CorrCap, [int]$TextCap)
    $init = $null
    if ($Ep.Initiator) {
        $i = $Ep.Initiator
        $init = [pscustomobject]@{
            src = $i.Source; at = (Format-Iso $i.RequestedAt); process = $i.Process; name = $i.ProcessName; user = $i.User
            action = $i.Action; reason = $i.ReasonText; code = $i.Code; decoded = $i.Reason.Text; planned = [bool]$i.Reason.Planned
            comment = $i.Comment; category = $i.Category; label = $i.Label; conf = $i.Conf; caveat = $i.Caveat
            delaySec = (Pick ($null -ne $i.DelaySec) ([math]::Round($i.DelaySec)) $null)
        }
    }
    $bug = $null
    if ($Ep.Bug) { $bug = [pscustomobject]@{ code = $Ep.Bug.Hex; name = $Ep.Bug.Name; cat = $Ep.Bug.Cat; hint = $Ep.Bug.Hint; params = $Ep.Bug.Params; source = $Ep.Bug.Source; dump = $Ep.Bug.Dump } }
    $k41 = $null
    if ($Ep.Kp41) { $k41 = [pscustomobject]@{ bugcheck = (Format-BugHex $Ep.Kp41.BugcheckCode); powerButton = $Ep.Kp41.PowerButton; longPress = $Ep.Kp41.LongPress; sleep = $Ep.Kp41.SleepInProgress } }
    $seq = @($Ep.Seq | Select-Object -First $SeqCap | ForEach-Object { [pscustomobject]@{ t = (Format-Iso $_.T); off = [math]::Round($_.Off); ch = $_.Ch; prov = $_.Prov; id = $_.Id; x = (Limit-Text $_.Text $TextCap) } })
    $corr = @($Ep.Corr | Select-Object -First $CorrCap | ForEach-Object { [pscustomobject]@{ t = (Format-Iso $_.T); off = [math]::Round($_.Off); pos = $_.Pos; ch = $_.Ch; id = $_.Id; tag = $_.Tag; x = (Limit-Text $_.Text $TextCap) } })
    $hyp = @($Ep.Hyp | ForEach-Object { [pscustomobject]@{ key = $_.Key; label = $_.Label; status = $_.Status; conf = $_.Conf; for = @($_.For | ForEach-Object { Limit-Text $_ $TextCap }); against = @($_.Against | ForEach-Object { Limit-Text $_ $TextCap }); gaps = @($_.Gaps) } })
    return [pscustomobject]@{
        id = $Ep.Id; focus = [bool]($Ep -eq $focus); current = [bool]$Ep.IsCurrent
        t0 = (Format-Iso $Ep.T0); down = (Format-Iso $Ep.Down); downSrc = $Ep.DownSource; boot = (Format-Iso $Ep.Boot); bootSrc = $Ep.BootSource; bootType = $Ep.BootType
        downtimeSec = (Pick ($null -ne $Ep.DowntimeSec) ([math]::Round($Ep.DowntimeSec)) $null)
        type = $Ep.Type; typeLabel = $typeLabels[$Ep.Type]; typeConf = $Ep.TypeConf; unexplained = [bool]$Ep.Unexplained
        initiator = $init; kp41 = $k41; bug = $bug; dumpFail = @($Ep.DumpFail); dumps = @($Ep.MatchedDumps)
        kp109 = (Pick $Ep.Kp109 ([pscustomobject]@{ action = $Ep.Kp109.Action; reason = $Ep.Kp109.Reason }) $null)
        lastAlive = (Pick $Ep.LastAlive ([pscustomobject]@{ t = (Format-Iso $Ep.LastAlive.T); prov = $Ep.LastAlive.Prov; id = $Ep.LastAlive.Id }) $null)
        sessions = @($Ep.Sessions); seq = $seq; corr = $corr; hyp = $hyp
        established = @($Ep.Established); notEstablished = @($Ep.NotEstablished); ask = @($Ep.Ask); next = @($Ep.Next)
    }
}

function Build-Payload {
    param([int]$SeqCap, [int]$CorrCap, [int]$TextCap, [bool]$FullOthers)
    $eps = @()
    foreach ($ep in $episodes) {
        if ($FullOthers -or $ep -eq $focus) { $eps += ConvertTo-JsonEpisode $ep $SeqCap $CorrCap $TextCap }
        else { $eps += ConvertTo-JsonEpisode $ep 6 0 80 }
    }
    $cov = @()
    foreach ($ch in $script:Channels) {
        $c = Get-ChanState $ch
        $covers = $null
        if ($c.state -eq 'enabled' -and $c.oldest) { $covers = [bool]($c.oldest -le $lookStart) }
        $cov += [pscustomobject]@{ log = $ch; short = (Get-ChanShort $ch); state = $c.state; oldest = (Format-Iso $c.oldest); covers = $covers; error = $c.error; capped = [bool]$script:Truncated.ContainsKey($ch) }
    }
    return [pscustomobject]@{
        schema = $script:Schema; tool = $script:ToolName; ver = $script:ToolVer
        host = $script:Meta['host']; os = $script:Meta['os']; ps = $script:Meta['ps']; mode = $script:Meta['mode']
        generated = (Format-Iso $now); tz = $script:Meta['tz']; lastBoot = (Format-Iso $script:Meta['lastBoot']); fastStartup = $script:Meta['fastStartup']
        params = [pscustomobject]@{ lookbackDays = $LookbackDays; historyDays = $HistoryDays; windowBefore = $WindowBefore; windowAfter = $WindowAfter; incident = (Format-Iso $incidentT) }
        verdict = [pscustomobject]@{ status = $status; exit = $exitCode; headline = $headline; incidentSev = $incSev; incidentWhy = @($incWhy); healthSev = $healthSev; health = @($healthFlags)
                                     focus = (Pick $focus $focus.Id $null); transition = (Pick $focus $focus.Type $null); category = (Pick ($focus -and $focus.Initiator) $focus.Initiator.Category $null) }
        notes = @($script:Notes)
        episodes = $eps
        patterns = @($patterns)
        coverage = $cov
        cleared = @($hCleared | ForEach-Object { [pscustomobject]@{ t = (Format-Iso $_.T); channel = (Pick (Get-EvData $_ 'Channel') (Get-EvData $_ 'Channel') (Pick ($_.Id -eq 1102) 'Security' '')); by = (Get-EvData $_ 'SubjectUserName'); id = $_.Id } })
        dumpCap = [pscustomobject]@{ status = $script:DumpCap.status; type = $script:DumpCap.type; reasons = @($script:DumpCap.reasons) }
        dumps = @($dumpRows | ForEach-Object { [pscustomobject]@{ name = $_.name; loc = $_.loc; written = (Format-Iso $_.written); ageDays = $_.ageDays; sizeMB = $_.sizeMB; bug = $_.bugHex; bugName = $_.bugName; tag = $_.tag; episode = $_.episode } })
        health = [pscustomobject]@{ days = $HistoryDays; kp41 = $hKp41.Count; bugchecks = $hBsod.Count; whea = $hWhea.Count; wheaFatalLookback = $hWheaFatalL.Count
                                    storageResets = $hReset.Count; diskErrors = $hDisk.Count; diskPredictive = $hDiskPredL.Count; tdr = $hTdr.Count; liveKernel = $hLive.Count
                                    ntfs = $hNtfs.Count; problemDevices = $devCount; devices = @($script:Devices); appCrashes = $hApp.Count; topApps = @($appTop) }
        attribution = [pscustomobject]@{ taskHistory = $script:Attr.taskHistory; processAudit = $script:Attr.processAudit; cmdLine = $script:Attr.cmdLine; changed = @($script:Attr.changed); notes = @($script:Attr.notes) }
    }
}

$budget = $MaxJsonKB * 1024
$json = (Build-Payload 20 20 160 $true) | ConvertTo-Json -Depth 10 -Compress
if ($json.Length -gt $budget) { $json = (Build-Payload 14 12 120 $true) | ConvertTo-Json -Depth 10 -Compress }
if ($json.Length -gt $budget) { $json = (Build-Payload 14 12 120 $false) | ConvertTo-Json -Depth 10 -Compress }
if ($json.Length -gt $budget) { $json = (Build-Payload 10 8 90 $false) | ConvertTo-Json -Depth 10 -Compress }

# =============================================================================
# OUTPUT
# =============================================================================
$reportText = $script:sb.ToString()
if (-not $NoFiles) {
    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        $stamp = $now.ToString('yyyyMMdd_HHmmss', $script:Inv)
        $base = Join-Path $OutputDir ('CrashIncident_' + $script:Meta['host'] + '_' + $stamp)
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($base + '.txt', $reportText, $enc)
        [System.IO.File]::WriteAllText($base + '.json', $json, $enc)
        $reportText += ' Saved: ' + $base + '.txt / .json' + [Environment]::NewLine
    } catch {
        $reportText += ' (Could not save report files to ' + $OutputDir + ': ' + $_.Exception.Message + ')' + [Environment]::NewLine
    }
}

if ($ExportEventsPath) {
    try {
        $evOut = @($script:Pool.ToArray() | Sort-Object -Property T | ForEach-Object {
            [pscustomobject]@{ t = (Format-Iso $_.T); log = $_.Log; prov = $_.Prov; id = $_.Id; ver = $_.Ver; rec = $_.Rec; lvl = $_.Lvl; data = $_.Data; bin = $_.Bin; msg = $_.Msg } })
        $covOut = @($script:Channels | ForEach-Object { $c = Get-ChanState $_; [pscustomobject]@{ log = $_; state = $c.state; oldest = (Format-Iso $c.oldest); records = $c.records; maxMB = $c.maxMB; error = $c.error } })
        $exp = [pscustomobject]@{
            fixture = ('export-' + $script:Meta['host']); description = ('Evidence exported by ' + $script:ToolName + ' ' + $script:ToolVer)
            meta = [pscustomobject]@{ host = $script:Meta['host']; os = $script:Meta['os']; ps = $script:Meta['ps']; generated = (Format-Iso $now)
                                      lastBoot = (Format-Iso $script:Meta['lastBoot']); tz = $script:Meta['tz']; fastStartup = $script:Meta['fastStartup'] }
            coverage = $covOut
            dumps = @($script:Dumps | ForEach-Object { [pscustomobject]@{ name = $_.name; loc = $_.loc; written = (Format-Iso $_.written); sizeMB = $_.sizeMB; code = (Pick ($null -ne $_.code) ('0x{0:X}' -f [int64]$_.code) $null); params = @($_.params) } })
            dumpCap = [pscustomobject]@{ status = $script:DumpCap.status; type = $script:DumpCap.type; reasons = @($script:DumpCap.reasons); autoReboot = $script:DumpCap.autoReboot }
            devices = @($script:Devices)
            attribution = [pscustomobject]@{ taskHistory = $script:Attr.taskHistory; processAudit = $script:Attr.processAudit; cmdLine = $script:Attr.cmdLine }
            events = $evOut
        }
        $dir = Split-Path -Parent $ExportEventsPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($ExportEventsPath, ($exp | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        $reportText += ' Evidence exported: ' + $ExportEventsPath + ' (' + $evOut.Count + ' events)' + [Environment]::NewLine
    } catch {
        $reportText += ' (Evidence export failed: ' + $_.Exception.Message + ')' + [Environment]::NewLine
    }
}

Write-Output $reportText
if (-not $NoInlineJson) {
    # One line between ===markers=== (Atera's output page eats <<<NAME>>> as an HTML tag).
    Write-Host '===CRASHDIAG_JSON_BEGIN==='
    Write-Host $json
    Write-Host '===CRASHDIAG_JSON_END==='
}
exit $exitCode
