<#
=========================================================
Script Name: SSD_Hard_Drive_Info_Health_Status_Enhanced
Description: General disk/SSD/NVMe health + S.M.A.R.T. + endurance report. Pulls Windows-native
             storage counters and uses smartmontools for generic NVMe/SATA SMART. For Intel SSDs
             (only when one is present) it can use staged Intel MAS (intelmas) to read SMART that
             smartmontools cannot reach in RST/RAID mode. Also gathers replacement/clone-prep
             intelligence (controller mode, BIOS RST/AHCI, boot mode, partitions, free space) and
             prints a PASS/CONCERN/FAIL verdict on whether a drive is failing.
Category:    ScriptLibrary
Run Time:    10 minutes
Arguments:   -NoSmartInstall   (optional: never download/install smartmontools; SMART is
                                skipped if it is not already installed. Default: auto-install)
Run As:      System
=========================================================
#>
param([switch]$NoSmartInstall)

# =========================================================
# SSD / NVMe / SATA HEALTH + SMART + ENDURANCE + CLONE-PREP REPORT
# Windows PowerShell 5.1 / runs as SYSTEM (session 0) via RMM. No GUI / no interactive prompts.
# =========================================================

# ---- Debug toggles: turn on to dump raw tool output during testing ----
$EnableSmartctlDebug = $false
$EnableIntelMasDebug = $false

# ---- Intel MAS (intelmas): LOCAL-ONLY, never downloaded. Intel MAS is EOL; v2.5 is final. ----
# This script does NOT fetch Intel MAS from the internet: Intel's mirror is behind an AWS WAF
# bot-challenge (unattended downloads fail) AND a SYSTEM PowerShell download+install pattern
# trips EDR (SentinelOne). Instead, to capture Optane SMART/endurance, pre-stage Intel MAS in
# $StagingDir (C:\temp) in ANY of these forms and re-run:
#   - intelmas.exe sitting directly in C:\temp, or in any subfolder under it
#   - an already-unzipped Intel MAS folder under C:\temp (containing intelmas.exe)
#   - the Intel MAS zip (e.g. Intel_MAS_GUI_Tool_Win_2.5.zip) dropped in C:\temp - it is
#     extracted in place; if it contains only an MSI, that is installed silently
# If none of the above are present (or intelmas is already installed), Optane SMART is skipped.
$StagingDir = 'C:\temp'

# =========================================================
# HELPER FUNCTIONS
# =========================================================

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
}

# Parse "Key : Value" style text (smartctl/intelmas/cli) into a hashtable.
function ConvertFrom-KeyValueText {
    param([string[]]$Lines)
    $h = @{}
    if (-not $Lines) { return $h }
    foreach ($line in $Lines) {
        if ($line -match '^\s*(.+?)\s*:\s*(.*?)\s*$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            if ($key -and -not $h.ContainsKey($key)) { $h[$key] = $val }
        }
    }
    return $h
}

# Look up a value by any of several candidate key names, ignoring spacing/case.
function Get-KV {
    param($Hash, [string[]]$Keys)
    if (-not $Hash) { return $null }
    foreach ($k in $Keys) {
        $target = ($k -replace '\s', '').ToLower()
        foreach ($hk in $Hash.Keys) {
            if (($hk -replace '\s', '').ToLower() -eq $target) {
                if ("$($Hash[$hk])".Trim().Length -gt 0) { return $Hash[$hk] }
            }
        }
    }
    return $null
}

# Force TLS 1.2 for any download (PS 5.1 defaults can be too old for GitHub/Intel mirrors).
function Set-Tls12 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

# True only if the file really starts with the ZIP magic bytes 'PK'. A WAF challenge / HTML
# error page saved as .zip will fail this (and otherwise throws a cryptic "Central Directory corrupt").
function Test-IsZipFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $b  = New-Object byte[] 4
        $null = $fs.Read($b, 0, 4); $fs.Close()
        return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B)
    } catch { return $false }
}

# =========================================================
# 0. SYSTEM IDENTITY (for M.2 slot / BIOS context)
# =========================================================
Write-Section 'SYSTEM IDENTITY'
try {
    $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $os   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

    Write-Host ("Computer      : {0} {1}" -f $cs.Manufacturer, $cs.Model)
    Write-Host ("Motherboard   : {0} {1}" -f $bb.Manufacturer, $bb.Product)
    Write-Host ("BIOS          : {0}  (Date: {1})" -f $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)
    Write-Host ("OS            : {0}  Build {1}" -f $os.Caption, $os.BuildNumber)
    Write-Host ("Hostname      : {0}" -f $env:COMPUTERNAME)
}
catch {
    Write-Host "[-] Could not read system identity: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# =========================================================
# 1. GET PHYSICAL DISKS + DISK MAP
# =========================================================
try {
    $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
}
catch {
    Write-Host "[-] Failed to query physical disks: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$disks = @()
try { $disks = Get-Disk -ErrorAction SilentlyContinue } catch { $disks = @() }

# Is there an Intel / Optane device present? (gates the intelmas install)
$intelDevicePresent = [bool]($physicalDisks | Where-Object {
    $_.FriendlyName -match 'Intel|Optane' -or $_.Manufacturer -match 'Intel'
})
$optanePresent = [bool]($physicalDisks | Where-Object { $_.FriendlyName -match 'Optane' })

# =========================================================
# 2. RECENT DISK / STORAGE EVENT LOG SCAN
# =========================================================
$providers = @('disk', 'Ntfs', 'Storage-ClassPnP', 'volmgr', 'iaStorA', 'iaStorAC',
               'iaStorAVC', 'storahci', 'stornvme', 'VDS', 'Microsoft-Windows-WHEA-Logger')
# Only query providers actually registered on the System log - an unknown provider name makes
# Get-WinEvent error out the whole query (e.g. iaStorA on a non-RST PC would hide disk/Ntfs events).
$availProviders = @()
try { $availProviders = (Get-WinEvent -ListLog 'System' -ErrorAction SilentlyContinue).ProviderNames } catch {}
$useProviders = @($providers | Where-Object { $availProviders -contains $_ })
if (-not $useProviders) { $useProviders = @('disk', 'Ntfs') }
$diskEvents = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = $useProviders
    Level        = @(1, 2, 3)   # Critical, Error, Warning
    StartTime    = (Get-Date).AddDays(-90)
} -MaxEvents 500 -ErrorAction SilentlyContinue

$badBlockCount = 0
if ($diskEvents) {
    $badBlockCount = ($diskEvents | Where-Object { $_.Message -match 'bad block' }).Count
}
if ($badBlockCount -gt 0) {
    Write-Host "`n[!] ALERT: Found $badBlockCount 'Bad Block' entries in recent System events!" -ForegroundColor Red
}

# WHEA hardware-error summary: corrected (ID 17) vs uncorrectable (18 fatal / 19 non-fatal),
# broken down by the PCI device reported. A steady stream of corrected PCIe (AER) errors on the
# root port hosting the SSD points to PCIe link marginality (a known Optane H10 sensitivity).
$wheaCorrected = 0; $wheaUncorrectable = 0; $wheaByDevice = @{}
if ($diskEvents) {
    foreach ($e in ($diskEvents | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' })) {
        if ($e.Id -eq 17) { $wheaCorrected++ }
        elseif ($e.Id -eq 18 -or $e.Id -eq 19) { $wheaUncorrectable++ }
        $dev = 'Unknown device'
        if ($e.Message -match 'Name\s*:\s*(PCI\\VEN_[^\s]+)') { $dev = $matches[1] }
        elseif ($e.Message -match 'Component:\s*(.+)') { $dev = $matches[1].Trim() }
        if (-not $wheaByDevice.ContainsKey($dev)) { $wheaByDevice[$dev] = 0 }
        $wheaByDevice[$dev]++
    }
}

# =========================================================
# 3. AUTO-INSTALL smartmontools (generic SMART)
# =========================================================
$possibleSmartctlPaths = @(
    'C:\Program Files\smartmontools\bin\smartctl.exe',
    'C:\Program Files (x86)\smartmontools\bin\smartctl.exe'
)
$smartctlPath = $possibleSmartctlPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $smartctlPath -and $NoSmartInstall) {
    Write-Host "`n[i] smartmontools not installed - SMART attributes skipped (-NoSmartInstall)." -ForegroundColor Yellow
}
elseif (-not $smartctlPath) {
    Write-Host "`n[i] smartmontools missing. Starting headless install..." -ForegroundColor Yellow
    Get-Process | Where-Object { $_.ProcessName -like 'smartmontools*' -or $_.ProcessName -like 'setup*' } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Set-Tls12
    if (-not (Test-Path $StagingDir)) { New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null }

    $installerUrl  = 'https://github.com/smartmontools/smartmontools/releases/download/RELEASE_7_5/smartmontools-7.5.win32-setup.exe'
    $installerPath = Join-Path $StagingDir "smartmontools-setup-$(Get-Random -Maximum 99999).exe"
    try {
        Write-Host "[i] Downloading smartmontools..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -TimeoutSec 120
        if (-not (Test-Path $installerPath)) { throw "Download produced no file at $installerPath" }
        Unblock-File -Path $installerPath -ErrorAction SilentlyContinue
        $process = Start-Process -FilePath $installerPath -ArgumentList '/S /D=C:\Program Files\smartmontools' -PassThru -Wait
        Write-Host "[i] smartmontools installer exit code: $($process.ExitCode)" -ForegroundColor Cyan
        Start-Sleep -Seconds 3
        $smartctlPath = $possibleSmartctlPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($smartctlPath) { Write-Host "[+] smartctl at: $smartctlPath" -ForegroundColor Green }
        else { Write-Host "[-] smartctl.exe not found after install." -ForegroundColor Red }
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "[-] smartmontools install failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
$smartctlAvailable = $possibleSmartctlPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

# =========================================================
# 3b. LOCATE Intel MAS (intelmas) - LOCAL ONLY, NO DOWNLOAD
#     Authoritative tool for Optane H10 SMART/endurance. Resolution order:
#       1) already installed under C:\Program Files\Intel
#       2) intelmas.exe staged anywhere under C:\temp (loose, or an unzipped folder)
#       3) an Intel MAS zip in C:\temp -> extract in place; if only an MSI, install it silently
#     If none are found, Optane SMART is skipped (no internet fetch -> no WAF break, no EDR alert).
# =========================================================
$intelmasGlob = @(
    'C:\Program Files\Intel\Intel(R) Memory and Storage Tool CLI\intelmas.exe',
    'C:\Program Files\Intel\Intel(R) Memory and Storage Tool\intelmas.exe'
)
function Find-Intelmas {
    foreach ($p in $intelmasGlob) { if (Test-Path $p) { return $p } }
    $hit = Get-ChildItem 'C:\Program Files\Intel' -Recurse -Filter 'intelmas.exe' -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}
# First intelmas.exe found anywhere under a folder (covers loose exe + already-unzipped folder)
function Find-IntelmasUnder {
    param([string]$Root)
    if (-not (Test-Path $Root)) { return $null }
    $hit = Get-ChildItem $Root -Recurse -Filter 'intelmas.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}

$intelmasPath = Find-Intelmas

if (-not $intelmasPath -and $intelDevicePresent) {
    # 2) intelmas.exe already staged under C:\temp (loose or in an unzipped subfolder)
    $intelmasPath = Find-IntelmasUnder $StagingDir

    # 3) otherwise, look for a staged Intel MAS zip in C:\temp and extract it in place
    if (-not $intelmasPath) {
        $masZip = Get-ChildItem $StagingDir -Filter '*.zip' -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -match 'MAS|intelmas|Memory.*Storage' } | Select-Object -First 1
        if ($masZip) {
            Write-Host "`n[i] Found staged Intel MAS zip: $($masZip.Name) - extracting locally (no download)..." -ForegroundColor Yellow
            $extractDir = Join-Path $StagingDir 'intelmas-extracted'
            try {
                if (-not (Test-IsZipFile $masZip.FullName)) {
                    Write-Host "[-] $($masZip.Name) is not a valid zip - skipping." -ForegroundColor DarkYellow
                }
                else {
                    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
                    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
                    Expand-Archive -Path $masZip.FullName -DestinationPath $extractDir -Force
                    $intelmasPath = Find-IntelmasUnder $extractDir
                    if (-not $intelmasPath) {
                        # zip contained only an installer - install it silently, then re-locate
                        $msi = Get-ChildItem $extractDir -Recurse -Filter '*.msi' -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($msi) {
                            Write-Host "[i] Installing $($msi.Name) silently..." -ForegroundColor Yellow
                            $p = Start-Process 'msiexec.exe' -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -PassThru -Wait
                            Write-Host "[i] intelmas MSI exit code: $($p.ExitCode)" -ForegroundColor Cyan
                            Start-Sleep -Seconds 3
                            $intelmasPath = Find-Intelmas
                        }
                    }
                }
            }
            catch {
                Write-Host "[-] Intel MAS extract/install failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }
    }

    if ($intelmasPath) {
        Write-Host "[+] Using intelmas at: $intelmasPath" -ForegroundColor Green
    }
    else {
        Write-Host "`n[i] Intel MAS not staged locally - skipping Optane deep SMART (no download attempted)." -ForegroundColor DarkGray
        Write-Host "    To capture it: drop intelmas.exe or the Intel MAS zip into $StagingDir (or install Intel MAS), then re-run." -ForegroundColor DarkGray
    }
}

# =========================================================
# 4. DEVICE ENUMERATION DEBUG
# =========================================================
if ($EnableSmartctlDebug -and $smartctlAvailable) {
    Write-Host "`n[DEBUG] smartctl --scan-open:" -ForegroundColor DarkGray
    try { & $smartctlAvailable --scan-open } catch { Write-Host "[DEBUG] scan failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}

# =========================================================
# 4b. COLLECT INTEL MAS DATA (keyed by physical drive number where possible)
# =========================================================
$masDrives   = @()      # list of parsed Intel SSD records (for the dedicated section)
$masByDrive  = @{}      # physicalDriveNumber -> record (to enrich the main report)

if ($intelmasPath) {
    try {
        $listRaw = & $intelmasPath show -intelssd 2>$null
        if ($EnableIntelMasDebug) { Write-Host "`n[DEBUG] intelmas show -intelssd:`n$($listRaw -join [Environment]::NewLine)" -ForegroundColor DarkGray }

        $indices = @()
        foreach ($l in $listRaw) { if ($l -match '^\s*Index\s*:\s*(\d+)') { $indices += [int]$matches[1] } }
        if (-not $indices) { $indices = 0..7 }   # fall back to probing if list didn't expose Index
        $indices = $indices | Select-Object -Unique

        foreach ($i in $indices) {
            $detailRaw = & $intelmasPath show -intelssd $i 2>$null
            if (-not $detailRaw) { continue }
            $smartRaw  = & $intelmasPath show -nvmelog SmartHealthInfo -intelssd $i 2>$null

            if ($EnableIntelMasDebug) {
                Write-Host "`n[DEBUG] intelmas detail idx ${i}:`n$($detailRaw -join [Environment]::NewLine)" -ForegroundColor DarkGray
                Write-Host "`n[DEBUG] intelmas smart idx ${i}:`n$($smartRaw -join [Environment]::NewLine)" -ForegroundColor DarkGray
            }

            $d = ConvertFrom-KeyValueText -Lines $detailRaw
            $s = ConvertFrom-KeyValueText -Lines $smartRaw

            $devicePath = Get-KV $d @('DevicePath')
            $physNum = $null
            if ($devicePath -and $devicePath -match 'PHYSICALDRIVE(\d+)') { $physNum = [int]$matches[1] }

            $rec = [PSCustomObject]@{
                Index           = $i
                Model           = Get-KV $d @('ModelNumber', 'Model', 'DevSku', 'ProductFamily')
                Serial          = Get-KV $d @('SerialNumber', 'Serial')
                Firmware        = Get-KV $d @('Firmware', 'FirmwareRevision')
                PhysicalDrive   = $physNum
                DeviceStatus    = Get-KV $d @('DeviceStatus', 'Health')
                PercentageUsed  = $null   # set cleanly below (smart log preferred, then detail)
                EnduranceAnalyzer = Get-KV $d @('EnduranceAnalyzer')
                AvailableSpare  = Get-KV $s @('AvailableSpareNormalized', 'AvailableSpare', 'Available Spare')
                AvailSpareThresh = Get-KV $s @('AvailableSpareThreshold')
                MediaErrors     = Get-KV $s @('MediaandDataIntegrityErrors', 'Media and Data Integrity Errors')
                ErrLogEntries   = Get-KV $s @('NumberofErrorInformationLogEntries', 'Number of Error Information Log Entries')
                UnsafeShutdowns = Get-KV $s @('UnsafeShutdowns', 'Unsafe Shutdowns')
                PowerOnHours    = Get-KV $s @('PowerOnHours', 'Power On Hours')
                PowerCycles     = Get-KV $s @('PowerCycles', 'Power Cycles')
                DataWritten     = Get-KV $s @('DataUnitsWritten', 'Data Units Written', 'HostBytesWritten')
                DataRead        = Get-KV $s @('DataUnitsRead', 'Data Units Read', 'HostBytesRead')
                CriticalWarning = Get-KV $s @('CriticalWarning', 'critical_warning', 'Critical Warning')
                Temperature     = Get-KV $s @('Temperature-Celsius', 'Temperature - Celsius', 'CurrentTemperature', 'Temperature')
                LinkWidth       = Get-KV $d @('PCILinkWidth', 'NegotiatedLinkWidth')
                LinkSpeed       = Get-KV $d @('PCILinkSpeed', 'NegotiatedLinkSpeed')
            }
            # Re-pull PercentageUsed cleanly (the inline merge above is fragile); prefer smart log then detail.
            $pu = Get-KV $s @('PercentageUsed', 'Percentage Used')
            if (-not $pu) { $pu = Get-KV $d @('PercentageUsed', 'Percentage Used') }
            $rec.PercentageUsed = $pu

            $masDrives += $rec
            if ($null -ne $physNum -and -not $masByDrive.ContainsKey($physNum)) { $masByDrive[$physNum] = $rec }
        }
    }
    catch {
        Write-Host "[!] intelmas query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# =========================================================
# 5. BUILD PER-DISK REPORT
# =========================================================
$driveList = foreach ($disk in $physicalDisks) {

    # Resolve the real disk number (for /dev/pdN and Get-Partition), not just DeviceId.
    $diskNumber = $disk.DeviceId
    $matchedDisk = $disks | Where-Object { "$($_.Number)" -eq "$($disk.DeviceId)" } | Select-Object -First 1
    if (-not $matchedDisk -and $disk.SerialNumber) {
        $matchedDisk = $disks | Where-Object { $_.SerialNumber -and $_.SerialNumber.Trim() -eq $disk.SerialNumber.Trim() } | Select-Object -First 1
    }
    if ($matchedDisk) { $diskNumber = $matchedDisk.Number }

    # Windows-native reliability counters
    $stats = $null
    try { $stats = $disk | Get-StorageReliabilityCounter -ErrorAction Stop } catch { $stats = $null }

    # Partitions / volumes (drive letters + used/free)
    $partitions = $null
    try { $partitions = Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue } catch { $partitions = $null }
    $driveLetters = ($partitions | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter) -join ', '

    $usedBytes = 0; $totalVolBytes = 0; $partTypes = @()
    if ($partitions) {
        foreach ($p in $partitions) {
            if ($p.Type) { $partTypes += $p.Type }
            $vol = $null
            try { $vol = $p | Get-Volume -ErrorAction SilentlyContinue } catch { $vol = $null }
            if ($vol -and $vol.Size) {
                $totalVolBytes += [double]$vol.Size
                $usedBytes     += ([double]$vol.Size - [double]$vol.SizeRemaining)
            }
        }
    }

    # SMART defaults
    $mediaErrors='N/A'; $errorLogEntries='N/A'; $unsafeShutdowns='N/A'; $percentageUsed='N/A'
    $availableSpare='N/A'; $powerOnHours='N/A'; $powerCycles='N/A'; $dataUnitsRead='N/A'
    $dataUnitsWritten='N/A'; $criticalWarning='N/A'; $smartModel=$null; $smartSerial=$null
    $smartProtocol=$null; $smartTemp='N/A'; $smartSource='None'

    # ---- smartctl with improved NVMe addressing ----
    if ($smartctlAvailable) {
        $attempts = @(
            @{ dev = "/dev/pd$diskNumber";   type = 'nvme' },
            @{ dev = "/dev/pd$diskNumber";   type = $null  },
            @{ dev = "/dev/nvme$diskNumber"; type = 'nvme' }
        )
        foreach ($a in $attempts) {
            try {
                if ($a.type) { $smartText = & $smartctlAvailable -j -d $a.type -a $a.dev 2>$null }
                else         { $smartText = & $smartctlAvailable -j -a $a.dev 2>$null }
                if (-not $smartText) { continue }
                $smartRaw = $smartText | ConvertFrom-Json -ErrorAction Stop

                $hasNvme = $null -ne $smartRaw.nvme_smart_health_information_log
                $hasAta  = $null -ne $smartRaw.ata_smart_attributes.table
                if (-not ($hasNvme -or $hasAta -or $smartRaw.device.protocol)) { continue }

                if ($null -ne $smartRaw.model_name)     { $smartModel    = $smartRaw.model_name }
                if ($null -ne $smartRaw.serial_number)  { $smartSerial   = $smartRaw.serial_number }
                if ($null -ne $smartRaw.device.protocol){ $smartProtocol = $smartRaw.device.protocol }

                if ($hasNvme) {
                    $nvme = $smartRaw.nvme_smart_health_information_log
                    if ($null -ne $nvme.media_errors)        { $mediaErrors     = $nvme.media_errors }
                    if ($null -ne $nvme.num_err_log_entries) { $errorLogEntries = $nvme.num_err_log_entries }
                    if ($null -ne $nvme.unsafe_shutdowns)    { $unsafeShutdowns = $nvme.unsafe_shutdowns }
                    if ($null -ne $nvme.percentage_used)     { $percentageUsed  = "$($nvme.percentage_used)%" }
                    if ($null -ne $nvme.available_spare)     { $availableSpare  = "$($nvme.available_spare)%" }
                    if ($null -ne $nvme.power_on_hours)      { $powerOnHours    = $nvme.power_on_hours }
                    if ($null -ne $nvme.power_cycles)        { $powerCycles     = $nvme.power_cycles }
                    if ($null -ne $nvme.data_units_read)     { $dataUnitsRead   = $nvme.data_units_read }
                    if ($null -ne $nvme.data_units_written) { $dataUnitsWritten = $nvme.data_units_written }
                    if ($null -ne $nvme.critical_warning)    { $criticalWarning = $nvme.critical_warning }
                    if ($null -ne $nvme.temperature)         { $smartTemp       = "$($nvme.temperature) C" }
                    $smartSource = "smartctl ($($a.dev) -d nvme)"
                }
                elseif ($hasAta) {
                    foreach ($attr in $smartRaw.ata_smart_attributes.table) {
                        $rawVal = $attr.raw.value
                        switch ($attr.name) {
                            'Power_On_Hours'         { $powerOnHours = $rawVal }
                            'Power_Cycle_Count'      { $powerCycles  = $rawVal }
                            'Reported_Uncorrect'     { $mediaErrors  = $rawVal }
                            'Reallocated_Sector_Ct'  { $criticalWarning = "$rawVal reallocated" }
                            'Offline_Uncorrectable'  { if ($mediaErrors -eq 'N/A') { $mediaErrors = $rawVal } }
                            'Temperature_Celsius'    { $smartTemp    = "$rawVal C" }
                            'UDMA_CRC_Error_Count'   { $errorLogEntries = $rawVal }
                        }
                    }
                    $smartSource = "smartctl ($($a.dev) ATA)"
                }
                break  # got usable data; stop trying addresses
            }
            catch { continue }
        }
    }

    # ---- Enrich with Intel MAS (authoritative for Optane) where a mapping exists ----
    $mas = $null
    $dnKey = $null
    if ("$diskNumber" -match '^\d+$') { $dnKey = [int]$diskNumber }
    if ($null -ne $dnKey -and $masByDrive.ContainsKey($dnKey)) { $mas = $masByDrive[$dnKey] }
    if ($mas) {
        if ($mas.PercentageUsed)  { $percentageUsed  = "$($mas.PercentageUsed)%" }
        if ($mas.AvailableSpare)  { $availableSpare  = "$($mas.AvailableSpare)%" }
        if ($mas.MediaErrors)     { $mediaErrors     = $mas.MediaErrors }
        if ($mas.ErrLogEntries)   { $errorLogEntries = $mas.ErrLogEntries }
        if ($mas.UnsafeShutdowns) { $unsafeShutdowns = $mas.UnsafeShutdowns }
        if ($mas.PowerOnHours)    { $powerOnHours    = $mas.PowerOnHours }
        if ($mas.PowerCycles)     { $powerCycles     = $mas.PowerCycles }
        if ($mas.DataWritten)     { $dataUnitsWritten = $mas.DataWritten }
        if ($mas.DataRead)        { $dataUnitsRead   = $mas.DataRead }
        if ($mas.CriticalWarning) { $criticalWarning = $mas.CriticalWarning }
        if ($mas.Temperature)     { $smartTemp       = "$($mas.Temperature) C" }
        if ($mas.Serial)          { $smartSerial     = $mas.Serial }
        $smartSource = "Intel MAS (idx $($mas.Index))"
    }

    # Wear / endurance fallback
    $wearLevel = 'N/A'
    if ($percentageUsed -ne 'N/A') { $wearLevel = $percentageUsed }
    elseif ($stats -and $null -ne $stats.Wear) { $wearLevel = "$($stats.Wear)%" }

    # Temperature / read-write errors from Windows counters if SMART silent
    $readErrs = 0; $writeErrs = 0; $temp = 'N/A'
    if ($smartTemp -ne 'N/A') { $temp = $smartTemp }
    elseif ($stats -and $stats.Temperature) { $temp = "$($stats.Temperature) C" }
    if ($stats) {
        if ($null -ne $stats.ReadErrorsTotal)  { $readErrs  = $stats.ReadErrorsTotal }
        if ($null -ne $stats.WriteErrorsTotal) { $writeErrs = $stats.WriteErrorsTotal }
    }

    [PSCustomObject]@{
        Disk           = $diskNumber
        Drive          = if ($driveLetters) { $driveLetters } else { 'N/A' }
        Model          = $disk.FriendlyName
        BusType        = $disk.BusType
        MediaType      = $disk.MediaType
        Firmware       = $disk.FirmwareVersion
        SizeGB         = [math]::Round(($disk.Size / 1GB), 1)
        UsedGB         = if ($usedBytes) { [math]::Round(($usedBytes / 1GB), 1) } else { 'N/A' }
        Health         = $disk.HealthStatus
        OpStatus       = ($disk.OperationalStatus -join ',')
        PartStyle      = if ($matchedDisk) { $matchedDisk.PartitionStyle } else { 'N/A' }
        PartTypes      = if ($partTypes) { ($partTypes -join ', ') } else { 'N/A' }
        WearLevel      = $wearLevel
        ReadErrs       = $readErrs
        WriteErrs      = $writeErrs
        Temp           = $temp
        SpareAvail     = $availableSpare
        PowerOnHours   = $powerOnHours
        PowerCycles    = $powerCycles
        MediaErrs      = $mediaErrors
        ErrLogEvents   = $errorLogEntries
        UnsafeDowns    = $unsafeShutdowns
        CriticalWarn   = $criticalWarning
        DataReadUnits  = $dataUnitsRead
        DataWriteUnits = $dataUnitsWritten
        Protocol       = if ($smartProtocol) { $smartProtocol } else { 'N/A' }
        Serial         = if ($smartSerial) { $smartSerial } else { $disk.SerialNumber }
        SmartSource    = $smartSource
    }
}

# =========================================================
# 6. OUTPUT: MAIN DRIVE REPORT
# =========================================================
Write-Section 'SSD HEALTH & USAGE REPORT'
$driveList | Format-List

if ($masDrives) {
    Write-Section 'INTEL MAS / OPTANE DEEP HEALTH (authoritative)'
    Write-Host 'Each entry is an Intel NVMe device. An Optane H10 normally appears as TWO entries' -ForegroundColor Gray
    Write-Host '(the Optane cache module + the QLC NAND SSD).' -ForegroundColor Gray
    $masDrives | Format-List Index, Model, Serial, Firmware, PhysicalDrive, DeviceStatus,
        PercentageUsed, EnduranceAnalyzer, AvailableSpare, AvailSpareThresh, MediaErrors,
        ErrLogEntries, UnsafeShutdowns, PowerOnHours, PowerCycles, DataWritten, DataRead,
        CriticalWarning, Temperature, LinkWidth, LinkSpeed
}

if (-not $smartctlAvailable) {
    Write-Host "`n[!] smartmontools unavailable - generic SMART shows N/A." -ForegroundColor Red
}
# If the controller is in RST/RAID mode, the NVMe device is claimed by iaStor and is NOT
# exposed for SMART passthrough - smartctl returns nothing. Only Intel MAS can read it.
$raidBlind = $driveList | Where-Object { $_.BusType -eq 'RAID' -and $_.SmartSource -eq 'None' }
if ($raidBlind) {
    Write-Host "`n[!] Controller is in Intel RST/RAID mode - smartctl cannot reach the NVMe device for SMART." -ForegroundColor Yellow
    Write-Host "    Intel MAS (intelmas) is the ONLY way to read endurance/media-error data on this PC." -ForegroundColor Yellow
}
if ($intelDevicePresent -and -not $intelmasPath) {
    Write-Host "[!] Intel SSD present but Intel MAS not staged - deep SMART (endurance/wear) shows N/A." -ForegroundColor Red
    Write-Host "    To capture it (no download is attempted): drop intelmas.exe or the Intel MAS zip into" -ForegroundColor DarkYellow
    Write-Host "    $StagingDir, or install Intel MAS on this PC, then re-run." -ForegroundColor DarkYellow
}

# =========================================================
# 7. CLONE-PREP INTELLIGENCE
# =========================================================
Write-Section 'CLONE-PREP INTELLIGENCE'

# 7a. Storage controllers + active boot storage driver -> RST vs AHCI inference
$rstMode = $false
try {
    $scsi = Get-CimInstance Win32_SCSIController -ErrorAction SilentlyContinue
    Write-Host 'Storage controllers:'
    foreach ($c in $scsi) { Write-Host ("  - {0}" -f $c.Name) }
    $rstDriver = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -in @('iaStorAC', 'iaStorAVC', 'iaStorA', 'iaStorV') -and $_.State -eq 'Running' }
    if ($rstDriver -or ($scsi | Where-Object { $_.Name -match 'RAID|Rapid Storage|RST' })) {
        $rstMode = $true
        Write-Host "BIOS storage mode  : Intel RST / RAID mode - INFERRED" -ForegroundColor Yellow
    } else {
        Write-Host "BIOS storage mode  : AHCI / standard NVMe (no Intel RST driver active) - INFERRED" -ForegroundColor Green
    }
}
catch { Write-Host "[-] Controller query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

# 7b. Optane caching / management services present?
$optaneSvc = Get-Service -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match 'RstMwService|iaStorAfs|OptaneMemory' -or $_.DisplayName -match 'Optane|Rapid Storage' }
$optaneCachingLikely = $optanePresent -and ($rstMode -or $optaneSvc)
if ($optaneSvc) {
    Write-Host "Optane/RST services: $((($optaneSvc | Select-Object -ExpandProperty Name) -join ', '))"
}
if ($optaneCachingLikely) {
    Write-Host "Optane caching     : LIKELY ENABLED" -ForegroundColor Yellow
    Write-Host "  >> Before cloning: DISABLE Optane acceleration first so the cache flushes to the" -ForegroundColor Yellow
    Write-Host "     NAND, otherwise the clone will be incomplete / unbootable." -ForegroundColor Yellow
} elseif ($optanePresent) {
    Write-Host "Optane caching     : Optane hardware present but no active caching driver detected." -ForegroundColor Green
}

# 7c. Boot mode + Secure Boot (clone must preserve UEFI/GPT vs Legacy/MBR)
try {
    $bootMode = 'Unknown'
    try {
        $bcd = & "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>$null
        if ($bcd -match 'winload\.efi')     { $bootMode = 'UEFI' }
        elseif ($bcd -match 'winload\.exe') { $bootMode = 'Legacy BIOS' }
    } catch {}
    if ($bootMode -eq 'Unknown') {
        # Fallback: presence of an EFI System Partition implies UEFI
        $esp = Get-Partition -ErrorAction SilentlyContinue |
               Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }
        if ($esp) { $bootMode = 'UEFI (ESP present)' }
    }
    Write-Host "Firmware/boot mode : $bootMode"
    try { Write-Host "Secure Boot        : $([bool](Confirm-SecureBootUEFI -ErrorAction Stop))" }
    catch { Write-Host "Secure Boot        : N/A (legacy BIOS or insufficient privilege)" }
}
catch { Write-Host "[-] Boot mode query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

# 7d. OS-disk sizing guidance for the replacement SSD
$osDisk = $driveList | Where-Object { $_.Drive -match 'C' } | Select-Object -First 1
if ($osDisk) {
    Write-Host ("OS disk            : Disk {0}, {1} GB total, {2} GB used, {3}/{4}" -f `
        $osDisk.Disk, $osDisk.SizeGB, $osDisk.UsedGB, $osDisk.PartStyle, $osDisk.PartTypes)
    Write-Host "  >> Replacement SSD must be >= used space; matching/larger total avoids resize hassle." -ForegroundColor Gray
}
if ($rstMode) {
    Write-Host "  >> If you clone to a plain NVMe and the BIOS stays in RST/RAID mode, switching to AHCI" -ForegroundColor Yellow
    Write-Host "     later will cause INACCESSIBLE_BOOT_DEVICE. Enable storahci boot-start before swapping," -ForegroundColor Yellow
    Write-Host "     or keep the controller mode consistent with the clone target." -ForegroundColor Yellow
}

# =========================================================
# 8. HEALTH VERDICT (prove / disprove "drive is failing")
# =========================================================
Write-Section 'HEALTH VERDICT'

$flags = New-Object System.Collections.Generic.List[string]
$concerns = 0; $fails = 0

function Test-NumberPresent { param($v) return ($v -ne $null -and "$v" -ne 'N/A' -and "$v" -ne '') }

foreach ($d in $driveList) {
    # Endurance / percentage used
    if ((Test-NumberPresent $d.WearLevel) -and ("$($d.WearLevel)" -match '(\d+)')) {
        $pu = [int]$matches[1]
        if ($pu -ge 90)     { $fails++;    $flags.Add("$($d.Model): endurance ${pu}% used (>=90% = end of life)") }
        elseif ($pu -ge 80) { $concerns++; $flags.Add("$($d.Model): endurance ${pu}% used (>=80% = ageing)") }
    }
    # Available spare
    if ((Test-NumberPresent $d.SpareAvail) -and ("$($d.SpareAvail)" -match '(\d+)')) {
        $sp = [int]$matches[1]
        if ($sp -lt 10) { $fails++; $flags.Add("$($d.Model): available spare ${sp}% (<10% = critical)") }
    }
    # Media errors
    if ((Test-NumberPresent $d.MediaErrs) -and ("$($d.MediaErrs)" -match '^\d+$') -and ([int]$d.MediaErrs -gt 0)) {
        $concerns++; $flags.Add("$($d.Model): $($d.MediaErrs) media/integrity errors")
    }
    # Critical warning bits
    if ((Test-NumberPresent $d.CriticalWarn) -and ("$($d.CriticalWarn)" -match '\d') -and ("$($d.CriticalWarn)" -notmatch '^0( reallocated)?$')) {
        if ("$($d.CriticalWarn)" -match 'reallocated') { $concerns++ } else { $fails++ }
        $flags.Add("$($d.Model): critical warning = $($d.CriticalWarn)")
    }
    # Windows health
    if ("$($d.Health)" -and "$($d.Health)" -ne 'Healthy') { $concerns++; $flags.Add("$($d.Model): Windows health = $($d.Health)") }
    # Near-full disk: an SSD with little free space slows down and has no headroom
    if (($d.SizeGB -gt 0) -and (Test-NumberPresent $d.UsedGB) -and ("$($d.UsedGB)" -match '^\d')) {
        $pctFull = [math]::Round((([double]$d.UsedGB) / ([double]$d.SizeGB)) * 100, 0)
        if ($pctFull -ge 90) {
            $concerns++
            $flags.Add("$($d.Model): drive ${pctFull}% full ($($d.UsedGB)/$($d.SizeGB) GB) - low free space / write-slowdown")
        }
    }
}
if ($badBlockCount -gt 0) { $fails++; $flags.Add("$badBlockCount bad-block events in System log") }
if ($wheaUncorrectable -gt 0) { $fails++;    $flags.Add("$wheaUncorrectable UNCORRECTABLE WHEA hardware errors (PCIe/fatal)") }
if ($wheaCorrected -ge 5)     { $concerns++; $flags.Add("$wheaCorrected corrected PCIe (WHEA-17) errors - PCIe link marginality on the storage path") }

$verdict = 'PASS'; $vColor = 'Green'
if ($fails -gt 0)      { $verdict = 'FAIL';    $vColor = 'Red' }
elseif ($concerns -gt 0){ $verdict = 'CONCERN'; $vColor = 'Yellow' }

Write-Host "VERDICT: $verdict" -ForegroundColor $vColor
if ($flags.Count) { $flags | ForEach-Object { Write-Host "  - $_" -ForegroundColor $vColor } }
else { Write-Host "  - No wear-out, media-error, spare-depletion, or bad-block indicators found." -ForegroundColor Green }

# PCIe / WHEA hardware-error breakdown
if ($wheaCorrected -gt 0 -or $wheaUncorrectable -gt 0) {
    Write-Host ''
    Write-Host "PCIe / WHEA hardware errors (last 90 days): $wheaCorrected corrected, $wheaUncorrectable uncorrectable" -ForegroundColor Yellow
    $wheaByDevice.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        Write-Host ("    {0,3}x  {1}" -f $_.Value, $_.Key)
    }
    Write-Host "    'Corrected' errors are recovered by hardware (not immediately fatal), but a steady stream on" -ForegroundColor Gray
    Write-Host "    the SSD's PCIe root port signals link marginality - check ASPM/BIOS and storage driver/firmware, reseat the" -ForegroundColor Gray
    Write-Host "    M.2, and watch for escalation to UNCORRECTABLE (IDs 18/19)." -ForegroundColor Gray
}

Write-Host ''
if ($verdict -eq 'PASS') {
    Write-Host '  - No data-backed evidence this drive is failing (no wear-out, spare depletion, media' -ForegroundColor Gray
    Write-Host '    errors or bad blocks in the data collected).' -ForegroundColor Gray
} else {
    Write-Host "  - Indicators above ($verdict) support replacing or further investigating this drive." -ForegroundColor Gray
}
if ($optanePresent -and -not $intelmasPath) {
    Write-Host '  - CAVEAT: this is an Intel Optane drive and Intel MAS did not run, so its endurance/wear is' -ForegroundColor DarkYellow
    Write-Host '    unconfirmed. Stage intelmas (see earlier note) and re-run before declaring it healthy.' -ForegroundColor DarkYellow
}

# =========================================================
# 9. DISK / STORAGE EVENTS
# =========================================================
Write-Section 'DISK / STORAGE EVENTS (last 90 days, max 500)'
if ($diskEvents) {
    Write-Host "Note: ShadowCopy/VSS errors are often benign backup issues." -ForegroundColor Gray
    $diskEvents | Group-Object ProviderName, Id |
        Sort-Object Count -Descending |
        Select-Object Count, @{N='Provider/Id';E={$_.Name}},
            @{N='LastSeen';E={ ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated }} |
        Format-Table -AutoSize
    Write-Host 'Most recent 15 events:' -ForegroundColor Gray
    $diskEvents | Sort-Object TimeCreated -Descending | Select-Object -First 15 TimeCreated, ProviderName, Id, Message |
        Format-Table -Wrap
}
else {
    Write-Host "[+] No disk errors or warnings in recent System logs." -ForegroundColor Green
}
