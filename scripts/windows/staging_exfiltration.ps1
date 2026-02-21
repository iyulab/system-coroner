# scripts/windows/staging_exfiltration.ps1
#
# Detection: Data staging and exfiltration artifacts
# MITRE: T1074 (Data Staged), T1560 (Archive Collected Data),
#        T1048 (Exfiltration Over Alt Protocol), T1052 (Exfiltration Over Physical Medium)
# Requires: Standard User (Admin recommended for SRUM/USB registry)
# Expected runtime: ~20s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at        = (Get-Date -Format "o")
        hostname            = $env:COMPUTERNAME
        check               = "staging_exfiltration"
        temp_archives       = @()
        usb_devices         = @()
        vss_deletion        = @()
        exfil_tool_prefetch = @()
        srum_large_senders  = @()
        errors              = @()
    }

    # Known legitimate backup processes (SAFE filter)
    $safeBackupProcesses = @(
        'veeam', 'wbadmin', 'windowsserverbackup', 'ntbackup', 'backupexec',
        'arcserve', 'dpmra', 'veamvss', 'mspub', 'sqlwriter'
    )

    function Test-SafeProcess {
        param([string]$Name)
        $lower = $Name.ToLower()
        foreach ($proc in $safeBackupProcesses) {
            if ($lower -like "*$proc*") { return $true }
        }
        return $false
    }

    # --- Temp Archives (staging indicator) ---
    $stagingDirs = @(
        $env:TEMP,
        $env:TMP,
        "C:\Users\Public",
        "C:\ProgramData"
    )

    $archiveExtensions = @('.zip', '.7z', '.rar', '.tar', '.gz', '.tar.gz', '.tgz', '.bz2')

    try {
        foreach ($dir in $stagingDirs) {
            if (-not (Test-Path $dir)) { continue }

            Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $ext = [System.IO.Path]::GetExtension($_.Name).ToLower()
                    $archiveExtensions -contains $ext -and
                    $_.CreationTime -gt (Get-Date).AddDays(-7)
                } | ForEach-Object {
                    $result.temp_archives += [PSCustomObject]@{
                        file_name   = $_.Name
                        file_path   = $_.FullName
                        size_bytes  = $_.Length
                        created     = $_.CreationTime.ToString("o")
                        modified    = $_.LastWriteTime.ToString("o")
                    }
                }
        }
    } catch {
        $result.errors += "temp_archives: $($_.Exception.Message)"
    }

    # --- USB/External Storage Connections ---
    try {
        $usbKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbKey) {
            Get-ChildItem $usbKey -ErrorAction SilentlyContinue | ForEach-Object {
                $deviceClass = $_.PSChildName
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $instanceKey = $_
                    $props = Get-ItemProperty $instanceKey.PSPath -ErrorAction SilentlyContinue
                    $result.usb_devices += [PSCustomObject]@{
                        device_class     = $deviceClass
                        instance_id      = $instanceKey.PSChildName
                        friendly_name    = if ($props.FriendlyName) { $props.FriendlyName } else { "" }
                        manufacturer     = if ($props.Mfg) { $props.Mfg } else { "" }
                    }
                }
            }
            # Limit to 20
            if ($result.usb_devices.Count -gt 20) {
                $result.usb_devices = $result.usb_devices | Select-Object -First 20
            }
        }
    } catch {
        $result.errors += "usb_devices: $($_.Exception.Message)"
    }

    # --- VSS Deletion (ransomware + exfiltration cleanup) ---
    try {
        $vssPatterns = @('vssadmin.*delete.*shadows', 'wmic.*shadowcopy.*delete', 'bcdedit.*recoveryenabled.*no')
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688) and TimeCreated[@SystemTime>='$($sevenDaysAgo.ToUniversalTime().ToString("o"))']]]
    </Select>
  </Query>
</QueryList>
"@
        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction Stop

        foreach ($evt in $events) {
            $xml     = [xml]$evt.ToXml()
            $data    = $xml.Event.EventData.Data
            $cmdLine = ($data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            if (-not $cmdLine) { continue }

            foreach ($pattern in $vssPatterns) {
                if ($cmdLine -imatch $pattern) {
                    $procName = ($data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
                    $account  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                    $result.vss_deletion += [PSCustomObject]@{
                        time         = $evt.TimeCreated.ToString("o")
                        command_line = $cmdLine
                        process_name = if ($procName) { Split-Path $procName -Leaf } else { "" }
                        account      = $account
                    }
                    break
                }
            }
        }
    } catch {
        $result.errors += "vss_deletion: $($_.Exception.Message)"
    }

    # --- Exfiltration Tool Prefetch ---
    $exfilTools = @('rclone', 'winscp', 'putty', 'filezilla', 'pscp', 'scp', 'ftp', 'megatools')
    try {
        $prefetchDir = "C:\Windows\Prefetch"
        if (Test-Path $prefetchDir) {
            Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
                Where-Object {
                    $exeName = ($_.Name -replace '-[0-9A-F]{8}\.pf$', '').ToLower()
                    $found = $false
                    foreach ($tool in $exfilTools) {
                        if ($exeName -like "*$tool*") { $found = $true; break }
                    }
                    $found
                } | ForEach-Object {
                    $result.exfil_tool_prefetch += [PSCustomObject]@{
                        name      = $_.Name -replace '-[0-9A-F]{8}\.pf$', ''
                        last_run  = $_.LastWriteTime.ToString("o")
                        created   = $_.CreationTime.ToString("o")
                    }
                }
        }
    } catch {
        $result.errors += "exfil_prefetch: $($_.Exception.Message)"
    }

    # --- SRUM: Large outbound transfers (> 50MB) ---
    # SRUM ESE database requires native parsing; approximate via WMI network stats
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            # Look for processes with significant network activity
            $_.HandleCount -gt 100 -and -not (Test-SafeProcess $_.ProcessName)
        } | Select-Object -First 20

        # Note: Real SRUM parsing requires ESE library (native tool recommended)
        # Here we record a note about the limitation
        if ($processes) {
            $result.srum_large_senders += [PSCustomObject]@{
                note = "SRUM ESE database requires native parsing tool (e.g. srum-dump). " +
                       "Running process list collected as proxy metric."
                active_processes = ($processes | Select-Object ProcessName, Id, HandleCount |
                    ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ", "
            }
        }
    } catch {
        $result.errors += "srum: $($_.Exception.Message)"
    }

    $result | ConvertTo-Json -Depth 4 -Compress

} catch {
    @{ error = $_.Exception.Message; check = "staging_exfiltration" } | ConvertTo-Json -Compress
}
