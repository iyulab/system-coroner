# scripts/windows/persistence.ps1
#
# Detection: Registry Run keys, scheduled tasks, suspicious services
# MITRE: T1547, T1053, T1543
# Requires: Standard User (Admin for service binaries)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at    = (Get-Date -Format "o")
        hostname        = $env:COMPUTERNAME
        check           = "persistence"
        registry_run    = @()
        scheduled_tasks = @()
        services        = @()
        winlogon        = @()
        ifeo            = @()
        errors          = @()
    }

    # Helper: extract the executable path from a command-line value string.
    # Handles quoted paths, unquoted paths with arguments, and environment variables.
    function Resolve-ExePath {
        param([string]$RawValue)
        if (-not $RawValue) { return $null }
        $expanded = [Environment]::ExpandEnvironmentVariables($RawValue)
        # Quoted path: "C:\path\to\file.exe" [args]
        if ($expanded -match '^"([^"]+\.exe)"') { return $Matches[1] }
        # Unquoted path ending with .exe before a space or end-of-string
        if ($expanded -match '^([A-Za-z]:\\[^\s"]+\.exe)') { return $Matches[1] }
        # First whitespace-delimited token (may omit .exe extension)
        $token = ($expanded -split '\s+')[0].Trim('"')
        if ($token -match '\.(exe|com|scr|pif)$') { return $token }
        return $null
    }

    # Helper: return Authenticode signature info for an executable path.
    function Get-SignatureInfo {
        param([string]$Path)
        if (-not $Path) { return [PSCustomObject]@{ status = "PathNotResolved"; signer = ""; issuer = ""; path = "" } }
        if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            return [PSCustomObject]@{ status = "FileNotFound"; signer = ""; issuer = ""; path = $Path }
        }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            return [PSCustomObject]@{
                status = $sig.Status.ToString()
                signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { "" }
                path   = $Path
            }
        }
        catch { return [PSCustomObject]@{ status = "Error"; signer = ""; issuer = ""; path = $Path } }
    }

    # --- Registry Run keys (WFC-005: all 7 paths including WOW64) ---
    $runKeys = @(
        # 64-bit hive paths
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        # WOW64 (32-bit apps on 64-bit OS — common malware hiding spot)
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($key in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS(Path|Drive|Provider|ParentPath|ChildName)'
                } | ForEach-Object {
                    $exePath = Resolve-ExePath -RawValue $_.Value
                    $result.registry_run += [PSCustomObject]@{
                        key       = $key
                        name      = $_.Name
                        value     = $_.Value
                        signature = Get-SignatureInfo -Path $exePath
                    }
                }
            }
        }
        catch { $result.errors += "registry $key`: $($_.Exception.Message)" }
    }

    # --- Winlogon entries ---
    try {
        $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
        if ($winlogon) {
            $result.winlogon = @(
                [PSCustomObject]@{ name = "Userinit"; value = $winlogon.Userinit },
                [PSCustomObject]@{ name = "Shell"; value = $winlogon.Shell }
            )
        }
    }
    catch { $result.errors += "winlogon: $($_.Exception.Message)" }

    # --- Image File Execution Options (debugger hijacking) ---
    try {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        $ifeoKeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
        if ($ifeoKeys) {
            foreach ($ifeo in $ifeoKeys) {
                $debugger = (Get-ItemProperty -Path $ifeo.PSPath -ErrorAction SilentlyContinue).Debugger
                if ($debugger) {
                    $result.ifeo += [PSCustomObject]@{
                        target   = $ifeo.PSChildName
                        debugger = $debugger
                    }
                }
            }
        }
    }
    catch { $result.errors += "ifeo: $($_.Exception.Message)" }

    # --- Scheduled Tasks ---
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch '\\Microsoft\\' } |
            ForEach-Object {
                $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                $actions = $_.Actions | ForEach-Object {
                    [PSCustomObject]@{
                        type      = $_.CimClass.CimClassName
                        execute   = $_.Execute
                        arguments = $_.Arguments
                    }
                }
                [PSCustomObject]@{
                    name        = $_.TaskName
                    path        = $_.TaskPath
                    state       = $_.State.ToString()
                    run_as      = $_.Principal.UserId
                    run_level   = $_.Principal.RunLevel.ToString()
                    actions     = @($actions)
                    last_run    = if ($info -and $info.LastRunTime.Year -gt 2000) { $info.LastRunTime.ToString("o") } else { "" }
                    next_run    = if ($info -and $info.NextRunTime.Year -gt 2000) { $info.NextRunTime.ToString("o") } else { "" }
                }
            }
        if ($tasks) {
            $result.scheduled_tasks = @($tasks)
        }
    }
    catch { $result.errors += "tasks: $($_.Exception.Message)" }

    # --- Non-Microsoft services with suspicious paths ---
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PathName -and (
                    $_.PathName -match '\\Temp\\|\\AppData\\|\\Users\\' -or
                    $_.PathName -match 'cmd\.exe|powershell\.exe' -or
                    (-not ($_.PathName -match '\\Windows\\|\\Program Files'))
                )
            } |
            Select-Object -Property Name, DisplayName, State, StartMode, PathName, StartName |
            ForEach-Object {
                $exePath = Resolve-ExePath -RawValue $_.PathName
                [PSCustomObject]@{
                    name         = $_.Name
                    display_name = $_.DisplayName
                    state        = $_.State
                    start_mode   = $_.StartMode
                    path         = $_.PathName
                    run_as       = $_.StartName
                    signature    = Get-SignatureInfo -Path $exePath
                }
            }
        if ($services) {
            $result.services = @($services)
        }
    }
    catch { $result.errors += "services: $($_.Exception.Message)" }

    # --- WFC-006: Base64-encoded command detection ---
    # Detect base64-encoded PowerShell commands in autorun locations
    try {
        $base64Detections = @()

        # Helper: check a value for base64/encoded PowerShell patterns
        function Test-EncodedCommand {
            param([string]$Value, [string]$Source)
            if (-not $Value) { return }
            # Match -EncodedCommand or -Enc flag followed by base64
            if ($Value -match '-[Ee]nc(odedCommand)?\s+([A-Za-z0-9+/]{20,}={0,2})') {
                return [PSCustomObject]@{
                    source       = $Source
                    pattern      = "-EncodedCommand"
                    value        = $Value.Substring(0, [Math]::Min($Value.Length, 200))
                }
            }
            # Match standalone long base64 strings that look like payloads
            if ($Value -match 'FromBase64String|[A-Za-z0-9+/]{100,}={0,2}') {
                return [PSCustomObject]@{
                    source       = $Source
                    pattern      = "Base64Payload"
                    value        = $Value.Substring(0, [Math]::Min($Value.Length, 200))
                }
            }
            return $null
        }

        # Check registry run key values
        foreach ($entry in $result.registry_run) {
            $detection = Test-EncodedCommand -Value $entry.value -Source "registry:$($entry.key)\$($entry.name)"
            if ($detection) { $base64Detections += $detection }
        }

        # Check service paths
        foreach ($svc in $result.services) {
            $detection = Test-EncodedCommand -Value $svc.path -Source "service:$($svc.name)"
            if ($detection) { $base64Detections += $detection }
        }

        # Check scheduled task arguments
        foreach ($task in $result.scheduled_tasks) {
            foreach ($action in $task.actions) {
                $combined = "$($action.execute) $($action.arguments)"
                $detection = Test-EncodedCommand -Value $combined -Source "task:$($task.name)"
                if ($detection) { $base64Detections += $detection }
            }
        }

        if ($base64Detections) {
            $result | Add-Member -NotePropertyName "base64_detections" -NotePropertyValue @($base64Detections)
        }
    }
    catch { $result.errors += "base64_scan: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "persistence"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
