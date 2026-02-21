# scripts/windows/log_tampering.ps1
#
# Detection: Security/System log clearing, audit policy changes
# MITRE: T1070, T1562
# Requires: Administrator
# Expected runtime: ~10s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at       = (Get-Date -Format "o")
        hostname           = $env:COMPUTERNAME
        check              = "log_tampering"
        log_cleared_events = @()
        audit_changes      = @()
        log_sizes          = @()
        eventlog_service   = @{}
        errors             = @()
    }

    $startTime = (Get-Date).AddHours(-72)

    # --- EID 1102: Security log cleared ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 1102; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.log_cleared_events += @($events | ForEach-Object {
                [PSCustomObject]@{
                    time     = $_.TimeCreated.ToString("o")
                    event_id = 1102
                    log_name = "Security"
                    message  = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid1102: $($_.Exception.Message)" }

    # --- EID 104: System/Application log cleared ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'; Id = 104; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.log_cleared_events += @($events | ForEach-Object {
                [PSCustomObject]@{
                    time     = $_.TimeCreated.ToString("o")
                    event_id = 104
                    log_name = "System"
                    message  = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid104: $($_.Exception.Message)" }

    # --- EID 4719: Audit policy changed ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4719; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.audit_changes = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid4719: $($_.Exception.Message)" }

    # --- Event log sizes (small size = suspicious) ---
    try {
        $logNames = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
        foreach ($logName in $logNames) {
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                if ($log) {
                    $result.log_sizes += [PSCustomObject]@{
                        name          = $logName
                        file_size_mb  = [math]::Round($log.FileSize / 1MB, 2)
                        max_size_mb   = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
                        record_count  = $log.RecordCount
                        is_enabled    = $log.IsEnabled
                        last_write    = if ($log.LastWriteTime) { $log.LastWriteTime.ToString("o") } else { "" }
                    }
                }
            }
            catch { }
        }
    }
    catch { $result.errors += "log_sizes: $($_.Exception.Message)" }

    # --- Event Log service status ---
    try {
        $svc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
        if ($svc) {
            $result.eventlog_service = @{
                name       = $svc.Name
                status     = $svc.Status.ToString()
                start_type = $svc.StartType.ToString()
            }
        }
    }
    catch { $result.errors += "eventlog_svc: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "log_tampering"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
