# scripts/windows/lateral_movement.ps1
#
# Detection: RDP, PsExec, WinRM, Pass-the-Hash lateral movement
# MITRE: T1021, T1570, T1135
# Requires: Administrator (Security event log)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at      = (Get-Date -Format "o")
        hostname          = $env:COMPUTERNAME
        check             = "lateral_movement"
        network_logons    = @()
        rdp_logons        = @()
        psexec_traces     = @()
        winrm_activity    = @()
        smb_shares        = @()
        rdp_history       = @()
        errors            = @()
    }

    $startTime = (Get-Date).AddHours(-72)

    # --- EID 4624 Type 3: Network logons ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4624; StartTime = $startTime
        } -MaxEvents 1000 -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $ns = @{e = 'http://schemas.microsoft.com/win/2004/08/events/event'}
                $logonType = ($xml | Select-Xml -XPath '//e:Data[@Name="LogonType"]' -Namespace $ns).Node.'#text'
                $sourceIP = ($xml | Select-Xml -XPath '//e:Data[@Name="IpAddress"]' -Namespace $ns).Node.'#text'
                $targetUser = ($xml | Select-Xml -XPath '//e:Data[@Name="TargetUserName"]' -Namespace $ns).Node.'#text'
                $logonProcess = ($xml | Select-Xml -XPath '//e:Data[@Name="LogonProcessName"]' -Namespace $ns).Node.'#text'

                if ($logonType -eq '3' -and $sourceIP -and $sourceIP -ne '-' -and $sourceIP -ne '::1' -and $sourceIP -ne '127.0.0.1') {
                    $result.network_logons += [PSCustomObject]@{
                        time           = $event.TimeCreated.ToString("o")
                        source_ip      = $sourceIP
                        target_user    = $targetUser
                        logon_process  = $logonProcess
                    }
                }

                # Type 10: RemoteInteractive (RDP)
                if ($logonType -eq '10') {
                    $result.rdp_logons += [PSCustomObject]@{
                        time        = $event.TimeCreated.ToString("o")
                        source_ip   = $sourceIP
                        target_user = $targetUser
                    }
                }
            }

            # Aggregate network logons by source IP
            if ($result.network_logons.Count -gt 50) {
                $result.network_logons = @($result.network_logons |
                    Group-Object source_ip |
                    ForEach-Object {
                        [PSCustomObject]@{
                            source_ip = $_.Name
                            count     = $_.Count
                            users     = ($_.Group.target_user | Select-Object -Unique) -join ", "
                            first     = ($_.Group | Select-Object -Last 1).time
                            last      = ($_.Group | Select-Object -First 1).time
                        }
                    } | Sort-Object count -Descending | Select-Object -First 30
                )
            }
        }
    }
    catch { $result.errors += "logon_events: $($_.Exception.Message)" }

    # --- PsExec traces ---
    try {
        # Check for PSEXESVC service
        $psexecSvc = Get-Service -Name "PSEXESVC" -ErrorAction SilentlyContinue
        if ($psexecSvc) {
            $result.psexec_traces += [PSCustomObject]@{
                type   = "service"
                name   = "PSEXESVC"
                status = $psexecSvc.Status.ToString()
            }
        }

        # Check for PsExec pipe
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match 'psexec' }
        foreach ($pipe in $pipes) {
            $result.psexec_traces += [PSCustomObject]@{
                type = "pipe"
                name = $pipe
            }
        }

        # EID 7045: New service installed (PsExec pattern)
        $svcEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'; Id = 7045; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if ($svcEvents) {
            foreach ($event in $svcEvents) {
                if ($event.Message -match 'PSEXESVC|psexec') {
                    $result.psexec_traces += [PSCustomObject]@{
                        type    = "event"
                        time    = $event.TimeCreated.ToString("o")
                        message = ($event.Message -replace '\r?\n', ' ').Substring(0, [Math]::Min(300, $event.Message.Length))
                    }
                }
            }
        }
    }
    catch { $result.errors += "psexec: $($_.Exception.Message)" }

    # --- WinRM activity ---
    try {
        $winrmEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-WinRM/Operational'; Id = 6; StartTime = $startTime
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        if ($winrmEvents) {
            $result.winrm_activity = @($winrmEvents | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = ($_.Message -replace '\r?\n', ' ').Substring(0, [Math]::Min(300, $_.Message.Length))
                }
            } | Select-Object -First 30)
        }
    }
    catch { $result.errors += "winrm: $($_.Exception.Message)" }

    # --- Network shares ---
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|print\$)$' }
        if ($shares) {
            $result.smb_shares = @($shares | ForEach-Object {
                [PSCustomObject]@{
                    name        = $_.Name
                    path        = $_.Path
                    description = $_.Description
                }
            })
        }
    }
    catch { $result.errors += "smb_shares: $($_.Exception.Message)" }

    # --- RDP connection history (outbound from this server) ---
    try {
        $rdpKey = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers"
        if (Test-Path $rdpKey) {
            $servers = Get-ChildItem -Path $rdpKey -ErrorAction SilentlyContinue
            if ($servers) {
                $result.rdp_history = @($servers | ForEach-Object {
                    $hint = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
                    [PSCustomObject]@{
                        server        = $_.PSChildName
                        username_hint = $hint
                    }
                })
            }
        }
    }
    catch { $result.errors += "rdp_history: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "lateral_movement"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
