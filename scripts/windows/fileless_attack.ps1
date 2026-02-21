# scripts/windows/fileless_attack.ps1
#
# Detection: WMI event subscriptions, PowerShell script block logging, process injection
# MITRE: T1546.003, T1055, T1059.001
# Requires: Standard User
# Expected runtime: ~10s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at           = (Get-Date -Format "o")
        hostname               = $env:COMPUTERNAME
        check                  = "fileless_attack"
        wmi_subscriptions      = @{
            event_filters   = @()
            event_consumers = @()
            bindings        = @()
        }
        powershell_scriptblocks = @()
        suspicious_processes    = @()
        errors                  = @()
    }

    # --- WMI Event Subscriptions (persistence mechanism) ---
    try {
        $filters = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        if ($filters) {
            $result.wmi_subscriptions.event_filters = @($filters | ForEach-Object {
                [PSCustomObject]@{
                    name  = $_.Name
                    query = $_.Query
                    lang  = $_.QueryLanguage
                }
            })
        }
    }
    catch { $result.errors += "wmi_filters: $($_.Exception.Message)" }

    try {
        $consumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
        if ($consumers) {
            $result.wmi_subscriptions.event_consumers += @($consumers | ForEach-Object {
                [PSCustomObject]@{
                    name        = $_.Name
                    type        = "CommandLine"
                    executable  = $_.ExecutablePath
                    command     = $_.CommandLineTemplate
                }
            })
        }
        $scriptConsumers = Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        if ($scriptConsumers) {
            $result.wmi_subscriptions.event_consumers += @($scriptConsumers | ForEach-Object {
                [PSCustomObject]@{
                    name    = $_.Name
                    type    = "ActiveScript"
                    engine  = $_.ScriptingEngine
                    script  = if ($_.ScriptText.Length -gt 2000) { $_.ScriptText.Substring(0, 2000) + "..." } else { $_.ScriptText }
                }
            })
        }
    }
    catch { $result.errors += "wmi_consumers: $($_.Exception.Message)" }

    try {
        $bindings = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        if ($bindings) {
            $result.wmi_subscriptions.bindings = @($bindings | ForEach-Object {
                [PSCustomObject]@{
                    filter   = $_.Filter.ToString()
                    consumer = $_.Consumer.ToString()
                }
            })
        }
    }
    catch { $result.errors += "wmi_bindings: $($_.Exception.Message)" }

    # --- PowerShell Script Block Logging (EID 4104) ---
    try {
        $startTime = (Get-Date).AddHours(-72)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $startTime
        } -MaxEvents 200 -ErrorAction SilentlyContinue

        if ($events) {
            # Filter for suspicious script blocks
            $suspiciousKeywords = @(
                'Invoke-Mimikatz', 'Invoke-Shellcode', 'Invoke-ReflectivePEInjection',
                'Get-GPPPassword', 'Invoke-Kerberoast', 'AmsiUtils',
                'Bypass', 'System.Reflection.Assembly', 'VirtualAlloc',
                'CreateThread', 'memset', 'kernel32', 'ntdll',
                'DllImport', 'WScript.Shell', 'Net.WebClient',
                'DownloadString', 'FromBase64String', 'EncodedCommand',
                'Invoke-WMIMethod', 'Invoke-CimMethod'
            )
            $keywordPattern = ($suspiciousKeywords -join '|')

            foreach ($event in $events) {
                $scriptBlock = $event.Properties[2].Value
                if ($scriptBlock -match $keywordPattern) {
                    $result.powershell_scriptblocks += [PSCustomObject]@{
                        time        = $event.TimeCreated.ToString("o")
                        script_id   = $event.Properties[3].Value
                        content     = if ($scriptBlock.Length -gt 2000) { $scriptBlock.Substring(0, 2000) + "..." } else { $scriptBlock }
                        matched     = ($suspiciousKeywords | Where-Object { $scriptBlock -match $_ }) -join ", "
                    }
                }
            }
        }
    }
    catch { $result.errors += "ps_scriptblocks: $($_.Exception.Message)" }

    # --- Processes without disk image ---
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -eq $null -and $_.Id -gt 4 -and $_.ProcessName -notmatch '^(Idle|System|Registry|Memory Compression|Secure System)$'
        } | ForEach-Object {
            [PSCustomObject]@{
                pid          = $_.Id
                name         = $_.ProcessName
                working_set  = $_.WorkingSet64
                start_time   = if ($_.StartTime) { $_.StartTime.ToString("o") } else { "" }
            }
        }
        if ($processes) {
            $result.suspicious_processes = @($processes)
        }
    }
    catch { $result.errors += "processes: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "fileless_attack"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
