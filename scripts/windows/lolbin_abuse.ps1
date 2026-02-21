# scripts/windows/lolbin_abuse.ps1
#
# Detection: Living-off-the-Land binary abuse via process creation events
# MITRE: T1218, T1059
# Requires: Administrator (Security event log 4688)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at       = (Get-Date -Format "o")
        hostname           = $env:COMPUTERNAME
        check              = "lolbin_abuse"
        suspicious_events  = @()
        long_cmdlines      = @()
        errors             = @()
    }

    $startTime = (Get-Date).AddHours(-72)

    # LOLBin process names to watch
    $lolbins = @(
        'powershell.exe', 'pwsh.exe', 'certutil.exe', 'mshta.exe',
        'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe',
        'bitsadmin.exe', 'wmic.exe', 'msiexec.exe', 'installutil.exe',
        'msconfig.exe', 'msbuild.exe', 'cmstp.exe', 'esentutl.exe'
    )

    # Suspicious argument patterns
    $suspiciousPatterns = @(
        '-[Ee]ncoded[Cc]ommand',
        '-[Ww]indow[Ss]tyle\s+[Hh]idden',
        'IEX|Invoke-Expression|Invoke-WebRequest|iwr|wget|curl',
        '-urlcache\s+-split\s+-f',
        'http://|https://',
        '/i:http|/u\s+/s',
        'bitsadmin.*\/transfer',
        'process\s+call\s+create',
        'base64',
        'FromBase64String',
        'DownloadString|DownloadFile',
        'Net\.WebClient',
        'Start-BitsTransfer'
    )
    $combinedPattern = ($suspiciousPatterns -join '|')

    # --- EID 4688: Process creation with suspicious LOLBin usage ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4688; StartTime = $startTime
        } -MaxEvents 2000 -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $ns = @{e = 'http://schemas.microsoft.com/win/2004/08/events/event'}
                $newProcessName = ($xml | Select-Xml -XPath '//e:Data[@Name="NewProcessName"]' -Namespace $ns).Node.'#text'
                $cmdLine = ($xml | Select-Xml -XPath '//e:Data[@Name="CommandLine"]' -Namespace $ns).Node.'#text'
                $parentProcessName = ($xml | Select-Xml -XPath '//e:Data[@Name="ParentProcessName"]' -Namespace $ns).Node.'#text'

                if (-not $newProcessName) { continue }

                $processFileName = [System.IO.Path]::GetFileName($newProcessName).ToLower()

                if ($processFileName -in $lolbins) {
                    $isSuspicious = $false

                    # Check for suspicious arguments
                    if ($cmdLine -and $cmdLine -match $combinedPattern) {
                        $isSuspicious = $true
                    }

                    # Check for abnormally long command lines
                    if ($cmdLine -and $cmdLine.Length -gt 500) {
                        $isSuspicious = $true
                        $result.long_cmdlines += [PSCustomObject]@{
                            time         = $event.TimeCreated.ToString("o")
                            process      = $newProcessName
                            cmd_length   = $cmdLine.Length
                            cmd_preview  = $cmdLine.Substring(0, [Math]::Min(500, $cmdLine.Length))
                        }
                    }

                    if ($isSuspicious) {
                        $result.suspicious_events += [PSCustomObject]@{
                            time           = $event.TimeCreated.ToString("o")
                            process        = $newProcessName
                            parent_process = $parentProcessName
                            command_line   = if ($cmdLine.Length -gt 2000) { $cmdLine.Substring(0, 2000) + "..." } else { $cmdLine }
                        }
                    }
                }
            }
        }
    }
    catch { $result.errors += "eid4688: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "lolbin_abuse"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
