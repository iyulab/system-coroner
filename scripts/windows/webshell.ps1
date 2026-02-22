# scripts/windows/webshell.ps1
#
# Detection: Web shell files in web server root directories
# MITRE: T1505.003, T1190
# Requires: Standard User (Admin for IIS log access)
# Expected runtime: ~15s (timeout: 60s)

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $scanStart = Get-Date
    $timeoutSeconds = 50  # bail at 50s to leave margin before 60s hard kill

    $result = @{
        collected_at     = (Get-Date -Format "o")
        hostname         = $env:COMPUTERNAME
        check            = "webshell"
        web_servers      = @()
        suspicious_files = @()
        recent_files     = @()
        iis_anomalies    = @()
        scan_incomplete  = $false
        errors           = @()
    }

    # --- Detect web server installations ---
    $webRoots = @()

    # IIS
    try {
        $iisRoot = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).PathWWWRoot
        if ($iisRoot -and (Test-Path $iisRoot)) {
            $webRoots += $iisRoot
            $result.web_servers += [PSCustomObject]@{ type = "IIS"; root = $iisRoot }
        }
    }
    catch { }

    # IIS sites
    try {
        if (Get-Command Get-WebSite -ErrorAction SilentlyContinue) {
            $sites = Get-WebSite -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                $physPath = $site.physicalPath
                if ($physPath -and (Test-Path $physPath) -and $physPath -notin $webRoots) {
                    $webRoots += $physPath
                    $result.web_servers += [PSCustomObject]@{ type = "IIS-Site"; root = $physPath; name = $site.name }
                }
            }
        }
    }
    catch { }

    # Common web server paths
    $commonPaths = @(
        "C:\xampp\htdocs",
        "C:\Apache24\htdocs",
        "C:\nginx\html",
        "C:\tomcat\webapps"
    )
    foreach ($p in $commonPaths) {
        if ((Test-Path $p) -and $p -notin $webRoots) {
            $webRoots += $p
            $result.web_servers += [PSCustomObject]@{ type = "detected"; root = $p }
        }
    }

    if ($webRoots.Count -eq 0) {
        $result | Add-Member -NotePropertyName "no_web_server" -NotePropertyValue $true
        $result | ConvertTo-Json -Depth 10 -Compress
        exit 0
    }

    # --- Scan web roots for suspicious files ---
    $suspiciousExtensions = @('.php', '.asp', '.aspx', '.jsp', '.cfm', '.jspx', '.ashx', '.asmx')
    $suspiciousPatterns = @(
        'eval\s*\(', 'base64_decode\s*\(', 'exec\s*\(', 'system\s*\(',
        'cmd\.exe', 'powershell', 'WScript\.Shell', 'Server\.CreateObject',
        'Runtime\.getRuntime', 'ProcessBuilder',
        'passthru\s*\(', 'shell_exec\s*\(', 'proc_open\s*\(',
        'assert\s*\(', 'preg_replace.*\/e'
    )
    $suspiciousPattern = ($suspiciousPatterns -join '|')

    # Dangerous file types that should not be in web roots
    $dangerousExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf')

    $scanTimedOut = $false
    foreach ($root in $webRoots) {
        if ($scanTimedOut) { break }
        try {
            # Check script files for suspicious content
            $scriptFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLower() -in $suspiciousExtensions }

            foreach ($file in $scriptFiles) {
                if (((Get-Date) - $scanStart).TotalSeconds -ge $timeoutSeconds) {
                    $scanTimedOut = $true; break
                }
                try {
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue -TotalCount 50000
                    if ($content -and $content -match $suspiciousPattern) {
                        $matches_found = ($suspiciousPatterns | Where-Object { $content -match $_ }) -join ", "
                        $result.suspicious_files += [PSCustomObject]@{
                            path        = $file.FullName
                            extension   = $file.Extension
                            size_bytes  = $file.Length
                            created     = $file.CreationTime.ToString("o")
                            modified    = $file.LastWriteTime.ToString("o")
                            patterns    = $matches_found
                            preview     = if ($content.Length -gt 500) { $content.Substring(0, 500) + "..." } else { $content }
                        }
                    }
                }
                catch { }
            }

            if ($scanTimedOut) { break }

            # Check for dangerous file types
            $dangerousFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLower() -in $dangerousExtensions }

            foreach ($file in $dangerousFiles) {
                if (((Get-Date) - $scanStart).TotalSeconds -ge $timeoutSeconds) {
                    $scanTimedOut = $true; break
                }
                $result.suspicious_files += [PSCustomObject]@{
                    path       = $file.FullName
                    extension  = $file.Extension
                    size_bytes = $file.Length
                    created    = $file.CreationTime.ToString("o")
                    modified   = $file.LastWriteTime.ToString("o")
                    patterns   = "dangerous_extension_in_webroot"
                }
            }

            if ($scanTimedOut) { break }

            # Recently modified files (7 days)
            $recent = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 30 |
                ForEach-Object {
                    [PSCustomObject]@{
                        path     = $_.FullName
                        size     = $_.Length
                        modified = $_.LastWriteTime.ToString("o")
                        created  = $_.CreationTime.ToString("o")
                    }
                }
            if ($recent) {
                $result.recent_files += @($recent)
            }
        }
        catch { $result.errors += "scan $root`: $($_.Exception.Message)" }
    }

    if ($scanTimedOut) {
        $result.scan_incomplete = $true
        $result.errors += "scan timed out after ${timeoutSeconds}s — partial results returned"
    }

    # --- IIS log anomalies (POST to static-like paths) ---
    try {
        $iisLogPath = "C:\inetpub\logs\LogFiles"
        if (Test-Path $iisLogPath) {
            $logFiles = Get-ChildItem -Path $iisLogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 3

            foreach ($logFile in $logFiles) {
                $content = Get-Content -Path $logFile.FullName -Tail 500 -ErrorAction SilentlyContinue
                if ($content) {
                    $anomalies = $content | Where-Object {
                        $_ -match 'POST.*\.(jpg|png|gif|css|txt|ico)' -or
                        $_ -match '(eval|exec|cmd|powershell|system)' -or
                        $_ -match '(\.\./|\.\.\\|%2e%2e)' # directory traversal
                    } | Select-Object -First 20
                    if ($anomalies) {
                        $result.iis_anomalies += @($anomalies | ForEach-Object {
                            [PSCustomObject]@{
                                log_file = $logFile.Name
                                line     = $_
                            }
                        })
                    }
                }
            }
        }
    }
    catch { $result.errors += "iis_logs: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "webshell"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
