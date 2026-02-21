# scripts/windows/file_download.ps1
#
# Detection: File download artifacts — tools/payloads brought in by attacker
# MITRE: T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode),
#        T1608 (Stage Capabilities)
# Requires: Standard User
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at      = (Get-Date -Format "o")
        hostname          = $env:COMPUTERNAME
        check             = "file_download"
        zone_marked_files = @()
        recent_executables = @()
        bits_transfers    = @()
        errors            = @()
    }

    # Safe download domains (Mark-of-the-Web HostUrl)
    $safeDomains = @(
        'microsoft.com', 'windows.com', 'windowsupdate.com', 'windows.net',
        'office.com', 'office365.com', 'microsoftonline.com',
        'digicert.com', 'verisign.com', 'symantec.com', 'comodo.com',
        'adobe.com', 'google.com', 'googleusercontent.com',
        'github.com', 'githubusercontent.com'
    )

    function Test-SafeHostUrl {
        param([string]$Url)
        if (-not $Url) { return $true }
        foreach ($domain in $safeDomains) {
            if ($Url -imatch [regex]::Escape($domain)) { return $true }
        }
        return $false
    }

    # Executable/script extensions (high risk when zone-marked)
    $execExtensions = @('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi', '.scr', '.pif', '.com')

    # Search directories for Zone.Identifier ADS (Mark of the Web)
    $searchDirs = @(
        [System.Environment]::GetFolderPath("MyDocuments") + "\..\Downloads",
        $env:TEMP,
        [System.Environment]::GetFolderPath("Desktop"),
        "C:\Users\Public"
    )

    foreach ($dir in $searchDirs) {
        try {
            if (-not (Test-Path $dir)) { continue }

            $files = Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 100

            foreach ($file in $files) {
                try {
                    $zoneStream = Get-Content "$($file.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
                    if (-not $zoneStream) { continue }

                    $zoneId  = 0
                    $hostUrl = ""
                    $referrerUrl = ""
                    foreach ($line in $zoneStream) {
                        if ($line -match '^ZoneId=(\d+)') { $zoneId = [int]$matches[1] }
                        if ($line -match '^HostUrl=(.+)') { $hostUrl = $matches[1].Trim() }
                        if ($line -match '^ReferrerUrl=(.+)') { $referrerUrl = $matches[1].Trim() }
                    }

                    # Only zone 3 (Internet) and zone 4 (Restricted)
                    if ($zoneId -lt 3) { continue }

                    $ext = [System.IO.Path]::GetExtension($file.Name).ToLower()
                    $isExec  = $execExtensions -contains $ext
                    $isSafe  = Test-SafeHostUrl $hostUrl
                    $isTemp  = $file.DirectoryName -imatch '\\Temp|\\Tmp|\\Users\\Public'

                    # Risk classification
                    $risk = "low"
                    if ($isExec -and $isTemp -and -not $isSafe) { $risk = "high" }
                    elseif ($isExec -and -not $isSafe)          { $risk = "medium" }
                    elseif ($isSafe)                            { $risk = "safe" }

                    if ($risk -ne "safe") {
                        $result.zone_marked_files += [PSCustomObject]@{
                            file_name   = $file.Name
                            file_path   = $file.FullName
                            extension   = $ext
                            zone_id     = $zoneId
                            host_url    = $hostUrl
                            referrer    = $referrerUrl
                            created     = $file.CreationTime.ToString("o")
                            modified    = $file.LastWriteTime.ToString("o")
                            size_bytes  = $file.Length
                            is_exec     = $isExec
                            in_temp     = $isTemp
                            risk        = $risk
                        }
                    }
                } catch {
                    # ADS read errors are normal — skip silently
                }
            }
        } catch {
            $result.errors += "zone_scan[$dir]: $($_.Exception.Message)"
        }

        if ($result.zone_marked_files.Count -ge 50) { break }
    }

    # --- BITS Transfer History ---
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction Stop | Where-Object {
            $_.JobState -in @('Transferred', 'Complete', 'Error') -and
            $_.TransferType -eq 'Download'
        } | Select-Object -First 20

        foreach ($job in $bitsJobs) {
            $isSafe = Test-SafeHostUrl $job.FileUrl
            if (-not $isSafe) {
                $result.bits_transfers += [PSCustomObject]@{
                    display_name  = $job.DisplayName
                    file_url      = $job.FileUrl
                    local_name    = $job.LocalName
                    state         = $job.JobState.ToString()
                    created       = if ($job.CreationTime) { $job.CreationTime.ToString("o") } else { "" }
                    bytes_total   = $job.BytesTotal
                }
            }
        }
    } catch {
        $result.errors += "bits: $($_.Exception.Message)"
    }

    $result | ConvertTo-Json -Depth 4 -Compress

} catch {
    @{ error = $_.Exception.Message; check = "file_download" } | ConvertTo-Json -Compress
}
