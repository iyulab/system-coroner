# scripts/windows/file_access.ps1
#
# Detection: File access artifacts — what files the attacker browsed and opened
# MITRE: T1083 (File and Directory Discovery), T1552 (Unsecured Credentials),
#        T1005 (Data from Local System)
# Requires: Standard User (reads current user profile)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at      = (Get-Date -Format "o")
        hostname          = $env:COMPUTERNAME
        check             = "file_access"
        recent_items      = @()
        sensitive_lnk     = @()
        errors            = @()
    }

    # --- Sensitive file/path patterns ---
    $sensitivePatterns = @(
        '\\SAM$',
        '\\NTDS\.dit$',
        '\\SYSTEM$',
        '\\SECURITY$',
        '\.pfx$',
        '\.pem$',
        '\.key$',
        '\.p12$',
        'id_rsa',
        '\.kdb$',
        '\.kdbx$',
        '\.rdp$',
        '\\backup\\',
        'shadow',
        '\.bak$',
        'passwords',
        'credential',
        '\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles.*\\logins\.json',
        '\\AppData\\Local\\Google\\Chrome.*\\Login Data',
        '\\AppData\\Roaming\\Microsoft\\Credentials\\'
    )

    function Test-SensitivePath {
        param([string]$Path)
        foreach ($pattern in $sensitivePatterns) {
            if ($Path -imatch $pattern) { return $true }
        }
        return $false
    }

    # --- Safe path filter (skip LNKs pointing to system/program dirs) ---
    function Test-SafeLnkTarget {
        param([string]$Target)
        if (-not $Target) { return $false }
        return ($Target -imatch '^C:\\Windows\\' -or $Target -imatch '^C:\\Program Files')
    }

    # --- Recent Items LNK Files ---
    try {
        $recentDir = [System.Environment]::GetFolderPath("Recent")
        if (Test-Path $recentDir) {
            $lnkFiles = Get-ChildItem $recentDir -Filter "*.lnk" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 200

            $wshell = New-Object -ComObject WScript.Shell

            foreach ($lnk in $lnkFiles) {
                try {
                    $shortcut = $wshell.CreateShortcut($lnk.FullName)
                    $target = $shortcut.TargetPath

                    # Skip safe targets
                    if (Test-SafeLnkTarget $target) { continue }

                    $isSensitive = Test-SensitivePath $target

                    $entry = [PSCustomObject]@{
                        lnk_name      = $lnk.Name
                        target_path   = $target
                        accessed      = $lnk.LastWriteTime.ToString("o")
                        is_sensitive  = $isSensitive
                    }

                    if ($isSensitive) {
                        $result.sensitive_lnk += $entry
                    } else {
                        $result.recent_items += $entry
                    }
                } catch {
                    # Skip unparseable LNK files silently
                }
            }

            # Limit recent_items to 30 (sensitive_lnk: all)
            if ($result.recent_items.Count -gt 30) {
                $result.recent_items = $result.recent_items | Select-Object -First 30
            }
        }
    } catch {
        $result.errors += "recent_items: $($_.Exception.Message)"
    } finally {
        if ($wshell) {
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wshell) | Out-Null
        }
    }

    $result | ConvertTo-Json -Depth 4 -Compress

} catch {
    @{ error = $_.Exception.Message; check = "file_access" } | ConvertTo-Json -Compress
}
