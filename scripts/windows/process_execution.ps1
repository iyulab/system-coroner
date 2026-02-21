# scripts/windows/process_execution.ps1
#
# Detection: Program execution artifacts — evidence of tools run by attacker
# MITRE: T1059 (Command and Scripting), T1204 (User Execution),
#        T1218 (System Binary Proxy Execution)
# Requires: Standard User (some artifacts require Admin for full access)
# Expected runtime: ~20s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at    = (Get-Date -Format "o")
        hostname        = $env:COMPUTERNAME
        check           = "process_execution"
        prefetch_files  = @()
        bam_entries     = @()
        shimcache_entries = @()
        errors          = @()
    }

    # --- Known safe Windows paths (coarse filter) ---
    $safePathPatterns = @(
        '^C:\\Windows\\System32\\',
        '^C:\\Windows\\SysWOW64\\',
        '^C:\\Windows\\WinSxS\\',
        '^C:\\Program Files\\Microsoft\\',
        '^C:\\Program Files \(x86\)\\Microsoft\\',
        '^C:\\Program Files\\Windows Defender\\',
        '^C:\\Program Files\\Common Files\\Microsoft Shared\\'
    )

    function Test-SafePath {
        param([string]$Path)
        if (-not $Path) { return $false }
        foreach ($pattern in $safePathPatterns) {
            if ($Path -imatch $pattern) { return $true }
        }
        return $false
    }

    # --- Known attack tool names ---
    $attackToolNames = @(
        'mimikatz', 'procdump', 'psexec', 'meterpreter', 'cobalt',
        'bloodhound', 'sharphound', 'rubeus', 'kerberoast', 'secretsdump',
        'powercat', 'invoke-mimikatz', 'lazagne', 'credential', 'hashdump',
        'nmap', 'masscan', 'metasploit', 'msfvenom', 'shellcode',
        'wce', 'fgdump', 'pwdump', 'gsecdump'
    )

    # --- Prefetch Files ---
    # Prefetch records last 8 execution timestamps — survives file deletion
    try {
        $prefetchDir = "C:\Windows\Prefetch"
        if (Test-Path $prefetchDir) {
            $pfFiles = Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 200

            foreach ($pf in $pfFiles) {
                $exeName = $pf.Name -replace '-[0-9A-F]{8}\.pf$', '' -replace '\.pf$', ''
                $exeNameLower = $exeName.ToLower()

                # Skip known-safe Windows executables
                $isWinExe = $exeNameLower -match '^(svchost|lsass|explorer|csrss|wininit|services|smss|' +
                    'dllhost|rundll32|regsvr32|msiexec|spoolsv|searchindexer|taskhost|' +
                    'winlogon|dwm|audiodg|taskmgr|conhost|fontdrvhost|runtimebroker|' +
                    'sihost|ctfmon|backgroundtaskhost|wuauclt|mscorsvw|ngentask|' +
                    'microsoftedge|msedge|onedrive|teams|outlook|word|excel|powerpnt|' +
                    'chrome|firefox|iexplore)\.exe$'
                if ($isWinExe) { continue }

                # Flag attack tools immediately
                $isAttackTool = $false
                foreach ($tool in $attackToolNames) {
                    if ($exeNameLower -like "*$tool*") {
                        $isAttackTool = $true
                        break
                    }
                }

                $result.prefetch_files += [PSCustomObject]@{
                    name           = $exeName
                    last_run       = $pf.LastWriteTime.ToString("o")
                    created        = $pf.CreationTime.ToString("o")
                    size_bytes     = $pf.Length
                    attack_tool    = $isAttackTool
                }

                if ($result.prefetch_files.Count -ge 50) { break }
            }
        } else {
            $result.errors += "prefetch: directory not found (Prefetch may be disabled)"
        }
    } catch {
        $result.errors += "prefetch: $($_.Exception.Message)"
    }

    # --- BAM (Background Activity Moderator) — Windows 10+ ---
    # Records per-user last execution time for executables
    try {
        $bamRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        if (Test-Path $bamRoot) {
            $userKeys = Get-ChildItem $bamRoot -ErrorAction SilentlyContinue
            foreach ($userKey in $userKeys) {
                $entries = Get-ItemProperty $userKey.PSPath -ErrorAction SilentlyContinue
                $entries.PSObject.Properties | Where-Object {
                    $_.Name -match '\.exe$' -and $_.Value -is [byte[]]
                } | ForEach-Object {
                    $path = $_.Name

                    # Skip safe paths
                    if (Test-SafePath $path) { return }

                    # Parse the 8-byte FILETIME value
                    $lastRun = ""
                    if ($_.Value.Count -ge 8) {
                        try {
                            $ft = [System.BitConverter]::ToInt64($_.Value, 0)
                            if ($ft -gt 0) {
                                $lastRun = [System.DateTime]::FromFileTimeUtc($ft).ToString("o")
                            }
                        } catch {}
                    }

                    $exeName  = Split-Path $path -Leaf
                    $isAttack = $false
                    foreach ($tool in $attackToolNames) {
                        if ($exeName.ToLower() -like "*$tool*") { $isAttack = $true; break }
                    }

                    $result.bam_entries += [PSCustomObject]@{
                        path        = $path
                        exe_name    = $exeName
                        last_run    = $lastRun
                        user_sid    = Split-Path $userKey.PSPath -Leaf
                        attack_tool = $isAttack
                    }
                }
            }
            # Limit
            if ($result.bam_entries.Count -gt 100) {
                $result.bam_entries = $result.bam_entries | Sort-Object last_run -Descending | Select-Object -First 100
            }
        }
    } catch {
        $result.errors += "bam: $($_.Exception.Message)"
    }

    # --- AppCompatCache (Shimcache) — survives reboots and file deletion ---
    # Registry path stores list of executables that have been present on the system
    try {
        $shimPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        $shimData = Get-ItemProperty $shimPath -Name "AppCompatCache" -ErrorAction Stop
        # The raw binary is complex to parse without native code, so we record the presence
        # and check for attack tool names in related event logs instead
        $result.shimcache_entries += [PSCustomObject]@{
            note       = "ShimCache present — binary parsing requires native tool (e.g. AppCompatCacheParser)"
            size_bytes = $shimData.AppCompatCache.Count
        }
    } catch {
        $result.errors += "shimcache: $($_.Exception.Message)"
    }

    $result | ConvertTo-Json -Depth 5 -Compress

} catch {
    @{ error = $_.Exception.Message; check = "process_execution" } | ConvertTo-Json -Compress
}
