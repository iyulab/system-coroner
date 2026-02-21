# scripts/windows/account_compromise.ps1
#
# Detection: Account creation, privilege escalation, brute force
# MITRE: T1136, T1078, T1550
# Requires: Administrator (Security event log access)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at = (Get-Date -Format "o")
        hostname     = $env:COMPUTERNAME
        check        = "account_compromise"
        events       = @{
            account_created         = @()
            account_deleted         = @()
            group_added             = @()
            explicit_creds          = @()
            failed_logons           = @()
            successful_logons_by_ip = @()  # EID 4624 from external IPs — brute-force correlation
            interactive_logons      = @()  # EID 4624 Type 2/10 — console/RDP presence
        }
        admin_members = @()
        recent_accounts = @()
        hidden_accounts = @()
        errors       = @()
    }

    # --- Security event log queries (72 hours) ---
    $startTime = (Get-Date).AddHours(-72)

    # EID 4720: Account created — structured parse (target account + who created it)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4720; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.events.account_created = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time        = $_.TimeCreated.ToString("o")
                    target_user = try { $_.Properties[0].Value } catch { "" }  # new account name
                    created_by  = try { $_.Properties[2].Value } catch { "" }  # creator account
                }
            })
        }
    }
    catch { $result.errors += "eid4720: $($_.Exception.Message)" }

    # EID 4726: Account deleted
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4726; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.events.account_deleted = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid4726: $($_.Exception.Message)" }

    # EID 4732: Member added to security-enabled group
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4732; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.events.group_added = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid4732: $($_.Exception.Message)" }

    # EID 4648: Explicit credential use (Pass-the-Hash indicator)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4648; StartTime = $startTime
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($events) {
            $result.events.explicit_creds = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = $_.Message -replace '\r?\n', ' '
                }
            })
        }
    }
    catch { $result.errors += "eid4648: $($_.Exception.Message)" }

    # EID 4625: Failed logons (brute force detection)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4625; StartTime = $startTime
        } -MaxEvents 500 -ErrorAction SilentlyContinue
        if ($events) {
            # Aggregate by source IP
            $grouped = $events | Group-Object { ($_.Properties[19]).Value } | ForEach-Object {
                [PSCustomObject]@{
                    source_ip = $_.Name
                    count     = $_.Count
                    first     = ($_.Group | Select-Object -Last 1).TimeCreated.ToString("o")
                    last      = ($_.Group | Select-Object -First 1).TimeCreated.ToString("o")
                }
            } | Sort-Object count -Descending | Select-Object -First 20
            $result.events.failed_logons = @($grouped)
        }
    }
    catch { $result.errors += "eid4625: $($_.Exception.Message)" }

    # EID 4624: Successful logons — critical for brute-force correlation
    # If 4625 (failures) spike then 4624 (success) from same IP follows → confirmed initial access
    # If 4625 spikes but NO 4624 from that IP → brute-force likely failed
    try {
        $events4624 = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4624; StartTime = $startTime
        } -MaxEvents 1000 -ErrorAction SilentlyContinue

        if ($events4624) {
            # Part A: Network logons (Type 3=network, 10=RemoteInteractive) from external IPs
            # Correlate against failed_logons to detect successful brute-force
            $extNetLogons = $events4624 | Where-Object {
                $logonType = try { $_.Properties[8].Value } catch { -1 }
                $srcIp = try { $_.Properties[18].Value } catch { "" }
                ($logonType -in @(3, 10)) -and
                $srcIp -and $srcIp -ne '-' -and $srcIp -ne '::1' -and $srcIp -ne '' -and
                $srcIp -notmatch '^(127\.|0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            }
            if ($extNetLogons) {
                $grouped = $extNetLogons | Group-Object { try { $_.Properties[18].Value } catch { "-" } } | ForEach-Object {
                    $sample = $_.Group | Select-Object -First 1
                    [PSCustomObject]@{
                        source_ip   = $_.Name
                        count       = $_.Count
                        first       = ($_.Group | Select-Object -Last 1).TimeCreated.ToString("o")
                        last        = ($_.Group | Select-Object -First 1).TimeCreated.ToString("o")
                        logon_type  = try { $sample.Properties[8].Value } catch { 0 }
                        target_user = try { $sample.Properties[5].Value } catch { "" }
                    }
                } | Sort-Object count -Descending | Select-Object -First 20
                $result.events.successful_logons_by_ip = @($grouped)
            }

            # Part B: Interactive/RDP logons (Type 2=Console, 10=RDP)
            # Shows whether a person was physically/remotely present on the machine
            $skipUsers = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
            $interactiveLogons = $events4624 | Where-Object {
                $logonType = try { $_.Properties[8].Value } catch { -1 }
                $user = try { $_.Properties[5].Value } catch { "" }
                ($logonType -in @(2, 10)) -and
                ($user -notin $skipUsers) -and
                -not ($user -match '^(UMFD|DWM)-\d+$')
            } | Select-Object -First 20 | ForEach-Object {
                [PSCustomObject]@{
                    time        = $_.TimeCreated.ToString("o")
                    logon_type  = try { $_.Properties[8].Value } catch { 0 }  # 2=Console, 10=RDP
                    user        = try { $_.Properties[5].Value } catch { "" }
                    workstation = try { $_.Properties[11].Value } catch { "" }
                    source_ip   = try { $_.Properties[18].Value } catch { "-" }
                }
            }
            if ($interactiveLogons) {
                $result.events.interactive_logons = @($interactiveLogons)
            }
        }
    }
    catch { $result.errors += "eid4624: $($_.Exception.Message)" }

    # --- Current Administrators group members ---
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($admins) {
            $result.admin_members = @($admins | ForEach-Object {
                [PSCustomObject]@{
                    name           = $_.Name
                    object_class   = $_.ObjectClass
                    principal_source = $_.PrincipalSource.ToString()
                }
            })
        }
    }
    catch { $result.errors += "admin_members: $($_.Exception.Message)" }

    # --- All local accounts (no description filter — suspicious accounts often have no description) ---
    try {
        $users = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                name              = $_.Name
                enabled           = $_.Enabled
                password_expires  = if ($_.PasswordExpires) { $_.PasswordExpires.ToString("o") } else { "never" }
                password_last_set = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("o") } else { "" }
                last_logon        = if ($_.LastLogon) { $_.LastLogon.ToString("o") } else { "" }
                description       = if ($_.Description) { $_.Description } else { "" }
            }
        }
        if ($users) {
            $result.recent_accounts = @($users)
        }
    }
    catch { $result.errors += "recent_accounts: $($_.Exception.Message)" }

    # --- Hidden accounts ($ suffix pattern) ---
    try {
        $hidden = Get-LocalUser -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\$$' -and $_.Name -ne "$env:COMPUTERNAME$" }
        if ($hidden) {
            $result.hidden_accounts = @($hidden | ForEach-Object {
                [PSCustomObject]@{
                    name    = $_.Name
                    enabled = $_.Enabled
                }
            })
        }
    }
    catch { $result.errors += "hidden_accounts: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "account_compromise"
        error        = $_.Exception.Message
        events       = @{}
    } | ConvertTo-Json -Compress
    exit 1
}
