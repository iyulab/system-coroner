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
            account_created  = @()
            account_deleted  = @()
            group_added      = @()
            explicit_creds   = @()
            failed_logons    = @()
        }
        admin_members = @()
        recent_accounts = @()
        hidden_accounts = @()
        errors       = @()
    }

    # --- Security event log queries (72 hours) ---
    $startTime = (Get-Date).AddHours(-72)

    # EID 4720: Account created
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4720; StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $result.events.account_created = @($events | ForEach-Object {
                [PSCustomObject]@{
                    time    = $_.TimeCreated.ToString("o")
                    message = $_.Message -replace '\r?\n', ' ' | Select-Object -First 1
                    xml     = $_.ToXml()
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

    # --- Recently created local accounts ---
    try {
        $users = Get-LocalUser -ErrorAction SilentlyContinue |
            Where-Object { $_.Description -ne $null } |
            ForEach-Object {
                [PSCustomObject]@{
                    name              = $_.Name
                    enabled           = $_.Enabled
                    password_expires  = if ($_.PasswordExpires) { $_.PasswordExpires.ToString("o") } else { "never" }
                    last_logon        = if ($_.LastLogon) { $_.LastLogon.ToString("o") } else { "" }
                    description       = $_.Description
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
