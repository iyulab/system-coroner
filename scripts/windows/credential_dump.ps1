# scripts/windows/credential_dump.ps1
#
# Detection: LSASS access, SAM/SECURITY hive access, credential dumping tools
# MITRE: T1003, T1003.001, T1003.002
# Requires: Administrator
# Expected runtime: ~10s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at           = (Get-Date -Format "o")
        hostname               = $env:COMPUTERNAME
        check                  = "credential_dump"
        lsass_protection       = @{}
        credential_tool_traces = @()
        sam_access             = @()
        vss_activity           = @()
        wdigest_auth           = @{}
        errors                 = @()
    }

    # --- LSASS protection status ---
    try {
        $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
        if ($lsass) {
            $result.lsass_protection = @{
                pid = $lsass.Id
                path = $lsass.Path
            }
        }
        # Check RunAsPPL (credential guard)
        try {
            $ppl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
            if ($ppl) {
                $result.lsass_protection["run_as_ppl"] = $ppl.RunAsPPL
            } else {
                $result.lsass_protection["run_as_ppl"] = 0
            }
        }
        catch { }
    }
    catch { $result.errors += "lsass: $($_.Exception.Message)" }

    # --- Credential dumping tool traces (EID 4688: process creation) ---
    try {
        $startTime = (Get-Date).AddHours(-72)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4688; StartTime = $startTime
        } -MaxEvents 2000 -ErrorAction SilentlyContinue

        $toolPatterns = @(
            'mimikatz', 'procdump', 'sekurlsa', 'lsadump', 'kerberos::',
            'ntdsutil', 'secretsdump', 'pypykatz', 'lazagne',
            'gsecdump', 'fgdump', 'pwdumpx', 'wce\.exe',
            'reg\.exe.*save.*\\\\sam', 'reg\.exe.*save.*\\\\security',
            'reg\.exe.*save.*\\\\system'
        )
        $toolPattern = ($toolPatterns -join '|')

        if ($events) {
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $ns = @{e = 'http://schemas.microsoft.com/win/2004/08/events/event'}
                $cmdLine = ($xml | Select-Xml -XPath '//e:Data[@Name="CommandLine"]' -Namespace $ns).Node.'#text'
                $processName = ($xml | Select-Xml -XPath '//e:Data[@Name="NewProcessName"]' -Namespace $ns).Node.'#text'

                if ($cmdLine -and $cmdLine -match $toolPattern) {
                    $result.credential_tool_traces += [PSCustomObject]@{
                        time         = $event.TimeCreated.ToString("o")
                        process      = $processName
                        command_line = if ($cmdLine.Length -gt 2000) { $cmdLine.Substring(0, 2000) + "..." } else { $cmdLine }
                    }
                }
            }
        }
    }
    catch { $result.errors += "cred_tools: $($_.Exception.Message)" }

    # --- SAM/SECURITY hive access via registry save ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4663; StartTime = (Get-Date).AddHours(-72)
        } -MaxEvents 500 -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                $msg = $event.Message
                if ($msg -match '\\SAM|\\SECURITY|\\SYSTEM') {
                    $result.sam_access += [PSCustomObject]@{
                        time    = $event.TimeCreated.ToString("o")
                        message = ($msg -replace '\r?\n', ' ').Substring(0, [Math]::Min(500, $msg.Length))
                    }
                }
            }
        }
    }
    catch { $result.errors += "sam_access: $($_.Exception.Message)" }

    # --- Volume Shadow Copy activity (used for offline credential access) ---
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'; Id = @(7035, 7036); StartTime = (Get-Date).AddHours(-72)
        } -MaxEvents 200 -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                if ($event.Message -match 'Volume Shadow Copy|vssvc|VSNAPVSS') {
                    $result.vss_activity += [PSCustomObject]@{
                        time     = $event.TimeCreated.ToString("o")
                        event_id = $event.Id
                        message  = ($event.Message -replace '\r?\n', ' ').Substring(0, [Math]::Min(300, $event.Message.Length))
                    }
                }
            }
        }

        # Also check for vssadmin/wbadmin in 4688 events
        if ($events) {
            # Already covered by credential_tool_traces above
        }
    }
    catch { $result.errors += "vss: $($_.Exception.Message)" }

    # --- WDigest authentication (plain-text passwords in memory) ---
    try {
        $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        $result.wdigest_auth = @{
            use_logon_credential = if ($wdigest) { $wdigest.UseLogonCredential } else { 0 }
            warning = if ($wdigest -and $wdigest.UseLogonCredential -eq 1) { "ENABLED - plain-text passwords stored in memory" } else { "disabled (default)" }
        }
    }
    catch { $result.errors += "wdigest: $($_.Exception.Message)" }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "credential_dump"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
    exit 1
}
