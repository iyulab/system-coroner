# scripts/windows/discovery_recon.ps1
#
# Detection: Internal reconnaissance — system/network discovery commands
# MITRE: T1046 (Network Service Scanning), T1082 (System Info Discovery),
#        T1083 (File/Dir Discovery), T1087 (Account Discovery),
#        T1069 (Permission Groups Discovery)
# Requires: Standard User (Admin recommended for full event log access)
# Expected runtime: ~15s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at    = (Get-Date -Format "o")
        hostname        = $env:COMPUTERNAME
        check           = "discovery_recon"
        recon_commands  = @()
        rdp_mru         = @()
        errors          = @()
    }

    # --- Recon command patterns from Event 4688 (Process Creation) ---
    # Filter: last 7 days, known recon tool names and arguments
    $reconPatterns = @(
        # Account / domain discovery
        'net\s+(user|group|localgroup|accounts)',
        'whoami\s+(/all|/groups|/priv)',
        'nltest\s+/domain_trusts',
        'dsquery\s+\*',
        # Network discovery
        'arp\s+-a',
        'route\s+print',
        'ipconfig\s+(/all|/displaydns)',
        'nslookup',
        'net\s+(view|use)\b',
        # Port scan patterns (nmap, masscan running on host)
        '\bnmap\b',
        '\bmasscan\b',
        # BloodHound / SharpHound
        'SharpHound',
        'BloodHound',
        '-CollectionMethod\s+All',
        # Remote execution discovery
        'psexec',
        'wmic\s+/node',
        # SQL Server xp_cmdshell
        'xp_cmdshell',
        # File system enumeration
        'dir\s+/s\s+/b',
        'tree\s+/f',
        # systeminfo
        '\bsysteminfo\b'
    )

    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688) and TimeCreated[@SystemTime>='$($sevenDaysAgo.ToUniversalTime().ToString("o"))']]]
    </Select>
  </Query>
</QueryList>
"@
        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction Stop

        foreach ($evt in $events) {
            $xml  = [xml]$evt.ToXml()
            $data = $xml.Event.EventData.Data

            $procName = ($data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
            $cmdLine  = ($data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            $account  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $parentProc = ($data | Where-Object { $_.Name -eq 'ParentProcessName' }).'#text'

            if (-not $cmdLine) { continue }

            # Coarse filter: skip monitoring agents
            if ($procName -match 'scom|nagios|zabbix|nessus|splunk' -or
                $account -match 'SYSTEM$|LOCAL SERVICE$|NETWORK SERVICE$') {
                continue
            }

            $matched = $false
            foreach ($pattern in $reconPatterns) {
                if ($cmdLine -imatch $pattern -or $procName -imatch $pattern) {
                    $matched = $true
                    break
                }
            }

            if ($matched) {
                $result.recon_commands += [PSCustomObject]@{
                    time         = $evt.TimeCreated.ToString("o")
                    process_name = if ($procName) { Split-Path $procName -Leaf } else { "" }
                    process_path = $procName
                    command_line = if ($cmdLine.Length -gt 300) { $cmdLine.Substring(0,300) + "..." } else { $cmdLine }
                    account      = $account
                    parent_proc  = if ($parentProc) { Split-Path $parentProc -Leaf } else { "" }
                    event_id     = 4688
                }
            }

            # Limit to 50 most recent
            if ($result.recon_commands.Count -ge 50) { break }
        }
    } catch {
        $result.errors += "event_4688: $($_.Exception.Message)"
    }

    # --- RDP Client MRU (pivot evidence: this host connected to other hosts) ---
    try {
        $rdpKey = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
        if (Test-Path $rdpKey) {
            Get-ChildItem $rdpKey -ErrorAction SilentlyContinue | ForEach-Object {
                $server = $_.PSChildName
                $props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $result.rdp_mru += [PSCustomObject]@{
                    server    = $server
                    username  = if ($props.UsernameHint) { $props.UsernameHint } else { "" }
                }
            }
        }
    } catch {
        $result.errors += "rdp_mru: $($_.Exception.Message)"
    }

    $result | ConvertTo-Json -Depth 4 -Compress

} catch {
    @{ error = $_.Exception.Message; check = "discovery_recon" } | ConvertTo-Json -Compress
}
