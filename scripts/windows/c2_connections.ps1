# scripts/windows/c2_connections.ps1
#
# Detection: C2 communication, reverse shells, beacon traffic
# MITRE: T1071, T1048, T1095
# Requires: Standard User (Admin recommended for process details)
# Expected runtime: ~10s

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

try {
    $result = @{
        collected_at = (Get-Date -Format "o")
        hostname     = $env:COMPUTERNAME
        check        = "c2_connections"
        connections  = @()
        dns_cache    = @()
        errors       = @()
    }

    # --- External TCP connections with process mapping ---
    # WFC-004: Authenticode signature check helper
    function Get-ProcessSignatureStatus {
        param([string]$Path)
        if (-not $Path -or -not (Test-Path $Path -ErrorAction SilentlyContinue)) { return "unknown" }
        try {
            $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
            if ($sig) { return $sig.Status.ToString() } else { return "unknown" }
        } catch { return "error" }
    }

    # Track paths already checked to avoid repeated signature lookups
    $checkedSignatures = @{}

    try {
        $rawConns = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object {
                $_.RemoteAddress -notmatch '^(127\.|0\.|::1|::$)' -and
                $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            }

        if ($rawConns) {
            $connections = $rawConns | ForEach-Object {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $procPath = if ($proc) { $proc.Path } else { "" }

                # WFC-004: Check signature (cache by path, limit to first 10 unique paths)
                $sigStatus = "skipped"
                if ($procPath -and $checkedSignatures.Count -lt 10) {
                    if (-not $checkedSignatures.ContainsKey($procPath)) {
                        $checkedSignatures[$procPath] = Get-ProcessSignatureStatus -Path $procPath
                    }
                    $sigStatus = $checkedSignatures[$procPath]
                }

                [PSCustomObject]@{
                    local_address    = $_.LocalAddress
                    local_port       = $_.LocalPort
                    remote_address   = $_.RemoteAddress
                    remote_port      = $_.RemotePort
                    state            = $_.State.ToString()
                    pid              = $_.OwningProcess
                    process_name     = if ($proc) { $proc.ProcessName } else { "unknown" }
                    process_path     = $procPath
                    signature_status = $sigStatus
                    creation_time    = if ($proc -and $proc.StartTime) { $proc.StartTime.ToString("o") } else { "" }
                }
            }
            $result.connections = @($connections)
        }
    }
    catch {
        # WFC-001: Fallback to netstat if Get-NetTCPConnection fails (older OS or WMI issues)
        $result.errors += "Get-NetTCPConnection failed ($($_.Exception.Message)); falling back to netstat"
        try {
            $netstatLines = & netstat -nao 2>$null
            $parsed = @()
            foreach ($line in $netstatLines) {
                if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+ESTABLISHED\s+(\d+)') {
                    $localIP  = $Matches[1]
                    $remoteIP = $Matches[3]
                    # Filter RFC1918 and loopback
                    if ($remoteIP -match '^(127\.|0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { continue }
                    $pid = [int]$Matches[5]
                    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    $parsed += [PSCustomObject]@{
                        local_address    = $localIP
                        local_port       = [int]$Matches[2]
                        remote_address   = $remoteIP
                        remote_port      = [int]$Matches[4]
                        state            = "ESTABLISHED"
                        pid              = $pid
                        process_name     = if ($proc) { $proc.ProcessName } else { "unknown" }
                        process_path     = if ($proc) { $proc.Path } else { "" }
                        signature_status = "skipped"
                        source           = "netstat_fallback"
                    }
                }
            }
            if ($parsed) { $result.connections = @($parsed) }
        }
        catch {
            $result.errors += "netstat fallback also failed: $($_.Exception.Message)"
        }
    }

    # --- Listening ports on unusual ports ---
    try {
        $suspiciousPorts = @(4444, 1337, 8080, 9001, 5555, 6666, 7777, 8888, 1234, 31337)
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -in $suspiciousPorts } |
            ForEach-Object {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    local_port   = $_.LocalPort
                    pid          = $_.OwningProcess
                    process_name = if ($proc) { $proc.ProcessName } else { "unknown" }
                    process_path = if ($proc) { $proc.Path } else { "" }
                }
            }
        if ($listeners) {
            $result | Add-Member -NotePropertyName "suspicious_listeners" -NotePropertyValue @($listeners)
        }
    }
    catch {
        $result.errors += "listeners: $($_.Exception.Message)"
    }

    # --- CHK-001: Event 7045 — Service installation (RAT/C2 persistence indicator) ---
    try {
        $svcInstalls = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($svcInstalls) {
            $result | Add-Member -NotePropertyName "service_installs" -NotePropertyValue @(
                $svcInstalls | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $data = $xml.Event.EventData.Data
                    $svcName  = ($data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
                    $imgPath  = ($data | Where-Object { $_.Name -eq "ImagePath" }).'#text'
                    $svcType  = ($data | Where-Object { $_.Name -eq "ServiceType" }).'#text'
                    $startType = ($data | Where-Object { $_.Name -eq "StartType" }).'#text'
                    $account  = ($data | Where-Object { $_.Name -eq "AccountName" }).'#text'
                    [PSCustomObject]@{
                        time         = $_.TimeCreated.ToString("o")
                        service_name = $svcName
                        image_path   = $imgPath
                        service_type = $svcType
                        start_type   = $startType
                        account      = $account
                    }
                }
            )
        }
    }
    catch {
        $result.errors += "service_installs: $($_.Exception.Message)"
    }

    # --- DNS client cache (potential DGA domains) ---
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
            Select-Object -First 100 -Property Entry, RecordName, Data, TimeToLive
        if ($dnsCache) {
            $result.dns_cache = @($dnsCache)
        }
    }
    catch {
        $result.errors += "dns_cache: $($_.Exception.Message)"
    }

    $result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{
        collected_at = (Get-Date -Format "o")
        check        = "c2_connections"
        error        = $_.Exception.Message
        connections  = @()
    } | ConvertTo-Json -Compress
    exit 1
}
