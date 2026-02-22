# Intrusion Detection Checks Reference

Complete list of intrusion indicators that system-coroner detects.
Each check is designed around the question: **"What might an attacker have done on this server?"**

---

## Detection Map (MITRE ATT&CK)

```
Initial Access              Internal Activity           Persistence
──────────────────     ──────────────────────     ──────────────────────
Webshell detection     Credential dumping          Registry Run keys
                       Lateral movement            Scheduled task implant
                       LOLBin abuse                Service implant
                                                   WMI subscription (Fileless)
                       ──────────────────────
                       C2 communication
                       Log deletion/tampering
                       Account manipulation
```

---

## Implementation Status

| Check ID | Script | Platform | MITRE ATT&CK | Status |
|----------|--------|----------|--------------|--------|
| `c2_connections` | `scripts/windows/c2_connections.ps1` | Windows | T1071.001, T1071.004, T1048.003, T1095, T1573 | ✅ |
| `account_compromise` | `scripts/windows/account_compromise.ps1` | Windows | T1136.001, T1078.003, T1550.002, T1110.003 | ✅ |
| `persistence` | `scripts/windows/persistence.ps1` | Windows | T1547.001, T1053.005, T1543.003, T1546.001, T1027.010 | ✅ |
| `lolbin_abuse` | `scripts/windows/lolbin_abuse.ps1` | Windows | T1218.002, T1218.010, T1218.011, T1059.001, T1059.003, T1105 | ✅ |
| `fileless_attack` | `scripts/windows/fileless_attack.ps1` | Windows | T1546.003, T1055.002, T1059.001, T1620 | ✅ |
| `log_tampering` | `scripts/windows/log_tampering.ps1` | Windows | T1070.001, T1562.002, T1562.006 | ✅ |
| `credential_dump` | `scripts/windows/credential_dump.ps1` | Windows | T1003.001, T1003.002, T1003.003, T1552.002 | ✅ |
| `lateral_movement` | `scripts/windows/lateral_movement.ps1` | Windows | T1021.001, T1021.002, T1021.006, T1570, T1135 | ✅ |
| `webshell` | `scripts/windows/webshell.ps1` | Windows | T1505.003, T1190, T1036.005 | ✅ |
| `discovery_recon` | `scripts/windows/discovery_recon.ps1` | Windows | T1046, T1082, T1083, T1087, T1069 | ✅ |
| `process_execution` | `scripts/windows/process_execution.ps1` | Windows | T1059, T1204, T1218 | ✅ |
| `file_access` | `scripts/windows/file_access.ps1` | Windows | T1083, T1552, T1005 | ✅ |
| `file_download` | `scripts/windows/file_download.ps1` | Windows | T1105, T1140, T1608 | ✅ |
| `staging_exfiltration` | `scripts/windows/staging_exfiltration.ps1` | Windows | T1074, T1560, T1048, T1052 | ✅ |
| `c2_connections` | `scripts/linux/c2_connections.sh` | Linux | T1071.001, T1071.004, T1048.003, T1095, T1090 | ✅ |
| `persistence` | `scripts/linux/persistence.sh` | Linux | T1053.003, T1543.002, T1037.004, T1574.006, T1546.004 | ✅ |
| `log_tampering` | `scripts/linux/log_tampering.sh` | Linux | T1070.001, T1070.002, T1562.001 | ✅ |
| `account_compromise` | `scripts/linux/account_compromise.sh` | Linux | T1136.001, T1098.004, T1110.001 | ✅ |
| `credential_dump` | `scripts/linux/credential_dump.sh` | Linux | T1003.008, T1003.007, T1552.001 | ✅ |
| `fileless_attack` | `scripts/linux/fileless_attack.sh` | Linux | T1059.004, T1620, T1027.002 | ✅ |
| `lolbin_abuse` | `scripts/linux/lolbin_abuse.sh` | Linux | T1059.004, T1105, T1218 | ✅ |
| `lateral_movement` | `scripts/linux/lateral_movement.sh` | Linux | T1021.004, T1572, T1563.001 | ✅ |
| `webshell` | `scripts/linux/webshell.sh` | Linux | T1505.003, T1190 | ✅ |
| `discovery_recon` | `scripts/linux/discovery_recon.sh` | Linux | T1046, T1082, T1083, T1087 | ✅ |
| `staging_exfiltration` | `scripts/linux/staging_exfiltration.sh` | Linux | T1074, T1560, T1048 | ✅ |

Test fixtures: `tests/fixtures/{platform}/{clean,compromised}/{check_id}.json`

---

## Sigma Rule Pre-Detection (SIG-001)

Before LLM analysis, all collected evidence is evaluated against embedded Sigma rules.
Results appear in the report as **"Sigma Rule Matches"** — deterministic, independent of LLM.

| Rule | Scope | Level |
|------|-------|-------|
| C2 Connection from Temp Path | `c2_connections` | high |
| Credential Harvesting Tool Detected | `credential_dump` | critical |
| Base64-Encoded Persistence Command | `persistence` | high |

Rules are embedded in `internal/sigma/rules/windows/` and evaluated via `github.com/bradleyjkemp/sigma-go`.

---

## Windows Server Detection Checks

---

### `c2_connections` — C2 Communication and Reverse Shell Detection

**Goal:** Detect attacker C2 server communication, reverse shells, and beacon traffic.

**What is collected:**
- All outbound external connections (process name + PID + remote IP:Port)
- Connections to attacker-preferred ports (4444, 1337, 8080, 9001, etc.)
- Non-HTTPS connections over port 443 (SSL tunneling disguise)
- Processes repeatedly connecting to the same external IP (beacon pattern)
- DNS query anomalies (DGA domains, abnormally long subdomains)
- Event 7045 (service installation) — ServiceName, ImagePath, ServiceType, StartType, AccountName

**LLM analysis focus:**
- Are system processes (`svchost.exe`, `lsass.exe`) making external connections?
- Is connection frequency regular (beacon signature — 30s, 60s intervals)?
- Is the remote IP a known cloud/CDN, or unknown?
- Is the connecting process running from an expected path?
- Service installations (Event 7045): PSEXESVC, services from Temp/AppData paths, suspicious service types
- Correlate service installation timestamps with external connections for C2→persistence timeline

**MITRE:** T1071 (Application Layer Protocol), T1048 (Exfiltration Over C2), T1095 (Non-Standard Port), T1543.003 (Windows Service)

---

### `account_compromise` — Account Takeover and Manipulation

**Goal:** Detect evidence that an attacker created accounts, took over existing ones, or escalated privileges.

**What is collected:**
- Event ID 4720 (account created), 4726 (account deleted)
- Event ID 4732 (added to Administrators), 4733 (removed from Administrators)
- Event ID 4648 (explicit credentials used — Pass-the-Hash indicator)
- Event ID 4625 (login failure) — frequency analysis by source IP
- Full current Administrators group membership
- Recently created accounts (with creation timestamp)
- Accounts with `$` suffix (hidden account pattern)
- Accounts with no password expiry + Administrator group membership

**LLM analysis focus:**
- Account created outside business hours?
- Large number of 4625 events in a short window (brute force)?
- Did 4648 events originate from an unusual process?
- Unknown account in the Administrators group?

**MITRE:** T1136 (Create Account), T1078 (Valid Accounts), T1550 (Pass-the-Hash)

---

### `persistence` — Post-Reboot Survival Mechanism Detection

**Goal:** Detect items an attacker installed to re-execute after a server reboot.

**What is collected:**

*Registry autorun (7 paths)*
- `HKLM\SOFTWARE\...\Run`, `RunOnce` (64-bit)
- `HKCU\SOFTWARE\...\Run`, `RunOnce` (64-bit)
- `HKLM\SOFTWARE\WOW6432Node\...\Run`, `RunOnce` (32-bit on 64-bit OS — frequent malware hiding spot)
- `HKCU\SOFTWARE\WOW6432Node\...\Run`
- `HKLM\...\Winlogon` (Userinit, Shell values)
- `HKLM\...\Image File Execution Options` (debugger hijacking, T1546.001)
- `HKLM\SYSTEM\CurrentControlSet\Services` (service registration)

*Scheduled tasks*
- All registered tasks (execution path, trigger, run-as account)
- Recently created tasks (by creation timestamp)
- Non-standard tasks running as SYSTEM

*Services*
- All non-Microsoft services
- Services whose binary path is in Temp, AppData, or user directories
- Services directly invoking `cmd.exe` or `powershell.exe`

**LLM analysis focus:**
- Items running from Temp/AppData paths (almost always malicious)
- PowerShell commands with `-EncodedCommand` or Base64 payload (`base64_detections` field)
- WOW64 Run key entries (legitimate 64-bit software rarely uses these)
- Entries created within the last few days
- Names disguised as legitimate programs (typos, lookalike characters, Unicode)

**MITRE:** T1547.001, T1053.005, T1543.003, T1546.001, T1027.010

---

### `lolbin_abuse` — Living-off-the-Land Attack Detection

**Goal:** Detect attacks using built-in Windows tools to evade detection.

Attackers abuse legitimate Windows binaries — `powershell.exe`, `certutil.exe`, `mshta.exe`, etc. — to perform malicious actions without dropping additional files, bypassing antivirus.

**What is collected:**

| Tool | Attacker abuse method |
|------|-----------------------|
| `powershell.exe` | Base64-encoded commands, `-EncodedCommand`, `-WindowStyle Hidden` |
| `certutil.exe` | File download (`-urlcache -split -f`) |
| `mshta.exe` | Remote HTA file execution |
| `wscript.exe` / `cscript.exe` | VBScript/JScript payload execution |
| `regsvr32.exe` | Remote code execution via COM object (Squiblydoo) |
| `rundll32.exe` | DLL sideloading |
| `bitsadmin.exe` | Background file download |
| `wmic.exe` | Remote process execution, reconnaissance |
| `net.exe` / `net1.exe` | Account manipulation, share enumeration |

- Event log 4688 (process creation) scanned for anomalous arguments to the above tools
- PowerShell command lines with abnormally large length
- Above tools launched from unexpected parent processes

**MITRE:** T1218 (System Binary Proxy Execution), T1059 (Command and Scripting Interpreter)

---

### `fileless_attack` — Fileless Attack Detection

**Goal:** Detect memory-based and WMI-based attacks that leave no files on disk.

**What is collected:**

*WMI persistence*
- WMI event subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding)
- Unknown WMI subscriptions (a key attacker persistence technique)

*PowerShell*
- Script block logging events (Event ID 4104)
- Module logging events (Event ID 4103)
- Execution history requiring Base64 decoding

*Process injection indicators*
- Processes existing only in memory (no disk image)
- System processes with anomalous parent processes
- Processes with abnormally large allocated memory

*Registry-based payloads*
- Executable code traces stored in registry (long binary values)

**MITRE:** T1546.003 (WMI Event Subscription), T1055 (Process Injection), T1059.001 (PowerShell)

---

### `log_tampering` — Log Deletion and Tampering Detection

**Goal:** Detect evidence that an attacker wiped or disabled logs to cover their tracks.

Log deletion is one of the strongest indicators that immediately elevates confidence to **Confirmed**.

**What is collected:**
- Event ID 1102 (Security log cleared — administrator direct wipe)
- Event ID 104 (System log cleared)
- Current vs. maximum size of each event log (abnormally small = suspicious)
- Log fill percentage and mode (Circular/Retain/AutoBackup) per log
- Event log service state (stopped = suspicious)
- Windows Defender log deletion or disabled state
- Audit policy disabled (Event ID 4719)
- Abnormal last-modified timestamps on log files (gaps)

**Report-level analysis (RP-009 Log Capacity Warning):**
- Disabled logs → high severity (no events being recorded)
- Circular mode + ≥90% full → high severity (oldest events being overwritten, evidence loss)
- <5% full with records → medium severity (recently cleared, cross-reference 1102/104)
- Warnings displayed as banners in the HTML report

**LLM analysis focus:**
- Presence of 1102/104 events → immediately consider escalating to Confirmed
- Log deletion outside business hours
- Event patterns immediately before/after log deletion

**MITRE:** T1070 (Indicator Removal), T1562 (Impair Defenses)

---

### `credential_dump` — Credential Dumping Evidence

**Goal:** Detect evidence that an attacker extracted password hashes or plaintext credentials.

**What is collected:**
- Processes that accessed LSASS (Event ID 10 — if Sysmon is installed)
- `procdump.exe`, `mimikatz`, `sekurlsa`-related event history
- SAM, SECURITY, SYSTEM registry hive access history
- `ntdsutil.exe` execution history (AD environments — NTDS.dit dump)
- Volume Shadow Copy access history (`vssadmin`, `wbadmin`)
- WDigest authentication enabled state (when enabled, plaintext passwords exposed in memory)

**LLM analysis focus:**
- Unexpected process accessing LSASS
- Attempts to directly copy the SAM hive
- VSS deletion history (common to ransomware + credential dumping)

**MITRE:** T1003 (OS Credential Dumping), T1003.001 (LSASS Memory), T1003.002 (SAM)

---

### `lateral_movement` — Internal Movement Evidence

**Goal:** Detect evidence that an attacker moved from this server to others, or arrived from other servers.

**What is collected:**
- Event ID 4624 Type 3 (network logon) — access from unexpected sources
- Event ID 4624 Type 10 (RemoteInteractive — RDP)
- SMB connection history (anomalous internal IP pairs)
- WinRM / PSRemoting connection history (Event ID 6)
- PsExec usage traces (service name `PSEXESVC`, pipe `\psexec`)
- `net use` / `net view` history (internal network reconnaissance)
- RDP recent connection history (`HKCU\...\Terminal Server Client\Servers`)
- Anomalous port scan patterns to internal IP ranges

**MITRE:** T1021 (Remote Services), T1570 (Lateral Tool Transfer), T1135 (Network Share Discovery)

---

### `webshell` — Webshell Detection

**Goal:** Detect webshell files planted via web servers.

Only runs if a web server is detected (IIS, Apache, nginx, Tomcat — auto-detected).

**What is collected:**
- Recently modified files in web root directories (24h, 7d, 30d windows)
- `.php`, `.asp`, `.aspx`, `.jsp`, `.cfm` files containing suspicious patterns:
  - Files with `eval(`, `base64_decode(`, `exec(`, `system(`, `cmd.exe`
- IIS log anomalies (POST to static files, unusual User-Agent)
- `.exe`, `.dll`, `.ps1` files in web directories (should not exist)
- Files suspected as recently uploaded (creation time vs. deployment time)

**MITRE:** T1505.003 (Web Shell), T1190 (Exploit Public-Facing Application)

---

### `discovery_recon` — Internal Reconnaissance Detection

**Goal:** Detect attacker reconnaissance commands used to map the environment.

**What is collected:**
- Event 4688 (process creation) scanned for known recon command patterns (last 7 days)
- `net user`, `net group`, `net localgroup`, `whoami /all`, `nltest`, `dsquery` command execution
- `nmap`, `ipconfig`, `arp -a`, `route print`, `netstat` network reconnaissance
- `BloodHound` / `SharpHound` execution traces (Active Directory mapping)
- `systeminfo`, `wmic` system discovery commands
- RDP MRU (Most Recently Used) connections from registry

**LLM analysis focus:**
- Cluster of recon commands executed within a short window (attacker reconnaissance phase)
- BloodHound or SharpHound execution (almost always malicious in a non-pentest context)
- Recon commands executed by unexpected accounts or from unusual paths
- RDP MRU entries to internal servers not normally accessed by the account

**MITRE:** T1046 (Network Service Scanning), T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery)

---

### `process_execution` — Process Execution Artifact Detection

**Goal:** Detect attacker tool execution through forensic artifacts that survive file deletion.

**What is collected:**
- Prefetch files (`C:\Windows\Prefetch\*.pf`) — evidence of program execution even if the binary was deleted
- BAM (Background Activity Moderator) entries — recent execution timestamps from registry
- ShimCache (Application Compatibility Cache) entries — program execution history
- Filtering of known-safe Windows system paths to reduce noise

**LLM analysis focus:**
- Known attack tools in Prefetch (mimikatz, procdump, bloodhound, meterpreter, etc.)
- Executables run from Temp, Users\Public, PerfLogs paths (attacker staging locations)
- Execution artifacts for binaries no longer present on disk (deleted after use)
- BAM timestamps clustered during non-business hours

**MITRE:** T1059 (Command and Scripting Interpreter), T1204 (User Execution), T1218 (System Binary Proxy Execution)

---

### `file_access` — File Access Artifact Detection

**Goal:** Detect files and folders browsed by an attacker via Recent Items and LNK files.

**What is collected:**
- Recent Items (LNK files) from all user profiles — what files were opened
- LNK target path analysis for sensitive file access:
  - SAM, NTDS.dit, SYSTEM, SECURITY hives
  - `.pfx`, `.pem`, `id_rsa` certificates and keys
  - `credentials`, `password`, `secret` files
- File access timestamps and target paths

**LLM analysis focus:**
- LNK files targeting SAM/NTDS.dit (credential extraction attempt)
- Access to certificate/key files (.pfx, id_rsa) — potential key theft
- Access patterns suggesting systematic exploration of sensitive directories
- Recent Items from admin accounts showing unusual file access

**MITRE:** T1083 (File and Directory Discovery), T1552 (Unsecured Credentials), T1005 (Data from Local System)

---

### `file_download` — File Download Artifact Detection

**Goal:** Detect externally downloaded tools and payloads via Zone.Identifier and BITS transfers.

**What is collected:**
- Zone.Identifier (Mark-of-the-Web) alternate data streams on files in staging directories
- Zone.Id=3 (Internet download) + executable extensions in Temp/Public paths
- BITS (Background Intelligent Transfer Service) transfer history
- Recently created executables in user-writable directories
- Safe domain filtering (microsoft.com, windows.com, etc. excluded)

**LLM analysis focus:**
- Zone.Id=3 executables in staging paths (Temp, Users\Public) — externally downloaded tools
- BITS transfers to/from unusual URLs (attacker tool delivery)
- Downloaded executables with names mimicking legitimate tools
- Download timestamps correlating with other attack indicators

**MITRE:** T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files), T1608 (Stage Capabilities)

---

### `staging_exfiltration` — Data Staging and Exfiltration Detection

**Goal:** Detect data staging artifacts: temp archives, USB devices, VSS deletion, and exfiltration tools.

**What is collected:**
- Archive files (.zip, .7z, .rar) in Temp and Public directories (data staging)
- USB device connection history from registry (USBSTOR)
- VSS (Volume Shadow Copy) deletion commands (`vssadmin delete shadows`, `wmic shadowcopy delete`)
- Exfiltration tool traces in Prefetch (rclone, WinSCP, FileZilla, pscp)
- SRUM (System Resource Usage Monitor) for processes with large network send volumes
- Known-safe backup processes filtered out (Veeam, wbadmin, etc.)

**LLM analysis focus:**
- VSS deletion (strong ransomware/anti-forensics indicator)
- Archives in Temp/Public created shortly before or during incident timeframe
- Exfiltration tools (rclone, WinSCP) not normally present on the server
- SRUM entries showing large data transfers by unusual processes
- USB device connections during non-business hours

**MITRE:** T1074 (Data Staged), T1560 (Archive Collected Data), T1048 (Exfiltration Over Alternative Protocol), T1052 (Exfiltration Over Physical Medium)

---

## Linux-specific Checks (additional)

---

### `discovery_recon` (Linux) — Internal Reconnaissance Detection

**Goal:** Detect attacker reconnaissance commands from bash history and process list.

**What is collected:**
- Bash history entries from all user home directories + /root
- Known recon command patterns: `id`, `whoami`, `uname -a`, `cat /etc/passwd`
- Network reconnaissance: `nmap`, `netstat`, `ss`, `ip addr`, `arp`
- BloodHound/LinPEAS/LinEnum execution traces
- SUID file enumeration (`find / -perm -4000`)

**LLM analysis focus:**
- Cluster of recon commands in bash history indicating systematic reconnaissance
- LinPEAS/LinEnum execution (privilege escalation enumeration tools)
- SUID enumeration followed by exploitation attempts
- Recon commands executed by service accounts (should not have interactive history)

**MITRE:** T1046 (Network Service Scanning), T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1087 (Account Discovery)

---

### `staging_exfiltration` (Linux) — Data Staging and Exfiltration Detection

**Goal:** Detect data staging archives in /tmp//dev/shm, exfiltration commands, and USB events.

**What is collected:**
- Archive files in staging directories (/tmp, /dev/shm, /var/tmp)
- Exfiltration commands in bash history: `rclone`, `nc`, `scp`, `rsync`, `curl --upload`
- USB device connection events from dmesg/syslog
- Large file creation in temporary directories

**LLM analysis focus:**
- Archives in /tmp or /dev/shm created during incident timeframe
- Exfiltration tool commands (rclone, nc) in bash history
- Data transfer to external IPs via curl/wget/scp
- /dev/shm usage (RAM-based, evidence destroyed on reboot)

**MITRE:** T1074 (Data Staged), T1560 (Archive Collected Data), T1048 (Exfiltration Over Alternative Protocol)

---

## Confidence Impact by Check

| Check | Standalone finding | Combined findings |
|-------|--------------------|-------------------|
| Active C2 connection | → confirmed | — |
| Log deletion (Event 1102) | → confirmed | — |
| Webshell found | → confirmed | — |
| BloodHound/SharpHound execution | → confirmed | — |
| VSS deletion | → high | + archive in Temp → confirmed |
| Unknown WMI subscription | → high | + account manipulation → confirmed |
| Known attack tool in Prefetch | → high | + C2 connection → confirmed |
| Sensitive file LNK (SAM/NTDS.dit) | → high | + credential dump → confirmed |
| Zone.Id=3 executable in staging path | → medium | + process execution → high |
| Anomalous autorun entry | → medium | + LOLBin → high |
| Unusual account created | → medium | + external connection → high |
| Credential dump tool trace | → high | + lateral movement → confirmed |
| Exfiltration tool (rclone/WinSCP) | → medium | + staging archive → high |
| Recon command cluster | → medium | + lateral movement → high |

---

## Rule-Based Scoring (Stage 2 Filter)

Before LLM analysis, `internal/analyzer/filter.go` applies deterministic rules to each collected item:

| Rule | Check | Score | Trigger |
|------|-------|-------|---------|
| `KnownAttackTool` | process_execution | 100 | mimikatz/procdump/bloodhound/meterpreter etc. |
| `TempPathExec` | process_execution | 80 | Executable in `\Temp\`, `\Users\Public\`, `\PerfLogs\` |
| `SensitiveFileLNK` | file_access | 90 | LNK target = SAM/NTDS.dit/.pfx/id_rsa/credentials |
| `ZoneId3Executable` | file_download | 85 | Zone.Id=3 + exec extension + staging path |
| `VssDeletion` | staging_exfiltration | 90 | `vssadmin delete shadows` / `wmic shadowcopy delete` |
| `TempArchive` | staging_exfiltration | 65 | Archive (.zip/.7z) in Temp/Public directory |
| `ExfilTool` | staging_exfiltration | 75 | rclone/WinSCP/filezilla in Prefetch |
| `BloodHoundPattern` | discovery_recon | 100 | SharpHound.exe or `-CollectionMethod All` |
| `ReconCommand` | discovery_recon | 60 | nltest /domain_trusts, net group "Domain Admins", whoami /all |
| `UnsignedExternalConn` | c2_connections | 75 | Unsigned process with active external connection |
| `SuspiciousPort` | c2_connections | 70 | Connection to known C2 ports (4444, 31337, 5555, etc.) |
| `SystemProcessExternal` | c2_connections | 85 | svchost/lsass/csrss connecting to external IP |
| `SuspiciousServiceInstall` | c2_connections | 85-95 | PSEXESVC or service binary in Temp/AppData path |

SUSPICIOUS items are forwarded to the LLM with `rule_flags` annotation for confirmation/refutation.
SAFE items (Windows paths, known-good domains) are excluded before LLM to reduce token usage.

## Interactive Serve Mode

After analysis completes, an interactive HTTP server starts automatically (disable with `--no-serve`). The browser opens to the report.

```
coroner                                               # serve enabled by default
coroner --no-serve                                    # disable serve (CI/scripted use)
coroner --port 9000                                   # custom port (default: 8742)
coroner --fixture tests/fixtures/ --skip-collect      # serve with fixture data
```

Use the "Analyst Feedback" button in the report to provide additional context. The LLM re-evaluates findings with the analyst's input and updates the report.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serve current report HTML |
| `/health` | GET | Health check (`{"status":"ok"}`) |
| `/re-evaluate` | POST | Re-analyze with analyst context, return updated HTML |

### Re-evaluate Request

```json
{
  "context": "rclone.exe is a backup tool installed by the ops team"
}
```

---

## Planned Additions (Windows)

- `ransomware_indicators` — ransomware activity patterns (VSS deletion, mass file modification)
- `defense_evasion` — AV/EDR disabling, process hiding detection
- `supply_chain` — software update compromise traces

## Planned Additions (Linux)

- `process_execution` — bash_history + /proc based execution evidence
- `file_access` — auditd OPEN/READ events for sensitive files
- `file_download` — wget/curl download artifacts
- `rootkit_indicators` — hidden processes/files, LD_PRELOAD manipulation
- `suid_abuse` — SUID binary manipulation, capabilities abuse
- `container_escape` — container breakout and privilege escalation traces
