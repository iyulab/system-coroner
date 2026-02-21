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
| `c2_connections` | `scripts/linux/c2_connections.sh` | Linux | T1071.001, T1071.004, T1048.003, T1095, T1090 | ✅ |
| `persistence` | `scripts/linux/persistence.sh` | Linux | T1053.003, T1543.002, T1037.004, T1574.006, T1546.004 | ✅ |
| `log_tampering` | `scripts/linux/log_tampering.sh` | Linux | T1070.001, T1070.002, T1562.001 | ✅ |
| `account_compromise` | `scripts/linux/account_compromise.sh` | Linux | T1136.001, T1098.004, T1110.001 | ✅ |
| `credential_dump` | `scripts/linux/credential_dump.sh` | Linux | T1003.008, T1003.007, T1552.001 | ✅ |
| `fileless_attack` | `scripts/linux/fileless_attack.sh` | Linux | T1059.004, T1620, T1027.002 | ✅ |
| `lolbin_abuse` | `scripts/linux/lolbin_abuse.sh` | Linux | T1059.004, T1105, T1218 | ✅ |
| `lateral_movement` | `scripts/linux/lateral_movement.sh` | Linux | T1021.004, T1572, T1563.001 | ✅ |
| `webshell` | `scripts/linux/webshell.sh` | Linux | T1505.003, T1190 | ✅ |

Test fixtures: `tests/fixtures/{platform}/{clean,compromised}/{check_id}.json` (9 × 2 per platform)

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

**LLM analysis focus:**
- Are system processes (`svchost.exe`, `lsass.exe`) making external connections?
- Is connection frequency regular (beacon signature — 30s, 60s intervals)?
- Is the remote IP a known cloud/CDN, or unknown?
- Is the connecting process running from an expected path?

**MITRE:** T1071 (Application Layer Protocol), T1048 (Exfiltration Over C2), T1095 (Non-Standard Port)

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
- Event log service state (stopped = suspicious)
- Windows Defender log deletion or disabled state
- Audit policy disabled (Event ID 4719)
- Abnormal last-modified timestamps on log files (gaps)

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

## Confidence Impact by Check

| Check | Standalone finding | Combined findings |
|-------|--------------------|-------------------|
| Active C2 connection | → Confirmed | — |
| Log deletion (Event 1102) | → Confirmed | — |
| Webshell found | → Confirmed | — |
| Unknown WMI subscription | → Likely | + account manipulation → Confirmed |
| Anomalous autorun entry | → Suspected | + LOLBin → Likely |
| Unusual account created | → Suspected | + external connection → Likely |
| Credential dump tool trace | → Likely | + lateral movement → Confirmed |

---

## Planned Additions (Windows)

- `ransomware_indicators` — ransomware activity patterns (VSS deletion, mass file modification)
- `data_exfiltration` — large-volume external data transfer evidence
- `defense_evasion` — AV/EDR disabling, process hiding detection
- `supply_chain` — software update compromise traces

## Planned Additions (Linux)

- `rootkit_indicators` — hidden processes/files, LD_PRELOAD manipulation, kernel module verification
- `suid_abuse` — SUID binary manipulation, capabilities abuse
