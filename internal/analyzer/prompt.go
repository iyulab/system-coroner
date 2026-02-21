package analyzer

import "fmt"

// WindowsSystemPrompt is the forensic analyst persona prompt for Windows servers.
const WindowsSystemPrompt = `You are an expert digital forensics and incident response (DFIR) analyst with 15+ years of experience investigating APT intrusions on Windows Server environments.

Your task is to analyze forensic data collected from a Windows server and determine whether it shows signs of compromise. You must be precise, evidence-based, and methodical.

FABRICATION PROHIBITION:
- NEVER generate IP addresses, domain names, file hashes, registry paths, MITRE technique IDs, usernames, or filenames that do not appear verbatim in the provided input data.
- If a suspicious pattern is expected but not present in the data, state "not observed in data" — do not invent representative examples.
- Every specific artifact cited in your findings (IPs, hashes, paths, command lines) MUST be quoted directly from the input.

ASSUME NOTHING:
- For each anomalous item, explicitly consider BOTH a benign explanation AND a malicious explanation before reaching your conclusion.
- Do not assume malice without first ruling out legitimate causes (scheduled tasks, software updates, monitoring agents, etc.).
- State your alternative hypotheses in the BASELINE and DEVIATION sections of your reasoning chain.

ANALYSIS RULES:
1. Every finding MUST cite specific data from the input (quote the exact entry)
2. For each finding, assess:
   - WHAT was found (specific artifact)
   - WHY it is suspicious (map to MITRE ATT&CK technique where possible)
   - CONFIDENCE level: confirmed (99%+), high (80-98%), medium (50-79%), low (20-49%), informational (<20%)
   - RECOMMENDED ACTION: Isolate Immediately / Investigate Further / Monitor / Ignore
3. Cross-correlate findings across different data sources
4. Explicitly state what NORMAL looks like for each finding to justify why this is ABNORMAL
5. If data is insufficient to make a determination, say so — do not speculate

CONFIDENCE CALIBRATION:
- confirmed: Multiple independent indicators from different data sources all point to the same conclusion.
- high: Strong single indicator or 2 correlated indicators.
- medium: Single indicator but legitimate explanation possible.
- low: Anomalous but could be normal.
- informational: Reference only, cannot act on alone.

NEVER assign confirmed based on a single data source.
NEVER assign low when multiple independent indicators align.

For each finding, include your reasoning chain:
1. OBSERVATION: What exactly did you see in the data?
2. BASELINE: What would be NORMAL for this type of data? What benign explanation exists?
3. DEVIATION: How does this observation differ from normal? Why does the benign explanation not apply?
4. CONTEXT: Do other findings corroborate or contradict this?
5. CONCLUSION: What is your assessment and confidence level?

OUTPUT FORMAT: Respond ONLY with valid JSON matching the provided schema. Do not include any text outside the JSON object.`

// LinuxSystemPrompt is the forensic analyst persona prompt for Linux servers.
const LinuxSystemPrompt = `You are an expert digital forensics and incident response (DFIR) analyst with 15+ years of experience investigating APT intrusions on Linux server environments.

Your task is to analyze forensic data collected from a Linux server and determine whether it shows signs of compromise. You must be precise, evidence-based, and methodical.

LINUX-SPECIFIC CONTEXT:
- Data sources include /proc filesystem, syslog/journald, auth.log, wtmp/btmp, cron, systemd units, SSH config
- Process information comes from /proc/{pid}/ entries (cmdline, exe, fd, maps)
- Persistence mechanisms: cron jobs, systemd services/timers, init scripts, .bashrc/.profile, authorized_keys
- Log sources: /var/log/auth.log, /var/log/syslog, journalctl, wtmp, btmp, lastlog
- Network data from /proc/net/tcp, ss, netstat
- User/group info from /etc/passwd, /etc/shadow, /etc/group

FABRICATION PROHIBITION:
- NEVER generate IP addresses, domain names, file hashes, file paths, MITRE technique IDs, usernames, or process names that do not appear verbatim in the provided input data.
- If a suspicious pattern is expected but not present in the data, state "not observed in data" — do not invent representative examples.
- Every specific artifact cited in your findings MUST be quoted directly from the input.

ASSUME NOTHING:
- For each anomalous item, explicitly consider BOTH a benign explanation AND a malicious explanation before reaching your conclusion.
- Do not assume malice without first ruling out legitimate causes (cron maintenance tasks, package updates, monitoring daemons, etc.).
- State your alternative hypotheses in the BASELINE and DEVIATION sections of your reasoning chain.

ANALYSIS RULES:
1. Every finding MUST cite specific data from the input (quote the exact entry)
2. For each finding, assess:
   - WHAT was found (specific artifact)
   - WHY it is suspicious (map to MITRE ATT&CK technique where possible)
   - CONFIDENCE level: confirmed (99%+), high (80-98%), medium (50-79%), low (20-49%), informational (<20%)
   - RECOMMENDED ACTION: Isolate Immediately / Investigate Further / Monitor / Ignore
3. Cross-correlate findings across different data sources
4. Explicitly state what NORMAL looks like for each finding to justify why this is ABNORMAL
5. If data is insufficient to make a determination, say so — do not speculate

CONFIDENCE CALIBRATION:
- confirmed: Multiple independent indicators from different data sources all point to the same conclusion.
- high: Strong single indicator or 2 correlated indicators.
- medium: Single indicator but legitimate explanation possible.
- low: Anomalous but could be normal.
- informational: Reference only, cannot act on alone.

NEVER assign confirmed based on a single data source.
NEVER assign low when multiple independent indicators align.

For each finding, include your reasoning chain:
1. OBSERVATION: What exactly did you see in the data?
2. BASELINE: What would be NORMAL for this type of data? What benign explanation exists?
3. DEVIATION: How does this observation differ from normal? Why does the benign explanation not apply?
4. CONTEXT: Do other findings corroborate or contradict this?
5. CONCLUSION: What is your assessment and confidence level?

OUTPUT FORMAT: Respond ONLY with valid JSON matching the provided schema. Do not include any text outside the JSON object.`

// SystemPrompt is kept for backward compatibility; defaults to Windows.
const SystemPrompt = WindowsSystemPrompt

// GetSystemPrompt returns the appropriate system prompt for the given OS.
func GetSystemPrompt(osName string) string {
	if osName == "linux" {
		return LinuxSystemPrompt
	}
	return WindowsSystemPrompt
}

// CheckPrompts maps check IDs to their specialized analysis prompts.
var CheckPrompts = map[string]string{
	"c2_connections": `Analyze the following network connection data from server %s for Command & Control (C2) indicators.

KNOWN LEGITIMATE DESTINATIONS (whitelist):
- 13.107.0.0/16, 20.0.0.0/8, 23.0.0.0/8 (Microsoft)
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Internal)

ANALYSIS TARGETS:
1. Connections to external IPs not in whitelist
2. Beacon patterns (connections at regular intervals ±10%%)
3. Unusual ports (4444, 8080, 8443, 1337, 9001, high ephemeral ports)
4. System processes (svchost, lsass, services) connecting externally
5. Long-duration connections (>30 min) to single IP
6. DNS cache entries with DGA-like domain names (high entropy, long subdomains)

DATA:
%s`,

	"account_compromise": `Analyze the following account and authentication data from server %s for persistence and privilege escalation indicators.

ANALYSIS TARGETS:
1. New accounts created outside change windows (Event 4720)
2. Accounts added to privileged groups (Event 4732)
3. Explicit credential use from abnormal processes (Event 4648 — Pass-the-Hash indicator)
4. Failed logon patterns: brute force threshold >50 from same source/hour (Event 4625)
5. Temporal correlation between these events
6. Hidden accounts ($ suffix) or accounts with password-never-expires + admin
7. Unknown accounts in Administrators group

DATA:
%s`,

	"persistence": `Analyze the following persistence mechanism data from server %s for attacker-installed survival mechanisms.

ANALYSIS TARGETS:
1. Registry Run key entries pointing to Temp, AppData, or user directories (almost always malicious)
2. Base64-encoded PowerShell commands in any autorun
3. Recently created scheduled tasks running as SYSTEM from non-standard paths
4. Services with binary paths in Temp/AppData/Users directories
5. Services executing cmd.exe or powershell.exe directly
6. Winlogon Userinit or Shell modifications
7. Image File Execution Options debugger hijacking
8. Names that mimic legitimate programs (typosquatting)

DATA:
%s`,

	"lolbin_abuse": `Analyze the following process creation data from server %s for Living-off-the-Land binary abuse.

ANALYSIS TARGETS:
1. PowerShell with -EncodedCommand or -WindowStyle Hidden
2. certutil.exe with -urlcache -split -f (file download)
3. mshta.exe executing remote HTA files
4. regsvr32.exe with /i:http (Squiblydoo attack)
5. rundll32.exe loading DLLs from unusual paths
6. bitsadmin.exe /transfer (background download)
7. Abnormal parent-child process relationships (e.g., Excel spawning PowerShell)
8. Command lines longer than 500 characters (often encoded payloads)

DATA:
%s`,

	"fileless_attack": `Analyze the following data from server %s for fileless attack indicators.

ANALYSIS TARGETS:
1. WMI EventSubscriptions with CommandLineEventConsumer or ActiveScriptEventConsumer (APT persistence)
2. PowerShell script blocks (EID 4104) containing: Invoke-Mimikatz, Invoke-Shellcode, VirtualAlloc, DllImport, Net.WebClient, DownloadString, FromBase64String, AmsiUtils
3. Processes running without a disk image (memory-only execution)
4. FilterToConsumerBindings (WMI event subscription chain)
5. Any WMI subscription that is NOT a known Windows/Microsoft default

DATA:
%s`,

	"log_tampering": `Analyze the following log integrity data from server %s for evidence of anti-forensic activity.

CRITICAL: Log clearing (Event 1102) on a server is ALMOST NEVER legitimate. This is one of the strongest indicators of compromise.

ANALYSIS TARGETS:
1. Event 1102 (Security log cleared) — near-automatic Confirmed confidence
2. Event 104 (System log cleared)
3. Event 4719 (Audit policy changed) — attackers disable logging before actions
4. Event log sizes abnormally small relative to max size (logs cleared then slowly refilling)
5. EventLog service stopped or disabled
6. Temporal analysis: what happened just before and after log clearing

DATA:
%s`,

	"credential_dump": `Analyze the following credential access data from server %s for credential theft indicators.

ANALYSIS TARGETS:
1. LSASS protection status (RunAsPPL disabled = vulnerable to Mimikatz)
2. Process creation events matching known credential tools: mimikatz, procdump, sekurlsa, ntdsutil, pypykatz, lazagne
3. Registry save commands targeting SAM, SECURITY, or SYSTEM hives
4. Volume Shadow Copy activity (used for offline credential extraction)
5. WDigest UseLogonCredential enabled (plain-text passwords in memory)
6. Any combination of LSASS access + credential tool = HIGH confidence

DATA:
%s`,

	"lateral_movement": `Analyze the following network logon data from server %s for lateral movement indicators.

ANALYSIS TARGETS:
1. Type 3 (Network) logons from unusual internal IPs or at unusual times
2. Type 10 (RDP) logons from unexpected sources
3. PsExec traces: PSEXESVC service, named pipes, Event 7045 service installation
4. WinRM activity (Event 6 in WinRM/Operational)
5. Multiple Type 3 logons from same source to different accounts (credential spray)
6. Non-standard SMB shares
7. Outbound RDP history (this server used as pivot point)
8. Temporal correlation with other attack indicators

DATA:
%s`,

	"webshell": `Analyze the following web server data from server %s for web shell indicators.

ANALYSIS TARGETS:
1. Script files (.php, .asp, .aspx, .jsp) containing eval(), exec(), system(), base64_decode(), cmd.exe, WScript.Shell
2. Executable files (.exe, .dll, .ps1) in web root directories (should never exist)
3. Recently created/modified files in web root (potential upload via exploit)
4. IIS log anomalies: POST requests to static file extensions (.jpg, .css, .txt)
5. Directory traversal attempts in IIS logs (../ or %%2e%%2e)
6. Creation timestamp much newer than other files (uploaded vs deployed)

DATA:
%s`,
}

// LinuxCheckPrompts maps check IDs to Linux-specific analysis prompts.
var LinuxCheckPrompts = map[string]string{
	"c2_connections": `Analyze the following network connection data from Linux server %s for Command & Control (C2) indicators.

Data is collected from /proc/net/tcp, ss, and process inspection via /proc/{pid}/.

KNOWN LEGITIMATE DESTINATIONS (whitelist):
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Internal)
- Package manager destinations (apt, yum mirrors)

ANALYSIS TARGETS:
1. Connections to external IPs from unexpected processes (especially those running from /tmp, /dev/shm, /var/tmp)
2. Beacon patterns (connections at regular intervals ±10%%)
3. Unusual ports (4444, 8080, 8443, 1337, 9001, high ephemeral ports)
4. Processes with deleted executables (exe -> (deleted)) connecting externally
5. Long-duration connections (>30 min) to single IP
6. DNS queries with DGA-like domain names (high entropy, long subdomains)
7. Connections from processes running as root that should not need network access

DATA:
%s`,

	"account_compromise": `Analyze the following account and authentication data from Linux server %s for persistence and privilege escalation indicators.

Data sources: /etc/passwd, /etc/shadow metadata, /etc/group, auth.log, wtmp, lastlog.

ANALYSIS TARGETS:
1. New user accounts with UID 0 (root equivalent) or UID < 1000 (system range)
2. Accounts added to sudo/wheel group recently
3. Users with login shell but no legitimate purpose
4. Failed login patterns in auth.log: brute force threshold >50 from same source/hour
5. SSH logins from unusual IPs or at unusual times
6. Accounts with no password aging (never expires)
7. Recently modified /etc/passwd or /etc/shadow
8. su/sudo usage patterns from unexpected accounts
9. Temporal correlation between account creation and other suspicious events

DATA:
%s`,

	"persistence": `Analyze the following persistence mechanism data from Linux server %s for attacker-installed survival mechanisms.

ANALYSIS TARGETS:
1. Cron jobs executing from /tmp, /dev/shm, /var/tmp, or hidden directories
2. Systemd services/timers with ExecStart pointing to unusual paths
3. Init scripts recently added or modified
4. SSH authorized_keys additions (especially for root or service accounts)
5. Modified shell profiles (.bashrc, .profile, /etc/profile.d/) with suspicious commands
6. LD_PRELOAD or /etc/ld.so.preload entries (shared library injection)
7. Kernel modules recently loaded (especially unsigned or from unusual paths)
8. At jobs or anacron entries that execute suspicious commands
9. Modified /etc/rc.local or systemd generator scripts

DATA:
%s`,

	"lolbin_abuse": `Analyze the following process and command data from Linux server %s for Living-off-the-Land binary abuse.

ANALYSIS TARGETS:
1. curl/wget downloading executables to /tmp, /dev/shm, or hidden directories
2. python/python3/perl/ruby executing inline code or remote scripts
3. ncat/nc/socat creating reverse shells or listening on unusual ports
4. base64 decoding piped to bash/sh execution
5. find/xargs being used for privilege escalation (SUID abuse)
6. gcc/make compiling code in /tmp (exploit compilation)
7. dd being used to read /dev/mem or /dev/sda (raw disk/memory access)
8. strace/ltrace/gdb attached to running processes (credential interception)
9. Unusual parent-child process relationships (e.g., web server spawning shell)

DATA:
%s`,

	"fileless_attack": `Analyze the following data from Linux server %s for fileless and memory-resident attack indicators.

ANALYSIS TARGETS:
1. Processes running from /proc/{pid}/exe pointing to deleted files
2. Processes with /dev/shm or /run/shm as working directory
3. memfd_create usage (anonymous memory-backed file execution)
4. Processes executing from /proc/self/fd/ paths
5. Shell processes with suspicious environment variables (LD_PRELOAD, LD_LIBRARY_PATH)
6. High-entropy process names or command lines suggesting obfuscation
7. Processes with mapped memory regions from unusual paths (/dev/shm, /tmp)
8. Python/Perl/Ruby processes with inline eval of encoded payloads

DATA:
%s`,

	"log_tampering": `Analyze the following log integrity data from Linux server %s for evidence of anti-forensic activity.

CRITICAL: Log file deletion or truncation on a production server is ALMOST NEVER legitimate. This is one of the strongest indicators of compromise.

ANALYSIS TARGETS:
1. Zero-size or recently truncated log files (auth.log, syslog, wtmp, btmp, lastlog)
2. Gaps in log timestamps (entries missing for a time period)
3. Corrupted wtmp/btmp records (binary log tampering)
4. Missing or modified logrotate configuration
5. Auditd service stopped or disabled
6. rsyslog/syslog-ng configuration changes
7. Journal/journald vacuum or rotate executed outside normal schedule
8. History file (.bash_history) cleared or symlinked to /dev/null
9. Temporal analysis: what events are missing from the time window of other suspicious activity

DATA:
%s`,

	"credential_dump": `Analyze the following credential access data from Linux server %s for credential theft indicators.

ANALYSIS TARGETS:
1. /etc/shadow access by non-root processes (direct read attempts)
2. Processes accessing /proc/{pid}/maps or /proc/{pid}/mem of other processes
3. Known credential tools: mimipenguin, LaZagne, linPEAS, linux-exploit-suggester
4. SSH private key access from unusual processes or users
5. SUID binary abuse for privilege escalation (GTFOBins patterns)
6. Capabilities abuse (cap_setuid, cap_dac_override on unusual binaries)
7. ptrace attachment to sshd, su, sudo, or login processes
8. /etc/pam.d/ modifications (PAM backdoor)
9. Keylogger indicators on TTY/PTY devices

DATA:
%s`,

	"lateral_movement": `Analyze the following network activity data from Linux server %s for lateral movement indicators.

ANALYSIS TARGETS:
1. SSH connections to/from internal hosts at unusual times or from unexpected users
2. SSH tunneling/port forwarding (-L, -R, -D flags in process command lines)
3. SCP/SFTP transfers of suspicious files (tools, scripts, archives)
4. Internal network scanning patterns (multiple connection attempts to same port across IPs)
5. Ansible/Salt/Puppet/Chef ad-hoc command execution from unexpected sources
6. NFS/CIFS mount activity to internal hosts
7. Proxychains or SOCKS proxy process activity
8. Outbound SSH from service accounts that should not initiate connections
9. Temporal correlation: lateral movement usually follows initial compromise indicators

DATA:
%s`,

	"webshell": `Analyze the following web server data from Linux server %s for web shell indicators.

ANALYSIS TARGETS:
1. Script files (.php, .jsp, .py, .pl, .cgi) containing eval(), exec(), system(), passthru(), shell_exec(), base64_decode(), or popen()
2. Executable files or scripts in web root that don't belong to the application
3. Recently created/modified files in web document roots
4. Web server processes (apache2, nginx, httpd) spawning shell processes
5. Unusual POST requests to static file paths in access logs
6. Files with creation timestamp significantly different from deployment
7. Hidden files (dot-prefix) in web-accessible directories
8. World-writable directories under web root

DATA:
%s`,
}

// BuildCheckPrompt creates a user prompt for a specific check, selecting OS-appropriate prompts.
func BuildCheckPrompt(checkID, hostname, osName, data string) string {
	// Select prompt map based on OS
	prompts := CheckPrompts
	if osName == "linux" {
		prompts = LinuxCheckPrompts
	}

	tmpl, ok := prompts[checkID]
	if !ok {
		return fmt.Sprintf("Analyze the following data from server %s for intrusion indicators.\n\nDATA:\n%s", hostname, data)
	}
	return fmt.Sprintf(tmpl, hostname, data)
}

// SynthesisPrompt is used for Phase 2 cross-analysis.
const SynthesisPrompt = `You are performing the FINAL SYNTHESIS of a multi-check forensic analysis on server %s.

Below are the individual findings from %d detection checks. Your task is to:
1. Cross-correlate findings across different checks
2. Reconstruct the attack timeline (if evidence supports it)
3. Map to MITRE ATT&CK Kill Chain phases
4. Provide a consolidated IoC list
5. Make the final isolation recommendation
6. Identify data gaps that could change the assessment

ISOLATION DECISION MATRIX:
- confirmed finding (any) → ISOLATE_IMMEDIATELY
- 2+ "high" findings → ISOLATE_IMMEDIATELY
- 1 "high" finding → INVESTIGATE_URGENTLY
- "medium" findings only → MONITOR_CLOSELY
- "low"/"informational" only → NO_ACTION

INDIVIDUAL CHECK FINDINGS:
%s

Respond with JSON matching the verdict schema.`

// InjectAnalystContext prepends analyst-provided context to a user prompt.
// If analystContext is empty, the original prompt is returned unchanged.
func InjectAnalystContext(userPrompt, analystContext string) string {
	if analystContext == "" {
		return userPrompt
	}
	header := fmt.Sprintf(`ANALYST CONTEXT (provided by the analyst reviewing this report):
%s

Based on the above context, update your analysis. Items the analyst has explicitly confirmed as normal should have their risk level and confidence reduced accordingly. Do NOT fabricate — only adjust items that are directly addressed by the analyst's context.

---

`, analystContext)
	return header + userPrompt
}

// BuildSynthesisPrompt creates the cross-analysis prompt.
func BuildSynthesisPrompt(hostname, osName string, checkCount int, findingsJSON string) string {
	serverDesc := hostname
	if osName != "" {
		serverDesc = fmt.Sprintf("%s (%s)", hostname, osName)
	}
	return fmt.Sprintf(SynthesisPrompt, serverDesc, checkCount, findingsJSON)
}
