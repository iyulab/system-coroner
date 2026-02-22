# system-coroner

> **Has an attacker already gotten in? — Automated intrusion evidence collection and LLM-powered forensic report generator**

system-coroner scans a server for indicators of compromise (IoC) the moment it runs, feeds the raw evidence to an LLM for analysis, and produces a single `report.html`. No agent installation. One binary, one run.

![report.html preview](docs/report-preview.png)

---

## What this tool answers

- Is there evidence an attacker entered this server?
- Is any process currently communicating with a C2 server?
- Did an attacker create accounts or escalate privileges?
- Was malware installed to survive a reboot?
- Are there signs that logs have been wiped?
- Should this server be isolated from the network right now?

**This is not a security configuration auditor or vulnerability scanner. Its purpose is to find traces of intrusions that have already happened.**

---

## How it works

```
Run
 ↓
Intrusion-evidence collection scripts run in parallel (PowerShell / Bash)
 ↓
Raw IoC output saved to disk → output/{timestamp}/*.json, *.log, *.md
 ↓
Sigma rule engine scans collected evidence (deterministic pre-detection)
 ↓
LLM analyzes each result from an intrusion-scenario perspective
 ↓
Cross-check synthesis → isolation verdict included
 ↓
report.html generated ✅
```

---

## Quick start

```bash
# Windows Server — PowerShell 5.1+, Administrator recommended
.\coroner.exe --config config.toml

# Linux — Bash 4+, root recommended
sudo ./coroner --config config.toml

# Output
# → output/2026-02-21T14-00-00/report.html  (auto-opens in browser)
# → output/2026-02-21T14-00-00/*.json       (raw evidence preserved)
```

> **Running as Administrator/root gives access to more evidence.** Windows: Security event log, LSASS protection state. Linux: `/etc/shadow`, audit logs, full `/proc` process mapping.

### CLI options

```bash
./coroner --config config.toml                          # Full run (collect + LLM + report + serve)
./coroner --collect-only                                # Collect only, no LLM calls
./coroner --only c2_connections,log_tampering            # Run specific checks only
./coroner --fixture tests/fixtures/linux/clean/ --skip-collect  # Test LLM analysis with fixtures
./coroner --verbose                                     # Verbose output with per-check status
./coroner --no-serve                                    # Disable interactive server after analysis (CI/scripted use)
./coroner --port 9000                                   # Set interactive server port (default: 8742)
```

---

## Windows Defender False Positive

On Windows, Defender may flag system-coroner with alerts such as:

```
Behavior:Win32/Execution.A!ml
Trojan:PowerShell/PSAttackTool.A
```

### Why this happens

system-coroner embeds PowerShell collection scripts directly in the binary and launches them at runtime using:

```
powershell.exe -ExecutionPolicy Bypass -EncodedCommand <base64>
```

- **`-ExecutionPolicy Bypass`** — required to run embedded scripts without requiring the server's execution policy to be configured in advance. The script content itself is read-only forensic collection code.
- **`-EncodedCommand <base64>`** — the embedded script is passed as a Base64-encoded string to avoid writing a `.ps1` file to disk (consistent with the evidence-first, no-footprint design principle).

These two flags together are a well-known pattern used by attackers, so Defender's heuristic engine flags them regardless of intent. This is a **false positive** — no malicious code is present.

### Resolution

Add a Defender exclusion for the directory containing `coroner.exe`:

**Option 1 — PowerShell (Administrator)**
```powershell
Add-MpPreference -ExclusionPath "C:\path\to\system-coroner"
```

**Option 2 — Windows Security UI**
1. Open **Windows Security** → **Virus & threat protection**
2. Click **Manage settings** under "Virus & threat protection settings"
3. Scroll to **Exclusions** → **Add or remove exclusions**
4. Add **Folder** exclusion for the directory containing `coroner.exe`

**Option 3 — Group Policy (domain environments)**
```
Computer Configuration → Administrative Templates →
Windows Components → Microsoft Defender Antivirus →
Exclusions → Path Exclusions
```

> **Note:** The exclusion applies to the folder only. Files outside that folder are still protected. You can verify the binary's integrity against the published SHA-256 hash on the [GitHub Releases](https://github.com/iyulab/system-coroner/releases) page before running.

---

## Installation

| Platform | Binary |
|----------|--------|
| Windows (amd64) | `coroner-windows-amd64.exe` |
| Linux (amd64) | `coroner-linux-amd64` |
| Linux (arm64) | `coroner-linux-arm64` |

```bash
# Build from source
git clone https://github.com/iyulab/system-coroner
cd system-coroner
go build -o coroner ./cmd/coroner
```

---

## Configuration

On first run: `cp config.example.toml config.toml`, then set your API key.

```toml
[llm]
# provider: "anthropic" | "openai" | "ollama" | "gpustack"
provider = "anthropic"
api_key  = "sk-ant-..."
model    = "claude-sonnet-4-6"

# Optional: override the default endpoint (proxies, local Anthropic-compatible servers)
# endpoint = "http://localhost/v1"

# HTTP timeout in seconds; 0 = provider default (anthropic/openai: 120s, ollama/gpustack: 300s)
# timeout = 0

[output]
dir          = "output"
open_browser = true
keep_raw     = true        # Preserve raw IoC files (always recommended for forensics)

[baseline]
# Declare known-good artifacts so they are not flagged as threats.
# known_paths     = ["D:\\monitoring\\agent", "C:\\ops\\tools"]
# known_accounts  = ["backup_svc", "monitoring_agent"]
# known_processes = ["backup.exe", "agent.exe"]

[checks]
# All checks are enabled by default. Set false to disable individual ones.
# c2_connections        = true
# persistence           = true
# log_tampering         = true
# account_compromise    = true
# credential_dump       = true
# fileless_attack       = true
# lolbin_abuse          = true
# lateral_movement      = true
# webshell              = true
# discovery_recon       = true
# process_execution     = true
# file_access           = true
# file_download         = true
# staging_exfiltration  = true
```

### LLM Providers

| Provider | Default endpoint | Notes |
|----------|-----------------|-------|
| `anthropic` | `https://api.anthropic.com/v1` | Structured output via `tool_use` |
| `openai` | `https://api.openai.com/v1` | JSON mode |
| `ollama` | `http://localhost:11434` | Fully offline; constrained JSON output |
| `gpustack` | `http://localhost/v1` | OpenAI-compatible API |

---

## Report structure

### Isolation verdict (top banner)
- **ISOLATE IMMEDIATELY** / **ISOLATION RECOMMENDED** / **INVESTIGATION NEEDED** / **NO INTRUSION DETECTED**
- Color-coded: red pulse animation (critical) → red → yellow → green

### Summary stats
Confirmed / High / Medium / Low / Clean counts at a glance.

### Scoring Matrix
Summary table of all findings: Check, Title, Confidence, Risk, and Conclusion for quick triage.

### Sigma Rule Matches
Deterministic pre-detection results independent of LLM analysis. Sigma rules are embedded in the binary and evaluated against raw collected evidence before LLM calls.

### Finding cards (per check)
- Confidence badge + Risk badge + title
- Attack scenario description
- Specific evidence items (from raw collected data)
- MITRE ATT&CK technique tags (T-number)
- Immediate action checklist
- Collapsible: Reasoning chain, Forensic next steps, Raw evidence JSON

### Attack timeline
Reconstructed attacker activity sequence from cross-check synthesis.

### IoC table
Unified list of IPs, file hashes, processes, registry keys — exportable as CSV or JSON.

### Collection failures
Checks that failed to collect data, with `FailureKind` classification: `timeout`, `permission_denied`, `script_error`, `not_found`, `unknown`.

### Evidence gap analysis
Forensic impact analysis of collection failures — identifies which attack techniques become undetectable when specific checks fail to collect data.

### Log capacity warnings
Event log capacity and mode warnings — detects disabled logs, circular-mode logs near capacity (evidence overwrite risk), and recently cleared logs.

### Evidence integrity
SHA-256 hashes for all collected files (chain-of-custody).

---

## Confidence levels

| Level | Meaning | Example |
|-------|---------|---------|
| **confirmed** | Intrusion certain | Active C2 connection, known malware hash, event log wipe |
| **high** | Strong evidence of intrusion | Suspicious process + anomalous account + autorun simultaneously |
| **medium** | Requires investigation | Multiple individually-explainable but suspicious items |
| **low** | Weak indicators only | Single low-severity anomaly, likely benign |
| **informational** | Notable but not suspicious | Unusual configuration, no threat evidence |
| **clean** | No intrusion evidence | All collected items within normal range |

---

## Privacy and data handling

- Collected data is sent only to the configured LLM API
- `report.html` and raw evidence files are stored locally only
- With Ollama (`provider = "ollama"`), all analysis is fully offline — no external transmissions
- API keys are managed via config file or `CORONER_API_KEY` environment variable and never appear in output files

---

## Roadmap

- [x] Windows Server — PowerShell-based intrusion detection (14 checks)
- [x] Linux — Bash-based intrusion detection (11 checks)
- [x] Sigma rule pre-detection engine (embedded rules, deterministic layer)
- [x] Evidence package export (ZIP with chain-of-custody metadata)
- [x] GPUStack provider (OpenAI-compatible local LLM)
- [x] Stage 2 rule-based scoring engine (`internal/analyzer/filter.go`)
- [x] Interactive serve mode with analyst feedback re-evaluation
- [x] Scoring matrix in report
- [x] Baseline configuration (known-good paths, accounts, processes)
- [ ] macOS support
- [ ] Delta report (compare against previous scan)
- [ ] YARA rule integration
- [ ] VirusTotal API integration (auto-lookup file hashes)

---

## License

MIT License — *Built by [iyulab](https://github.com/iyulab)*
