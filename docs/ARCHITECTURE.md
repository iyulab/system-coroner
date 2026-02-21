# Architecture

## Design Principles

1. **Evidence-first** — Raw collected data is always written to disk before LLM analysis. IoC evidence is preserved regardless of LLM API failures.
2. **Intrusion-scenario analysis** — The LLM is never asked "is this normal?" It is asked "is this an intrusion trace? What did the attacker do?"
3. **Never abort** — If any collection check fails, the rest continue and a partial report is produced. An empty report never happens.
4. **Single binary** — No installation required. Copy one binary, run it.

---

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (cobra)                          │
│                    cmd/coroner/main.go                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────▼───────────────┐
          │          Orchestrator         │
          │     internal/orchestrator/    │
          │                               │
          │  Stage 1: Collect             │
          │  Stage 1.5: Sigma match       │
          │  Stage 2: LLM Analyze         │
          │  Stage 3: Report              │
          │  Stage 4: Evidence export     │
          └───┬──────────────────────┬────┘
              │                      │
  ┌───────────▼──────────┐  ┌────────▼────────────┐
  │      Collector        │  │      Analyzer        │
  │  internal/collector/  │  │  internal/analyzer/  │
  │                       │  │                      │
  │ - Parallel script run │  │ - Preprocessing      │
  │ - Per-check timeout   │  │   · Known-Good filter│
  │ - IoC raw file save   │  │   · Field truncation │
  │ - FailureKind classify│  │   · Event aggregation│
  │                       │  │ - LLM HTTP client    │
  │                       │  │ - Intrusion prompts  │
  │                       │  │ - Structured JSON    │
  │                       │  │ - Confidence scoring │
  └───────────┬───────────┘  └────────┬────────────┘
              │                       │
  ┌───────────▼───────────┐  ┌────────▼────────────┐
  │   Sigma Engine        │  │      Reporter        │
  │   internal/sigma/     │  │  internal/reporter/  │
  │                       │  │                      │
  │ - Embedded rules      │  │ - Isolation verdict  │
  │ - Deterministic match │  │ - Timeline reconstruct│
  │ - Level classification│  │ - MITRE mapping      │
  │   (critical/high/...) │  │ - report.html render │
  └───────────────────────┘  │ - ZIP evidence package│
                             └────────┬────────────┘
                                      │
  ┌───────────────────────────────────▼──────────────────────┐
  │  scripts/windows/         scripts/linux/                  │
  │  *.ps1 (9 checks)         *.sh (9 checks)                 │
  │  (embedded via go:embed)                                  │
  └───────────────────────────────────────────────────────────┘
                                      │
                           ┌──────────▼───────────────────┐
                           │  output/{timestamp}/          │
                           │  ├── *.json (9 raw results)  │
                           │  ├── manifest.json            │
                           │  └── report.html              │
                           │                               │
                           │  output/{timestamp}.zip       │
                           │  └── package_info.json        │
                           │     (SHA-256 hashes, metadata)│
                           └──────────────────────────────┘
```

---

## Directory Structure

```
system-coroner/
│
├── cmd/
│   └── coroner/
│       └── main.go                    # CLI entry point, flag parsing
│
├── internal/
│   ├── config/
│   │   └── config.go                  # config.toml loading and validation
│   │
│   ├── collector/
│   │   ├── collector.go               # Parallel execution orchestration (accepts fs.FS)
│   │   ├── runner.go                  # os/exec wrapper, timeout handling, classifyFailure()
│   │   ├── result.go                  # CollectionResult struct + FailureKind type (6 constants)
│   │   └── writer.go                  # Raw IoC file persistence
│   │
│   ├── platform/
│   │   ├── platform.go                # OS detection, Check type definition
│   │   ├── windows.go                 # Windows check definitions (9 checks)
│   │   └── linux.go                   # Linux check definitions (9 checks)
│   │
│   ├── sigma/
│   │   ├── engine.go                  # Sigma Engine: New(fs.FS), NewDefault(), MatchAll()
│   │   ├── types.go                   # SigmaMatch{CheckID, RuleTitle, RuleID, Level, Event}
│   │   └── rules/
│   │       └── windows/
│   │           ├── c2_connections.yml      # C2 from Temp path (high)
│   │           ├── credential_dump.yml     # Credential harvesting tools (critical)
│   │           └── persistence.yml         # Base64-encoded commands (high)
│   │
│   ├── analyzer/
│   │   ├── analyzer.go                # Two-phase LLM orchestration
│   │   ├── client.go                  # LLM HTTP client: Anthropic, OpenAI, Ollama, GPUStack
│   │   ├── preprocess.go              # Known-Good filter, field truncation, event aggregation
│   │   ├── prompt.go                  # Intrusion-scenario prompt generation
│   │   ├── response.go                # Structured response parsing
│   │   └── schema.go                  # Finding, Verdict schema + JSON Schema definitions
│   │
│   └── reporter/
│       ├── reporter.go                # html/template rendering
│       ├── aggregator.go              # Confidence aggregation, isolation verdict logic
│       ├── exporter.go                # ZIP evidence package with SHA-256 hashes
│       └── templates/
│           └── report.html.tmpl       # Self-contained HTML report template
│
├── scripts/
│   ├── windows/                       # PowerShell collection scripts (9 files)
│   └── linux/                         # Bash collection scripts (9 files)
│
├── tests/
│   └── fixtures/
│       ├── windows/
│       │   ├── clean/                 # Normal environment fixtures (9 files)
│       │   └── compromised/           # Compromised environment fixtures (9 files)
│       └── linux/
│           ├── clean/
│           └── compromised/
│
├── config.example.toml
├── go.mod
├── Makefile
└── README.md
```

---

## Key Design Decisions

### 1. Script embedding (go:embed)

Scripts are embedded in the binary at build time. Users need only one file.

```go
//go:embed windows/*.ps1
var windowsScripts embed.FS

//go:embed linux/*.sh
var linuxScripts embed.FS
```

The `Collector` accepts `fs.FS` (not `embed.FS` directly), enabling `testing/fstest.MapFS` in unit tests without touching the real embedded filesystem.

### 2. Parallel collection (goroutine per check)

All detection checks run concurrently. 9 checks × average 10s ≠ 90s — only the slowest check's duration (~30s) is paid.

```
goroutine: c2_connections.ps1      ─┐
goroutine: account_compromise.ps1  ─┤
goroutine: persistence.ps1         ─┤──► ResultChannel ──► Writer
goroutine: lolbin_abuse.ps1        ─┤
goroutine: log_tampering.ps1       ─┘
```

Each goroutine has an individual timeout. On timeout, the process is killed and partial results are recorded.

### 3. Sigma pre-detection (Stage 1.5)

After collection and before LLM analysis, all raw results are fed to the embedded Sigma engine:

```
Collection results → Sigma Engine → SigmaMatches[]
                                          ↓
                             Passed to Reporter + Orchestrator
                             (independent of LLM analysis)
```

This provides deterministic, rule-based detection that does not depend on LLM availability or behavior. Rules are scoped by `logsource.category` matching the `Check.ID`.

### 4. Evidence-first persistence

Raw output is written to disk before LLM analysis is invoked. LLM API failure never loses evidence.

```
Script → stdout capture → disk write → LLM analysis
                                ↑
                        This always happens first
```

### 5. Intrusion-scenario LLM prompts

The LLM is not given generic analysis tasks. It receives specific intrusion hypotheses:

```
❌ Generic:
"Analyze this data and identify security issues."

✅ Intrusion-specific:
"You are a digital forensics expert.
The following is output from the [c2_connections] check.
Determine whether C2 communication, reverse shells, or beacon patterns are present.
For any suspicious items, cite the specific field and value from the raw data.
Respond only in this JSON format: ..."
```

### 6. Two-phase analysis

Per-check analysis and cross-check synthesis are separated. This prevents context window overflow and enables cross-check correlation:

```
c2_connections  → Finding{ confidence: "suspected", risk: "high" }
log_tampering   → Finding{ confidence: "confirmed", risk: "critical" }
account_changes → Finding{ confidence: "likely",    risk: "high" }
        │
        └──► Aggregator ──► cross-check synthesis ──► overall verdict
                            "Log deletion + C2 suspect + account changes
                             → Confirmed, immediate isolation"
```

---

## LLM Providers

Configured via `config.toml` `[llm]` section.

| Provider | Structured output mechanism | Default timeout |
|----------|-----------------------------|----------------|
| `anthropic` | `tool_use` API (enforces JSON schema) | 120s |
| `openai` | `response_format: json_object` | 120s |
| `ollama` | `format` field (JSON schema or `"json"`) | 300s |
| `gpustack` | OpenAI-compatible API (reuses `OpenAIProvider`) | 300s |

All providers implement the `Provider` interface:
```go
type Provider interface {
    Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
```

`FormatSetter` is an optional interface for providers that support structured output schemas (Anthropic, Ollama):
```go
type FormatSetter interface {
    SetFormat(schema interface{})
}
```

---

## LLM Response Schema

Schema definitions: `internal/analyzer/schema.go`

### Phase 1: Per-check analysis (Finding)

```json
{
  "check": "c2_connections",
  "intrusion_confidence": "likely",
  "risk_level": "high",
  "title": "svchost.exe anomalous external connection detected",
  "attack_scenario": "System process impersonation for C2 beaconing",
  "evidence": ["PID 4821 → 185.220.101.45:4444"],
  "ioc": {
    "ips": ["185.220.101.45"],
    "processes": ["C:\\Users\\Public\\svchost.exe"],
    "ports": [4444],
    "hashes": [], "registry_keys": [], "domains": [], "user_accounts": []
  },
  "mitre": ["T1071", "T1036"],
  "immediate_actions": ["Terminate PID 4821 immediately"],
  "forensic_next_steps": ["Collect memory dump"],
  "reasoning_chain": {
    "observation": "svchost.exe running from non-standard path",
    "baseline": "Legitimate svchost.exe resides in C:\\Windows\\System32",
    "deviation": "C:\\Users\\Public path is a frequent attacker staging location",
    "context": "External IP on port 4444 → beacon pattern",
    "conclusion": "High probability of C2 communication"
  }
}
```

### Phase 2: Cross-check synthesis (Verdict)

```json
{
  "overall_verdict": {
    "status": "compromised",
    "confidence": "confirmed",
    "recommendation": "Isolate from network immediately",
    "summary": "Active C2 communication confirmed + log deletion detected"
  },
  "findings": [{ "id": "F-01", "severity": "critical", "..." : "..." }],
  "timeline": [
    { "timestamp": "2026-02-20T21:30:00Z", "event": "...", "kill_chain_phase": "initial_access" }
  ],
  "ioc_list": [{ "type": "ip", "value": "185.220.101.45", "context": "C2 server" }],
  "data_gaps": ["Sysmon not installed — process injection detection limited"]
}
```

---

## Isolation Verdict Logic

```go
func (a *Aggregator) ShouldIsolate(findings []Finding) IsolationRecommendation {
    // Immediate isolation: any Confirmed finding
    for _, f := range findings {
        if f.IntrusionConfidence == "confirmed" {
            return IsolationRecommendation{
                Isolate: true,
                Urgency: "immediate",
                Reason:  f.Title,
            }
        }
    }

    // Composite isolation: 2+ Likely findings simultaneously
    if countByConfidence(findings, "likely") >= 2 {
        return IsolationRecommendation{
            Isolate: true,
            Urgency: "urgent",
            Reason:  "Multiple high-confidence intrusion indicators found simultaneously",
        }
    }

    return IsolationRecommendation{Isolate: false}
}
```

---

## Error Handling

> **Principle: Never abort** — no error stops the full pipeline. An empty report never happens.

### Collection stage (Collector)

`FailureKind` is set on `collector.Result` when a script fails:

| Error type | Exit code | FailureKind | Recovery |
|-----------|-----------|-------------|----------|
| Timeout | -1 | `timeout` | Kill process, record empty result |
| Permission denied (Windows: 5, Linux: 126) | 5 / 126 | `permission_denied` | Skip check, continue |
| Script error (non-zero exit) | 1–255 | `script_error` | Preserve partial output |
| Interpreter not found (Windows: 9009, Linux: 127) | 9009 / 127 | `not_found` | Skip check |
| embed.FS read failure | -1 | `unknown` | Classified as build issue, continue |
| `exec.ErrNotFound` (Go level) | -1 | `not_found` | Interpreter absent |
| stderr contains "access denied" | any positive | `permission_denied` | Re-classified from stderr text |

Classification priority in `internal/collector/runner.go` → `classifyFailure()`:
1. `TimedOut == true` → `FailureTimeout`
2. `errors.Is(err, exec.ErrNotFound)` → `FailureNotFound`
3. Exit code switch (5, 126, 127, 9009)
4. `ExitCode > 0` + stderr pattern → `FailurePermission` or `FailureScriptError`
5. `ExitCode == -1` → `FailureUnknown`

### Analysis stage (Analyzer)

| Error type | Recovery | Report impact |
|-----------|----------|---------------|
| LLM API error (network/auth) | `AnalyzeAll` continues (partial results allowed) | Affected Finding missing |
| LLM response JSON parse failure | Preserved as `RawFinding` | Shown in "Analysis Failures" section |
| LLM field validation failure | Normalized to `informational`/`none` | Finding created with low confidence |
| Complete LLM failure | `stderr` warning, continue | Empty Findings, no Verdict — raw evidence preserved |

### Reporter stage

| Error type | Severity | Recovery |
|-----------|---------|----------|
| Output directory creation failure | **Fatal** | Immediate error return (disk space/permissions) |
| HTML template rendering failure | **Fatal** | Immediate error return (prevented by build-time template validation) |
| ZIP evidence creation failure | Non-fatal | `stderr` warning, continue |
| `manifest.json` save failure | Non-fatal | `stderr` warning, hash verification unavailable |

### API error truncation

LLM API error messages are truncated to 512 bytes (`internal/analyzer/client.go`):
```go
const maxLen = 512
// Prevents sensitive information leakage while retaining diagnostic detail
```

---

## Evidence Package (ZIP Export)

After report generation, `output/{timestamp}.zip` is automatically created:

```
output/2026-02-21T14-00-00.zip
└── 2026-02-21T14-00-00/
    ├── c2_connections.json
    ├── account_compromise.json
    ├── ... (all collection results)
    ├── manifest.json
    ├── report.html
    └── package_info.json         ← auto-generated metadata
```

`package_info.json`:
```json
{
  "version": "1.0",
  "hostname": "target-server",
  "os": "windows",
  "created_at": "2026-02-21T14:00:00Z",
  "tool_version": "v0.3.0",
  "files": [
    { "name": "c2_connections.json", "sha256": "a1b2c3...", "size": 4096 }
  ]
}
```

Implementation: `internal/reporter/exporter.go` — follows DFIR evidence preservation principles (NIST IR 8387).

---

## Build and Release

```bash
make build-all   # Cross-compile all platforms
# → build/coroner-windows-amd64.exe
# → build/coroner-linux-amd64
# → build/coroner-darwin-arm64
# → build/coroner-darwin-amd64

make test        # Unit tests (175 passing)
make lint        # golangci-lint
```

GitHub Actions → goreleaser → GitHub Releases (triggered on version tag push).
