# Changelog

All notable changes to system-coroner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] — 2026-02-22

### Added
- **Incomplete assessment detection** (AGG-001): isolation/banner urgency now factors in collection failures — ≥2 HIGH-impact gaps escalate to "investigate", INCOMPLETE ASSESSMENT sub-banner displayed
- **Self-process exclusion** (FP-006): coroner PID and child PowerShell processes annotated with `_analysis_hint` to prevent false positives in staging_exfiltration analysis
- **Stderr excerpt in failures** (CF-001): `StderrExcerpt()` captures first 200 chars of script stderr; permission keyword detection appends re-run hint; new column in Collection Failures table
- **Benign IoC filtering** (IOC-001): IoC table filters by finding confidence — clean/informational excluded, low marked as `low_confidence`, medium+ as `active`; deduplication favors suspicious over benign
- **Finding type classification** (ANA-005): `finding_type` enum (`intrusion_indicator`, `exposure`, `informational`) separates intrusion evidence from hardening gaps; new "Hardening Recommendations" report section for exposure findings
- **Combined evidence gap analysis** (GAP-001): 8 predefined multi-check failure scenarios with compound blind spot descriptions and kill chain gap mapping
- **Webshell progressive scan** (WEB-001): timeout increased to 60s with elapsed-time check; outputs partial results with `scan_incomplete` flag when approaching timeout

### Fixed
- **Log capacity fixture alignment** (RP-010): test fixtures updated to match actual `log_tampering.ps1` output format (`name` field, `fill_percent`, `log_mode`, `is_enabled`, `record_count`); added `RealScriptOutput` test reproducing D6DQSB24 scenario

### Internal
- Phase 12 complete: 8 issues from D6DQSB24 field assessment resolved
- Sprint 08: 7 commits, all tests passing

---

## [0.3.0] — 2026-02-21

### Added
- **Sigma Rules preprocessing pipeline** (SIG-001): deterministic detection layer before LLM analysis
  - New `internal/sigma` package with `Engine`, `SigmaMatch` types
  - 3 embedded Windows Sigma rules: C2 connection from Temp path (high), credential harvesting tool (critical), base64-encoded persistence (high)
  - Rules matched per-check via `logsource.category` scoping
  - Results displayed in HTML report as a dedicated "Sigma Rule Matches" section
- **Exit code classification** (ARCH-004): `FailureKind` type with 6 constants (`none`, `timeout`, `permission_denied`, `script_error`, `not_found`, `unknown`)
  - `classifyFailure()` maps exit codes (5, 126, 127, 9009) and stderr patterns to `FailureKind`
  - HTML report shows FailureKind badge per collection failure
- **Raw evidence JSON viewer** (UI-007): syntax-highlighted collapsible raw JSON for each finding
- **Anthropic custom endpoint support** (ARCH-007): configurable base URL (compatible with proxies and local Anthropic-compatible servers)
- **`embed.FS` → `fs.FS` abstraction** (ARCH-008): `Collector.New()` accepts any `fs.FS`, enabling `testing/fstest.MapFS` in integration tests
- **`Collect()` integration tests**: 4 tests covering evidence-first principle, missing script handling, parallel collection, and context cancellation
- **Error handling matrix documentation** (ARCH-009): collector/analyzer/reporter error classification in `docs/ARCHITECTURE.md`

### Changed
- Verbose output format improved (ARCH-005): aligned check ID column + FailureKind status per check

### Internal
- Tests: 153 → 175 (+22 across Sprint 03 + Cycle 40)
- New packages: `internal/sigma` (Engine + 3 Sigma rules)
- Dependencies added: `github.com/bradleyjkemp/sigma-go v0.6.6` (+ aho-corasick, jsonpath, gval, yaml.v3)

---

## [0.2.0] — 2026-02-21

### Added
- **Structured LLM output** via Anthropic `tool_use` API: deterministic JSON schema parsing, confidence scoring, MITRE sub-technique mapping
- **Linux compromised fixtures** (9 checks): real-world attack pattern test data
- **Evidence package export**: ZIP archive of all collected JSON + report.html + manifest
- **Dark/Light theme toggle** in HTML report
- **IoC export** (CSV/JSON) from HTML report
- **Kill chain phase badges** with color coding
- **4-level isolation banner**: immediate/urgent/monitor/clean with color-coded severity
- **Collection failure section** in HTML report
- **Windows check enhancements**:
  - WFC-001: `netstat` fallback for network connection collection
  - WFC-004: Authenticode signature verification for process binaries
  - WFC-005: 7 Run key registry paths scanned
  - WFC-006: Base64 pattern detection in registry values
- **DET-006**: MITRE ATT&CK sub-technique full mapping (T1xxx.xxx format)

### Changed
- Phase 3 LLM prompt anti-hallucination improvements: Known-Good filter, field truncation, structured system prompt
- Analyzer two-phase design: per-check analysis → cross-check synthesis

### Internal
- Tests: 48 → 153 (+105 across Sprint 02)
- E2E acceptance tests with `adaptiveMockProvider`
- `httptest`-based LLM provider tests

---

## [0.1.0] — 2026-02-21

### Added
- **Initial project structure**: Go module, CLI (cobra), config (TOML), platform detection
- **Windows detection scripts** (9 checks via PowerShell):
  - `c2_connections`: External TCP connections with process mapping
  - `credential_dump`: LSASS protection, credential tools, SAM access
  - `persistence`: Registry run keys, scheduled tasks, services, IFEO
  - `lateral_movement`: SMB shares, WMI subscriptions, remote sessions
  - `log_tampering`: Event log clearing, audit policy changes
  - `fileless_attack`: PowerShell execution policy, WMI commands, AMSI bypass
  - `lolbin_abuse`: Living-off-the-land binary detection
  - `webshell`: IIS/Apache web path scanning for web shells
  - `account_compromise`: Failed login attempts, account lockouts
- **Linux detection scripts** (9 checks via Bash):
  - `c2_connections`, `credential_dump`, `persistence`, `lateral_movement`,
    `log_tampering`, `fileless_attack`, `lolbin_abuse`, `webshell`, `account_compromise`
- **LLM Analyzer**: OpenAI/Anthropic/Ollama provider support, intrusion-scenario prompts
- **HTML Reporter**: dark-theme report with findings, IoC list, evidence hashes
- **Evidence integrity**: SHA-256 per file + `manifest.json` chain-of-custody
- **Parallel collection**: goroutine-based with per-check timeout
- **Fixture-based testing**: clean/compromised JSON fixtures for all 9 Windows checks
- **CI pipeline**: GitHub Actions for build + test
- **Security hardening**: path traversal prevention, API error truncation, embed namespace isolation
- **Config support**: `config.toml` for LLM provider, output directory, timeout, check enable/disable

### Architecture
- Single binary via `go:embed` — no installation or extraction needed
- Evidence-first: raw JSON saved to disk before LLM analysis
- Never abort: any stage failure continues remaining pipeline
- Intrusion-scenario framing: "What did the attacker do?" not "Is this suspicious?"

---

[0.3.0]: https://github.com/iyulab/system-coroner/releases/tag/v0.3.0
[0.2.0]: https://github.com/iyulab/system-coroner/releases/tag/v0.2.0
[0.1.0]: https://github.com/iyulab/system-coroner/releases/tag/v0.1.0
