package orchestrator

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iyulab/system-coroner/internal/analyzer"
	"github.com/iyulab/system-coroner/internal/collector"
	"github.com/iyulab/system-coroner/internal/config"
	"github.com/iyulab/system-coroner/internal/platform"
)

// mockProvider returns a fixed JSON response for any LLM call.
type mockProvider struct {
	response string
	calls    int
}

func (m *mockProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	m.calls++
	return m.response, nil
}

func newMockFinding(checkID string) string {
	f := analyzer.Finding{
		Check:               checkID,
		Title:               "Test finding for " + checkID,
		IntrusionConfidence: "medium",
		RiskLevel:           "medium",
		AttackScenario:      "Test scenario",
		Evidence:            []string{"test evidence"},
		MITRE:               []string{"T1071"},
		ImmediateActions:    []string{"investigate"},
		ForensicNextSteps:   []string{"memory dump"},
		ReasoningChain: analyzer.ReasoningChain{
			Observation: "observed anomaly",
			Baseline:    "normal baseline",
			Deviation:   "deviation found",
			Context:     "context info",
			Conclusion:  "needs investigation",
		},
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func newMockVerdict() string {
	v := analyzer.Verdict{
		OverallVerdict: analyzer.OverallVerdict{
			Status:         "suspicious",
			Confidence:     "medium",
			Summary:        "test summary",
			Recommendation: "investigate",
		},
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func testConfig() *config.Config {
	return &config.Config{
		LLM: config.LLMConfig{
			Provider: "anthropic",
			APIKey:   "test-key",
			Model:    "test-model",
		},
		Output: config.OutputConfig{
			Dir: "",
		},
		Checks: map[string]bool{},
	}
}

func TestNew(t *testing.T) {
	cfg := testConfig()
	opts := Options{Version: "test-0.1.0"}
	orch := New(cfg, opts)

	if orch == nil {
		t.Fatal("expected non-nil orchestrator")
	}
	if orch.cfg != cfg {
		t.Error("config not set")
	}
}

func TestNewWithFilter(t *testing.T) {
	cfg := testConfig()
	opts := Options{Only: []string{"c2_connections"}}
	orch := New(cfg, opts)

	for _, c := range orch.checks {
		if c.ID != "c2_connections" {
			t.Errorf("expected only c2_connections, got %s", c.ID)
		}
	}
}

func TestLoadFixtures(t *testing.T) {
	// Create temp fixture dir
	tmpDir := t.TempDir()

	// Write a fixture file
	fixtureData := `{"test": "data"}`
	err := os.WriteFile(filepath.Join(tmpDir, "c2_connections.json"), []byte(fixtureData), 0644)
	if err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	checks := []platform.Check{
		{ID: "c2_connections"},
		{ID: "missing_check"},
	}

	results, err := loadFixtures(tmpDir, checks)
	if err != nil {
		t.Fatalf("loadFixtures error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// First should succeed
	if results[0].Error != nil {
		t.Errorf("expected no error for c2_connections, got %v", results[0].Error)
	}
	if string(results[0].Stdout) != fixtureData {
		t.Errorf("expected fixture data, got %s", string(results[0].Stdout))
	}

	// Second should have error (missing fixture)
	if results[1].Error == nil {
		t.Error("expected error for missing_check")
	}
}

func TestLoadFixtures_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	results, err := loadFixtures(tmpDir, nil)
	if err != nil {
		t.Fatalf("loadFixtures error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestLoadFixtures_NonExistentDir(t *testing.T) {
	_, err := loadFixtures("/nonexistent/path/that/doesnt/exist", []platform.Check{{ID: "test"}})
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadFixtures_NotADirectory(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "not-a-dir.txt")
	os.WriteFile(tmpFile, []byte("hello"), 0644)

	_, err := loadFixtures(tmpFile, []platform.Check{{ID: "test"}})
	if err == nil {
		t.Fatal("expected error for file (not directory)")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadFixtures_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	// Write a fixture file in parent directory
	os.WriteFile(filepath.Join(tmpDir, "..", "secret.json"), []byte("secret"), 0644)

	// Try to read it via path traversal in check ID
	checks := []platform.Check{
		{ID: "../secret"},
	}

	results, err := loadFixtures(tmpDir, checks)
	if err != nil {
		t.Fatalf("loadFixtures error: %v", err)
	}

	// The path traversal check should have resulted in an error for this check
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected error for path traversal attempt")
	}
}

func TestRunCollectOnly(t *testing.T) {
	cfg := testConfig()
	cfg.Output.Dir = t.TempDir()
	opts := Options{
		CollectOnly: true,
		SkipCollect: true,
		Fixture:     t.TempDir(),
		Version:     "test",
	}

	// Create a fixture
	fixtureData := `{"test": "data"}`
	check := platform.GetChecks()
	if len(check) == 0 {
		t.Skip("no checks available on this platform")
	}
	firstCheckID := check[0].ID
	os.WriteFile(filepath.Join(opts.Fixture, firstCheckID+".json"), []byte(fixtureData), 0644)

	orch := New(cfg, opts)
	if len(orch.checks) == 0 {
		t.Skip("no checks available on this platform")
	}

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
}

func TestRunFixtureWithMockLLM(t *testing.T) {
	cfg := testConfig()
	outputDir := t.TempDir()
	cfg.Output.Dir = outputDir

	fixtureDir := t.TempDir()

	checks := platform.GetChecks()
	if len(checks) == 0 {
		t.Skip("no checks available on this platform")
	}

	// Only test with 1 check for speed
	firstCheck := checks[0]
	fixtureData := `{"test": "fixture data for analysis"}`
	os.WriteFile(filepath.Join(fixtureDir, firstCheck.ID+".json"), []byte(fixtureData), 0644)

	opts := Options{
		SkipCollect: true,
		Fixture:     fixtureDir,
		Only:        []string{firstCheck.ID},
		Version:     "test-0.1.0",
	}

	// Create mock that returns finding JSON, then verdict JSON
	mock := &mockProvider{}
	// The mock needs to handle both per-check and synthesis calls
	// For simplicity, alternate between finding and verdict responses
	callCount := 0
	findingResp := newMockFinding(firstCheck.ID)
	verdictResp := newMockVerdict()

	adaptiveMock := &adaptiveMockProvider{
		findingResp: findingResp,
		verdictResp: verdictResp,
		callCount:   &callCount,
	}
	_ = mock // suppress unused

	orch := New(cfg, opts)
	orch.SetProvider(adaptiveMock)

	if len(orch.checks) == 0 {
		t.Skip("no checks available")
	}

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Verify report was generated
	entries, _ := os.ReadDir(outputDir)
	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			reportPath := filepath.Join(outputDir, entry.Name(), "report.html")
			if _, err := os.Stat(reportPath); err == nil {
				found = true
				content, _ := os.ReadFile(reportPath)
				if !strings.Contains(string(content), "system-coroner") {
					t.Error("report should contain system-coroner")
				}
			}
		}
	}
	if !found {
		t.Error("expected report.html to be generated")
	}
}

// adaptiveMockProvider returns finding JSON for per-check calls
// and verdict JSON for the synthesis call.
type adaptiveMockProvider struct {
	findingResp string
	verdictResp string
	callCount   *int
}

func (m *adaptiveMockProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	*m.callCount++
	// Synthesis prompt contains "FINAL SYNTHESIS" (case-insensitive check)
	upper := strings.ToUpper(userPrompt)
	if strings.Contains(upper, "SYNTHESIS") || strings.Contains(upper, "CROSS-ANALYSIS") {
		return m.verdictResp, nil
	}
	return m.findingResp, nil
}

func newMockCleanFinding(checkID string) string {
	f := analyzer.Finding{
		Check:               checkID,
		Title:               "No intrusion indicators found for " + checkID,
		IntrusionConfidence: "clean",
		RiskLevel:           "none",
		AttackScenario:      "No attack scenario identified",
		Evidence:            []string{},
		MITRE:               []string{},
		ImmediateActions:    []string{},
		ForensicNextSteps:   []string{},
		ReasoningChain: analyzer.ReasoningChain{
			Observation: "system state appears normal",
			Baseline:    "expected baseline configuration",
			Deviation:   "no deviations detected",
			Context:     "standard operating environment",
			Conclusion:  "no indicators of compromise",
		},
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func newMockCleanVerdict() string {
	v := analyzer.Verdict{
		OverallVerdict: analyzer.OverallVerdict{
			Status:         "CLEAN",
			Confidence:     "high",
			Summary:        "No indicators of compromise detected",
			Recommendation: "CONTINUE_MONITORING",
		},
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRunCleanFixtureWithMockLLM(t *testing.T) {
	cfg := testConfig()
	outputDir := t.TempDir()
	cfg.Output.Dir = outputDir

	// Use actual clean fixture files
	fixtureDir := filepath.Join("..", "..", "tests", "fixtures", "windows", "clean")
	if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
		t.Skip("clean fixtures not found")
	}

	checks := platform.GetChecks()
	if len(checks) == 0 {
		t.Skip("no checks available on this platform")
	}

	firstCheck := checks[0]
	opts := Options{
		SkipCollect: true,
		Fixture:     fixtureDir,
		Only:        []string{firstCheck.ID},
		Version:     "test-0.1.0",
	}

	callCount := 0
	adaptiveMock := &adaptiveMockProvider{
		findingResp: newMockCleanFinding(firstCheck.ID),
		verdictResp: newMockCleanVerdict(),
		callCount:   &callCount,
	}

	orch := New(cfg, opts)
	orch.SetProvider(adaptiveMock)

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Verify report generated
	entries, _ := os.ReadDir(outputDir)
	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			reportPath := filepath.Join(outputDir, entry.Name(), "report.html")
			if _, err := os.Stat(reportPath); err == nil {
				found = true
				content, _ := os.ReadFile(reportPath)
				if !strings.Contains(string(content), "system-coroner") {
					t.Error("report should contain system-coroner")
				}
			}
		}
	}
	if !found {
		t.Error("expected report.html to be generated")
	}
}

func newMockCompromisedFinding(checkID string) string {
	f := analyzer.Finding{
		Check:               checkID,
		Title:               "Active intrusion detected: " + checkID,
		IntrusionConfidence: "confirmed",
		RiskLevel:           "critical",
		AttackScenario:      "APT-style intrusion with " + checkID + " indicators",
		Evidence:            []string{"malicious process found", "C2 callback detected"},
		MITRE:               []string{"T1071", "T1059"},
		ImmediateActions:    []string{"isolate server immediately", "preserve memory dump"},
		ForensicNextSteps:   []string{"full disk forensics", "network traffic analysis"},
		IoC: analyzer.IoC{
			IPs:       []string{"185.220.101.42", "91.215.85.17"},
			Processes: []string{"/tmp/.cache/update.sh", "/dev/shm/.x"},
			Domains:   []string{"update-service.xyz"},
		},
		ReasoningChain: analyzer.ReasoningChain{
			Observation: "multiple C2 indicators and persistence mechanisms",
			Baseline:    "clean server with standard services",
			Deviation:   "unauthorized processes, suspicious network connections",
			Context:     "consistent with APT lateral movement pattern",
			Conclusion:  "confirmed intrusion requiring immediate isolation",
		},
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func newMockCompromisedVerdict() string {
	v := analyzer.Verdict{
		OverallVerdict: analyzer.OverallVerdict{
			Status:         "COMPROMISED",
			Confidence:     "confirmed",
			Summary:        "Active APT intrusion confirmed with C2, persistence, and lateral movement",
			Recommendation: "ISOLATE_IMMEDIATELY",
		},
		Timeline: []analyzer.TimelineEvent{
			{Timestamp: "2026-02-20T21:30", Event: "Initial webshell upload", KillChainPhase: "initial_access"},
			{Timestamp: "2026-02-20T22:15", Event: "Privilege escalation via SUID", KillChainPhase: "privilege_escalation"},
			{Timestamp: "2026-02-21T01:30", Event: "Lateral movement to 10.0.2.50", KillChainPhase: "lateral_movement"},
		},
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRunCompromisedFixtureWithMockLLM(t *testing.T) {
	cfg := testConfig()
	outputDir := t.TempDir()
	cfg.Output.Dir = outputDir

	// Use Linux compromised fixture files
	fixtureDir := filepath.Join("..", "..", "tests", "fixtures", "linux", "compromised")
	if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
		t.Skip("compromised fixtures not found")
	}

	// Test with 3 checks that have compromised data
	checkIDs := []string{"c2_connections", "persistence", "webshell"}
	opts := Options{
		SkipCollect: true,
		Fixture:     fixtureDir,
		Only:        checkIDs,
		Version:     "test-0.1.0",
	}

	callCount := 0
	adaptiveMock := &adaptiveMockProvider{
		findingResp: newMockCompromisedFinding("c2_connections"),
		verdictResp: newMockCompromisedVerdict(),
		callCount:   &callCount,
	}

	orch := New(cfg, opts)
	orch.SetProvider(adaptiveMock)

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Verify report generated with isolation recommendation
	entries, _ := os.ReadDir(outputDir)
	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			reportPath := filepath.Join(outputDir, entry.Name(), "report.html")
			if _, err := os.Stat(reportPath); err == nil {
				found = true
				content, _ := os.ReadFile(reportPath)
				html := string(content)

				// Report should contain isolation indicators
				if !strings.Contains(html, "system-coroner") {
					t.Error("report should contain system-coroner")
				}
				// Should contain IoC data
				if !strings.Contains(html, "185.220.101.42") {
					t.Error("report should contain IoC IP address")
				}
			}
		}
	}
	if !found {
		t.Error("expected report.html to be generated")
	}

	// Mock should have been called: 3 per-check + 1 synthesis = 4
	if callCount < 3 {
		t.Errorf("expected at least 3 LLM calls, got %d", callCount)
	}
}

func TestRunAllLinuxFixtures(t *testing.T) {
	cfg := testConfig()
	outputDir := t.TempDir()
	cfg.Output.Dir = outputDir

	// Use all Linux compromised fixtures
	fixtureDir := filepath.Join("..", "..", "tests", "fixtures", "linux", "compromised")
	if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
		t.Skip("linux compromised fixtures not found")
	}

	allChecks := []string{
		"c2_connections", "persistence", "log_tampering",
		"account_compromise", "credential_dump", "fileless_attack",
		"lolbin_abuse", "lateral_movement", "webshell",
	}
	opts := Options{
		SkipCollect: true,
		Fixture:     fixtureDir,
		Only:        allChecks,
		Version:     "test-0.1.0",
	}

	callCount := 0
	adaptiveMock := &adaptiveMockProvider{
		findingResp: newMockCompromisedFinding("generic"),
		verdictResp: newMockCompromisedVerdict(),
		callCount:   &callCount,
	}

	orch := New(cfg, opts)
	orch.SetProvider(adaptiveMock)

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Should have 9 per-check calls + 1 synthesis = 10 (may vary due to prompt detection)
	if callCount < 9 {
		t.Errorf("expected at least 9 LLM calls (9 checks + synthesis), got %d", callCount)
	}
}

func TestRunE2E_FullPipeline_WithZipExport(t *testing.T) {
	cfg := testConfig()
	outputDir := t.TempDir()
	cfg.Output.Dir = outputDir

	// Use Windows clean fixtures for a full E2E test
	fixtureDir := filepath.Join("..", "..", "tests", "fixtures", "windows", "clean")
	if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
		t.Skip("windows clean fixtures not found")
	}

	// Run all 9 checks
	allChecks := []string{
		"c2_connections", "persistence", "log_tampering",
		"account_compromise", "credential_dump", "fileless_attack",
		"lolbin_abuse", "lateral_movement", "webshell",
	}
	opts := Options{
		SkipCollect: true,
		Fixture:     fixtureDir,
		Only:        allChecks,
		Version:     "test-0.2.0",
	}

	callCount := 0
	adaptiveMock := &adaptiveMockProvider{
		findingResp: newMockCleanFinding("generic"),
		verdictResp: newMockCleanVerdict(),
		callCount:   &callCount,
	}

	orch := New(cfg, opts)
	orch.SetProvider(adaptiveMock)

	err := orch.Run(context.Background())
	if err != nil {
		t.Fatalf("E2E Run error: %v", err)
	}

	// Find the output subdirectory
	entries, _ := os.ReadDir(outputDir)
	var runDir string
	for _, entry := range entries {
		if entry.IsDir() {
			runDir = filepath.Join(outputDir, entry.Name())
			break
		}
	}
	if runDir == "" {
		t.Fatal("no output subdirectory created")
	}

	// Verify report.html exists
	reportPath := filepath.Join(runDir, "report.html")
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Error("report.html not generated")
	}

	// Verify ZIP evidence package exists
	zipPath := runDir + ".zip"
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		t.Error("evidence package ZIP not generated")
	} else {
		// Verify ZIP is valid and contains package_info.json
		r, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open zip: %v", err)
		}
		defer r.Close()

		hasPackageInfo := false
		hasReport := false
		for _, f := range r.File {
			name := filepath.Base(f.Name)
			if name == "package_info.json" {
				hasPackageInfo = true
			}
			if name == "report.html" {
				hasReport = true
			}
		}
		if !hasPackageInfo {
			t.Error("ZIP missing package_info.json")
		}
		if !hasReport {
			t.Error("ZIP missing report.html")
		}
	}

	// Verify LLM was called: 9 checks + 1 synthesis = 10
	if callCount < 9 {
		t.Errorf("expected at least 9 LLM calls, got %d", callCount)
	}
}

func TestBuildMeta(t *testing.T) {
	results := []collector.Result{
		{CheckID: "a", ExitCode: 0, CollectedAt: time.Now()},
		{CheckID: "b", ExitCode: 1, Error: fmt.Errorf("failed"), CollectedAt: time.Now()},
	}
	meta := collector.BuildMeta("test-host", "windows", time.Now(), results)
	if meta.TotalChecks != 2 {
		t.Errorf("expected 2 checks, got %d", meta.TotalChecks)
	}
	if meta.Succeeded != 1 {
		t.Errorf("expected 1 succeeded, got %d", meta.Succeeded)
	}
	if meta.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", meta.Failed)
	}
}
