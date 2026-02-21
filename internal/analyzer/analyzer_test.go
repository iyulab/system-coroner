package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// mockProvider returns predetermined responses for testing.
type mockProvider struct {
	responses map[int]string // keyed by call index
	callCount int
	err       error
}

func (m *mockProvider) Analyze(ctx context.Context, system, user string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	idx := m.callCount
	m.callCount++
	if resp, ok := m.responses[idx]; ok {
		return resp, nil
	}
	return m.responses[0], nil
}

func sampleFindingJSON(checkID, confidence, risk string) string {
	f := Finding{
		Check:               checkID,
		IntrusionConfidence: confidence,
		RiskLevel:           risk,
		Title:               fmt.Sprintf("Test finding for %s", checkID),
		AttackScenario:      "Test scenario",
		Evidence:            []string{"test evidence"},
		IoC:                 IoC{IPs: []string{"1.2.3.4"}},
		MITRE:               []string{"T1071"},
		ImmediateActions:    []string{"investigate"},
		ForensicNextSteps:   []string{"collect memory dump"},
		ReasoningChain: ReasoningChain{
			Observation: "test observation",
			Baseline:    "test baseline",
			Deviation:   "test deviation",
			Context:     "test context",
			Conclusion:  "test conclusion",
		},
	}
	data, _ := json.Marshal(f)
	return string(data)
}

func sampleVerdictJSON() string {
	v := Verdict{
		OverallVerdict: OverallVerdict{
			Status:         "COMPROMISED",
			Confidence:     "high",
			Recommendation: "ISOLATE_IMMEDIATELY",
			Summary:        "Active C2 communication detected",
		},
		Findings: []VerdictFinding{
			{
				ID:       "F-001",
				Severity: "CRITICAL",
				Title:    "Active C2 connection",
				Category: "C2_Communication",
			},
		},
		Timeline: []TimelineEvent{
			{
				Timestamp:      "2026-02-20T02:45:33Z",
				Event:          "C2 connection established",
				FindingID:      "F-001",
				KillChainPhase: "command_and_control",
			},
		},
		IoCList: []IoCEntry{
			{Type: "ip", Value: "185.220.101.45", Context: "C2 server"},
		},
		DataGaps: []string{"Sysmon not installed"},
	}
	data, _ := json.Marshal(v)
	return string(data)
}

func TestAnalyzeCheck_Success(t *testing.T) {
	mock := &mockProvider{
		responses: map[int]string{
			0: sampleFindingJSON("c2_connections", "high", "high"),
		},
	}

	a := New(mock, "TEST-HOST", "windows", false)
	finding, err := a.AnalyzeCheck(context.Background(), "c2_connections", `{"connections":[]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding.Check != "c2_connections" {
		t.Errorf("check = %q", finding.Check)
	}
	if finding.IntrusionConfidence != "high" {
		t.Errorf("confidence = %q", finding.IntrusionConfidence)
	}
}

func TestAnalyzeCheck_Retry(t *testing.T) {
	callCount := 0
	mock := &mockProvider{
		responses: map[int]string{
			1: sampleFindingJSON("c2_connections", "medium", "medium"),
		},
	}
	// First call fails, second succeeds
	originalAnalyze := mock.Analyze
	mock2 := &retryMockProvider{
		failFirst:       true,
		successResponse: sampleFindingJSON("c2_connections", "medium", "medium"),
	}
	_ = originalAnalyze
	_ = callCount

	a := New(mock2, "TEST-HOST", "windows", false)
	finding, err := a.AnalyzeCheck(context.Background(), "c2_connections", `{}`)
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if finding.IntrusionConfidence != "medium" {
		t.Errorf("confidence = %q", finding.IntrusionConfidence)
	}
}

type retryMockProvider struct {
	failFirst       bool
	failed          bool
	successResponse string
}

func (m *retryMockProvider) Analyze(ctx context.Context, system, user string) (string, error) {
	if m.failFirst && !m.failed {
		m.failed = true
		return "", fmt.Errorf("temporary error")
	}
	return m.successResponse, nil
}

func TestAnalyzeCheck_ProviderError(t *testing.T) {
	mock := &mockProvider{
		err: fmt.Errorf("API error"),
	}

	a := New(mock, "TEST-HOST", "windows", false)
	_, err := a.AnalyzeCheck(context.Background(), "c2_connections", `{}`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAnalyzeAll_Success(t *testing.T) {
	callCount := 0
	mock := &indexedMockProvider{
		responses: []string{
			sampleFindingJSON("c2_connections", "high", "high"),
			sampleFindingJSON("log_tampering", "confirmed", "critical"),
			sampleVerdictJSON(),
		},
	}
	_ = callCount

	a := New(mock, "TEST-HOST", "windows", false)
	result, err := a.AnalyzeAll(context.Background(), map[string]string{
		"c2_connections": `{"connections":[]}`,
		"log_tampering":  `{"log_cleared_events":[]}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(result.Findings))
	}
}

type indexedMockProvider struct {
	responses []string
	idx       int
	mu        sync.Mutex
}

func (m *indexedMockProvider) Analyze(ctx context.Context, system, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.responses) {
		return m.responses[len(m.responses)-1], nil
	}
	resp := m.responses[m.idx]
	m.idx++
	return resp, nil
}

func TestParseFinding_Valid(t *testing.T) {
	raw := sampleFindingJSON("test", "high", "critical")
	finding, err := ParseFinding("test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.Check != "test" {
		t.Errorf("check = %q", finding.Check)
	}
	if finding.IntrusionConfidence != "high" {
		t.Errorf("confidence = %q", finding.IntrusionConfidence)
	}
}

func TestParseFinding_WithCodeFence(t *testing.T) {
	raw := "```json\n" + sampleFindingJSON("test", "medium", "medium") + "\n```"
	finding, err := ParseFinding("test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.IntrusionConfidence != "medium" {
		t.Errorf("confidence = %q", finding.IntrusionConfidence)
	}
}

func TestParseFinding_InvalidJSON(t *testing.T) {
	_, err := ParseFinding("test", "not json at all")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseFinding_InvalidConfidence(t *testing.T) {
	raw := sampleFindingJSON("test", "UNKNOWN_LEVEL", "high")
	finding, err := ParseFinding("test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.IntrusionConfidence != "informational" {
		t.Errorf("invalid confidence should default to informational, got %q", finding.IntrusionConfidence)
	}
}

func TestParseFinding_InvalidRiskLevel(t *testing.T) {
	raw := sampleFindingJSON("test", "high", "INVALID")
	finding, err := ParseFinding("test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.RiskLevel != "low" {
		t.Errorf("invalid risk level should default to low, got %q", finding.RiskLevel)
	}
}

func TestParseFinding_MissingFields(t *testing.T) {
	// Minimal JSON with no optional fields
	raw := `{"check":"","intrusion_confidence":"","risk_level":"","title":""}`
	finding, err := ParseFinding("missing_test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.Check != "missing_test" {
		t.Errorf("check = %q, want missing_test", finding.Check)
	}
	if finding.Title != "Untitled finding for missing_test" {
		t.Errorf("title = %q, want default", finding.Title)
	}
	if finding.IntrusionConfidence != "informational" {
		t.Errorf("confidence = %q, want informational", finding.IntrusionConfidence)
	}
	if finding.RiskLevel != "low" {
		t.Errorf("risk = %q, want low", finding.RiskLevel)
	}
}

func TestParseFinding_ConfidenceCaseNormalization(t *testing.T) {
	raw := sampleFindingJSON("test", "HIGH", "CRITICAL")
	finding, err := ParseFinding("test", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding.IntrusionConfidence != "high" {
		t.Errorf("confidence = %q, want high (lowercase)", finding.IntrusionConfidence)
	}
	if finding.RiskLevel != "critical" {
		t.Errorf("risk = %q, want critical (lowercase)", finding.RiskLevel)
	}
}

func TestParseVerdict_Valid(t *testing.T) {
	raw := sampleVerdictJSON()
	verdict, err := ParseVerdict(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.OverallVerdict.Status != "COMPROMISED" {
		t.Errorf("status = %q", verdict.OverallVerdict.Status)
	}
	if len(verdict.IoCList) != 1 {
		t.Errorf("ioc_list count = %d", len(verdict.IoCList))
	}
}

func TestBuildCheckPrompt_Known(t *testing.T) {
	prompt := BuildCheckPrompt("c2_connections", "WEB-01", "windows", `{"data":"test"}`)
	if prompt == "" {
		t.Error("prompt should not be empty")
	}
	if !contains(prompt, "WEB-01") {
		t.Error("prompt should contain hostname")
	}
	if !contains(prompt, "C2") {
		t.Error("prompt should contain C2 reference")
	}
}

func TestBuildCheckPrompt_Linux(t *testing.T) {
	prompt := BuildCheckPrompt("c2_connections", "LINUX-01", "linux", `{"data":"test"}`)
	if prompt == "" {
		t.Error("prompt should not be empty")
	}
	if !contains(prompt, "LINUX-01") {
		t.Error("prompt should contain hostname")
	}
	if !contains(prompt, "/proc") {
		t.Error("linux prompt should reference /proc filesystem")
	}
}

func TestBuildCheckPrompt_Unknown(t *testing.T) {
	prompt := BuildCheckPrompt("unknown_check", "WEB-01", "windows", `{}`)
	if !contains(prompt, "WEB-01") {
		t.Error("fallback prompt should contain hostname")
	}
}

func TestGetSystemPrompt_Windows(t *testing.T) {
	prompt := GetSystemPrompt("windows")
	if !contains(prompt, "Windows Server") {
		t.Error("windows prompt should reference Windows Server")
	}
}

func TestGetSystemPrompt_Linux(t *testing.T) {
	prompt := GetSystemPrompt("linux")
	if !contains(prompt, "Linux server") {
		t.Error("linux prompt should reference Linux server")
	}
	if !contains(prompt, "/proc") {
		t.Error("linux prompt should reference /proc filesystem")
	}
}

func TestBuildSynthesisPrompt(t *testing.T) {
	prompt := BuildSynthesisPrompt("WEB-01", "windows", 9, `[{"check":"test"}]`)
	if !contains(prompt, "WEB-01") {
		t.Error("synthesis prompt should contain hostname")
	}
	if !contains(prompt, "windows") {
		t.Error("synthesis prompt should contain OS name")
	}
	if !contains(prompt, "9") {
		t.Error("synthesis prompt should contain check count")
	}
}

func TestBuildSynthesisPrompt_EmptyOS(t *testing.T) {
	prompt := BuildSynthesisPrompt("WEB-01", "", 5, `[]`)
	if !contains(prompt, "WEB-01") {
		t.Error("synthesis prompt should contain hostname")
	}
	// Should not contain parentheses when OS is empty
	if contains(prompt, "()") {
		t.Error("synthesis prompt should not contain empty parentheses")
	}
}

func TestAnalyzer_AnalystContextInjected(t *testing.T) {
	var capturedPrompts []string
	mock := &capturingMockProvider{
		response: sampleFindingJSON("c2_connections", "high", "high"),
		onCall: func(system, user string) {
			capturedPrompts = append(capturedPrompts, user)
		},
	}

	a := New(mock, "TEST-HOST", "windows", false)
	a.SetAnalystContext("rclone.exe is a legitimate backup tool")
	_, _ = a.AnalyzeAll(context.Background(), map[string]string{
		"c2_connections": `{"connections":[]}`,
	})

	// The first prompt (per-check) should contain the analyst context
	if len(capturedPrompts) == 0 {
		t.Fatal("no prompts captured")
	}
	firstPrompt := capturedPrompts[0]
	if !contains(firstPrompt, "rclone.exe is a legitimate backup tool") {
		t.Errorf("analyst context not injected into prompt")
	}
	if !contains(firstPrompt, "ANALYST CONTEXT") {
		t.Errorf("ANALYST CONTEXT header not found in prompt")
	}
}

func TestInjectAnalystContext_Empty(t *testing.T) {
	original := "original prompt"
	result := InjectAnalystContext(original, "")
	if result != original {
		t.Errorf("empty context should return original prompt, got: %s", result)
	}
}

func TestInjectAnalystContext_NonEmpty(t *testing.T) {
	result := InjectAnalystContext("original", "my context")
	if !contains(result, "ANALYST CONTEXT") {
		t.Error("should contain ANALYST CONTEXT header")
	}
	if !contains(result, "my context") {
		t.Error("should contain the analyst context")
	}
	if !contains(result, "original") {
		t.Error("should contain the original prompt")
	}
}

// capturingMockProvider captures the user prompt for inspection.
type capturingMockProvider struct {
	response string
	onCall   func(system, user string)
}

func (m *capturingMockProvider) Analyze(ctx context.Context, system, user string) (string, error) {
	if m.onCall != nil {
		m.onCall(system, user)
	}
	return m.response, nil
}

func TestOllamaProvider_ImplementsFormatSetter(t *testing.T) {
	p, err := NewProvider("ollama", "", "test-model", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fs, ok := p.(FormatSetter)
	if !ok {
		t.Fatal("OllamaProvider should implement FormatSetter")
	}
	// Verify SetFormat doesn't panic
	fs.SetFormat(FindingSchema)
	fs.SetFormat(VerdictSchema)
	fs.SetFormat(nil)
}

func TestOpenAIProvider_DoesNotImplementFormatSetter(t *testing.T) {
	p, err := NewProvider("openai", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("NewProvider(openai): %v", err)
	}
	if _, ok := p.(FormatSetter); ok {
		t.Error("openai should NOT implement FormatSetter")
	}
}

func TestAnthropicProvider_ImplementsFormatSetter(t *testing.T) {
	p, err := NewProvider("anthropic", "key", "model", "", 0)
	if err != nil {
		t.Fatalf("NewProvider(anthropic): %v", err)
	}
	fs, ok := p.(FormatSetter)
	if !ok {
		t.Fatal("AnthropicProvider should implement FormatSetter")
	}
	// Verify SetFormat does not panic
	fs.SetFormat(FindingSchema)
	fs.SetFormat(VerdictSchema)
	fs.SetFormat(nil)
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		provider string
		wantErr  bool
	}{
		{"anthropic", false},
		{"openai", false},
		{"ollama", false},
		{"unknown", true},
	}

	for _, tt := range tests {
		p, err := NewProvider(tt.provider, "key", "model", "", 0)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NewProvider(%q): expected error", tt.provider)
			}
		} else {
			if err != nil {
				t.Errorf("NewProvider(%q): %v", tt.provider, err)
			}
			if p == nil {
				t.Errorf("NewProvider(%q): provider is nil", tt.provider)
			}
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
