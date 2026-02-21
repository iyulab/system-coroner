package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iyulab/system-coroner/internal/analyzer"
)

func TestNew(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil reporter")
	}
	if rep.tmpl == nil {
		t.Fatal("expected non-nil template")
	}
}

func TestGenerate(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test-0.1.0",
		Isolation: IsolationRecommendation{
			Isolate: false,
			Urgency: "none",
			Reason:  "No intrusion detected",
			Banner:  "green",
		},
		ConfidenceSummary:  ConfidenceSummary{},
		TotalChecks:        9,
		Findings:           nil,
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if filepath.Base(path) != "report.html" {
		t.Errorf("expected report.html, got %s", filepath.Base(path))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	html := string(content)
	if !strings.Contains(html, "test-host") {
		t.Error("report should contain hostname")
	}
	if !strings.Contains(html, "NO INTRUSION DETECTED") {
		t.Error("report should contain green banner text")
	}
	if !strings.Contains(html, "banner-green") {
		t.Error("report should have green banner class")
	}
}

func TestGenerate_WithFindings(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "compromised-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test-0.1.0",
		Isolation: IsolationRecommendation{
			Isolate: true,
			Urgency: "immediate",
			Reason:  "Confirmed backdoor",
			Banner:  "red",
		},
		ConfidenceSummary: ConfidenceSummary{Confirmed: 1, High: 1},
		TotalChecks:       9,
		Findings: []analyzer.Finding{
			{
				Check:               "c2_connections",
				Title:               "Active C2 Channel Detected",
				IntrusionConfidence: "confirmed",
				RiskLevel:           "critical",
				AttackScenario:      "Reverse shell to external C2",
				Evidence:            []string{"TCP 4444 -> 1.2.3.4"},
				MITRE:               []string{"T1071"},
				ImmediateActions:    []string{"Block 1.2.3.4"},
				ForensicNextSteps:   []string{"Capture memory dump"},
				ReasoningChain: analyzer.ReasoningChain{
					Observation: "Outbound connection on port 4444",
					Baseline:    "No legitimate service uses port 4444",
					Deviation:   "Classic C2 port",
					Context:     "Combined with other indicators",
					Conclusion:  "Active C2 communication confirmed",
				},
				IoC: analyzer.IoC{
					IPs: []string{"1.2.3.4"},
				},
			},
		},
		IoCs: []analyzer.IoCEntry{
			{Type: "ip", Value: "1.2.3.4", Context: "c2_connections"},
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	html := string(content)
	checks := []string{
		"ISOLATE IMMEDIATELY",
		"banner-critical",
		"Active C2 Channel Detected",
		"confidence-confirmed",
		"risk-critical",
		"T1071",
		"1.2.3.4",
		"Block 1.2.3.4",
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("report should contain %q", check)
		}
	}
}

func TestGenerate_BannerRed_UrgentNotImmediate(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation: IsolationRecommendation{
			Isolate: true,
			Urgency: "urgent",
			Reason:  "Multiple high findings",
			Banner:  "red",
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	// Check the applied class on the banner div (not CSS definitions which always appear in the template)
	if !strings.Contains(html, `class="banner banner-red"`) {
		t.Error("urgent (non-immediate) isolation should apply banner-red class to the banner div")
	}
	if strings.Contains(html, `class="banner banner-critical"`) {
		t.Error("urgent (non-immediate) isolation should not apply banner-critical class to the banner div")
	}
}

func TestGenerate_WithCollectionFailures(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation:   IsolationRecommendation{Banner: "yellow", Urgency: "monitor"},
		TotalChecks: 9,
		CollectionFailures: []CollectionFailure{
			{CheckID: "log_tampering", CheckName: "로그 삭제/변조 흔적 탐지", Error: "access denied", FailureKind: "permission_denied"},
			{CheckID: "account_compromise", CheckName: "계정 탈취 및 조작 흔적", Error: "script timeout", FailureKind: "timeout"},
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	if !strings.Contains(html, "Collection Failures") {
		t.Error("report should contain Collection Failures section")
	}
	if !strings.Contains(html, "log_tampering") {
		t.Error("report should contain failed check ID")
	}
	if !strings.Contains(html, "access denied") {
		t.Error("report should contain error message")
	}
	if !strings.Contains(html, "permission_denied") {
		t.Error("report should contain failure kind badge")
	}
	if !strings.Contains(html, "fk-permission") {
		t.Error("report should contain failure kind CSS class")
	}
}

func TestGenerate_KillChainTimeline(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation:   IsolationRecommendation{Banner: "green", Urgency: "none"},
		TotalChecks: 9,
		Verdict: &analyzer.Verdict{
			OverallVerdict: analyzer.OverallVerdict{
				Status: "compromised", Confidence: "high",
				Recommendation: "Isolate", Summary: "APT activity",
			},
			Timeline: []analyzer.TimelineEvent{
				{Timestamp: "2024-01-01T00:00:00Z", Event: "Phishing email", KillChainPhase: "Initial Access"},
				{Timestamp: "2024-01-01T01:00:00Z", Event: "Payload execution", KillChainPhase: "Execution"},
				{Timestamp: "2024-01-01T02:00:00Z", Event: "C2 beacon", KillChainPhase: "Command and Control"},
				{Timestamp: "2024-01-01T03:00:00Z", Event: "Data staged", KillChainPhase: "Exfiltration"},
			},
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	// Each Kill Chain phase should get a distinct CSS class
	killChainChecks := []string{"kc-initial", "kc-execution", "kc-lateral", "kc-impact"}
	for _, cls := range killChainChecks {
		if !strings.Contains(html, cls) {
			t.Errorf("report should contain kill chain class %q", cls)
		}
	}
}

func TestGenerate_IoCExportButtons(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation:   IsolationRecommendation{Banner: "red", Urgency: "immediate"},
		IoCs: []analyzer.IoCEntry{
			{Type: "ip", Value: "1.2.3.4", Context: "c2_connections"},
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	if !strings.Contains(html, "Export CSV") {
		t.Error("report should contain Export CSV button")
	}
	if !strings.Contains(html, "Export JSON") {
		t.Error("report should contain Export JSON button")
	}
	if !strings.Contains(html, "downloadIoCs") {
		t.Error("report should contain downloadIoCs JS function")
	}
	if !strings.Contains(html, `id="ioc-table"`) {
		t.Error("report should have ioc-table id for JS targeting")
	}
}

func TestGenerate_ThemeToggle(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation:   IsolationRecommendation{Banner: "green", Urgency: "none"},
		ConfidenceSummary: ConfidenceSummary{
			Confirmed: 1, High: 2, Medium: 3, Low: 4, Clean: 5,
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	// Theme toggle button and JS
	if !strings.Contains(html, "theme-toggle") {
		t.Error("report should contain theme-toggle button")
	}
	if !strings.Contains(html, "toggleTheme") {
		t.Error("report should contain toggleTheme JS function")
	}
	if !strings.Contains(html, `data-theme="light"`) {
		t.Error("report should contain light theme CSS override")
	}
	// Expanded stat cards
	if !strings.Contains(html, ">Low<") {
		t.Error("report should contain Low stat card label")
	}
	if !strings.Contains(html, ">Clean<") {
		t.Error("report should contain Clean stat card label")
	}
}

func TestGenerate_WithVerdict(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		Isolation:   IsolationRecommendation{Banner: "yellow"},
		TotalChecks: 9,
		Verdict: &analyzer.Verdict{
			OverallVerdict: analyzer.OverallVerdict{
				Status:         "compromised",
				Confidence:     "high",
				Summary:        "Multiple indicators",
				Recommendation: "Isolate and investigate",
			},
			Timeline: []analyzer.TimelineEvent{
				{Timestamp: "2024-01-01T00:00:00Z", Event: "Initial access", KillChainPhase: "Initial Access"},
			},
			DataGaps: []string{"Missing firewall logs"},
		},
		CollectionDuration: "5s",
		AnalysisDuration:   "10s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	html := string(content)
	if !strings.Contains(html, "Overall Verdict") {
		t.Error("report should contain verdict section")
	}
	if !strings.Contains(html, "Attack Timeline") {
		t.Error("report should contain timeline section")
	}
	if !strings.Contains(html, "Data Gaps") {
		t.Error("report should contain data gaps section")
	}
}

func TestGenerate_RawCheckData_JSONViewer(t *testing.T) {
	rep, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tmpDir := t.TempDir()
	rawJSON := `{"check":"c2_connections","items":[{"ip":"1.2.3.4","port":443}]}`
	data := ReportData{
		Hostname:    "test-host",
		OS:          "windows",
		GeneratedAt: time.Now().UTC(),
		Version:     "test",
		TotalChecks: 1,
		Findings: []analyzer.Finding{
			{
				Check:               "c2_connections",
				IntrusionConfidence: "high",
				RiskLevel:           "high",
				Title:               "Suspicious C2 connection",
				AttackScenario:      "External C2 communication",
			},
		},
		RawCheckData: map[string]string{
			"c2_connections": rawJSON,
		},
		CollectionDuration: "1s",
		AnalysisDuration:   "2s",
	}

	path, err := rep.Generate(data, tmpDir)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	content, _ := os.ReadFile(path)
	html := string(content)

	if !strings.Contains(html, "Raw Evidence") {
		t.Error("report should contain Raw Evidence section")
	}
	if !strings.Contains(html, "rv-c2_connections") {
		t.Error("report should contain json viewer pre element ID")
	}
	if !strings.Contains(html, "1.2.3.4") {
		t.Error("report should contain raw JSON content")
	}
	if !strings.Contains(html, "highlightJson") {
		t.Error("report should contain JSON syntax highlighter function")
	}
	if !strings.Contains(html, "copyJsonViewer") {
		t.Error("report should contain copyJsonViewer function")
	}
}
