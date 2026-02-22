package reporter

import "testing"

func TestAnalyzeEvidenceGaps_NoFailures(t *testing.T) {
	gaps := AnalyzeEvidenceGaps(nil)
	if gaps != nil {
		t.Errorf("expected nil for no failures, got %d gaps", len(gaps))
	}
}

func TestAnalyzeEvidenceGaps_KnownCheck(t *testing.T) {
	failures := []CollectionFailure{
		{CheckID: "c2_connections", CheckName: "C2 Communication", FailureKind: "timeout", Error: "timeout after 30s"},
	}
	gaps := AnalyzeEvidenceGaps(failures)
	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	g := gaps[0]
	if g.CheckID != "c2_connections" {
		t.Errorf("checkID = %q, want c2_connections", g.CheckID)
	}
	if g.ImpactSeverity != "high" {
		t.Errorf("severity = %q, want high", g.ImpactSeverity)
	}
	if g.MissingData == "" {
		t.Error("missing_data should not be empty")
	}
	if g.BlindSpots == "" {
		t.Error("blind_spots should not be empty")
	}
	if g.Impact == "" {
		t.Error("impact should not be empty")
	}
}

func TestAnalyzeEvidenceGaps_UnknownCheck(t *testing.T) {
	failures := []CollectionFailure{
		{CheckID: "custom_check", CheckName: "Custom Check", FailureKind: "script_error", Error: "some error"},
	}
	gaps := AnalyzeEvidenceGaps(failures)
	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].ImpactSeverity != "medium" {
		t.Errorf("unknown check should default to medium severity, got %q", gaps[0].ImpactSeverity)
	}
}

func TestAnalyzeEvidenceGaps_MultipleFailures(t *testing.T) {
	failures := []CollectionFailure{
		{CheckID: "log_tampering", CheckName: "Log Tampering", FailureKind: "permission_denied", Error: "access denied"},
		{CheckID: "persistence", CheckName: "Persistence", FailureKind: "timeout", Error: "timeout"},
		{CheckID: "webshell", CheckName: "Webshell", FailureKind: "not_found", Error: "no web root"},
	}
	gaps := AnalyzeEvidenceGaps(failures)
	if len(gaps) != 3 {
		t.Fatalf("expected 3 gaps, got %d", len(gaps))
	}

	// Verify severities
	expectedSeverities := map[string]string{
		"log_tampering": "high",
		"persistence":   "high",
		"webshell":      "medium",
	}
	for _, g := range gaps {
		expected, ok := expectedSeverities[g.CheckID]
		if !ok {
			t.Errorf("unexpected check ID %q", g.CheckID)
			continue
		}
		if g.ImpactSeverity != expected {
			t.Errorf("%s severity = %q, want %q", g.CheckID, g.ImpactSeverity, expected)
		}
	}
}

func TestAnalyzeEvidenceGaps_CheckNameFallback(t *testing.T) {
	failures := []CollectionFailure{
		{CheckID: "persistence", CheckName: "", FailureKind: "timeout", Error: "timeout"},
	}
	gaps := AnalyzeEvidenceGaps(failures)
	if gaps[0].CheckName != "persistence" {
		t.Errorf("expected CheckName fallback to ID, got %q", gaps[0].CheckName)
	}
}
