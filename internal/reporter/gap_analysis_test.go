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

// --- GAP-001: Combined gap analysis tests ---

func TestCombinedGaps_AccountAndFileless(t *testing.T) {
	gaps := DescribeCombinedGaps([]string{"account_compromise", "fileless_attack"})
	if len(gaps) == 0 {
		t.Fatal("expected at least 1 combined gap for account_compromise + fileless_attack")
	}
	found := false
	for _, g := range gaps {
		if g.Scenario == "Fileless initial access via compromised credentials" {
			found = true
			if g.KillChainGap == "" {
				t.Error("kill chain gap should not be empty")
			}
			if g.CombinedImpact == "" {
				t.Error("combined impact should not be empty")
			}
			if len(g.CheckIDs) != 2 {
				t.Errorf("expected 2 check IDs, got %d", len(g.CheckIDs))
			}
		}
	}
	if !found {
		t.Error("expected specific combined gap scenario")
	}
}

func TestCombinedGaps_SingleFailure(t *testing.T) {
	gaps := DescribeCombinedGaps([]string{"c2_connections"})
	if len(gaps) != 0 {
		t.Errorf("single failure should produce no combined gaps, got %d", len(gaps))
	}
}

func TestCombinedGaps_NoFailures(t *testing.T) {
	gaps := DescribeCombinedGaps(nil)
	if len(gaps) != 0 {
		t.Errorf("no failures should produce no combined gaps, got %d", len(gaps))
	}
}

func TestCombinedGaps_AllFailed(t *testing.T) {
	// Simulate worst case: many checks failed
	all := []string{
		"account_compromise", "fileless_attack", "process_execution",
		"credential_dump", "c2_connections", "lateral_movement",
		"persistence", "log_tampering", "staging_exfiltration",
	}
	gaps := DescribeCombinedGaps(all)
	if len(gaps) == 0 {
		t.Fatal("expected multiple combined gaps for worst-case scenario")
	}
	// Should match all 8 defined combinations
	if len(gaps) != 8 {
		t.Errorf("expected 8 combined gaps for all-failed scenario, got %d", len(gaps))
	}
}

func TestCombinedGaps_NonMatchingChecks(t *testing.T) {
	// Checks that don't form any known combination
	gaps := DescribeCombinedGaps([]string{"webshell", "discovery_recon"})
	if len(gaps) != 0 {
		t.Errorf("unrelated checks should produce no combined gaps, got %d", len(gaps))
	}
}

func TestCombinedGaps_ThreeCheckCombo(t *testing.T) {
	gaps := DescribeCombinedGaps([]string{"fileless_attack", "process_execution", "credential_dump"})
	found := false
	for _, g := range gaps {
		if len(g.CheckIDs) == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 3-check combination gap")
	}
}
