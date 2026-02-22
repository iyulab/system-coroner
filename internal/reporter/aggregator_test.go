package reporter

import (
	"testing"

	"github.com/iyulab/system-coroner/internal/analyzer"
)

func TestShouldIsolate_Confirmed(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "test", IntrusionConfidence: "confirmed", Title: "Confirmed intrusion"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if !result.Isolate {
		t.Error("expected Isolate=true for confirmed finding")
	}
	if result.Urgency != "immediate" {
		t.Errorf("expected urgency=immediate, got %s", result.Urgency)
	}
	if result.Banner != "red" {
		t.Errorf("expected banner=red, got %s", result.Banner)
	}
}

func TestShouldIsolate_TwoHigh(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "high"},
		{Check: "b", IntrusionConfidence: "high"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if !result.Isolate {
		t.Error("expected Isolate=true for 2+ high findings")
	}
	if result.Urgency != "urgent" {
		t.Errorf("expected urgency=urgent, got %s", result.Urgency)
	}
}

func TestShouldIsolate_OneHigh(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "high"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if result.Isolate {
		t.Error("expected Isolate=false for single high finding")
	}
	if result.Urgency != "monitor" {
		t.Errorf("expected urgency=monitor, got %s", result.Urgency)
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
}

func TestShouldIsolate_MediumOnly(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "medium"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if result.Isolate {
		t.Error("expected Isolate=false for medium finding")
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
}

func TestShouldIsolate_Clean(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{}
	result := agg.ShouldIsolate(findings, nil)
	if result.Isolate {
		t.Error("expected Isolate=false for no findings")
	}
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green, got %s", result.Banner)
	}
}

func TestSummarizeConfidence(t *testing.T) {
	findings := []analyzer.Finding{
		{IntrusionConfidence: "confirmed"},
		{IntrusionConfidence: "high"},
		{IntrusionConfidence: "high"},
		{IntrusionConfidence: "medium"},
		{IntrusionConfidence: "low"},
		{IntrusionConfidence: "informational"},
		{IntrusionConfidence: "clean"},
	}
	s := SummarizeConfidence(findings)
	if s.Confirmed != 1 {
		t.Errorf("expected Confirmed=1, got %d", s.Confirmed)
	}
	if s.High != 2 {
		t.Errorf("expected High=2, got %d", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("expected Medium=1, got %d", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("expected Low=1, got %d", s.Low)
	}
	if s.Informational != 1 {
		t.Errorf("expected Informational=1, got %d", s.Informational)
	}
	if s.Clean != 1 {
		t.Errorf("expected Clean=1, got %d", s.Clean)
	}
}

func TestCollectAllIoCs(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check:               "c2",
			IntrusionConfidence: "high",
			IoC: analyzer.IoC{
				IPs:     []string{"1.2.3.4"},
				Domains: []string{"evil.com"},
				Hashes:  []string{"abc123"},
			},
		},
		{
			Check:               "persist",
			IntrusionConfidence: "medium",
			IoC: analyzer.IoC{
				Processes:    []string{"malware.exe"},
				RegistryKeys: []string{"HKLM\\Run\\bad"},
				UserAccounts: []string{"hacker"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 6 {
		t.Errorf("expected 6 IoCs, got %d", len(iocs))
	}

	typeCount := make(map[string]int)
	for _, ioc := range iocs {
		typeCount[ioc.Type]++
		if ioc.Status != "active" {
			t.Errorf("expected status=active for high/medium finding, got %s", ioc.Status)
		}
	}
	expected := map[string]int{
		"ip": 1, "domain": 1, "hash": 1,
		"process": 1, "registry_key": 1, "user_account": 1,
	}
	for typ, count := range expected {
		if typeCount[typ] != count {
			t.Errorf("expected %d %s IoCs, got %d", count, typ, typeCount[typ])
		}
	}
}

func TestCollectAllIoCs_Empty(t *testing.T) {
	iocs := CollectAllIoCs(nil)
	if len(iocs) != 0 {
		t.Errorf("expected 0 IoCs for nil findings, got %d", len(iocs))
	}
}

// --- IOC-001: Benign IoC filtering tests ---

func TestCollectAllIoCs_CleanFindingExcluded(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check:               "c2_connections",
			IntrusionConfidence: "clean",
			IoC: analyzer.IoC{
				IPs:     []string{"13.107.5.10"},
				Domains: []string{"wdcp.microsoft.com"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 0 {
		t.Errorf("expected 0 IoCs from clean finding, got %d", len(iocs))
	}
}

func TestCollectAllIoCs_InformationalExcluded(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check:               "staging_exfiltration",
			IntrusionConfidence: "informational",
			IoC: analyzer.IoC{
				Processes: []string{"MsMpEng.exe"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 0 {
		t.Errorf("expected 0 IoCs from informational finding, got %d", len(iocs))
	}
}

func TestCollectAllIoCs_LowConfidenceMarked(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check:               "lateral_movement",
			IntrusionConfidence: "low",
			IoC: analyzer.IoC{
				IPs: []string{"192.168.1.100"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IoC from low finding, got %d", len(iocs))
	}
	if iocs[0].Status != "low_confidence" {
		t.Errorf("expected status=low_confidence, got %s", iocs[0].Status)
	}
}

func TestCollectAllIoCs_MediumPlusActive(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check:               "c2",
			IntrusionConfidence: "confirmed",
			IoC: analyzer.IoC{
				IPs: []string{"185.220.101.42"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IoC, got %d", len(iocs))
	}
	if iocs[0].Status != "active" {
		t.Errorf("expected status=active for confirmed, got %s", iocs[0].Status)
	}
}

func TestCollectAllIoCs_SameIPSuspiciousWins(t *testing.T) {
	// Same IP from both clean and suspicious findings — suspicious wins
	findings := []analyzer.Finding{
		{
			Check:               "c2_connections",
			IntrusionConfidence: "clean",
			IoC: analyzer.IoC{
				IPs: []string{"8.8.8.8"},
			},
		},
		{
			Check:               "lateral_movement",
			IntrusionConfidence: "high",
			IoC: analyzer.IoC{
				IPs: []string{"8.8.8.8"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 1 {
		t.Fatalf("expected 1 deduplicated IoC, got %d", len(iocs))
	}
	if iocs[0].Status != "active" {
		t.Errorf("suspicious finding should win: expected status=active, got %s", iocs[0].Status)
	}
	if iocs[0].Context != "lateral_movement" {
		t.Errorf("expected context=lateral_movement, got %s", iocs[0].Context)
	}
}

func TestCollectAllIoCs_LowVsHighSameIP(t *testing.T) {
	// Same IP from low and high findings — high (active) should win
	findings := []analyzer.Finding{
		{
			Check:               "c2",
			IntrusionConfidence: "low",
			IoC: analyzer.IoC{
				IPs: []string{"5.5.5.5"},
			},
		},
		{
			Check:               "persist",
			IntrusionConfidence: "high",
			IoC: analyzer.IoC{
				IPs: []string{"5.5.5.5"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 1 {
		t.Fatalf("expected 1 deduplicated IoC, got %d", len(iocs))
	}
	if iocs[0].Status != "active" {
		t.Errorf("high confidence should win: expected active, got %s", iocs[0].Status)
	}
}

// --- AGG-001: Evidence gap escalation tests ---

func TestShouldIsolate_HighGapsEscalate_ThreeHighGaps(t *testing.T) {
	agg := &Aggregator{}
	// 3 high-impact failures, no findings → escalate to "investigate"
	failures := []CollectionFailure{
		{CheckID: "c2_connections", FailureKind: "timeout"},
		{CheckID: "persistence", FailureKind: "permission_denied"},
		{CheckID: "log_tampering", FailureKind: "script_error"},
	}
	result := agg.ShouldIsolate(nil, failures)
	if result.Urgency != "investigate" {
		t.Errorf("expected urgency=investigate for 3 high gaps, got %s", result.Urgency)
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow for 3 high gaps, got %s", result.Banner)
	}
	if result.Isolate {
		t.Error("gaps alone should not trigger isolation")
	}
	if !result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=true for 3 high gaps")
	}
}

func TestShouldIsolate_TwoHighGaps_NoFindings(t *testing.T) {
	agg := &Aggregator{}
	failures := []CollectionFailure{
		{CheckID: "account_compromise", FailureKind: "timeout"},
		{CheckID: "credential_dump", FailureKind: "permission_denied"},
	}
	result := agg.ShouldIsolate(nil, failures)
	if result.Urgency != "monitor" {
		t.Errorf("expected urgency=monitor for 2 high gaps, got %s", result.Urgency)
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
	if !result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=true for 2 high gaps")
	}
}

func TestShouldIsolate_OneHighGap_StaysClean(t *testing.T) {
	agg := &Aggregator{}
	failures := []CollectionFailure{
		{CheckID: "c2_connections", FailureKind: "timeout"},
	}
	result := agg.ShouldIsolate(nil, failures)
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none for 1 high gap, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green for 1 high gap, got %s", result.Banner)
	}
	if result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=false for 1 high gap")
	}
}

func TestShouldIsolate_MediumGapsOnly_StaysClean(t *testing.T) {
	agg := &Aggregator{}
	// medium-severity gaps should not trigger escalation
	failures := []CollectionFailure{
		{CheckID: "lolbin_abuse", FailureKind: "timeout"},
		{CheckID: "webshell", FailureKind: "script_error"},
		{CheckID: "discovery_recon", FailureKind: "permission_denied"},
	}
	result := agg.ShouldIsolate(nil, failures)
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none for medium-only gaps, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green for medium-only gaps, got %s", result.Banner)
	}
	if result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=false for medium-only gaps")
	}
}

func TestShouldIsolate_MixedGapsAndFindings_ConfirmedPriority(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "test", IntrusionConfidence: "confirmed", Title: "Active backdoor"},
	}
	failures := []CollectionFailure{
		{CheckID: "c2_connections", FailureKind: "timeout"},
		{CheckID: "persistence", FailureKind: "timeout"},
		{CheckID: "log_tampering", FailureKind: "timeout"},
	}
	result := agg.ShouldIsolate(findings, failures)
	// Confirmed finding should still take priority
	if result.Urgency != "immediate" {
		t.Errorf("confirmed finding should override gaps: expected urgency=immediate, got %s", result.Urgency)
	}
	if !result.Isolate {
		t.Error("confirmed finding should still trigger isolation")
	}
	if !result.IncompleteAssessment {
		t.Error("IncompleteAssessment should still be true even with confirmed finding")
	}
}

func TestShouldIsolate_MonitorEscalatesToInvestigate(t *testing.T) {
	agg := &Aggregator{}
	// 1 high finding (would be "monitor") + 2 high gaps → escalate to "investigate"
	findings := []analyzer.Finding{
		{Check: "c2", IntrusionConfidence: "high"},
	}
	failures := []CollectionFailure{
		{CheckID: "account_compromise", FailureKind: "timeout"},
		{CheckID: "fileless_attack", FailureKind: "script_error"},
	}
	result := agg.ShouldIsolate(findings, failures)
	if result.Urgency != "investigate" {
		t.Errorf("expected urgency=investigate for monitor+high gaps, got %s", result.Urgency)
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
	if !result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=true")
	}
}

func TestShouldIsolate_MediumFindingsEscalatesToInvestigate(t *testing.T) {
	agg := &Aggregator{}
	// medium findings (would be "monitor") + 3 high gaps → escalate to "investigate"
	findings := []analyzer.Finding{
		{Check: "persist", IntrusionConfidence: "medium"},
	}
	failures := []CollectionFailure{
		{CheckID: "c2_connections", FailureKind: "timeout"},
		{CheckID: "log_tampering", FailureKind: "timeout"},
		{CheckID: "credential_dump", FailureKind: "timeout"},
	}
	result := agg.ShouldIsolate(findings, failures)
	if result.Urgency != "investigate" {
		t.Errorf("expected urgency=investigate for medium+high gaps, got %s", result.Urgency)
	}
	if !result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=true")
	}
}

func TestShouldIsolate_NoGaps_NoChange(t *testing.T) {
	agg := &Aggregator{}
	// No findings, no failures → clean
	result := agg.ShouldIsolate(nil, nil)
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green, got %s", result.Banner)
	}
	if result.IncompleteAssessment {
		t.Error("expected IncompleteAssessment=false for clean verdict")
	}
}

// --- ANA-005: Finding type isolation and filtering tests ---

func TestDetermineIsolation_ExposureExcluded(t *testing.T) {
	agg := &Aggregator{}
	// Exposure findings should NOT trigger isolation, even with high confidence
	findings := []analyzer.Finding{
		{Check: "credential_dump", FindingType: "exposure", IntrusionConfidence: "confirmed", Title: "LSASS PPL disabled"},
		{Check: "credential_dump2", FindingType: "exposure", IntrusionConfidence: "high", Title: "WDigest enabled"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if result.Isolate {
		t.Error("exposure findings should NOT trigger isolation")
	}
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none for exposure-only findings, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green for exposure-only findings, got %s", result.Banner)
	}
}

func TestDetermineIsolation_IntrusionIndicatorCounts(t *testing.T) {
	agg := &Aggregator{}
	// Mix of intrusion_indicator and exposure: only intrusion should count
	findings := []analyzer.Finding{
		{Check: "c2", FindingType: "intrusion_indicator", IntrusionConfidence: "high", Title: "Active C2"},
		{Check: "cred", FindingType: "exposure", IntrusionConfidence: "high", Title: "PPL disabled"},
		{Check: "persist", FindingType: "intrusion_indicator", IntrusionConfidence: "high", Title: "Backdoor"},
	}
	result := agg.ShouldIsolate(findings, nil)
	// 2 intrusion_indicator with high → should trigger urgent isolation
	if !result.Isolate {
		t.Error("2 high intrusion indicators should trigger isolation")
	}
	if result.Urgency != "urgent" {
		t.Errorf("expected urgency=urgent, got %s", result.Urgency)
	}
}

func TestDetermineIsolation_EmptyFindingTypeDefaultsToIntrusion(t *testing.T) {
	agg := &Aggregator{}
	// Empty FindingType should be treated as intrusion_indicator (backward compat)
	findings := []analyzer.Finding{
		{Check: "c2", FindingType: "", IntrusionConfidence: "confirmed", Title: "C2 confirmed"},
	}
	result := agg.ShouldIsolate(findings, nil)
	if !result.Isolate {
		t.Error("empty finding_type should default to intrusion_indicator and trigger isolation")
	}
	if result.Urgency != "immediate" {
		t.Errorf("expected urgency=immediate, got %s", result.Urgency)
	}
}

func TestFilterIntrusionFindings(t *testing.T) {
	findings := []analyzer.Finding{
		{Check: "c2", FindingType: "intrusion_indicator"},
		{Check: "cred", FindingType: "exposure"},
		{Check: "old", FindingType: ""}, // defaults to intrusion_indicator
		{Check: "info", FindingType: "informational"},
	}
	result := FilterIntrusionFindings(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 intrusion findings, got %d", len(result))
	}
	if result[0].Check != "c2" {
		t.Errorf("first finding should be c2, got %s", result[0].Check)
	}
	if result[1].Check != "old" {
		t.Errorf("second finding should be old (empty=default), got %s", result[1].Check)
	}
}

func TestFilterExposureFindings(t *testing.T) {
	findings := []analyzer.Finding{
		{Check: "c2", FindingType: "intrusion_indicator"},
		{Check: "cred", FindingType: "exposure"},
		{Check: "wdigest", FindingType: "exposure"},
		{Check: "info", FindingType: "informational"},
	}
	result := FilterExposureFindings(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 exposure findings, got %d", len(result))
	}
	if result[0].Check != "cred" {
		t.Errorf("first exposure should be cred, got %s", result[0].Check)
	}
	if result[1].Check != "wdigest" {
		t.Errorf("second exposure should be wdigest, got %s", result[1].Check)
	}
}

func TestSummarizeConfidence_OnlyCountsIntrusionByDefault(t *testing.T) {
	// SummarizeConfidence counts ALL findings regardless of type
	// (it is the caller's responsibility to filter before calling)
	findings := []analyzer.Finding{
		{IntrusionConfidence: "high", FindingType: "intrusion_indicator"},
		{IntrusionConfidence: "high", FindingType: "exposure"},
		{IntrusionConfidence: "low", FindingType: "informational"},
	}
	s := SummarizeConfidence(findings)
	// All findings counted
	if s.High != 2 {
		t.Errorf("expected High=2, got %d", s.High)
	}
	if s.Low != 1 {
		t.Errorf("expected Low=1, got %d", s.Low)
	}
}

func TestCountHighImpactGaps(t *testing.T) {
	cases := []struct {
		name     string
		failures []CollectionFailure
		want     int
	}{
		{"nil", nil, 0},
		{"empty", []CollectionFailure{}, 0},
		{"one high", []CollectionFailure{{CheckID: "c2_connections"}}, 1},
		{"mixed", []CollectionFailure{
			{CheckID: "c2_connections"}, // high
			{CheckID: "lolbin_abuse"},   // medium
			{CheckID: "persistence"},    // high
			{CheckID: "webshell"},       // medium
			{CheckID: "log_tampering"},  // high
		}, 3},
		{"unknown check", []CollectionFailure{{CheckID: "custom_check"}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := countHighImpactGaps(tc.failures)
			if got != tc.want {
				t.Errorf("countHighImpactGaps() = %d, want %d", got, tc.want)
			}
		})
	}
}
