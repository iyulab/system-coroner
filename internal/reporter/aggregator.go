// Package reporter handles report generation from analysis results.
package reporter

import (
	"fmt"
	"strings"

	"github.com/iyulab/system-coroner/internal/analyzer"
)

// IsolationRecommendation represents the quarantine decision.
type IsolationRecommendation struct {
	Isolate              bool   `json:"isolate"`
	Urgency              string `json:"urgency"` // immediate, urgent, investigate, monitor, none
	Reason               string `json:"reason"`
	Banner               string `json:"banner"`                // red, yellow, green
	IncompleteAssessment bool   `json:"incomplete_assessment"` // true when collection gaps degrade confidence
}

// Aggregator computes the overall isolation recommendation from findings.
type Aggregator struct{}

// ShouldIsolate determines if the server should be isolated based on findings
// and collection failures. Collection gaps with high forensic impact escalate
// the urgency because "no findings" may simply mean "no visibility".
func (a *Aggregator) ShouldIsolate(findings []analyzer.Finding, failures []CollectionFailure) IsolationRecommendation {
	// ANA-005: Only intrusion indicators affect isolation decisions.
	// Exposure (hardening gaps) and informational findings are excluded.
	intrusions := filterIntrusionFindings(findings)

	highGaps := countHighImpactGaps(failures)
	gapNames := highImpactGapNames(failures)
	incomplete := highGaps >= 2

	// Immediate isolation: any confirmed finding
	for _, f := range intrusions {
		if f.IntrusionConfidence == "confirmed" {
			return IsolationRecommendation{
				Isolate:              true,
				Urgency:              "immediate",
				Reason:               f.Title,
				Banner:               "red",
				IncompleteAssessment: incomplete,
			}
		}
	}

	// Urgent isolation: 2+ high confidence findings
	highCount := countByConfidence(intrusions, "high")
	if highCount >= 2 {
		return IsolationRecommendation{
			Isolate:              true,
			Urgency:              "urgent",
			Reason:               "Multiple high-confidence intrusion indicators found simultaneously",
			Banner:               "red",
			IncompleteAssessment: incomplete,
		}
	}

	// Monitor: 1 high finding — escalate to investigate if gaps are significant
	if highCount == 1 {
		rec := IsolationRecommendation{
			Isolate:              false,
			Urgency:              "monitor",
			Reason:               "One high-confidence intrusion indicator found — further investigation required",
			Banner:               "yellow",
			IncompleteAssessment: incomplete,
		}
		if highGaps >= 2 {
			rec.Urgency = "investigate"
			rec.Reason = fmt.Sprintf("High-confidence intrusion indicator found AND %d HIGH-impact checks failed (%s). Assessment may be incomplete.", highGaps, gapNames)
		}
		return rec
	}

	// Warning: medium findings — escalate to investigate if gaps are significant
	mediumCount := countByConfidence(intrusions, "medium")
	if mediumCount > 0 {
		rec := IsolationRecommendation{
			Isolate:              false,
			Urgency:              "monitor",
			Reason:               "Suspicious indicators found — monitoring recommended",
			Banner:               "yellow",
			IncompleteAssessment: incomplete,
		}
		if highGaps >= 2 {
			rec.Urgency = "investigate"
			rec.Reason = fmt.Sprintf("Suspicious indicators found AND %d HIGH-impact checks failed (%s). Assessment may be incomplete.", highGaps, gapNames)
		}
		return rec
	}

	// Evidence gap escalation: high-impact collection failures degrade confidence
	// in a "clean" assessment. Use gap_analysis severity mapping.
	if highGaps >= 3 {
		return IsolationRecommendation{
			Isolate:              false,
			Urgency:              "investigate",
			Reason:               fmt.Sprintf("Incomplete assessment — %d critical evidence gaps (%s). Clean verdict is unreliable.", highGaps, gapNames),
			Banner:               "yellow",
			IncompleteAssessment: true,
		}
	}
	if highGaps >= 2 {
		return IsolationRecommendation{
			Isolate:              false,
			Urgency:              "monitor",
			Reason:               fmt.Sprintf("Incomplete assessment — %d high-impact evidence gaps (%s) reduce confidence.", highGaps, gapNames),
			Banner:               "yellow",
			IncompleteAssessment: true,
		}
	}

	// Clean
	return IsolationRecommendation{
		Isolate: false,
		Urgency: "none",
		Reason:  "No intrusion evidence found",
		Banner:  "green",
	}
}

// countHighImpactGaps counts collection failures with high forensic impact severity.
func countHighImpactGaps(failures []CollectionFailure) int {
	count := 0
	for _, f := range failures {
		desc, ok := checkGapDescriptions[f.CheckID]
		if ok && desc.severity == "high" {
			count++
		}
	}
	return count
}

// highImpactGapNames returns a comma-separated list of high-severity failed check IDs.
func highImpactGapNames(failures []CollectionFailure) string {
	var names []string
	for _, f := range failures {
		desc, ok := checkGapDescriptions[f.CheckID]
		if ok && desc.severity == "high" {
			names = append(names, f.CheckID)
		}
	}
	return strings.Join(names, ", ")
}

func countByConfidence(findings []analyzer.Finding, level string) int {
	count := 0
	for _, f := range findings {
		if f.IntrusionConfidence == level {
			count++
		}
	}
	return count
}

// filterIntrusionFindings returns only findings with finding_type "intrusion_indicator" (or empty/default).
// Exposure and informational findings are excluded from isolation and confidence decisions.
func filterIntrusionFindings(findings []analyzer.Finding) []analyzer.Finding {
	result := make([]analyzer.Finding, 0, len(findings))
	for _, f := range findings {
		ft := f.NormalizedFindingType()
		if ft == "intrusion_indicator" {
			result = append(result, f)
		}
	}
	return result
}

// FilterIntrusionFindings returns only findings with finding_type "intrusion_indicator" (or empty/default).
// Used to populate the main Findings section of the report.
func FilterIntrusionFindings(findings []analyzer.Finding) []analyzer.Finding {
	return filterIntrusionFindings(findings)
}

// FilterExposureFindings returns only findings with finding_type "exposure".
// Used to build the Hardening Recommendations section of the report.
func FilterExposureFindings(findings []analyzer.Finding) []analyzer.Finding {
	result := make([]analyzer.Finding, 0)
	for _, f := range findings {
		if f.FindingType == "exposure" {
			result = append(result, f)
		}
	}
	return result
}

// ConfidenceSummary aggregates confidence levels for display.
type ConfidenceSummary struct {
	Confirmed     int `json:"confirmed"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Clean         int `json:"clean"`
}

// SummarizeConfidence counts findings by confidence level.
func SummarizeConfidence(findings []analyzer.Finding) ConfidenceSummary {
	var s ConfidenceSummary
	for _, f := range findings {
		switch f.IntrusionConfidence {
		case "confirmed":
			s.Confirmed++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		case "informational":
			s.Informational++
		case "clean":
			s.Clean++
		}
	}
	return s
}

// iocStatusForConfidence maps intrusion confidence to IoC status.
// Returns ("", false) for benign findings whose IoCs should be excluded.
func iocStatusForConfidence(confidence string) (string, bool) {
	switch confidence {
	case "clean", "informational":
		return "", false // exclude from IoC table
	case "low":
		return "low_confidence", true
	default: // medium, high, confirmed
		return "active", true
	}
}

// CollectAllIoCs extracts IoCs from findings, filtering out benign ones (IOC-001).
// Findings with clean/informational confidence are excluded entirely.
// Low-confidence findings produce IoCs with Status "low_confidence".
// When the same value appears in both a benign and suspicious finding, the suspicious one wins.
func CollectAllIoCs(findings []analyzer.Finding) []analyzer.IoCEntry {
	// First pass: collect all IoC entries with their status
	type iocKey struct {
		typ   string
		value string
	}
	best := make(map[iocKey]analyzer.IoCEntry)

	for _, f := range findings {
		status, include := iocStatusForConfidence(f.IntrusionConfidence)
		if !include {
			continue
		}

		// Collect all IoC values from this finding
		var items []analyzer.IoCEntry
		for _, ip := range f.IoC.IPs {
			items = append(items, analyzer.IoCEntry{Type: "ip", Value: ip, Context: f.Check, FindingID: f.Check, Status: status})
		}
		for _, proc := range f.IoC.Processes {
			items = append(items, analyzer.IoCEntry{Type: "process", Value: proc, Context: f.Check, FindingID: f.Check, Status: status})
		}
		for _, domain := range f.IoC.Domains {
			items = append(items, analyzer.IoCEntry{Type: "domain", Value: domain, Context: f.Check, FindingID: f.Check, Status: status})
		}
		for _, hash := range f.IoC.Hashes {
			items = append(items, analyzer.IoCEntry{Type: "hash", Value: hash, Context: f.Check, FindingID: f.Check, Status: status})
		}
		for _, key := range f.IoC.RegistryKeys {
			items = append(items, analyzer.IoCEntry{Type: "registry_key", Value: key, Context: f.Check, FindingID: f.Check, Status: status})
		}
		for _, user := range f.IoC.UserAccounts {
			items = append(items, analyzer.IoCEntry{Type: "user_account", Value: user, Context: f.Check, FindingID: f.Check, Status: status})
		}

		// Dedup: suspicious status wins over low_confidence
		for _, entry := range items {
			key := iocKey{typ: entry.Type, value: entry.Value}
			if existing, ok := best[key]; ok {
				if existing.Status == "active" {
					continue // already at highest priority
				}
			}
			best[key] = entry
		}
	}

	entries := make([]analyzer.IoCEntry, 0, len(best))
	for _, entry := range best {
		entries = append(entries, entry)
	}
	return entries
}
