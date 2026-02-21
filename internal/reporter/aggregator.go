// Package reporter handles report generation from analysis results.
package reporter

import "github.com/iyulab/system-coroner/internal/analyzer"

// IsolationRecommendation represents the quarantine decision.
type IsolationRecommendation struct {
	Isolate bool   `json:"isolate"`
	Urgency string `json:"urgency"` // immediate, urgent, monitor, none
	Reason  string `json:"reason"`
	Banner  string `json:"banner"` // red, yellow, green
}

// Aggregator computes the overall isolation recommendation from findings.
type Aggregator struct{}

// ShouldIsolate determines if the server should be isolated based on findings.
func (a *Aggregator) ShouldIsolate(findings []analyzer.Finding) IsolationRecommendation {
	// Immediate isolation: any confirmed finding
	for _, f := range findings {
		if f.IntrusionConfidence == "confirmed" {
			return IsolationRecommendation{
				Isolate: true,
				Urgency: "immediate",
				Reason:  f.Title,
				Banner:  "red",
			}
		}
	}

	// Urgent isolation: 2+ high confidence findings
	highCount := countByConfidence(findings, "high")
	if highCount >= 2 {
		return IsolationRecommendation{
			Isolate: true,
			Urgency: "urgent",
			Reason:  "Multiple high-confidence intrusion indicators found simultaneously",
			Banner:  "red",
		}
	}

	// Monitor: 1 high finding
	if highCount == 1 {
		return IsolationRecommendation{
			Isolate: false,
			Urgency: "monitor",
			Reason:  "One high-confidence intrusion indicator found — further investigation required",
			Banner:  "yellow",
		}
	}

	// Warning: medium findings
	mediumCount := countByConfidence(findings, "medium")
	if mediumCount > 0 {
		return IsolationRecommendation{
			Isolate: false,
			Urgency: "monitor",
			Reason:  "Suspicious indicators found — monitoring recommended",
			Banner:  "yellow",
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

func countByConfidence(findings []analyzer.Finding, level string) int {
	count := 0
	for _, f := range findings {
		if f.IntrusionConfidence == level {
			count++
		}
	}
	return count
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

// CollectAllIoCs extracts all IoCs from findings into a flat list.
func CollectAllIoCs(findings []analyzer.Finding) []analyzer.IoCEntry {
	var entries []analyzer.IoCEntry
	for _, f := range findings {
		for _, ip := range f.IoC.IPs {
			entries = append(entries, analyzer.IoCEntry{Type: "ip", Value: ip, Context: f.Check, FindingID: f.Check})
		}
		for _, proc := range f.IoC.Processes {
			entries = append(entries, analyzer.IoCEntry{Type: "process", Value: proc, Context: f.Check, FindingID: f.Check})
		}
		for _, domain := range f.IoC.Domains {
			entries = append(entries, analyzer.IoCEntry{Type: "domain", Value: domain, Context: f.Check, FindingID: f.Check})
		}
		for _, hash := range f.IoC.Hashes {
			entries = append(entries, analyzer.IoCEntry{Type: "hash", Value: hash, Context: f.Check, FindingID: f.Check})
		}
		for _, key := range f.IoC.RegistryKeys {
			entries = append(entries, analyzer.IoCEntry{Type: "registry_key", Value: key, Context: f.Check, FindingID: f.Check})
		}
		for _, user := range f.IoC.UserAccounts {
			entries = append(entries, analyzer.IoCEntry{Type: "user_account", Value: user, Context: f.Check, FindingID: f.Check})
		}
	}
	return entries
}
