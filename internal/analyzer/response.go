package analyzer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseFinding parses a Finding from raw LLM JSON output.
// Returns the parsed Finding and any error.
// On parse failure, the raw output is preserved for the report.
func ParseFinding(checkID, rawOutput string) (Finding, error) {
	// Trim any markdown code fences
	cleaned := cleanJSONResponse(rawOutput)

	var finding Finding
	if err := json.Unmarshal([]byte(cleaned), &finding); err != nil {
		return Finding{}, fmt.Errorf("parse finding for %s: %w", checkID, err)
	}

	// Ensure check ID matches
	if finding.Check == "" {
		finding.Check = checkID
	}

	// Validate confidence level
	if finding.IntrusionConfidence != "" {
		finding.IntrusionConfidence = strings.ToLower(finding.IntrusionConfidence)
		if !ValidConfidenceLevels[finding.IntrusionConfidence] {
			finding.IntrusionConfidence = "informational"
		}
	}

	// Validate risk level
	if finding.RiskLevel != "" {
		finding.RiskLevel = strings.ToLower(finding.RiskLevel)
		if !ValidRiskLevels[finding.RiskLevel] {
			finding.RiskLevel = "low"
		}
	}

	// Validate required fields
	if finding.Title == "" {
		finding.Title = "Untitled finding for " + checkID
	}
	if finding.IntrusionConfidence == "" {
		finding.IntrusionConfidence = "informational"
	}
	if finding.RiskLevel == "" {
		finding.RiskLevel = "low"
	}

	return finding, nil
}

// ParseVerdict parses a Verdict from raw LLM JSON output.
func ParseVerdict(rawOutput string) (Verdict, error) {
	cleaned := cleanJSONResponse(rawOutput)

	var verdict Verdict
	if err := json.Unmarshal([]byte(cleaned), &verdict); err != nil {
		return Verdict{}, fmt.Errorf("parse verdict: %w", err)
	}

	return verdict, nil
}

// cleanJSONResponse strips markdown code fences and leading/trailing whitespace.
func cleanJSONResponse(raw string) string {
	s := strings.TrimSpace(raw)

	// Remove ```json ... ``` wrapper
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}

	return strings.TrimSpace(s)
}
