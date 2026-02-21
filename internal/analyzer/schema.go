// Package analyzer implements LLM-based forensic analysis of collected IoC data.
package analyzer

// Finding represents the LLM analysis result for a single check.
type Finding struct {
	Check               string         `json:"check"`
	IntrusionConfidence string         `json:"intrusion_confidence"`
	RiskLevel           string         `json:"risk_level"`
	Title               string         `json:"title"`
	AttackScenario      string         `json:"attack_scenario"`
	Evidence            []string       `json:"evidence"`
	IoC                 IoC            `json:"ioc"`
	MITRE               []string       `json:"mitre"`
	ImmediateActions    []string       `json:"immediate_actions"`
	ForensicNextSteps   []string       `json:"forensic_next_steps"`
	ReasoningChain      ReasoningChain `json:"reasoning_chain"`
}

// IoC contains extracted Indicators of Compromise.
type IoC struct {
	IPs          []string `json:"ips"`
	Processes    []string `json:"processes"`
	Ports        []int    `json:"ports"`
	Hashes       []string `json:"hashes"`
	RegistryKeys []string `json:"registry_keys"`
	Domains      []string `json:"domains"`
	UserAccounts []string `json:"user_accounts"`
}

// ReasoningChain enforces Chain-of-Thought analysis.
type ReasoningChain struct {
	Observation string `json:"observation"`
	Baseline    string `json:"baseline"`
	Deviation   string `json:"deviation"`
	Context     string `json:"context"`
	Conclusion  string `json:"conclusion"`
}

// Verdict represents the overall cross-analysis result (Phase 2).
type Verdict struct {
	OverallVerdict OverallVerdict   `json:"overall_verdict"`
	Findings       []VerdictFinding `json:"findings"`
	Timeline       []TimelineEvent  `json:"timeline"`
	IoCList        []IoCEntry       `json:"ioc_list"`
	DataGaps       []string         `json:"data_gaps"`
}

// OverallVerdict is the top-level judgment.
type OverallVerdict struct {
	Status         string `json:"status"`
	Confidence     string `json:"confidence"`
	Recommendation string `json:"recommendation"`
	Summary        string `json:"summary"`
}

// VerdictFinding is a synthesized finding from cross-analysis.
type VerdictFinding struct {
	ID                string   `json:"id"`
	Severity          string   `json:"severity"`
	Title             string   `json:"title"`
	Category          string   `json:"category"`
	MITRETechnique    string   `json:"mitre_technique"`
	Evidence          string   `json:"evidence"`
	Analysis          string   `json:"analysis"`
	Confidence        string   `json:"confidence"`
	RecommendedAction string   `json:"recommended_action"`
	CrossReferences   []string `json:"cross_references"`
}

// TimelineEvent represents a single event in the attack timeline.
type TimelineEvent struct {
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	FindingID      string `json:"finding_id"`
	KillChainPhase string `json:"kill_chain_phase"`
}

// IoCEntry represents a single IoC in the consolidated list.
type IoCEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Context   string `json:"context"`
	FindingID string `json:"finding_id"`
}

// AnalysisResult wraps the complete analysis output.
type AnalysisResult struct {
	Findings    []Finding    `json:"findings"`
	Verdict     *Verdict     `json:"verdict,omitempty"`
	RawFindings []RawFinding `json:"raw_findings,omitempty"`
}

// RawFinding preserves the original LLM response when parsing fails.
type RawFinding struct {
	CheckID    string `json:"check_id"`
	RawOutput  string `json:"raw_output"`
	ParseError string `json:"parse_error"`
}

// ValidConfidenceLevels are the accepted intrusion confidence values.
var ValidConfidenceLevels = map[string]bool{
	"confirmed":     true,
	"high":          true,
	"medium":        true,
	"low":           true,
	"informational": true,
	"clean":         true,
}

// ValidRiskLevels are the accepted risk level values.
var ValidRiskLevels = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"none":     true,
}

// FindingSchema is a JSON Schema for constrained LLM output (Ollama format parameter).
var FindingSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"check":                map[string]interface{}{"type": "string"},
		"intrusion_confidence": map[string]interface{}{"type": "string", "enum": []string{"confirmed", "high", "medium", "low", "informational", "clean"}},
		"risk_level":           map[string]interface{}{"type": "string", "enum": []string{"critical", "high", "medium", "low", "none"}},
		"title":                map[string]interface{}{"type": "string"},
		"attack_scenario":      map[string]interface{}{"type": "string"},
		"evidence":             map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"ioc": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ips":           map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"processes":     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"ports":         map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}},
				"hashes":        map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"registry_keys": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"domains":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"user_accounts": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
			},
		},
		"mitre":               map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"immediate_actions":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"forensic_next_steps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		"reasoning_chain": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"observation": map[string]interface{}{"type": "string"},
				"baseline":    map[string]interface{}{"type": "string"},
				"deviation":   map[string]interface{}{"type": "string"},
				"context":     map[string]interface{}{"type": "string"},
				"conclusion":  map[string]interface{}{"type": "string"},
			},
		},
	},
	"required": []interface{}{"check", "intrusion_confidence", "risk_level", "title"},
}

// VerdictSchema is a JSON Schema for constrained LLM synthesis output.
var VerdictSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"overall_verdict": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"status":         map[string]interface{}{"type": "string"},
				"confidence":     map[string]interface{}{"type": "string"},
				"recommendation": map[string]interface{}{"type": "string"},
				"summary":        map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"status", "confidence", "recommendation", "summary"},
		},
		"findings":  map[string]interface{}{"type": "array"},
		"timeline":  map[string]interface{}{"type": "array"},
		"ioc_list":  map[string]interface{}{"type": "array"},
		"data_gaps": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
	},
	"required": []interface{}{"overall_verdict"},
}
