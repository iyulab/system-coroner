package sigma

// SigmaMatch records a Sigma rule hit against a collected check result.
type SigmaMatch struct {
	CheckID   string                 `json:"check_id"`
	RuleTitle string                 `json:"rule_title"`
	RuleID    string                 `json:"rule_id,omitempty"`
	Level     string                 `json:"level"` // informational | low | medium | high | critical
	Event     map[string]interface{} `json:"event"` // matched event item for evidence
}
