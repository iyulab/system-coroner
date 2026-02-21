package analyzer

import (
	"strings"
)

// FilterResult classifies a single collected item's risk level for routing decisions.
type FilterResult int

const (
	// FilterSafe indicates the item is known-good and should be excluded from LLM analysis.
	FilterSafe FilterResult = iota
	// FilterUncertain indicates the item requires LLM context judgment.
	FilterUncertain
	// FilterSuspicious indicates the item matched a rule violation; LLM receives the item
	// with an explanation note for confirmation or refutation.
	FilterSuspicious
)

// ScoredItem is a single collected artifact with its rule-based risk score and classification.
type ScoredItem struct {
	// Raw holds the original JSON object for the item.
	Raw map[string]interface{}
	// Result is the rule classification.
	Result FilterResult
	// Score is the rule-based risk contribution (0–100).
	// SAFE items contribute 0; SUSPICIOUS items contribute 40–100 based on rule severity.
	Score int
	// Reason is the human-readable rule violation description, included in the LLM prompt
	// when Result == FilterSuspicious.
	Reason string
}

// CheckRuleScore aggregates rule-based scoring results for one check.
type CheckRuleScore struct {
	CheckID         string
	Score           int // 0–100 normalized
	SuspiciousCount int
	UncertainCount  int
	Items           []ScoredItem
}

// FilterRule is the interface for a single rule that evaluates one collected item.
type FilterRule interface {
	// Name returns a short identifier used in Reason strings.
	Name() string
	// Apply evaluates the item and returns (classification, score, reason).
	// Score is ignored when classification is FilterSafe.
	Apply(item map[string]interface{}) (FilterResult, int, string)
}

// ApplyRules evaluates all rules against all items and returns a CheckRuleScore.
// Items where at least one rule fires SUSPICIOUS take the highest score found.
// Items where no rule fires default to FilterUncertain with score 20.
func ApplyRules(checkID string, items []map[string]interface{}, rules []FilterRule) CheckRuleScore {
	scored := make([]ScoredItem, 0, len(items))

	for _, item := range items {
		bestResult := FilterUncertain
		bestScore := 20 // default uncertain score
		var reasons []string

		for _, rule := range rules {
			result, score, reason := rule.Apply(item)
			switch result {
			case FilterSafe:
				bestResult = FilterSafe
				bestScore = 0
				reasons = nil
				goto nextItem
			case FilterSuspicious:
				if result > bestResult || (result == bestResult && score > bestScore) {
					bestResult = result
					if score > bestScore {
						bestScore = score
					}
				}
				if reason != "" {
					reasons = append(reasons, "["+rule.Name()+"] "+reason)
				}
			}
		}

	nextItem:
		si := ScoredItem{
			Raw:    item,
			Result: bestResult,
			Score:  bestScore,
		}
		if len(reasons) > 0 {
			si.Reason = strings.Join(reasons, "; ")
		}
		scored = append(scored, si)
	}

	return buildCheckRuleScore(checkID, scored)
}

// buildCheckRuleScore computes the normalized 0–100 check score from scored items.
func buildCheckRuleScore(checkID string, items []ScoredItem) CheckRuleScore {
	crs := CheckRuleScore{CheckID: checkID, Items: items}

	var suspiciousSum int
	for _, si := range items {
		switch si.Result {
		case FilterSuspicious:
			crs.SuspiciousCount++
			suspiciousSum += si.Score
		case FilterUncertain:
			crs.UncertainCount++
		}
	}

	// Normalize: sum of suspicious scores divided by (total_items * 0.1), capped at 100.
	total := len(items)
	if total == 0 || crs.SuspiciousCount == 0 {
		return crs
	}
	normalizer := float64(total) * 0.1
	if normalizer < 1 {
		normalizer = 1
	}
	score := float64(suspiciousSum) / normalizer
	if score > 100 {
		score = 100
	}
	crs.Score = int(score)
	return crs
}

// SuspiciousAndUncertainItems returns items that should be forwarded to the LLM
// (all non-SAFE items), annotating SUSPICIOUS items with their rule reason.
func SuspiciousAndUncertainItems(crs CheckRuleScore) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(crs.Items))
	for _, si := range crs.Items {
		if si.Result == FilterSafe {
			continue
		}
		item := copyMap(si.Raw)
		if si.Result == FilterSuspicious && si.Reason != "" {
			item["rule_flags"] = si.Reason
			item["rule_score"] = si.Score
		}
		out = append(out, item)
	}
	return out
}

// copyMap performs a shallow copy of a string-keyed map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ============================================================
// Built-in rules
// ============================================================

// --- persistence rules ---

// UnsignedTempRunKeyRule flags Run key entries where the executable is unsigned AND
// lives in a temp/staging path — a strong indicator of a dropper establishing persistence.
type UnsignedTempRunKeyRule struct{}

func (r UnsignedTempRunKeyRule) Name() string { return "UnsignedTempRunKey" }
func (r UnsignedTempRunKeyRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	value := strings.ToLower(stringVal(item, "value", "path"))
	if !containsAny(value, `\temp\`, `\appdata\local\temp\`) {
		return FilterUncertain, 20, ""
	}
	sig := getNestedString(item, "signature", "status")
	if sig == "notsigned" || sig == "hashmismatch" || sig == "unknownerror" {
		return FilterSuspicious, 95, "unsigned executable in temp path registered as Run key: " + value
	}
	// Temp path alone (signature unavailable or file gone) is still suspicious
	return FilterSuspicious, 80, "Run key executable in temp/staging directory: " + value
}

// UnsignedRunKeyRule flags Run key entries whose binaries have an invalid or missing
// Authenticode signature outside of known system directories.
type UnsignedRunKeyRule struct{}

func (r UnsignedRunKeyRule) Name() string { return "UnsignedRunKey" }
func (r UnsignedRunKeyRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	sig := getNestedString(item, "signature", "status")
	// Skip if no signature data or signature is valid
	if sig == "" || sig == "valid" || sig == "pathnotresolved" || sig == "filenotfound" {
		return FilterUncertain, 20, ""
	}
	value := strings.ToLower(stringVal(item, "value", "path"))
	// System binaries may legitimately lack signatures in some edge cases
	if strings.HasPrefix(value, `c:\windows\system32\`) || strings.HasPrefix(value, `c:\windows\syswow64\`) {
		return FilterUncertain, 20, ""
	}
	return FilterSuspicious, 80, "Run key executable with invalid/missing signature ("+sig+"): "+value
}

// --- process_execution rules ---

// TempPathExecRule flags executables running from staging directories.
type TempPathExecRule struct{}

func (r TempPathExecRule) Name() string { return "TempPathExec" }
func (r TempPathExecRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	path := stringVal(item, "process_path", "path", "file_path")
	if path == "" {
		return FilterUncertain, 20, ""
	}
	lower := strings.ToLower(path)
	if containsAny(lower, `\temp\`, `\tmp\`, `\users\public\`, `\perflogs\`, `\programdata\temp`) {
		return FilterSuspicious, 80, "executable in staging directory: " + path
	}
	return FilterUncertain, 20, ""
}

// KnownAttackToolRule flags items whose name matches known attacker tools.
type KnownAttackToolRule struct{}

var knownAttackTools = []string{
	"mimikatz", "procdump", "psexec", "meterpreter", "cobalt",
	"bloodhound", "sharphound", "rubeus", "kerberoast", "secretsdump",
	"powercat", "lazagne", "hashdump", "wce", "fgdump", "pwdump",
	"gsecdump", "nmap", "masscan", "shellcode",
}

func (r KnownAttackToolRule) Name() string { return "KnownAttackTool" }
func (r KnownAttackToolRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	name := strings.ToLower(stringVal(item, "name", "exe_name", "process_name", "file_name"))
	for _, tool := range knownAttackTools {
		if strings.Contains(name, tool) {
			return FilterSuspicious, 100, "known attack tool name: " + name
		}
	}
	// attack_tool field set by the script
	if v, ok := item["attack_tool"]; ok {
		if b, ok := v.(bool); ok && b {
			return FilterSuspicious, 95, "attack_tool flag set by collection script"
		}
	}
	return FilterUncertain, 20, ""
}

// --- file_access rules ---

// SensitiveFileLNKRule flags LNK targets pointing to credential/key files.
type SensitiveFileLNKRule struct{}

var sensitivePathKeywords = []string{
	`\sam`, `\ntds.dit`, `\security`, `.pfx`, `.pem`, `.key`, `.p12`,
	"id_rsa", ".kdb", ".kdbx", ".rdp", `\backup\`, "shadow",
	"passwords", "credential", "logins.json", "login data",
}

func (r SensitiveFileLNKRule) Name() string { return "SensitiveFileLNK" }
func (r SensitiveFileLNKRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	target := strings.ToLower(stringVal(item, "target_path", "path", "file_path"))
	if target == "" {
		return FilterUncertain, 20, ""
	}
	// Safe: Windows/Program Files paths
	if strings.HasPrefix(target, `c:\windows\`) || strings.HasPrefix(target, `c:\program files`) {
		return FilterSafe, 0, ""
	}
	for _, kw := range sensitivePathKeywords {
		if strings.Contains(target, kw) {
			return FilterSuspicious, 90, "sensitive file/credential path accessed: " + target
		}
	}
	return FilterUncertain, 20, ""
}

// --- file_download rules ---

// ZoneId3ExecutableRule flags internet-downloaded executables in staging paths.
type ZoneId3ExecutableRule struct{}

func (r ZoneId3ExecutableRule) Name() string { return "ZoneId3Executable" }
func (r ZoneId3ExecutableRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	// Check the pre-computed risk field from the script
	if risk := stringVal(item, "risk"); risk == "high" {
		return FilterSuspicious, 85, "zone-marked executable in staging path (ZoneId>=3)"
	}
	if risk := stringVal(item, "risk"); risk == "safe" {
		return FilterSafe, 0, ""
	}
	if risk := stringVal(item, "risk"); risk == "medium" {
		return FilterSuspicious, 55, "zone-marked executable (ZoneId>=3, non-safe domain)"
	}
	return FilterUncertain, 20, ""
}

// --- staging_exfiltration rules ---

// TempArchiveRule flags recently created archives in staging directories.
type TempArchiveRule struct{}

func (r TempArchiveRule) Name() string { return "TempArchive" }
func (r TempArchiveRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	path := strings.ToLower(stringVal(item, "file_path", "path"))
	if path == "" {
		return FilterUncertain, 20, ""
	}
	if containsAny(path, `\temp\`, `\tmp\`, `\users\public\`, `\programdata\`) {
		ext := strings.ToLower(stringVal(item, "extension", "file_name"))
		if containsAny(ext, ".zip", ".7z", ".rar", ".tar", ".gz") {
			return FilterSuspicious, 65, "archive file in staging directory: " + path
		}
	}
	return FilterUncertain, 20, ""
}

// VssDeletionRule flags VSS shadow copy deletion commands.
type VssDeletionRule struct{}

func (r VssDeletionRule) Name() string { return "VssDeletion" }
func (r VssDeletionRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	cmd := strings.ToLower(stringVal(item, "command_line", "command"))
	if cmd == "" {
		return FilterUncertain, 20, ""
	}
	if containsAny(cmd, "vssadmin", "shadowcopy", "bcdedit.*recoveryenabled") {
		return FilterSuspicious, 90, "shadow copy deletion command: " + cmd
	}
	return FilterUncertain, 20, ""
}

// ExfilToolRule flags known exfiltration tools in prefetch.
type ExfilToolRule struct{}

var exfilToolNames = []string{"rclone", "winscp", "filezilla", "pscp", "megatools"}

func (r ExfilToolRule) Name() string { return "ExfilTool" }
func (r ExfilToolRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	name := strings.ToLower(stringVal(item, "name", "exe_name", "file_name"))
	for _, tool := range exfilToolNames {
		if strings.Contains(name, tool) {
			return FilterSuspicious, 75, "known exfiltration tool in prefetch: " + name
		}
	}
	return FilterUncertain, 20, ""
}

// --- discovery_recon rules ---

// BloodHoundPatternRule flags BloodHound/SharpHound execution patterns.
type BloodHoundPatternRule struct{}

func (r BloodHoundPatternRule) Name() string { return "BloodHoundPattern" }
func (r BloodHoundPatternRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	cmd := stringVal(item, "command_line", "command")
	proc := strings.ToLower(stringVal(item, "process_name", "exe_name"))
	cmdLower := strings.ToLower(cmd)
	if containsAny(proc, "sharphound", "bloodhound") ||
		containsAny(cmdLower, "sharphound", "bloodhound", "-collectionmethod all") {
		return FilterSuspicious, 100, "BloodHound/SharpHound execution pattern detected"
	}
	return FilterUncertain, 20, ""
}

// ReconCommandRule flags known recon commands from non-admin/non-system accounts.
type ReconCommandRule struct{}

var reconCmdPatterns = []string{
	"nltest /domain_trusts", "dsquery *", "net group \"domain admins\"",
	"whoami /all", "net view /domain", "arp -a", "route print",
}

func (r ReconCommandRule) Name() string { return "ReconCommand" }
func (r ReconCommandRule) Apply(item map[string]interface{}) (FilterResult, int, string) {
	cmd := strings.ToLower(stringVal(item, "command_line", "command"))
	if cmd == "" {
		return FilterUncertain, 20, ""
	}
	for _, pattern := range reconCmdPatterns {
		if strings.Contains(cmd, strings.ToLower(pattern)) {
			return FilterSuspicious, 60, "recon command detected: " + cmd
		}
	}
	return FilterUncertain, 20, ""
}

// ============================================================
// RulesForCheck returns the rule set for a given check ID.
// ============================================================

// RulesForCheck returns the applicable filter rules for a check.
// Returns an empty slice for checks without specialized rules (fallback: all items uncertain).
func RulesForCheck(checkID string) []FilterRule {
	switch checkID {
	case "persistence":
		return []FilterRule{UnsignedTempRunKeyRule{}, UnsignedRunKeyRule{}}
	case "process_execution":
		return []FilterRule{KnownAttackToolRule{}, TempPathExecRule{}}
	case "file_access":
		return []FilterRule{SensitiveFileLNKRule{}}
	case "file_download":
		return []FilterRule{ZoneId3ExecutableRule{}}
	case "staging_exfiltration":
		return []FilterRule{VssDeletionRule{}, TempArchiveRule{}, ExfilToolRule{}}
	case "discovery_recon":
		return []FilterRule{BloodHoundPatternRule{}, ReconCommandRule{}}
	default:
		return nil
	}
}

// ============================================================
// Helper functions
// ============================================================

// stringVal returns the first non-empty string value found among the given keys.
func stringVal(item map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := item[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// getNestedString traverses nested maps by the given keys and returns the lowercased string value.
func getNestedString(item map[string]interface{}, keys ...string) string {
	var cur interface{} = item
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = m[k]
	}
	if s, ok := cur.(string); ok {
		return strings.ToLower(s)
	}
	return ""
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
