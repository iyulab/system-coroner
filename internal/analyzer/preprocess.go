package analyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

const (
	// maxEventMessageLen is the maximum length for event message strings (e.g. command lines, log entries).
	maxEventMessageLen = 500
	// maxScriptTextLen is the maximum length for script/code content fields.
	maxScriptTextLen = 4000
	// maxDefaultFieldLen is the default maximum length for other string fields.
	maxDefaultFieldLen = 2000
)

// knownGoodCIDRs are IP ranges that represent known-legitimate infrastructure.
// Connections to these addresses are filtered from c2_connections data to reduce noise.
var knownGoodCIDRs = []string{
	// RFC 1918 private ranges
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	// Link-local
	"169.254.0.0/16",
	// Microsoft Azure (major blocks)
	"13.64.0.0/11",
	"13.107.0.0/16",
	"20.0.0.0/8",
	"23.96.0.0/13",
	"40.64.0.0/10",
	"52.0.0.0/8",
	"65.52.0.0/14",
	"104.40.0.0/13",
	"104.208.0.0/13",
	"168.61.0.0/16",
	// Windows Update / Microsoft CDN
	"23.32.0.0/11",
}

// parsedKnownGoodNets is the parsed form of knownGoodCIDRs, initialized on first use.
var parsedKnownGoodNets []*net.IPNet

// extraKnownGoodIPs holds additional IPs added at runtime (e.g. the host's own external IP).
var extraKnownGoodIPs []*net.IPNet

// knownGoodPaths holds operator-declared directories/files that are expected infrastructure.
// Artifacts whose paths start with one of these values are annotated as known-good (FP-003).
var knownGoodPaths []string

func init() {
	for _, cidr := range knownGoodCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedKnownGoodNets = append(parsedKnownGoodNets, n)
		}
	}
}

// AddKnownGoodPath registers a directory or file path as known-good operator infrastructure.
// Artifacts whose paths begin with this prefix will be annotated so the LLM does not treat
// them as attack artifacts. Accepts absolute paths; case-insensitive matching on Windows.
func AddKnownGoodPath(path string) {
	path = strings.TrimSpace(path)
	if path != "" {
		knownGoodPaths = append(knownGoodPaths, path)
	}
}

// AddKnownGoodIP registers an additional IP address or CIDR as known-good.
// This is used to exclude the host's own external IP from C2 detection.
// Accepts both bare IPs (treated as /32) and CIDR notation.
func AddKnownGoodIP(ipOrCIDR string) {
	ipOrCIDR = strings.TrimSpace(ipOrCIDR)
	if ipOrCIDR == "" {
		return
	}
	// Try CIDR first
	if strings.Contains(ipOrCIDR, "/") {
		_, n, err := net.ParseCIDR(ipOrCIDR)
		if err == nil {
			extraKnownGoodIPs = append(extraKnownGoodIPs, n)
		}
		return
	}
	// Bare IP → /32
	ip := net.ParseIP(ipOrCIDR)
	if ip == nil {
		return
	}
	_, n, _ := net.ParseCIDR(ipOrCIDR + "/32")
	if n != nil {
		extraKnownGoodIPs = append(extraKnownGoodIPs, n)
	}
}

// PreprocessResult holds the result of preprocessing along with reduction metrics.
type PreprocessResult struct {
	Data            string
	FilteredIPs     int // number of known-good connections filtered
	TruncatedFields int // number of string fields truncated
}

// Preprocess applies data reduction transformations to collector output before LLM analysis.
// It filters known-good IPs from network data and truncates overlong string fields to reduce
// token consumption. Returns the processed data; on JSON parse failure returns original data.
func Preprocess(checkID, osName, data string) PreprocessResult {
	var parsed interface{}
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		// Not valid JSON — apply raw string truncation only
		truncated := truncateRaw(data, maxScriptTextLen)
		truncCount := 0
		if truncated != data {
			truncCount = 1
		}
		return PreprocessResult{Data: truncated, TruncatedFields: truncCount}
	}

	ctx := &preprocessContext{checkID: checkID}
	processed := ctx.processValue(parsed)

	// Apply Known-Good IP filtering for network connection checks
	if isNetworkCheck(checkID) {
		processed = ctx.filterKnownGoodIPs(processed)
	}

	// Apply event aggregation to collapse large repetitive arrays
	if obj, ok := processed.(map[string]interface{}); ok {
		processed = ctx.aggregateRepeatEvents(obj)
	}

	// FP-002: Annotate account_compromise data with success/failure analysis note.
	// Brute-force failures alone (without 4624 success events) should not be CRITICAL.
	if checkID == "account_compromise" {
		if obj, ok := processed.(map[string]interface{}); ok {
			processed = annotateBruteForceContext(obj)
		}
	}

	// FP-003: Annotate items whose paths fall within operator-declared known-good directories.
	// This prevents coroner's own working directory and output from being flagged as attack staging.
	if len(knownGoodPaths) > 0 {
		if obj, ok := processed.(map[string]interface{}); ok {
			processed = annotateKnownGoodPaths(obj)
		}
	}

	result, err := json.Marshal(processed)
	if err != nil {
		return PreprocessResult{Data: data}
	}
	return PreprocessResult{
		Data:            string(result),
		FilteredIPs:     ctx.filteredIPs,
		TruncatedFields: ctx.truncatedFields,
	}
}

// preprocessContext carries state during recursive JSON traversal.
type preprocessContext struct {
	checkID         string
	filteredIPs     int
	truncatedFields int
}

// processValue recursively walks a JSON value and applies transformations.
func (c *preprocessContext) processValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return c.processObject(val)
	case []interface{}:
		return c.processArray(val)
	case string:
		return c.truncateString(val)
	default:
		return v
	}
}

func (c *preprocessContext) processObject(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		result[k] = c.processValue(v)
	}
	return result
}

func (c *preprocessContext) processArray(arr []interface{}) []interface{} {
	result := make([]interface{}, len(arr))
	for i, v := range arr {
		result[i] = c.processValue(v)
	}
	return result
}

// truncateString applies length limits based on check context.
func (c *preprocessContext) truncateString(s string) string {
	maxLen := maxDefaultFieldLen
	if isScriptCheck(c.checkID) {
		maxLen = maxScriptTextLen
	} else if isEventCheck(c.checkID) {
		maxLen = maxEventMessageLen
	}
	if len(s) <= maxLen {
		return s
	}
	c.truncatedFields++
	return s[:maxLen] + fmt.Sprintf("...[+%d chars]", len(s)-maxLen)
}

// filterKnownGoodIPs removes entries from connection arrays where the remote IP
// is within a known-good CIDR range (RFC1918, Microsoft Azure, etc.).
func (c *preprocessContext) filterKnownGoodIPs(v interface{}) interface{} {
	obj, ok := v.(map[string]interface{})
	if !ok {
		return v
	}

	result := make(map[string]interface{}, len(obj))
	for k, val := range obj {
		arr, ok := val.([]interface{})
		if !ok {
			result[k] = val
			continue
		}

		// Only filter arrays that look like connection lists
		if !isConnectionArray(k) {
			result[k] = val
			continue
		}

		filtered := make([]interface{}, 0, len(arr))
		for _, item := range arr {
			connObj, ok := item.(map[string]interface{})
			if !ok {
				filtered = append(filtered, item)
				continue
			}
			ip := extractRemoteIP(connObj)
			if ip != "" && isKnownGoodIP(ip) {
				c.filteredIPs++
				continue
			}
			filtered = append(filtered, item)
		}
		result[k] = filtered
	}
	return result
}

// extractRemoteIP extracts the remote IP from a connection object, trying common field names.
func extractRemoteIP(obj map[string]interface{}) string {
	for _, key := range []string{"remote_address", "remote_ip", "destination", "RemoteAddress", "ip"} {
		v, ok := obj[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		// Strip port if present (e.g. "1.2.3.4:443")
		if host, _, err := net.SplitHostPort(s); err == nil {
			return host
		}
		return s
	}
	return ""
}

// isKnownGoodIP checks whether an IP falls within any known-good CIDR range.
func isKnownGoodIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range parsedKnownGoodNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, n := range extraKnownGoodIPs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isNetworkCheck returns true for checks that involve network connection data.
func isNetworkCheck(checkID string) bool {
	return checkID == "c2_connections" || checkID == "lateral_movement"
}

// isScriptCheck returns true for checks where data may contain inline script code.
func isScriptCheck(checkID string) bool {
	switch checkID {
	case "fileless_attack", "lolbin_abuse", "persistence":
		return true
	}
	return false
}

// isEventCheck returns true for checks that produce Windows Event Log entries.
func isEventCheck(checkID string) bool {
	switch checkID {
	case "account_compromise", "log_tampering", "credential_dump":
		return true
	}
	return false
}

// isConnectionArray returns true if an array field name suggests it holds network connections.
func isConnectionArray(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "connection") ||
		strings.Contains(lower, "network") ||
		strings.Contains(lower, "traffic")
}

// aggregateRepeatEvents collapses large arrays of similar log entries into summaries.
// If an array named by an "aggregatable" key exceeds aggregateThreshold entries,
// it is replaced with a summary map: {"count": N, "key_breakdown": {key: count}}.
func (c *preprocessContext) aggregateRepeatEvents(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		arr, ok := v.([]interface{})
		if !ok || !isAggregatable(k) || len(arr) <= aggregateThreshold {
			result[k] = v
			continue
		}

		// Aggregate by the most relevant grouping key for this array type.
		groupKey := aggregateKeyFor(k)
		counts := make(map[string]int)
		for _, item := range arr {
			itemObj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			keyVal := stringField(itemObj, groupKey)
			if keyVal == "" {
				keyVal = "(unknown)"
			}
			counts[keyVal]++
		}

		result[k] = map[string]interface{}{
			"total_count":   len(arr),
			"summary":       fmt.Sprintf("%d entries aggregated (threshold: %d)", len(arr), aggregateThreshold),
			"group_by":      groupKey,
			"key_breakdown": counts,
		}
		c.truncatedFields++ // reuse counter to track aggregations
	}
	return result
}

const aggregateThreshold = 30 // arrays larger than this are summarized

// isAggregatable returns true for array field names that contain repetitive log events.
func isAggregatable(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "failure") ||
		strings.Contains(lower, "fail") ||
		strings.Contains(lower, "logon") ||
		strings.Contains(lower, "auth") ||
		strings.Contains(lower, "brute") ||
		strings.Contains(lower, "attempt")
}

// aggregateKeyFor returns the best field name to group by for a given array key.
func aggregateKeyFor(arrayKey string) string {
	lower := strings.ToLower(arrayKey)
	switch {
	case strings.Contains(lower, "logon") || strings.Contains(lower, "login") || strings.Contains(lower, "auth"):
		return "source"
	case strings.Contains(lower, "failure") || strings.Contains(lower, "fail"):
		return "source"
	default:
		return "source"
	}
}

// stringField returns the string value of a field in a JSON object, trying common name variants.
func stringField(obj map[string]interface{}, key string) string {
	if v, ok := obj[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	// Try common variants
	for _, k := range []string{"source_ip", "ip", "address", "from", "workstation"} {
		if k == key {
			continue
		}
		if v, ok := obj[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// annotateBruteForceContext adds an analysis hint to account_compromise data.
// If the data contains failed logon events but no corresponding 4624 success events,
// it annotates the data so the LLM does not escalate failures-only to CRITICAL.
// This addresses FP-002: brute-force with 0 successes should not be treated as
// confirmed account compromise.
func annotateBruteForceContext(obj map[string]interface{}) map[string]interface{} {
	hasFailures := false
	hasSuccesses := false
	failureCount := 0

	for _, v := range obj {
		arr, ok := v.([]interface{})
		if !ok {
			continue
		}
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// Check event_id or type fields
			evtID := fmt.Sprintf("%v", m["event_id"])
			evtType := strings.ToLower(fmt.Sprintf("%v", m["type"]))
			if evtID == "4625" || strings.Contains(evtType, "fail") {
				hasFailures = true
				failureCount++
			}
			if evtID == "4624" || strings.Contains(evtType, "success") {
				hasSuccesses = true
			}
		}
	}

	if hasFailures && !hasSuccesses && failureCount > 0 {
		result := make(map[string]interface{}, len(obj)+1)
		for k, v := range obj {
			result[k] = v
		}
		result["_analysis_hint"] = fmt.Sprintf(
			"IMPORTANT: %d failed logon attempts detected but NO successful logons (4624) found. "+
				"Authentication failures alone without successful access indicate a brute-force ATTEMPT, "+
				"not confirmed compromise. Confidence should be at most 'medium' unless other "+
				"corroborating evidence exists (lateral movement, persistence, etc.).",
			failureCount,
		)
		return result
	}
	return obj
}

// annotateKnownGoodPaths walks top-level arrays in a check's JSON output and annotates
// items whose path fields start with a known-good operator path. This prevents coroner's
// own output directory, config files, and tool directories from being flagged (FP-003).
func annotateKnownGoodPaths(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(obj)+1)
	matchedPaths := make(map[string]struct{})

	for k, v := range obj {
		arr, ok := v.([]interface{})
		if !ok {
			result[k] = v
			continue
		}

		annotated := make([]interface{}, 0, len(arr))
		for _, item := range arr {
			itemObj, ok := item.(map[string]interface{})
			if !ok {
				annotated = append(annotated, item)
				continue
			}

			if matched, kp := itemMatchesKnownGoodPath(itemObj); matched {
				copy := copyMap(itemObj)
				copy["_analysis_hint"] = "This path is within the operator's declared known-good directory (" +
					kp + "). It is expected operator/tool infrastructure, NOT an attack artifact — do not flag it."
				annotated = append(annotated, copy)
				matchedPaths[kp] = struct{}{}
			} else {
				annotated = append(annotated, itemObj)
			}
		}
		result[k] = annotated
	}

	// Add a top-level hint summarising which known-good paths were observed.
	if len(matchedPaths) > 0 {
		paths := make([]string, 0, len(matchedPaths))
		for p := range matchedPaths {
			paths = append(paths, p)
		}
		result["_operator_baseline"] = "The following paths are declared as known-good operator infrastructure and must NOT be treated as attack artifacts: " +
			strings.Join(paths, ", ")
	}

	return result
}

// itemMatchesKnownGoodPath checks whether any path-like field in the item starts with
// a registered known-good path. Returns (true, matchedPath) or (false, "").
func itemMatchesKnownGoodPath(item map[string]interface{}) (bool, string) {
	pathFields := []string{"value", "path", "file_path", "target_path", "execute", "arguments", "name"}
	for _, field := range pathFields {
		v, ok := item[field]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		sLower := strings.ToLower(s)
		for _, kp := range knownGoodPaths {
			if strings.HasPrefix(sLower, strings.ToLower(kp)) {
				return true, kp
			}
		}
	}
	return false, ""
}

// truncateRaw applies a simple length limit to non-JSON string data.
func truncateRaw(data string, maxLen int) string {
	if len(data) <= maxLen {
		return data
	}
	return data[:maxLen] + fmt.Sprintf("...[+%d chars]", len(data)-maxLen)
}
