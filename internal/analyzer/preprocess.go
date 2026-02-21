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

func init() {
	for _, cidr := range knownGoodCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedKnownGoodNets = append(parsedKnownGoodNets, n)
		}
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

// truncateRaw applies a simple length limit to non-JSON string data.
func truncateRaw(data string, maxLen int) string {
	if len(data) <= maxLen {
		return data
	}
	return data[:maxLen] + fmt.Sprintf("...[+%d chars]", len(data)-maxLen)
}
