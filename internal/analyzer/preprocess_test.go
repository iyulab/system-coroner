package analyzer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreprocess_InvalidJSON(t *testing.T) {
	result := Preprocess("c2_connections", "windows", "not json at all")
	if result.Data == "" {
		t.Error("result should not be empty")
	}
}

func TestPreprocess_ShortDataPassthrough(t *testing.T) {
	data := `{"key":"short value"}`
	result := Preprocess("c2_connections", "windows", data)
	if result.FilteredIPs != 0 {
		t.Errorf("no IPs to filter, got %d", result.FilteredIPs)
	}
	if result.TruncatedFields != 0 {
		t.Errorf("no fields to truncate, got %d", result.TruncatedFields)
	}
}

func TestPreprocess_KnownGoodIPFiltered(t *testing.T) {
	// RFC1918 address should be filtered from external_connections
	data := `{
		"external_connections": [
			{"remote_address": "10.0.0.5", "process_name": "chrome.exe"},
			{"remote_address": "185.220.101.42", "process_name": "svchost.exe"}
		]
	}`
	result := Preprocess("c2_connections", "windows", data)
	if result.FilteredIPs != 1 {
		t.Errorf("expected 1 filtered IP (10.0.0.5), got %d", result.FilteredIPs)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	conns := parsed["external_connections"].([]interface{})
	if len(conns) != 1 {
		t.Errorf("expected 1 connection remaining, got %d", len(conns))
	}
	remaining := conns[0].(map[string]interface{})
	if remaining["remote_address"] != "185.220.101.42" {
		t.Errorf("wrong connection remaining: %v", remaining["remote_address"])
	}
}

func TestPreprocess_MicrosoftAzureIPFiltered(t *testing.T) {
	// Azure IP 20.x.x.x should be filtered
	data := `{
		"external_connections": [
			{"remote_address": "20.50.100.200", "process_name": "update.exe"},
			{"remote_address": "8.8.8.8", "process_name": "svchost.exe"}
		]
	}`
	result := Preprocess("c2_connections", "windows", data)
	if result.FilteredIPs != 1 {
		t.Errorf("expected 1 filtered IP (Azure), got %d", result.FilteredIPs)
	}
}

func TestPreprocess_AllConnectionsFiltered(t *testing.T) {
	// All RFC1918 — result should be empty array
	data := `{"external_connections": [{"remote_address": "192.168.1.1"}]}`
	result := Preprocess("c2_connections", "windows", data)
	if result.FilteredIPs != 1 {
		t.Errorf("expected 1 filtered, got %d", result.FilteredIPs)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	conns := parsed["external_connections"].([]interface{})
	if len(conns) != 0 {
		t.Errorf("expected empty connections, got %d", len(conns))
	}
}

func TestPreprocess_NonNetworkCheckNoIPFilter(t *testing.T) {
	// persistence check should NOT filter IPs even if present
	data := `{
		"external_connections": [
			{"remote_address": "10.0.0.1"}
		]
	}`
	result := Preprocess("persistence", "windows", data)
	if result.FilteredIPs != 0 {
		t.Errorf("non-network check should not filter IPs, got %d", result.FilteredIPs)
	}
}

func TestPreprocess_LongStringTruncated(t *testing.T) {
	// For account_compromise (event check), strings > 500 chars should be truncated
	longValue := strings.Repeat("A", 600)
	data := `{"event_message": "` + longValue + `"}`
	result := Preprocess("account_compromise", "windows", data)
	if result.TruncatedFields != 1 {
		t.Errorf("expected 1 truncated field, got %d", result.TruncatedFields)
	}
	if strings.Contains(result.Data, strings.Repeat("A", 600)) {
		t.Error("truncated field should not contain the full original value")
	}
	if !strings.Contains(result.Data, "[+") {
		t.Error("truncated field should contain truncation marker")
	}
}

func TestPreprocess_ScriptCheckHigherLimit(t *testing.T) {
	// fileless_attack gets 4000 char limit — 1000 chars should pass through
	value1000 := strings.Repeat("X", 1000)
	data := `{"script_content": "` + value1000 + `"}`
	result := Preprocess("fileless_attack", "windows", data)
	if result.TruncatedFields != 0 {
		t.Errorf("1000-char field in script check should not be truncated, got %d truncations", result.TruncatedFields)
	}
}

func TestPreprocess_ScriptCheckVeryLongTruncated(t *testing.T) {
	// fileless_attack with 5000 chars should truncate
	value5000 := strings.Repeat("Y", 5000)
	data := `{"script_content": "` + value5000 + `"}`
	result := Preprocess("fileless_attack", "windows", data)
	if result.TruncatedFields != 1 {
		t.Errorf("5000-char field in script check should be truncated, got %d", result.TruncatedFields)
	}
}

func TestPreprocess_ValidJSONPreserved(t *testing.T) {
	// Small clean data should be preserved as valid JSON
	data := `{"connections": [{"remote_address": "185.220.101.42", "port": 4444}]}`
	result := Preprocess("c2_connections", "windows", data)
	var parsed interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Errorf("result should be valid JSON: %v", err)
	}
}

func TestIsKnownGoodIP(t *testing.T) {
	tests := []struct {
		ip       string
		wantGood bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.10", true},
		{"192.168.100.1", true},
		{"127.0.0.1", true},
		{"20.50.100.200", true},   // Azure
		{"13.107.5.10", true},     // Microsoft
		{"185.220.101.42", false}, // Tor exit node (not in known-good)
		{"8.8.8.8", false},        // Google DNS (not filtered)
		{"1.1.1.1", false},        // Cloudflare DNS (not filtered)
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		got := isKnownGoodIP(tt.ip)
		if got != tt.wantGood {
			t.Errorf("isKnownGoodIP(%q) = %v, want %v", tt.ip, got, tt.wantGood)
		}
	}
}

func TestExtractRemoteIP(t *testing.T) {
	tests := []struct {
		name   string
		obj    map[string]interface{}
		wantIP string
	}{
		{
			name:   "remote_address field",
			obj:    map[string]interface{}{"remote_address": "1.2.3.4"},
			wantIP: "1.2.3.4",
		},
		{
			name:   "remote_address with port",
			obj:    map[string]interface{}{"remote_address": "1.2.3.4:443"},
			wantIP: "1.2.3.4",
		},
		{
			name:   "destination field",
			obj:    map[string]interface{}{"destination": "5.6.7.8"},
			wantIP: "5.6.7.8",
		},
		{
			name:   "no IP field",
			obj:    map[string]interface{}{"process": "svchost.exe"},
			wantIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRemoteIP(tt.obj)
			if got != tt.wantIP {
				t.Errorf("extractRemoteIP() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestIsConnectionArray(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"external_connections", true},
		{"network_traffic", true},
		{"connection_list", true},
		{"dns_cache", false},
		{"processes", false},
		{"registry_keys", false},
	}

	for _, tt := range tests {
		got := isConnectionArray(tt.key)
		if got != tt.want {
			t.Errorf("isConnectionArray(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestPreprocess_AggregateLargeFailureArray(t *testing.T) {
	// Build 35 logon_failures entries — exceeds aggregateThreshold (30)
	entries := make([]string, 35)
	for i := range entries {
		entries[i] = `{"event_id":4625,"source":"10.0.0.50","account":"admin"}`
	}
	data := `{"logon_failures":[` + strings.Join(entries, ",") + `]}`

	result := Preprocess("account_compromise", "windows", data)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	// logon_failures should be aggregated into a summary object
	lf := parsed["logon_failures"]
	summary, ok := lf.(map[string]interface{})
	if !ok {
		t.Fatalf("expected aggregated summary, got %T: %v", lf, lf)
	}
	if summary["total_count"].(float64) != 35 {
		t.Errorf("total_count = %v, want 35", summary["total_count"])
	}
}

func TestPreprocess_SmallArrayNotAggregated(t *testing.T) {
	// 5 entries — below aggregateThreshold, should remain as array
	data := `{"logon_failures":[{"source":"1.2.3.4"},{"source":"5.6.7.8"}]}`
	result := Preprocess("account_compromise", "windows", data)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	arr, ok := parsed["logon_failures"].([]interface{})
	if !ok {
		t.Fatalf("expected array for small input, got %T", parsed["logon_failures"])
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 entries, got %d", len(arr))
	}
}

func TestPreprocess_NonAggregatableArrayNotSummarized(t *testing.T) {
	// "new_accounts" is not an aggregatable key
	data := `{"new_accounts":[{"account":"user1"},{"account":"user2"},{"account":"user3"},{"account":"user4"},{"account":"user5"},{"account":"user6"},{"account":"user7"},{"account":"user8"},{"account":"user9"},{"account":"user10"},{"account":"user11"},{"account":"user12"},{"account":"user13"},{"account":"user14"},{"account":"user15"},{"account":"user16"},{"account":"user17"},{"account":"user18"},{"account":"user19"},{"account":"user20"},{"account":"user21"},{"account":"user22"},{"account":"user23"},{"account":"user24"},{"account":"user25"},{"account":"user26"},{"account":"user27"},{"account":"user28"},{"account":"user29"},{"account":"user30"},{"account":"user31"}]}`
	result := Preprocess("account_compromise", "windows", data)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	// Should remain as array, not aggregated
	if _, ok := parsed["new_accounts"].([]interface{}); !ok {
		t.Errorf("non-aggregatable array should remain as array, got %T", parsed["new_accounts"])
	}
}

func TestIsAggregatable(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"logon_failures", true},
		{"auth_failures", true},
		{"login_attempts", true},
		{"brute_force_events", true},
		{"new_accounts", false},
		{"external_connections", false},
		{"dns_cache", false},
	}
	for _, tt := range tests {
		got := isAggregatable(tt.key)
		if got != tt.want {
			t.Errorf("isAggregatable(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestTruncateRaw(t *testing.T) {
	short := "hello"
	if got := truncateRaw(short, 100); got != short {
		t.Errorf("short string should pass through: %q", got)
	}

	long := strings.Repeat("x", 200)
	result := truncateRaw(long, 100)
	if len(result) >= 200 {
		t.Errorf("long string should be truncated")
	}
	if !strings.Contains(result, "[+") {
		t.Errorf("truncated string should have marker: %q", result)
	}
}

func TestAddKnownGoodIP_FiltersConnection(t *testing.T) {
	// Register a test IP as known-good
	AddKnownGoodIP("203.0.113.1") // TEST-NET-3 (RFC 5737)

	data := `{"connections":[
		{"remote_address":"203.0.113.1","remote_port":443,"process_name":"test.exe"},
		{"remote_address":"185.220.101.42","remote_port":443,"process_name":"evil.exe"}
	]}`
	result := Preprocess("c2_connections", "windows", data)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	conns, ok := parsed["connections"].([]interface{})
	if !ok {
		t.Fatal("connections field missing or wrong type")
	}

	// 203.0.113.1 should be filtered; 185.220.101.42 should remain
	if len(conns) != 1 {
		t.Errorf("expected 1 connection after filtering, got %d", len(conns))
	}
	if result.FilteredIPs != 1 {
		t.Errorf("expected 1 filtered IP, got %d", result.FilteredIPs)
	}
}

func TestAnnotateBruteForceContext_FailuresOnly(t *testing.T) {
	// Simulate account_compromise data with failures but no successes
	data := `{"logon_failures":[
		{"event_id":"4625","source":"10.10.10.5","type":"failure"},
		{"event_id":"4625","source":"10.10.10.5","type":"failure"},
		{"event_id":"4625","source":"10.10.10.5","type":"failure"}
	]}`
	result := Preprocess("account_compromise", "windows", data)

	if !strings.Contains(result.Data, "_analysis_hint") {
		t.Error("expected _analysis_hint annotation for failures-only data")
	}
	if !strings.Contains(result.Data, "brute-force ATTEMPT") {
		t.Error("expected brute-force ATTEMPT hint text")
	}
}

func TestAnnotateBruteForceContext_WithSuccess(t *testing.T) {
	// Failures + success → no extra annotation needed
	data := `{"logon_events":[
		{"event_id":"4625","type":"failure"},
		{"event_id":"4624","type":"success"}
	]}`
	result := Preprocess("account_compromise", "windows", data)

	if strings.Contains(result.Data, "_analysis_hint") {
		t.Error("should NOT add hint when success events exist")
	}
}

func TestPreprocess_SelfProcessExclusion(t *testing.T) {
	// Register a PID as belonging to the coroner tool
	ResetSelfPIDs()
	AddSelfPID(2668)
	AddSelfPID(2264)
	defer ResetSelfPIDs()

	data := `{"active_processes":[
		{"name":"coroner.exe","pid":2668,"cpu":1.2},
		{"name":"powershell.exe","pid":2264,"cpu":0.5},
		{"name":"svchost.exe","pid":1234,"cpu":0.1},
		{"name":"evil.exe","pid":9999,"cpu":50.0}
	]}`
	result := Preprocess("staging_exfiltration", "windows", data)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	procs, ok := parsed["active_processes"].([]interface{})
	if !ok {
		t.Fatal("active_processes field missing or wrong type")
	}

	// All 4 processes should still be present (annotated, not removed)
	if len(procs) != 4 {
		t.Errorf("expected 4 processes, got %d", len(procs))
	}

	hintCount := 0
	for _, p := range procs {
		pObj := p.(map[string]interface{})
		if _, ok := pObj["_analysis_hint"]; ok {
			hintCount++
		}
	}
	// coroner.exe (PID 2668) and powershell.exe (PID 2264) should be annotated
	if hintCount != 2 {
		t.Errorf("expected 2 annotated processes, got %d", hintCount)
	}
}

func TestPreprocess_NonSelfProcessRetained(t *testing.T) {
	// No self PIDs registered — unrelated PowerShell should NOT get hint
	ResetSelfPIDs()
	defer ResetSelfPIDs()

	data := `{"active_processes":[
		{"name":"powershell.exe","pid":5555,"cpu":0.3},
		{"name":"svchost.exe","pid":1234,"cpu":0.1}
	]}`
	result := Preprocess("staging_exfiltration", "windows", data)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	procs := parsed["active_processes"].([]interface{})
	for _, p := range procs {
		pObj := p.(map[string]interface{})
		if _, ok := pObj["_analysis_hint"]; ok {
			t.Errorf("unrelated process %v should NOT have _analysis_hint", pObj["name"])
		}
	}
}

func TestPreprocess_SelfProcessByName(t *testing.T) {
	// Even without PID registration, process named "coroner" should be annotated
	// when processing staging_exfiltration check (isProcessCheck returns true)
	ResetSelfPIDs()
	defer ResetSelfPIDs()

	data := `{"active_processes":[
		{"name":"coroner","pid":9876,"cpu":1.0},
		{"name":"nginx","pid":100,"cpu":0.5}
	]}`
	result := Preprocess("staging_exfiltration", "windows", data)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Data), &parsed); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	procs := parsed["active_processes"].([]interface{})
	coronerProc := procs[0].(map[string]interface{})
	if _, ok := coronerProc["_analysis_hint"]; !ok {
		t.Error("coroner process should have _analysis_hint even without PID registration")
	}
	nginxProc := procs[1].(map[string]interface{})
	if _, ok := nginxProc["_analysis_hint"]; ok {
		t.Error("nginx process should NOT have _analysis_hint")
	}
}
