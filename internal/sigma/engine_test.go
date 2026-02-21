package sigma

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/iyulab/system-coroner/internal/collector"
)

// testRule builds a minimal Sigma rule YAML for testing.
func testRule(category, title, field, value string) []byte {
	return []byte(`title: ` + title + `
id: test-` + category + `-001
status: experimental
logsource:
  product: system-coroner
  category: ` + category + `
detection:
  selection:
    ` + field + `|contains: '` + value + `'
  condition: selection
level: high
`)
}

func TestEngine_New_LoadsRules(t *testing.T) {
	fakeFS := fstest.MapFS{
		"windows/test.yml": &fstest.MapFile{
			Data: testRule("test_check", "Test Rule", "process_name", "malware"),
		},
	}
	eng, err := New(fakeFS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(eng.rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(eng.rules))
	}
}

func TestEngine_MatchAll_Hit(t *testing.T) {
	fakeFS := fstest.MapFS{
		"c2.yml": &fstest.MapFile{
			Data: testRule("c2_connections", "C2 Test", "process_name", "malware"),
		},
	}
	eng, _ := New(fakeFS)

	results := []collector.Result{
		{
			CheckID: "c2_connections",
			Stdout:  []byte(`{"connections":[{"process_name":"malware.exe","remote_address":"1.2.3.4"}]}`),
		},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].RuleTitle != "C2 Test" {
		t.Errorf("RuleTitle = %q, want %q", matches[0].RuleTitle, "C2 Test")
	}
	if matches[0].CheckID != "c2_connections" {
		t.Errorf("CheckID = %q, want %q", matches[0].CheckID, "c2_connections")
	}
	if matches[0].Level != "high" {
		t.Errorf("Level = %q, want %q", matches[0].Level, "high")
	}
}

func TestEngine_MatchAll_Miss(t *testing.T) {
	fakeFS := fstest.MapFS{
		"c2.yml": &fstest.MapFile{
			Data: testRule("c2_connections", "C2 Test", "process_name", "malware"),
		},
	}
	eng, _ := New(fakeFS)

	results := []collector.Result{
		{
			CheckID: "c2_connections",
			Stdout:  []byte(`{"connections":[{"process_name":"svchost.exe","remote_address":"8.8.8.8"}]}`),
		},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestEngine_MatchAll_CategoryFilter(t *testing.T) {
	// Rule targets c2_connections, result is from persistence — must NOT match
	fakeFS := fstest.MapFS{
		"c2.yml": &fstest.MapFile{
			Data: testRule("c2_connections", "C2 Rule", "process_name", "evil"),
		},
	}
	eng, _ := New(fakeFS)

	results := []collector.Result{
		{
			CheckID: "persistence",
			Stdout:  []byte(`{"registry_run_keys":[{"process_name":"evil.exe"}]}`),
		},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches (category mismatch), got %d", len(matches))
	}
}

func TestEngine_MatchAll_EmptyStdout(t *testing.T) {
	fakeFS := fstest.MapFS{
		"c2.yml": &fstest.MapFile{
			Data: testRule("c2_connections", "C2 Rule", "process_name", "evil"),
		},
	}
	eng, _ := New(fakeFS)

	results := []collector.Result{
		{CheckID: "c2_connections", Stdout: nil},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty stdout, got %d", len(matches))
	}
}

func TestEngine_MatchAll_InvalidJSON(t *testing.T) {
	fakeFS := fstest.MapFS{
		"c2.yml": &fstest.MapFile{
			Data: testRule("c2_connections", "C2 Rule", "process_name", "evil"),
		},
	}
	eng, _ := New(fakeFS)

	results := []collector.Result{
		{CheckID: "c2_connections", Stdout: []byte(`not json`)},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for invalid JSON, got %d", len(matches))
	}
}

func TestExtractEvents_Arrays(t *testing.T) {
	data := map[string]interface{}{
		"connections": []interface{}{
			map[string]interface{}{"process_name": "svchost.exe"},
			map[string]interface{}{"process_name": "cmd.exe"},
		},
		"dns_cache": []interface{}{
			map[string]interface{}{"name": "evil.com"},
		},
	}

	events := extractEvents(data)
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestExtractEvents_NestedObject(t *testing.T) {
	data := map[string]interface{}{
		"wdigest": map[string]interface{}{"UseLogonCredential": 1},
	}

	events := extractEvents(data)
	if len(events) != 1 {
		t.Errorf("expected 1 event from nested object, got %d", len(events))
	}
}

func TestEngine_DefaultRules(t *testing.T) {
	eng, err := NewDefault()
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}
	if len(eng.rules) == 0 {
		t.Error("expected at least one embedded rule")
	}
}

func TestEngine_DefaultRules_MatchCompromisedFixtures(t *testing.T) {
	eng, err := NewDefault()
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}

	// Fixture data mirrors tests/fixtures/windows/compromised/*.json
	c2JSON := []byte(`{"external_connections":[{"process_path":"C:\\Windows\\Temp\\svchost.exe","signature_status":"NotSigned","remote_address":"185.220.101.42"}]}`)
	credJSON := []byte(`{"credential_tools":[{"name":"mimikatz.exe","path":"C:\\Users\\admin\\Downloads\\mimikatz.exe"}]}`)
	persJSON := []byte(`{"base64_detections":[{"pattern":"-EncodedCommand","source":"registry:...","value":"powershell.exe -EncodedCommand JABj..."}]}`)

	results := []collector.Result{
		{CheckID: "c2_connections", Stdout: c2JSON},
		{CheckID: "credential_dump", Stdout: credJSON},
		{CheckID: "persistence", Stdout: persJSON},
	}

	matches := eng.MatchAll(context.Background(), results)
	if len(matches) < 3 {
		t.Errorf("expected at least 3 sigma matches from compromised data, got %d", len(matches))
		for _, m := range matches {
			t.Logf("  match: [%s] %s (check: %s)", m.Level, m.RuleTitle, m.CheckID)
		}
	}
}
