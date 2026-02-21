package analyzer

import (
	"testing"
)

func TestKnownAttackToolRule(t *testing.T) {
	rule := KnownAttackToolRule{}

	tests := []struct {
		name    string
		item    map[string]interface{}
		wantRes FilterResult
		wantMin int
	}{
		{
			name:    "mimikatz by name",
			item:    map[string]interface{}{"name": "MIMIKATZ.EXE"},
			wantRes: FilterSuspicious,
			wantMin: 90,
		},
		{
			name:    "attack_tool flag true",
			item:    map[string]interface{}{"name": "custom.exe", "attack_tool": true},
			wantRes: FilterSuspicious,
			wantMin: 90,
		},
		{
			name:    "normal process",
			item:    map[string]interface{}{"name": "notepad.exe"},
			wantRes: FilterUncertain,
			wantMin: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, score, _ := rule.Apply(tt.item)
			if res != tt.wantRes {
				t.Errorf("result = %d, want %d", res, tt.wantRes)
			}
			if tt.wantMin > 0 && score < tt.wantMin {
				t.Errorf("score = %d, want >= %d", score, tt.wantMin)
			}
		})
	}
}

func TestTempPathExecRule(t *testing.T) {
	rule := TempPathExecRule{}

	tests := []struct {
		name    string
		path    string
		wantRes FilterResult
	}{
		{"temp path", `C:\Users\bob\AppData\Local\Temp\evil.exe`, FilterSuspicious},
		{"users public", `C:\Users\Public\run.exe`, FilterSuspicious},
		{"system32", `C:\Windows\System32\notepad.exe`, FilterUncertain},
		{"program files", `C:\Program Files\App\app.exe`, FilterUncertain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := map[string]interface{}{"process_path": tt.path}
			res, _, _ := rule.Apply(item)
			if res != tt.wantRes {
				t.Errorf("path %q: result = %d, want %d", tt.path, res, tt.wantRes)
			}
		})
	}
}

func TestSensitiveFileLNKRule(t *testing.T) {
	rule := SensitiveFileLNKRule{}

	tests := []struct {
		name    string
		target  string
		wantRes FilterResult
	}{
		{"SAM hive", `C:\Windows\System32\config\SAM`, FilterSafe}, // Windows path → safe
		{"NTDS.dit", `C:\Windows\NTDS\NTDS.dit`, FilterSafe},       // Windows path → safe
		{"pfx on desktop", `C:\Users\admin\Desktop\admin.pfx`, FilterSuspicious},
		{"id_rsa", `/home/user/.ssh/id_rsa`, FilterSuspicious},
		{"normal doc", `C:\Users\alice\Documents\report.docx`, FilterUncertain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := map[string]interface{}{"target_path": tt.target}
			res, _, _ := rule.Apply(item)
			if res != tt.wantRes {
				t.Errorf("target %q: result = %d, want %d", tt.target, res, tt.wantRes)
			}
		})
	}
}

func TestVssDeletionRule(t *testing.T) {
	rule := VssDeletionRule{}

	tests := []struct {
		cmd     string
		wantRes FilterResult
	}{
		{"vssadmin delete shadows /all /quiet", FilterSuspicious},
		{"wmic shadowcopy delete", FilterSuspicious},
		{"dir C:\\", FilterUncertain},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			item := map[string]interface{}{"command_line": tt.cmd}
			res, _, _ := rule.Apply(item)
			if res != tt.wantRes {
				t.Errorf("cmd %q: result = %d, want %d", tt.cmd, res, tt.wantRes)
			}
		})
	}
}

func TestBloodHoundPatternRule(t *testing.T) {
	rule := BloodHoundPatternRule{}

	tests := []struct {
		proc    string
		cmd     string
		wantRes FilterResult
	}{
		{"SharpHound.exe", "SharpHound.exe -CollectionMethod All", FilterSuspicious},
		{"cmd.exe", "cmd /c dir", FilterUncertain},
		{"powershell.exe", "Invoke-BloodHound -CollectionMethod All", FilterSuspicious},
	}
	for _, tt := range tests {
		t.Run(tt.proc, func(t *testing.T) {
			item := map[string]interface{}{"process_name": tt.proc, "command_line": tt.cmd}
			res, _, _ := rule.Apply(item)
			if res != tt.wantRes {
				t.Errorf("proc=%q cmd=%q: result = %d, want %d", tt.proc, tt.cmd, res, tt.wantRes)
			}
		})
	}
}

func TestApplyRules_ScoreNormalization(t *testing.T) {
	items := []map[string]interface{}{
		{"name": "mimikatz.exe", "attack_tool": true}, // suspicious score=100
		{"name": "notepad.exe"},                       // uncertain
		{"name": "procdump.exe", "attack_tool": true}, // suspicious score=95+
	}
	rules := RulesForCheck("process_execution")
	crs := ApplyRules("process_execution", items, rules)

	if crs.SuspiciousCount < 2 {
		t.Errorf("expected >= 2 suspicious items, got %d", crs.SuspiciousCount)
	}
	if crs.Score <= 0 {
		t.Errorf("expected positive score, got %d", crs.Score)
	}
	if crs.Score > 100 {
		t.Errorf("score capped at 100, got %d", crs.Score)
	}
}

func TestApplyRules_AllSafe(t *testing.T) {
	// Windows path executables should all be safe via TempPathExec uncertainty → no SAFE rule
	// Use explicit safe test: rule.Apply returns SAFE
	rule := SensitiveFileLNKRule{}
	item := map[string]interface{}{"target_path": `C:\Windows\System32\notepad.exe`}
	res, score, _ := rule.Apply(item)
	if res != FilterSafe {
		t.Errorf("expected FilterSafe for Windows path, got %d", res)
	}
	if score != 0 {
		t.Errorf("expected score 0 for safe item, got %d", score)
	}
}

func TestSuspiciousAndUncertainItems_ExcludesSafe(t *testing.T) {
	items := []map[string]interface{}{
		{"target_path": `C:\Windows\System32\SAM`},            // Windows path → safe
		{"target_path": `C:\Users\admin\Desktop\admin.pfx`},   // suspicious
		{"target_path": `C:\Users\bob\Documents\report.docx`}, // uncertain
	}
	rules := RulesForCheck("file_access")
	crs := ApplyRules("file_access", items, rules)
	filtered := SuspiciousAndUncertainItems(crs)

	// SAM in Windows path is safe (filtered out); pfx and report pass through
	for _, item := range filtered {
		target := ""
		if v, ok := item["target_path"].(string); ok {
			target = v
		}
		if target == `C:\Windows\System32\SAM` {
			t.Error("safe item should have been excluded")
		}
	}
}

func TestRulesForCheck_UnknownCheck(t *testing.T) {
	rules := RulesForCheck("nonexistent_check")
	if rules != nil && len(rules) != 0 {
		t.Errorf("expected nil/empty rules for unknown check, got %d rules", len(rules))
	}
}
