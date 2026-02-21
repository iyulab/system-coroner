package platform

import (
	"runtime"
	"testing"
)

func TestDetectOS(t *testing.T) {
	got := DetectOS()
	if got != runtime.GOOS {
		t.Errorf("DetectOS() = %q, want %q", got, runtime.GOOS)
	}
}

func TestWindowsChecks_Count(t *testing.T) {
	checks := WindowsChecks()
	if len(checks) < 9 {
		t.Errorf("WindowsChecks() returned %d checks, want at least 9", len(checks))
	}
}

func TestWindowsChecks_UniqueIDs(t *testing.T) {
	checks := WindowsChecks()
	seen := make(map[string]bool)
	for _, c := range checks {
		if seen[c.ID] {
			t.Errorf("duplicate check ID: %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestWindowsChecks_AllHaveRequiredFields(t *testing.T) {
	checks := WindowsChecks()
	for _, c := range checks {
		if c.ID == "" {
			t.Error("check has empty ID")
		}
		if c.Name == "" {
			t.Errorf("check %q has empty Name", c.ID)
		}
		if c.Script == "" {
			t.Errorf("check %q has empty Script", c.ID)
		}
		if c.Timeout == 0 {
			t.Errorf("check %q has zero Timeout", c.ID)
		}
		if c.OutputFormat == "" {
			t.Errorf("check %q has empty OutputFormat", c.ID)
		}
	}
}

func TestFilterChecks_NoFilter(t *testing.T) {
	checks := WindowsChecks()
	filtered := FilterChecks(checks, nil)
	if len(filtered) != len(checks) {
		t.Errorf("FilterChecks with nil filter: got %d, want %d", len(filtered), len(checks))
	}
}

func TestFilterChecks_Subset(t *testing.T) {
	checks := WindowsChecks()
	filtered := FilterChecks(checks, []string{"c2_connections", "log_tampering"})
	if len(filtered) != 2 {
		t.Errorf("FilterChecks with 2 IDs: got %d, want 2", len(filtered))
	}
	ids := make(map[string]bool)
	for _, c := range filtered {
		ids[c.ID] = true
	}
	if !ids["c2_connections"] || !ids["log_tampering"] {
		t.Errorf("FilterChecks returned wrong IDs: %v", ids)
	}
}

func TestFilterChecks_NonExistent(t *testing.T) {
	checks := WindowsChecks()
	filtered := FilterChecks(checks, []string{"nonexistent"})
	if len(filtered) != 0 {
		t.Errorf("FilterChecks with nonexistent ID: got %d, want 0", len(filtered))
	}
}

func TestFilterEnabled_NilMap(t *testing.T) {
	checks := WindowsChecks()
	filtered := FilterEnabled(checks, nil)
	if len(filtered) != len(checks) {
		t.Errorf("FilterEnabled with nil map: got %d, want %d", len(filtered), len(checks))
	}
}

func TestFilterEnabled_DisableOne(t *testing.T) {
	checks := WindowsChecks()
	enabled := map[string]bool{
		"webshell": false,
	}
	filtered := FilterEnabled(checks, enabled)
	if len(filtered) != len(checks)-1 {
		t.Errorf("FilterEnabled disabling 1: got %d, want %d", len(filtered), len(checks)-1)
	}
	for _, c := range filtered {
		if c.ID == "webshell" {
			t.Error("webshell should be filtered out")
		}
	}
}

func TestLinuxChecks_Count(t *testing.T) {
	checks := LinuxChecks()
	if len(checks) != 9 {
		t.Errorf("LinuxChecks() returned %d checks, want 9", len(checks))
	}
}

func TestLinuxChecks_UniqueIDs(t *testing.T) {
	checks := LinuxChecks()
	seen := make(map[string]bool)
	for _, c := range checks {
		if seen[c.ID] {
			t.Errorf("duplicate linux check ID: %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestLinuxChecks_AllHaveRequiredFields(t *testing.T) {
	checks := LinuxChecks()
	for _, c := range checks {
		if c.ID == "" {
			t.Error("linux check has empty ID")
		}
		if c.Name == "" {
			t.Errorf("linux check %q has empty Name", c.ID)
		}
		if c.Script == "" {
			t.Errorf("linux check %q has empty Script", c.ID)
		}
		if c.Timeout == 0 {
			t.Errorf("linux check %q has zero Timeout", c.ID)
		}
		if c.OutputFormat == "" {
			t.Errorf("linux check %q has empty OutputFormat", c.ID)
		}
	}
}
