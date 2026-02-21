package scripts

import (
	"io/fs"
	"strings"
	"testing"
)

func TestWindowsScripts_EmbedAll9(t *testing.T) {
	expectedScripts := []string{
		"windows/c2_connections.ps1",
		"windows/account_compromise.ps1",
		"windows/persistence.ps1",
		"windows/lolbin_abuse.ps1",
		"windows/fileless_attack.ps1",
		"windows/log_tampering.ps1",
		"windows/credential_dump.ps1",
		"windows/lateral_movement.ps1",
		"windows/webshell.ps1",
	}

	for _, script := range expectedScripts {
		data, err := fs.ReadFile(WindowsScripts, script)
		if err != nil {
			t.Errorf("failed to read embedded script %s: %v", script, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("embedded script %s is empty", script)
			continue
		}
		// Verify it's a PowerShell script
		if !strings.Contains(string(data), "ConvertTo-Json") {
			t.Errorf("script %s doesn't contain ConvertTo-Json (might not be a valid collection script)", script)
		}
	}
}

func TestWindowsScripts_Count(t *testing.T) {
	var count int
	fs.WalkDir(WindowsScripts, "windows", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".ps1") {
			count++
		}
		return nil
	})

	if count < 9 {
		t.Errorf("expected at least 9 Windows scripts, got %d", count)
	}
}

func TestWindowsScripts_ValidJSON_OutputPattern(t *testing.T) {
	// Each script should output JSON with a "check" field
	entries, err := fs.ReadDir(WindowsScripts, "windows")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".ps1") {
			continue
		}
		data, _ := fs.ReadFile(WindowsScripts, "windows/"+entry.Name())
		content := string(data)

		// Verify script follows the template pattern
		checkID := strings.TrimSuffix(entry.Name(), ".ps1")
		if !strings.Contains(content, `check`) {
			t.Errorf("%s: missing 'check' field in output", entry.Name())
		}
		if !strings.Contains(content, checkID) {
			t.Errorf("%s: script doesn't reference its own check ID %q", entry.Name(), checkID)
		}
		if !strings.Contains(content, "errors") && !strings.Contains(content, "error") {
			t.Errorf("%s: missing error handling", entry.Name())
		}
	}
}

func TestLinuxScripts_EmbedAll9(t *testing.T) {
	expectedScripts := []string{
		"linux/c2_connections.sh",
		"linux/persistence.sh",
		"linux/log_tampering.sh",
		"linux/account_compromise.sh",
		"linux/credential_dump.sh",
		"linux/fileless_attack.sh",
		"linux/lolbin_abuse.sh",
		"linux/lateral_movement.sh",
		"linux/webshell.sh",
	}

	for _, script := range expectedScripts {
		data, err := fs.ReadFile(LinuxScripts, script)
		if err != nil {
			t.Errorf("failed to read embedded script %s: %v", script, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("embedded script %s is empty", script)
			continue
		}
		// Verify it starts with shebang
		if !strings.HasPrefix(string(data), "#!/bin/bash") {
			t.Errorf("script %s doesn't start with #!/bin/bash", script)
		}
		// Verify it outputs JSON with check field
		if !strings.Contains(string(data), "\"check\"") {
			t.Errorf("script %s doesn't contain 'check' field in output", script)
		}
	}
}

func TestLinuxScripts_Count(t *testing.T) {
	var count int
	fs.WalkDir(LinuxScripts, "linux", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sh") {
			count++
		}
		return nil
	})

	if count != 9 {
		t.Errorf("expected 9 Linux detection scripts, got %d", count)
	}
}
